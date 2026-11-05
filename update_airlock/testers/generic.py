"""Generic tester for any container.

Two runs in the sandbox: BASELINE with the image running now and CANDIDATE with the new image, each with a
fresh COPY of the writable data mounts (read-only mounts such as config files are passed read-only; sockets
and the skip list - docker.sock! - never). Same environment, command and user as production.

Checks (a check only fails if the baseline passes it and the candidate does not - many containers cannot
do their real job without network, which is the same for both images):
  starts and stays up for `stable_seconds`, healthcheck healthy (if the image has one),
  HTTP answer < 500 on `http_port` (if configured).

test options (containers.<name>.test):
  stable_seconds: 60, timeout_minutes: 10, http_port: 0, http_path: /,
  cap_add: [CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID, KILL], copy_exclude: [], copy_data: true
"""

from __future__ import annotations

import logging
import stat
import time
from pathlib import Path

import requests

from .. import dockerapi
from ..copying import copy_tree, dir_size, remove_tree
from ..inventory import Current, data_mounts
from ..sandbox import Sandbox
from ..util import AirlockError, Deadline, human_bytes, run
from . import TestResult

log = logging.getLogger("update_airlock.tester.generic")

DEFAULT_CAPS = ["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID", "KILL"]


def env_without_image_defaults(info: dict, image_info: dict) -> dict[str, str]:
    img_env = set(((image_info or {}).get("Config") or {}).get("Env") or [])
    out = {}
    for e in info["Config"].get("Env") or []:
        if e in img_env or "=" not in e:
            continue
        k, v = e.split("=", 1)
        out[k] = v
    return out


def _is_socket(path: str) -> bool:
    try:
        return stat.S_ISSOCK(Path(path).stat().st_mode)
    except OSError:
        return False


class GenericTester:
    def __init__(self, cfg, ccfg, current: Current, candidate_ref: str, sandbox: Sandbox, work: Path,
                 faults: list[str] | None = None, **_):
        self.cfg, self.c, self.cur, self.candidate, self.sb, self.work = cfg, ccfg, current, candidate_ref, sandbox, work
        self.faults = faults or []
        self.opt = {"stable_seconds": 60, "timeout_minutes": 10, "cap_add": DEFAULT_CAPS, "http_port": 0,
                    "http_path": "/", "copy_exclude": [], "copy_data": True, **(ccfg.raw.get("test") or {})}

    def _mounts(self, role: str) -> list[tuple[str, str, str]]:
        skip = self.c.raw["backup"]["skip_mounts"]
        out = []
        limit = float(self.c.raw["backup"].get("max_size_gb", 20)) * 1024 ** 3
        rw = {m.target for m in data_mounts(self.cur, skip)} if self.opt["copy_data"] else set()
        for i, m in enumerate(self.cur.mounts):
            if any(m.target == s or m.target.startswith(s.rstrip("/") + "/") or m.host_path == s for s in skip):
                continue
            if _is_socket(m.host_path):
                continue
            if not m.rw:
                out.append((m.host_path, m.target, "ro"))
                continue
            if m.target not in rw:
                continue
            src = Path(m.host_path)
            size = dir_size(src, self.opt["copy_exclude"]) if src.is_dir() else src.stat().st_size
            if size > limit:
                raise AirlockError(f"data mount {m.target} is {human_bytes(size)} (> backup.max_size_gb)")
            dst = self.work / role / f"mount{i}"
            copy_tree(src, dst, self.opt["copy_exclude"])
            out.append((str(dst), m.target, "rw"))
        return out

    def _run_one(self, role: str, image: str, deadline: Deadline, res: TestResult) -> dict:
        info, img = self.cur.info, self.cur.image_info
        cfg = info["Config"]
        img_cfg = img.get("Config") or {}
        cmd = cfg.get("Cmd") if cfg.get("Cmd") != img_cfg.get("Cmd") else None
        entry = cfg.get("Entrypoint") if cfg.get("Entrypoint") != img_cfg.get("Entrypoint") else None
        user = cfg.get("User") if cfg.get("User") != img_cfg.get("User") else None
        # `docker run --entrypoint` takes one executable; further entrypoint words go in front of the cmd.
        if entry:
            cmd = list(entry[1:]) + list(cmd if cmd is not None else (img_cfg.get("Cmd") or []))
        cname = self.sb.run_container(
            f"{self.cur.name}-{role}"[:40], image, mounts=self._mounts(role),
            env=env_without_image_defaults(info, img), cmd=cmd or None, user=user or None,
            entrypoint=(entry[0] if entry else None), cap_add=self.opt["cap_add"])
        f: dict = {"container": cname}
        if role == "candidate":
            sec = self.sb.inspect_security(cname)
            res.isolation["test_container"] = sec
            problems = self.sb.security_ok(sec)
            if not res.add("isolation of the test container (docker inspect)", not problems, "; ".join(problems) or
                           f"networks {sec['networks']}, no ports, no devices, cap_drop {sec['cap_drop']}"):
                raise AirlockError("test container is not isolated - aborted")
            if "crash-after-start" in self.faults:
                time.sleep(3)
                run(["docker", "kill", cname], check=False, quiet=True)
        stable = float(self.opt["stable_seconds"])
        t0 = time.monotonic()
        st = dockerapi.state(cname)
        while time.monotonic() - t0 < stable and not deadline.expired():
            st = dockerapi.state(cname)
            if not st.get("running"):
                break
            time.sleep(2)
        st = dockerapi.state(cname)
        f["up"] = bool(st.get("running"))
        f["up_detail"] = f"status {st.get('status')}, exit code {st.get('exit_code')} after {time.monotonic() - t0:.0f}s"
        f["has_health"] = st.get("health") is not None
        if f["has_health"] and f["up"]:
            while st.get("health") == "starting" and not deadline.expired():
                time.sleep(3)
                st = dockerapi.state(cname)
            f["healthy"] = st.get("health") == "healthy"
            f["health_detail"] = f"health: {st.get('health')}"
        if self.opt["http_port"] and f["up"]:
            ip = self.sb.container_ip(cname)
            url = f"http://{ip}:{self.opt['http_port']}{self.opt['http_path']}"
            code, last = None, ""
            dl = Deadline(min(120, deadline.remaining()))
            while not dl.expired():
                try:
                    code = requests.get(url, timeout=5).status_code
                    if code < 500:
                        break
                except requests.RequestException as e:
                    last = type(e).__name__
                time.sleep(3)
            f["http"] = code is not None and code < 500
            f["http_detail"] = f"{self.opt['http_path']} -> {code or last}"
        f["logs"] = self.sb.logs(cname, 30)[-2500:]
        if role == "candidate":
            tcp = self.sb.resolve_targets(self.cfg.sandbox["must_be_unreachable"])
            if f["up"] and run(["docker", "exec", cname, "python3", "-c", "1"], check=False, quiet=True).ok:
                f["probe"] = self.sb.in_container_probe(cname, tcp)
        self.sb.remove(cname)
        return f

    def _compare(self, res: TestResult, name: str, key: str, b: dict, c: dict, detail_key: str) -> None:
        if key not in c and key not in b:
            return
        cb, cc = b.get(key), c.get(key)
        if cc:
            res.add(name, True, c.get(detail_key, "ok"))
        elif not cb:
            res.add(name + " (n/a in the sandbox: fails with the current image too)", True,
                    f"candidate: {c.get(detail_key)}; current image: {b.get(detail_key)}")
            if key == "up":
                res.inconclusive = f"container does not run in isolation even with the current image ({b.get(detail_key)})"
        else:
            res.add(name, False, f"candidate: {c.get(detail_key)} (current image: {b.get(detail_key)})\n"
                                 f"log:\n{c.get('logs', '')[-800:]}")

    def run(self) -> TestResult:
        res = TestResult(container=self.cur.name, candidate=self.candidate, digest=self.candidate.split("@")[-1],
                         faults=list(self.faults), require_conclusive=bool(self.opt.get("require_conclusive", False)))
        deadline = Deadline(float(self.opt["timeout_minutes"]) * 60)
        try:
            b = self._run_one("baseline", self.cur.image_id, deadline, res)
            c = self._run_one("candidate", self.candidate, deadline, res)
            if c.get("probe"):
                res.isolation["in_container_probe"] = c["probe"]
                res.add("test container reaches nothing (connect attempts from inside)", all(p["ok"] for p in c["probe"]),
                        ", ".join(f"{p['target']} {'reachable' if p['reachable'] else 'blocked'}" for p in c["probe"]))
            self._compare(res, "container starts and stays up", "up", b, c, "up_detail")
            if c.get("has_health") or b.get("has_health"):
                self._compare(res, "healthcheck", "healthy", b, c, "health_detail")
            if self.opt["http_port"]:
                self._compare(res, "web interface answers", "http", b, c, "http_detail")
            res.isolation["logs_tail"] = c.get("logs", "")
        except AirlockError as e:
            res.error = str(e)
        finally:
            for cn in list(self.sb.containers):
                if cn.startswith(f"ua-{self.cur.name}"[:20]):
                    self.sb.remove(cn)
            remove_tree(self.work)
        return res.finish()
