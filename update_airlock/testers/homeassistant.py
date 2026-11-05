"""Home Assistant tester: the candidate image runs against a neutralised COPY of the real configuration.

Neutralising the copy (the sandbox network already blocks everything; this is the second layer):
- every config entry outside `allow_integrations` is disabled (ZHA, TP-Link, Tuya, Sonos, Alexa, MQTT,
  mobile_app ... never start), so nothing tries to talk to a device or a cloud;
- shell_command, wake_on_lan, rest_command, notify, sonos ... are removed from configuration.yaml;
- every automation gets `initial_state: false`;
- .ssh, backups, old *.bak files and logs are not copied at all;
- a trusted_networks auth provider for the sandbox subnet lets the tester log in without a password.

Two runs on identical copies: BASELINE with the image that runs in production now, CANDIDATE with the new
image. Only differences count ("new errors"), because the sandbox itself produces errors (no network,
disabled integrations) that have nothing to do with the update.

Checks: container starts and reaches RUNNING, check_config without (new) errors, web interface answers,
no new ERROR lines in the log, every component of the baseline is loaded, every used integration
(also the disabled ones) can be imported incl. requirements, test container cannot reach anything.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import time
from pathlib import Path

import requests
import yaml

from .. import hayaml
from ..copying import copy_tree, remove_tree
from ..inventory import Current
from ..sandbox import Sandbox
from ..util import AirlockError, Deadline, run
from . import TestResult

log = logging.getLogger("update_airlock.tester.ha")

DEFAULT_ALLOW = ["sun", "backup", "template", "utility_meter", "integration", "shopping_list", "analytics",
                 "radio_browser", "google_translate", "met", "history_stats", "derivative", "statistics",
                 "threshold", "min_max", "group", "counter", "timer", "schedule", "local_calendar", "local_todo"]
DEFAULT_REMOVE_KEYS = ["shell_command", "wake_on_lan", "rest_command", "notify", "telegram_bot", "sonos",
                       "command_line", "smtp", "mqtt", "zha_toolkit", "ssh"]
DEFAULT_EXCLUDE = ["backups", ".ssh", "*.bak", "*.bak-*", "*.bak.*", "home-assistant.log*", ".ha_run.lock",
                   "tts", ".cache", "*.tmp"]
CHECK_SCRIPT = Path(__file__).with_name("ha_integration_check.py")
FAULT_BLOCK = ("\n# --- update-airlock fault injection (test of the test) ---\n"
               "input_number:\n  update_airlock_fault:\n    name: broken on purpose\n    min: not-a-number\n"
               "    max: [1, 2]\n")

_LOG_RE = re.compile(r"^\S+ \S+ (ERROR|CRITICAL) \(([^)]*)\) \[([^\]]+)\] (.*)$")


def normalize_message(msg: str) -> str:
    m = re.sub(r"\x1b\[[0-9;]*m", "", msg)
    m = re.sub(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "<uuid>", m, flags=re.I)
    m = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b", "<ip>", m)
    m = re.sub(r"0x[0-9a-f]+", "<hex>", m, flags=re.I)
    m = re.sub(r"\b[0-9a-f]{12,}\b", "<hex>", m, flags=re.I)
    m = re.sub(r"\d+(\.\d+)?", "#", m)
    return m.strip()[:180]


def error_signatures(log_text: str, ignore: list[str] | None = None) -> dict[str, str]:
    """{signature: first example line} for ERROR/CRITICAL lines of a home-assistant.log."""
    out: dict[str, str] = {}
    pats = [re.compile(p) for p in (ignore or [])]
    for raw in log_text.splitlines():
        line = re.sub(r"\x1b\[[0-9;]*m", "", raw)
        m = _LOG_RE.match(line)
        if not m:
            continue
        if any(p.search(line) for p in pats):
            continue
        sig = f"{m.group(3)}: {normalize_message(m.group(4))}"
        out.setdefault(sig, line[:300])
    return out


_CC_ERR = re.compile(r"invalid config|error|not found|failed|unknown|cannot|unable|exception", re.I)


def check_config_errors(output: str) -> list[str]:
    """Error lines of `hass --script check_config`.

    The script exits 0 even with errors, so the text decides. Errors are listed in a block headed
    "Incorrect config" (older versions: "Failed config"), one sub-block per domain, followed by the echoed
    YAML; the block ends at "Successful config (partial)". Only real error sentences are kept (not the
    echoed YAML); a domain with an error block but no recognisable sentence is reported by its name.
    """
    errs: list[str] = []
    in_block = False
    domain = None
    domain_had_error = False
    for ln in output.splitlines():
        s = re.sub(r"\x1b\[[0-9;]*m", "", ln).rstrip()
        st = s.strip()
        if st.startswith(("Incorrect config", "Failed config")):
            in_block = True
            continue
        if st.startswith("Successful config"):
            if domain and not domain_had_error:
                errs.append(f"{domain}: invalid configuration")
            in_block, domain = False, None
            continue
        if st.startswith(("Error loading", "ERROR", "Fatal error")):
            errs.append(normalize_message(st))
            continue
        if not in_block or not st:
            continue
        indent = len(s) - len(s.lstrip(" "))
        m = re.match(r"^([a-z0-9_]+(?:\.[a-z0-9_]+)?):\s*$", st)
        if indent <= 2 and m:
            if domain and not domain_had_error:
                errs.append(f"{domain}: invalid configuration")
            domain, domain_had_error = m.group(1), False
            continue
        if _CC_ERR.search(st) and "[source " not in st:
            errs.append(normalize_message(st.lstrip("- ")))
            domain_had_error = True
    if in_block and domain and not domain_had_error:
        errs.append(f"{domain}: invalid configuration")
    return errs


def neutralize(config_dir: Path, subnet: str, allow: list[str], remove_keys: list[str]) -> dict:
    stats = {}
    ce = config_dir / ".storage" / "core.config_entries"
    if ce.exists():
        doc = json.loads(ce.read_text(encoding="utf-8"))
        disabled = kept = 0
        for e in doc["data"]["entries"]:
            if e.get("domain") in allow:
                kept += 1
            elif e.get("disabled_by") is None:
                e["disabled_by"] = "user"
                disabled += 1
        ce.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
        stats["config_entries_disabled"] = disabled
        stats["config_entries_kept"] = kept
    cy = config_dir / "configuration.yaml"
    data = hayaml.load(cy.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise AirlockError("configuration.yaml is not a mapping")
    removed = [k for k in remove_keys if k in data]
    for k in removed:
        data.pop(k)
    # switch/sensor platforms that act on the network (wake_on_lan, command_line ...)
    for dom in ("switch", "sensor", "binary_sensor", "notify", "light"):
        v = data.get(dom)
        if isinstance(v, list):
            data[dom] = [p for p in v if not (isinstance(p, dict) and p.get("platform") in remove_keys)]
    ha = data.get("homeassistant") if isinstance(data.get("homeassistant"), dict) else {}
    ha["auth_providers"] = [{"type": "trusted_networks", "trusted_networks": [subnet], "allow_bypass_login": True},
                            {"type": "homeassistant"}]
    data["homeassistant"] = ha
    cy.write_text("# Neutralised by update-airlock for the sandbox.\n" + hayaml.dump(data), encoding="utf-8")
    stats["yaml_removed"] = removed
    af = config_dir / "automations.yaml"
    if af.exists():
        autos = hayaml.load(af.read_text(encoding="utf-8")) or []
        if isinstance(autos, list):
            for a in autos:
                if isinstance(a, dict):
                    a["initial_state"] = False
            af.write_text(hayaml.dump(autos), encoding="utf-8")
            stats["automations_disabled"] = len(autos)
    for f in (".ha_run.lock",):
        (config_dir / f).unlink(missing_ok=True)
    return stats


class HAInstance:
    """One sandbox HA run (baseline or candidate)."""

    def __init__(self, sb: Sandbox, role: str, image: str, data: Path, cap_add: list[str]):
        self.sb, self.role, self.image, self.data, self.cap_add = sb, role, image, data, cap_add
        self.cname = ""
        self.ip = ""
        self.token = ""
        self.facts: dict = {}

    def start(self) -> None:
        self.cname = self.sb.run_container(
            f"ha-{self.role}", self.image, mounts=[(str(self.data), "/config", "rw"),
                                                   (str(CHECK_SCRIPT), "/airlock/check.py", "ro")],
            env={"PYTHONUNBUFFERED": "1"}, cap_add=self.cap_add, with_proxy_env=True)
        self.ip = self.sb.container_ip(self.cname)

    def url(self, p: str) -> str:
        return f"http://{self.ip}:8123{p}"

    def running(self) -> bool:
        r = run(["docker", "inspect", "-f", "{{.State.Running}}", self.cname], check=False, quiet=True)
        return r.stdout.strip() == "true"

    def wait_web(self, deadline: Deadline) -> tuple[bool, str]:
        last = ""
        while not deadline.expired():
            if not self.running():
                return False, f"container exited: {self.sb.logs(self.cname, 25)}"
            try:
                r = requests.get(self.url("/manifest.json"), timeout=5)
                if r.status_code == 200:
                    return True, "HTTP 200 /manifest.json"
                last = f"HTTP {r.status_code}"
            except requests.RequestException as e:
                last = type(e).__name__
            time.sleep(3)
        return False, f"no answer before the deadline ({last})"

    def login(self, deadline: Deadline) -> None:
        cid = f"http://{self.ip}:8123/"
        last = ""
        while not deadline.expired():
            try:
                r = requests.post(self.url("/auth/login_flow"), json={
                    "client_id": cid, "handler": ["trusted_networks", None], "redirect_uri": cid}, timeout=15)
                if r.status_code != 200:
                    last = f"login_flow HTTP {r.status_code}"
                    time.sleep(3)
                    continue
                flow = r.json()
                if flow.get("type") == "form":
                    users = {}
                    for fld in flow.get("data_schema", []):
                        if fld.get("name") == "user":
                            users = fld.get("options") or {}
                    if isinstance(users, list):
                        users = {u[0] if isinstance(u, (list, tuple)) else u.get("value"): 1 for u in users}
                    if not users:
                        raise AirlockError("sandbox login offers no user")
                    r = requests.post(self.url(f"/auth/login_flow/{flow['flow_id']}"),
                                      json={"client_id": cid, "user": next(iter(users))}, timeout=15)
                    flow = r.json()
                if flow.get("type") != "create_entry":
                    raise AirlockError(f"sandbox login did not finish: {str(flow)[:200]}")
                r = requests.post(self.url("/auth/token"), data={
                    "grant_type": "authorization_code", "code": flow["result"], "client_id": cid}, timeout=15)
                self.token = r.json()["access_token"]
                return
            except (requests.RequestException, ValueError, KeyError) as e:
                last = type(e).__name__
                time.sleep(3)
        raise AirlockError(f"sandbox login failed ({last})")

    def api(self, path: str, timeout: float = 30):
        r = requests.get(self.url(path), headers={"Authorization": f"Bearer {self.token}"}, timeout=timeout)
        return r

    def wait_running(self, deadline: Deadline) -> dict:
        cfg = {}
        while not deadline.expired():
            try:
                r = self.api("/api/config", 20)
                if r.status_code == 200:
                    cfg = r.json()
                    if cfg.get("state") == "RUNNING":
                        return cfg
            except (requests.RequestException, ValueError):
                pass
            if not self.running():
                break
            time.sleep(5)
        return cfg

    def exec(self, cmd: list[str], timeout: float) -> tuple[int, str]:
        r = run(["docker", "exec", self.cname, *cmd], check=False, quiet=True, timeout=timeout)
        return r.returncode, (r.stdout + "\n" + r.stderr)

    def log_text(self) -> str:
        f = self.data / "home-assistant.log"
        text = f.read_text(encoding="utf-8", errors="replace") if f.exists() else ""
        return text or self.sb.logs(self.cname, 5000)

    def stop(self) -> None:
        if self.cname:
            run(["docker", "stop", "-t", "60", self.cname], check=False, quiet=True, timeout=120)
            self.sb.remove(self.cname)


class HomeAssistantTester:
    def __init__(self, cfg, ccfg, current: Current, candidate_ref: str, sandbox: Sandbox, work: Path,
                 faults: list[str] | None = None, used_domains: list[str] | None = None):
        self.cfg, self.c, self.cur, self.candidate, self.sb, self.work = cfg, ccfg, current, candidate_ref, sandbox, work
        self.faults = faults or []
        self.used = sorted(set(used_domains or []))
        o = {"allow_integrations": DEFAULT_ALLOW, "remove_yaml_keys": DEFAULT_REMOVE_KEYS,
             "copy_exclude": DEFAULT_EXCLUDE, "copy_recorder_db": True, "timeout_minutes": 50,
             "start_timeout_minutes": 20, "settle_seconds": 90, "new_error_tolerance": 0,
             "ignore_error_patterns": [], "cap_add": [], "config_dir": "", "import_check": True,
             "import_skip": ["default_config"]}
        o.update(ccfg.raw.get("test") or {})
        self.opt = o

    def config_dir(self) -> Path:
        if self.opt["config_dir"]:
            return Path(self.opt["config_dir"])
        for m in self.cur.mounts:
            if m.target == "/config":
                return Path(m.host_path)
        raise AirlockError("no /config mount found - set containers.<name>.test.config_dir")

    def _instance(self, role: str, image: str, master: Path, res: TestResult, deadline: Deadline) -> HAInstance:
        data = self.work / role
        copy_tree(master, data, [], sqlite_online=False)
        if role == "candidate" and "broken-config" in self.faults:
            with open(data / "configuration.yaml", "a", encoding="utf-8") as f:
                f.write(FAULT_BLOCK)
        inst = HAInstance(self.sb, role, image, data, self.opt["cap_add"])
        inst.start()
        f = inst.facts
        start_dl = Deadline(min(deadline.remaining(), float(self.opt["start_timeout_minutes"]) * 60))
        f["web_ok"], f["web_detail"] = inst.wait_web(start_dl)
        if not f["web_ok"]:
            return inst
        inst.login(start_dl)
        cfg = inst.wait_running(start_dl)
        f["state"], f["version"] = cfg.get("state"), cfg.get("version")
        f["components"] = sorted(cfg.get("components") or [])
        time.sleep(min(float(self.opt["settle_seconds"]), deadline.remaining()))
        r = inst.api("/api/", 10)
        f["api_status"] = r.status_code
        rc, out = inst.exec(["python3", "-m", "homeassistant", "--script", "check_config", "-c", "/config"], 900)
        f["check_config_rc"], f["check_config_errors"] = rc, check_config_errors(out)
        f["check_config_tail"] = out.strip()[-1500:]
        if self.opt["import_check"] and self.used:
            doms = [d for d in self.used if d not in self.opt["import_skip"]]
            rc, out = inst.exec(["python3", "/airlock/check.py", "/config", *doms], 1800)
            try:
                f["imports"] = json.loads(out.strip().splitlines()[0] if out.strip().startswith("{") else
                                          next(ln for ln in out.splitlines() if ln.startswith("{")))["results"]
            except (StopIteration, ValueError, KeyError):
                f["imports"] = None
                f["imports_error"] = out.strip()[-600:]
        if role == "candidate":
            tcp = [t for t in self.sb.resolve_targets(self.cfg.sandbox["must_be_unreachable"])]
            f["probe"] = self.sb.in_container_probe(inst.cname, tcp)
            res.isolation["test_container"] = self.sb.inspect_security(inst.cname)
        f["errors"] = error_signatures(inst.log_text(), self.opt["ignore_error_patterns"])
        return inst

    def run(self) -> TestResult:
        res = TestResult(container=self.cur.name, candidate=self.candidate, digest=self.candidate.split("@")[-1],
                         faults=list(self.faults))
        deadline = Deadline(float(self.opt["timeout_minutes"]) * 60)
        insts: list[HAInstance] = []
        try:
            src = self.config_dir()
            master = self.work / "master"
            excl = list(self.opt["copy_exclude"])
            if not self.opt["copy_recorder_db"]:
                excl.append("home-assistant_v2.db*")
            stats = copy_tree(src, master, excl)
            stats.update(neutralize(master, self.cfg.sandbox["subnet"], self.opt["allow_integrations"],
                                    self.opt["remove_yaml_keys"]))
            res.isolation["neutralised_copy"] = stats
            if any((master / p).exists() for p in (".ssh",)):
                raise AirlockError("SSH keys ended up in the sandbox copy - aborted")

            base = self._instance("baseline", self.cur.image_id, master, res, deadline)
            insts.append(base)
            base.stop()
            if not base.facts.get("web_ok") or base.facts.get("state") != "RUNNING":
                raise AirlockError("baseline (the image running in production now) does not start in the sandbox, "
                                   f"so no comparison is possible: {base.facts.get('web_detail')} "
                                   f"state {base.facts.get('state')}")
            cand = self._instance("candidate", self.candidate, master, res, deadline)
            insts.append(cand)
            cand.stop()
            b, c = base.facts, cand.facts

            sec = res.isolation.get("test_container")
            if sec:
                problems = self.sb.security_ok(sec)
                res.add("isolation of the test container (docker inspect)", not problems, "; ".join(problems) or
                        f"networks {sec['networks']}, no ports, no devices, cap_drop {sec['cap_drop']}, cap_add {sec['cap_add']}")
            probe = c.get("probe") or []
            res.isolation["in_container_probe"] = probe
            if probe:
                res.add("test container reaches nothing (connect attempts from inside)", all(p["ok"] for p in probe),
                        ", ".join(f"{p['target']} {'reachable' if p['reachable'] else 'blocked'}"
                                  f"{' (control, must be reachable)' if p.get('expected') == 'reachable' else ''}"
                                  for p in probe))

            res.add("candidate starts", bool(c.get("web_ok")) and c.get("state") == "RUNNING",
                    f"{c.get('web_detail')}; state {c.get('state')}; version {c.get('version')}")
            if not c.get("web_ok"):
                return res
            expected = self.candidate.split("@")[0].rsplit(":", 1)[-1]
            if re.fullmatch(r"\d+\.\d+\.\d+", expected or ""):
                res.add("candidate runs the expected version", c.get("version") == expected,
                        f"expected {expected}, reports {c.get('version')}")
            res.add("web interface and API answer", c.get("api_status") == 200, f"/api/ -> HTTP {c.get('api_status')}")

            new_cfg_err = [e for e in c.get("check_config_errors", []) if e not in set(b.get("check_config_errors", []))]
            detail = "no errors" if not c.get("check_config_errors") else "\n".join(c["check_config_errors"][:15])
            if b.get("check_config_errors"):
                detail += f"\n(baseline already had {len(b['check_config_errors'])} error lines - only new ones count)"
            res.add("config check without errors", not new_cfg_err, detail if new_cfg_err else detail[:600])

            new_errors = {k: v for k, v in c.get("errors", {}).items() if k not in b.get("errors", {})}
            tol = int(self.opt["new_error_tolerance"])
            res.add("no new errors in the log", len(new_errors) <= tol,
                    (f"{len(new_errors)} new error type(s) vs. baseline ({len(b.get('errors', {}))} in baseline):\n"
                     + "\n".join(list(new_errors.values())[:10])) if new_errors else
                    f"none (baseline {len(b.get('errors', {}))}, candidate {len(c.get('errors', {}))} error types)")
            res.isolation["new_errors"] = list(new_errors.values())[:50]

            missing = sorted(set(b.get("components", [])) - set(c.get("components", [])))
            res.add("all components of the baseline loaded", not missing,
                    f"missing: {', '.join(missing)}" if missing else f"{len(c.get('components', []))} components loaded")

            if self.opt["import_check"] and self.used:
                ci, bi = c.get("imports"), b.get("imports") or {}
                if ci is None:
                    res.add("integrations can be loaded", False, f"check script failed: {c.get('imports_error', '')}")
                else:
                    bad = {d: r for d, r in ci.items() if not r.get("ok") and (bi.get(d) or {}).get("ok", True)}
                    pre = [d for d, r in ci.items() if not r.get("ok") and d not in bad]
                    det = (f"{len(ci) - len(bad) - len(pre)} of {len(ci)} OK"
                           + (f"; failing: " + "; ".join(f"{d}: {r.get('error')}" for d, r in bad.items()) if bad else "")
                           + (f"; already failing in baseline: {', '.join(pre)}" if pre else ""))
                    res.add("integrations can be loaded (incl. disabled ones)", not bad, det)
        except AirlockError as e:
            res.error = str(e)
        except (requests.RequestException, OSError, yaml.YAMLError) as e:
            res.error = f"{type(e).__name__}: {e}"
        finally:
            for i in insts:
                i.stop()
            for cn in list(self.sb.containers):
                if cn.startswith("ua-ha-"):
                    self.sb.remove(cn)
            remove_tree(self.work)
        return res.finish()
