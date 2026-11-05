"""The airlock sandbox. SAFETY-CRITICAL: a test container must never reach a real device.

Layers (each one alone would already block the LAN):
1. Test containers sit ONLY in an internal Docker network (--internal: no gateway, no route anywhere).
   DNS is pointed into nothing (--dns 0.0.0.0), so names do not resolve either.
2. The only other member of that network is an egress proxy (tinyproxy) that forwards HTTPS CONNECT to an
   allow-list of domains (PyPI + Home Assistant wheels, needed to install integration requirements).
   Requests to IP addresses or any other host are refused by the proxy (FilterDefaultDeny).
3. iptables: the proxy's outbound bridge may not reach private/link-local ranges (DOCKER-USER chain), and
   no sandbox bridge may open NEW connections to the host itself (INPUT chain).
4. No published ports, no devices, all capabilities dropped (only those configured are added back),
   no-new-privileges, memory/CPU/PID limits.
5. Before every test a probe container proves 1-3 against real targets (router, Zigbee dongle, host, internet).
   If a single target is reachable, the test is aborted before any service container starts.
Everything carries the label update-airlock.sandbox=1 and is removed after the run, after an abort, and at
the start of the next run (after a crash or reboot).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from .util import AirlockError, Deadline, run

log = logging.getLogger("update_airlock.sandbox")

LABEL = "update-airlock.sandbox=1"
RULE_TAG = "update-airlock"
PRIVATE_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10"]

TINYPROXY_CONF = """User nobody
Group nobody
Port {port}
Listen 0.0.0.0
Timeout 120
MaxClients 50
LogLevel Connect
Syslog Off
FilterDefaultDeny Yes
FilterExtended Yes
Filter "/etc/tinyproxy/filter"
FilterURLs Off
ConnectPort 443
DisableViaHeader Yes
"""

PROXY_DOCKERFILE = """FROM {base}
RUN apk add --no-cache tinyproxy
LABEL update-airlock.component=egress-proxy
CMD ["sh", "-c", "tinyproxy -d -c /etc/tinyproxy/tinyproxy.conf"]
"""


@dataclass
class IsolationResult:
    passed: bool
    checks: list[dict] = field(default_factory=list)
    inspect: dict = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict:
        return {"passed": self.passed, "checks": self.checks, "inspect": self.inspect, "error": self.error}


def filter_lines(domains: list[str]) -> str:
    lines = []
    for d in domains:
        esc = d.replace(".", r"\.")
        lines.append(rf"^(.+\.)?{esc}$")
    return "\n".join(lines) + "\n"


class Sandbox:
    def __init__(self, cfg: dict, run_id: str, work_root: Path):
        self.cfg = cfg
        self.run_id = run_id
        self.work_root = work_root
        self.containers: list[str] = []
        self.proxy_name = f"ua-proxy-{run_id}"
        self.proxy_url = f"http://{cfg['proxy_ip']}:{cfg['proxy_port']}"

    # ---------- networks and firewall ----------
    def _ensure_network(self, name: str, subnet: str, bridge: str, internal: bool) -> None:
        res = run(["docker", "network", "inspect", name], check=False, quiet=True)
        if res.ok:
            info = json.loads(res.stdout)[0]
            if bool(info.get("Internal")) != internal:
                raise AirlockError(f"Docker network {name} exists with internal={info.get('Internal')} "
                                   f"(expected {internal}). Remove it: docker network rm {name}")
            return
        args = ["docker", "network", "create", "--driver", "bridge", "--subnet", subnet,
                "--opt", f"com.docker.network.bridge.name={bridge}", "--label", LABEL]
        if internal:
            args += ["--internal", "--opt", "com.docker.network.bridge.enable_ip_masquerade=false"]
        run([*args, name])
        log.info("network %s (%s, internal=%s) created", name, subnet, internal)

    def _rules(self) -> list[list[str]]:
        c = self.cfg
        rules = []
        for br in (c["bridge_name"], c["egress_bridge_name"]):
            rules.append(["INPUT", "-i", br, "-m", "conntrack", "--ctstate", "NEW",
                          "-m", "comment", "--comment", f"{RULE_TAG}: sandbox must not reach the host", "-j", "DROP"])
        for net in PRIVATE_NETS:
            rules.append(["DOCKER-USER", "-i", c["egress_bridge_name"], "-d", net, "-m", "conntrack", "--ctstate", "NEW",
                          "-m", "comment", "--comment", f"{RULE_TAG}: egress proxy must not reach the LAN", "-j", "DROP"])
        # The internal bridge has no route anyway; this is belt and braces for forwarded traffic.
        rules.append(["DOCKER-USER", "-i", c["bridge_name"], "!", "-o", c["bridge_name"],
                      "-m", "comment", "--comment", f"{RULE_TAG}: sandbox must not leave its bridge", "-j", "DROP"])
        return rules

    def ensure_firewall(self) -> None:
        if not run(["iptables", "-L", "DOCKER-USER", "-n"], check=False, quiet=True).ok:
            run(["iptables", "-N", "DOCKER-USER"], check=False, quiet=True)
        for r in self._rules():
            if not run(["iptables", "-C", *r], check=False, quiet=True).ok:
                run(["iptables", "-I", *r])

    def firewall_present(self) -> bool:
        return all(run(["iptables", "-C", *r], check=False, quiet=True).ok for r in self._rules())

    def remove_firewall(self) -> None:
        for r in self._rules():
            while run(["iptables", "-C", *r], check=False, quiet=True).ok:
                run(["iptables", "-D", *r], check=False, quiet=True)

    def setup(self, deadline: Deadline) -> None:
        c = self.cfg
        self.cleanup_stale(self.cfg)
        self._ensure_network(c["network"], c["subnet"], c["bridge_name"], internal=True)
        self._ensure_network(c["egress_network"], c["egress_subnet"], c["egress_bridge_name"], internal=False)
        self.ensure_firewall()
        self.start_proxy(deadline)

    # ---------- egress proxy ----------
    def ensure_proxy_image(self) -> None:
        img = self.cfg["proxy_image"]
        if run(["docker", "image", "inspect", img], check=False, quiet=True).ok:
            return
        d = self.work_root / f"proxy-build-{self.run_id}"
        d.mkdir(parents=True, exist_ok=True)
        (d / "Dockerfile").write_text(PROXY_DOCKERFILE.format(base=self.cfg["proxy_base_image"]), encoding="utf-8")
        log.info("building egress proxy image %s", img)
        try:
            run(["docker", "build", "-q", "-t", img, str(d)], timeout=900)
        finally:
            for f in d.iterdir():
                f.unlink()
            d.rmdir()

    def start_proxy(self, deadline: Deadline) -> None:
        self.ensure_proxy_image()
        conf_dir = self.work_root / f"proxy-{self.run_id}"
        conf_dir.mkdir(parents=True, exist_ok=True)
        (conf_dir / "tinyproxy.conf").write_text(TINYPROXY_CONF.format(port=self.cfg["proxy_port"]), encoding="utf-8")
        (conf_dir / "filter").write_text(filter_lines(self.cfg["proxy_allow_domains"]), encoding="utf-8")
        for f in conf_dir.iterdir():
            f.chmod(0o644)
        conf_dir.chmod(0o755)
        self.containers.append(self.proxy_name)
        run(["docker", "create", "--name", self.proxy_name, "--label", LABEL, "--label", f"update-airlock.run={self.run_id}",
             "--network", self.cfg["egress_network"], "--restart", "no",
             "--memory", "64m", "--cpus", "0.5", "--pids-limit", "100",
             "--cap-drop", "ALL", "--cap-add", "SETUID", "--cap-add", "SETGID",
             "--security-opt", "no-new-privileges",
             "-v", f"{conf_dir}/tinyproxy.conf:/etc/tinyproxy/tinyproxy.conf:ro",
             "-v", f"{conf_dir}/filter:/etc/tinyproxy/filter:ro",
             self.cfg["proxy_image"]])
        run(["docker", "network", "connect", "--ip", self.cfg["proxy_ip"], self.cfg["network"], self.proxy_name])
        run(["docker", "start", self.proxy_name])
        while not deadline.expired():
            st = run(["docker", "inspect", "-f", "{{.State.Running}}", self.proxy_name], check=False, quiet=True)
            if st.stdout.strip() == "true":
                time.sleep(1)
                return
            time.sleep(1)
        raise AirlockError("egress proxy does not start: " + self.logs(self.proxy_name, 10))

    # ---------- containers ----------
    def run_container(self, name: str, image: str, *, mounts: list[tuple[str, str, str]] = (),
                      env: dict[str, str] | None = None, cmd: list[str] | None = None, user: str | None = None,
                      entrypoint: str | None = None, cap_add: list[str] | None = None,
                      with_proxy_env: bool = False, extra_args: list[str] | None = None) -> str:
        c = self.cfg
        cname = f"ua-{name}-{self.run_id}"
        run(["docker", "rm", "-f", "-v", cname], check=False, quiet=True)
        args = ["docker", "run", "-d", "--name", cname, "--hostname", f"ua-sandbox-{name}"[:63],
                "--label", LABEL, "--label", f"update-airlock.run={self.run_id}",
                "--network", c["network"],
                "--memory", c["memory"], "--memory-swap", c["memory"], "--cpus", str(c["cpus"]),
                "--pids-limit", str(c["pids_limit"]),
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--restart", "no",
                "--dns", "0.0.0.0", "--add-host", f"ua-sandbox-{name}:127.0.1.1"]
        for cap in cap_add or []:
            args += ["--cap-add", cap]
        for host, target, mode in mounts:
            args += ["-v", f"{host}:{target}:{mode}"]
        e = dict(env or {})
        if with_proxy_env:
            for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
                e[k] = self.proxy_url
            e["NO_PROXY"] = e["no_proxy"] = "localhost,127.0.0.1"
        for k, v in e.items():
            args += ["-e", f"{k}={v}"]
        if user:
            args += ["--user", user]
        if entrypoint is not None:
            args += ["--entrypoint", entrypoint]
        args += extra_args or []
        args.append(image)
        args += cmd or []
        self.containers.append(cname)
        run(args, timeout=180)
        return cname

    def container_ip(self, cname: str) -> str:
        fmt = "{{(index .NetworkSettings.Networks \"" + self.cfg["network"] + "\").IPAddress}}"
        ip = run(["docker", "inspect", "-f", fmt, cname], quiet=True).stdout.strip()
        if not ip:
            raise AirlockError(f"{cname} has no IP in the sandbox network")
        return ip

    @staticmethod
    def logs(cname: str, tail: int = 80) -> str:
        res = run(["docker", "logs", "--tail", str(tail), cname], check=False, quiet=True)
        return (res.stdout + res.stderr).strip()

    def remove(self, cname: str) -> None:
        run(["docker", "rm", "-f", "-v", cname], check=False, quiet=True)
        if cname in self.containers:
            self.containers.remove(cname)

    def teardown(self) -> None:
        """Remove everything of this run: containers, proxy config, networks, firewall rules."""
        for cn in list(self.containers):
            self.remove(cn)
        conf_dir = self.work_root / f"proxy-{self.run_id}"
        if conf_dir.exists():
            for f in conf_dir.iterdir():
                f.unlink()
            conf_dir.rmdir()
        for net in (self.cfg["network"], self.cfg["egress_network"]):
            run(["docker", "network", "rm", net], check=False, quiet=True)
        self.remove_firewall()

    @staticmethod
    def cleanup_work_dirs(work_root: Path) -> list[str]:
        """Remove copies of earlier runs (they can be GBs - an HA config with its database)."""
        import shutil
        removed = []
        if work_root and work_root.exists():
            for d in work_root.iterdir():
                if d.is_dir() and d.name.startswith(("run-", "proxy-")):
                    shutil.rmtree(d, ignore_errors=True)
                    removed.append(d.name)
        return removed

    @staticmethod
    def cleanup_stale(cfg: dict) -> list[str]:
        """Remove leftovers of earlier runs (crash, power loss, SIGKILL)."""
        ids = run(["docker", "ps", "-aq", "--filter", f"label={LABEL}"], check=False, quiet=True).stdout.split()
        for cid in ids:
            run(["docker", "rm", "-f", "-v", cid], check=False, quiet=True)
        return ids

    # ---------- security proof ----------
    def inspect_security(self, cname: str) -> dict:
        info = json.loads(run(["docker", "inspect", cname], quiet=True).stdout)[0]
        hc = info["HostConfig"]
        nets = info["NetworkSettings"]["Networks"]
        return {
            "container": cname,
            "networks": sorted(nets.keys()),
            "only_internal_network": list(nets.keys()) == [self.cfg["network"]],
            "network_mode": hc.get("NetworkMode"),
            "published_ports": hc.get("PortBindings") or {},
            "port_bindings_runtime": info["NetworkSettings"].get("Ports") or {},
            "devices": hc.get("Devices") or [],
            "device_cgroup_rules": hc.get("DeviceCgroupRules") or [],
            "privileged": bool(hc.get("Privileged")),
            "cap_drop": hc.get("CapDrop") or [],
            "cap_add": hc.get("CapAdd") or [],
            "security_opt": hc.get("SecurityOpt") or [],
            "dns": hc.get("Dns") or [],
            "memory": hc.get("Memory"),
            "nano_cpus": hc.get("NanoCpus"),
            "pids_limit": hc.get("PidsLimit"),
        }

    @staticmethod
    def security_ok(sec: dict) -> list[str]:
        problems = []
        if not sec["only_internal_network"]:
            problems.append(f"networks {sec['networks']}")
        if sec["network_mode"] in ("host",) or str(sec["network_mode"]).startswith("container:"):
            problems.append(f"network_mode {sec['network_mode']}")
        if sec["published_ports"] or any(v for v in sec["port_bindings_runtime"].values()):
            problems.append("published ports")
        if sec["devices"] or sec["device_cgroup_rules"]:
            problems.append("devices passed through")
        if sec["privileged"]:
            problems.append("privileged")
        if "ALL" not in [c.upper() for c in sec["cap_drop"]]:
            problems.append("capabilities not dropped")
        if any(c.upper() in ("NET_ADMIN", "NET_RAW", "SYS_ADMIN", "SYS_MODULE", "NET_BIND_SERVICE") for c in sec["cap_add"]):
            problems.append(f"dangerous capability {sec['cap_add']}")
        return problems

    def resolve_targets(self, targets: list[str]) -> list[str]:
        gw = default_gateway()
        lan = host_lan_ip()
        bridge = self.bridge_ip()
        out = []
        for t in targets:
            if "@gateway" in t:
                if not gw:
                    continue
                t = t.replace("@gateway", gw)
            if "@host_lan" in t:
                if not lan:
                    continue
                t = t.replace("@host_lan", lan)
            t = t.replace("@host_bridge", bridge)
            out.append(t)
        return out

    def bridge_ip(self) -> str:
        info = json.loads(run(["docker", "network", "inspect", self.cfg["network"]], quiet=True).stdout)[0]
        gw = (info["IPAM"]["Config"] or [{}])[0].get("Gateway")
        return gw or str(next(ipaddress.ip_network(self.cfg["subnet"]).hosts()))

    def probe(self, deadline: Deadline) -> IsolationResult:
        """Prove isolation from a probe container in the sandbox network and from the proxy itself."""
        direct = self.resolve_targets(self.cfg["must_be_unreachable"])
        deny = self.resolve_targets(self.cfg["proxy_must_deny"])
        allow = self.resolve_targets(self.cfg["proxy_must_allow"])
        px_host, px_port = self.cfg["proxy_ip"], self.cfg["proxy_port"]
        lines = ["set +e"]
        # Positive control: the proxy inside the sandbox network MUST be reachable - proves the probe works,
        # so "blocked" results below cannot come from a broken nc.
        lines.append(f'nc -z -w 3 {px_host} {px_port} >/dev/null 2>&1 && echo "REACH control {px_host}:{px_port}" '
                     f'|| echo "BLOCK control {px_host}:{px_port}"')
        for t in direct:
            h, p = t.rsplit(":", 1)
            lines.append(f'nc -z -w 3 {h} {p} >/dev/null 2>&1 && echo "REACH direct {t}" || echo "BLOCK direct {t}"')
        lines.append("timeout 10 nslookup example.com >/dev/null 2>&1 && echo 'REACH dns example.com' || echo 'BLOCK dns example.com'")
        lines.append("ip route 2>/dev/null | grep -q default && echo 'REACH route default' || echo 'BLOCK route default'")
        for t in deny + allow:
            lines.append(
                f"r=$(printf 'CONNECT {t} HTTP/1.1\\r\\nHost: {t}\\r\\n\\r\\n' | nc -w 8 {px_host} {px_port} 2>/dev/null | head -1); "
                f"case \"$r\" in *' 200 '*) echo \"REACH proxy {t}\";; *) echo \"BLOCK proxy {t} ${{r%%$(printf '\\r')}}\";; esac")
        cname = self.run_container("probe", self.cfg["probe_image"], entrypoint="/bin/sh", cmd=["-c", "\n".join(lines)])
        try:
            while not deadline.expired():
                if run(["docker", "inspect", "-f", "{{.State.Status}}", cname], quiet=True).stdout.strip() == "exited":
                    break
                time.sleep(1)
            out = self.logs(cname, 400)
            sec = self.inspect_security(cname)
        finally:
            self.remove(cname)
        # From the proxy container itself: its own outbound path must not reach the LAN either.
        proxy_checks = []
        for t in [x for x in direct if not x.startswith(("1.1.1.1", "8.8.8.8"))]:
            h, p = t.rsplit(":", 1)
            r = run(["docker", "exec", self.proxy_name, "sh", "-c", f"nc -z -w 3 {h} {p}"], check=False, quiet=True,
                    timeout=20)
            proxy_checks.append({"from": "proxy", "target": t, "reachable": r.ok, "expected": "blocked"})
        # Positive control for the proxy's own checks: an allowed internet host must work.
        for t in allow:
            h, p = t.rsplit(":", 1)
            r = run(["docker", "exec", self.proxy_name, "sh", "-c", f"nc -z -w 5 {h} {p}"], check=False, quiet=True,
                    timeout=20)
            proxy_checks.append({"from": "proxy", "target": t, "reachable": r.ok, "expected": "reachable"})
        checks = []
        passed = True
        for ln in out.splitlines():
            parts = ln.split(" ", 3)
            if len(parts) < 3 or parts[0] not in ("REACH", "BLOCK"):
                continue
            reachable = parts[0] == "REACH"
            kind, target = parts[1], parts[2]
            expected = "reachable" if ((kind == "proxy" and target in allow) or kind == "control") else "blocked"
            ok = reachable == (expected == "reachable")
            checks.append({"from": "probe", "via": kind, "target": target, "reachable": reachable,
                           "expected": expected, "ok": ok, "detail": parts[3] if len(parts) > 3 else ""})
            passed &= ok
        for pc in proxy_checks:
            pc["ok"] = pc["reachable"] == (pc["expected"] == "reachable")
            passed &= pc["ok"]
            checks.append(pc)
        if len([c for c in checks if c["from"] == "probe"]) < len(direct) + len(deny) + len(allow) + 3:
            return IsolationResult(False, checks, sec, f"probe produced incomplete output: {out[-300:]}")
        problems = self.security_ok(sec)
        if problems:
            passed = False
        if not self.firewall_present():
            passed = False
            problems.append("iptables rules missing")
        return IsolationResult(passed, checks, sec, "; ".join(problems))

    def in_container_probe(self, cname: str, targets: list[str]) -> list[dict]:
        """Try to connect FROM the real test container (python is available in HA images)."""
        code = ("import socket,sys\n"
                "for t in sys.argv[1:]:\n"
                "  h,p=t.rsplit(':',1)\n"
                "  s=socket.socket();s.settimeout(3)\n"
                "  try:\n"
                "    s.connect((h,int(p)));print('REACH',t)\n"
                "  except Exception as e:\n"
                "    print('BLOCK',t,type(e).__name__)\n"
                "  finally:\n"
                "    s.close()\n")
        control = f"{self.cfg['proxy_ip']}:{self.cfg['proxy_port']}"  # must be reachable (proves the probe works)
        res = run(["docker", "exec", cname, "python3", "-c", code, control, *targets], check=False, quiet=True,
                  timeout=120)
        out = []
        for ln in res.stdout.splitlines():
            p = ln.split(" ")
            if p[0] in ("REACH", "BLOCK") and len(p) >= 2:
                exp = "reachable" if p[1] == control else "blocked"
                out.append({"from": "test-container", "target": p[1], "reachable": p[0] == "REACH",
                            "expected": exp, "ok": (p[0] == "REACH") == (exp == "reachable")})
        if len(out) < len(targets) + 1:
            out.append({"from": "test-container", "target": "*", "reachable": None, "ok": False,
                        "detail": "incomplete probe output"})
        if not out:
            out.append({"from": "test-container", "target": "*", "reachable": None, "ok": False,
                        "detail": (res.stderr or res.stdout)[:200]})
        return out


def default_gateway() -> str | None:
    p = run(["ip", "-4", "route", "show", "default"], check=False, quiet=True).stdout.split()
    return p[p.index("via") + 1] if "via" in p else None


def host_lan_ip() -> str | None:
    p = run(["ip", "-4", "route", "get", "1.1.1.1"], check=False, quiet=True).stdout.split()
    return p[p.index("src") + 1] if "src" in p else None
