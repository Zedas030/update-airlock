"""Docker access: the CLI for most things, the Engine API (unix socket, stdlib only) where the CLI cannot
express it - re-creating a container from its own `docker inspect` data with a different image.
"""

from __future__ import annotations

import http.client
import json
import socket
from urllib.parse import quote

from .util import AirlockError, run

SOCKET = "/var/run/docker.sock"


class _UnixConn(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float = 120):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


def api(method: str, path: str, body: dict | None = None, timeout: float = 120, sock: str = SOCKET):
    conn = _UnixConn(sock, timeout)
    try:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        conn.request(method, path, body=data, headers=headers)
        r = conn.getresponse()
        raw = r.read()
        if r.status >= 300:
            try:
                msg = json.loads(raw).get("message", raw[:200])
            except ValueError:
                msg = raw[:200]
            raise AirlockError(f"Docker API {method} {path.split('?')[0]}: HTTP {r.status} {msg}")
        return json.loads(raw) if raw else None
    finally:
        conn.close()


# ---------- CLI helpers ----------
def inspect_container(name: str) -> dict | None:
    res = run(["docker", "inspect", "--type", "container", name], check=False, quiet=True)
    if not res.ok:
        return None
    return json.loads(res.stdout)[0]


def inspect_image(ref: str) -> dict | None:
    res = run(["docker", "image", "inspect", ref], check=False, quiet=True)
    if not res.ok:
        return None
    return json.loads(res.stdout)[0]


def container_names() -> list[str]:
    res = run(["docker", "ps", "-a", "--format", "{{.Names}}"], quiet=True)
    return [n for n in res.stdout.split() if n]


def pull(ref: str, timeout: float = 1800) -> None:
    run(["docker", "pull", "-q", ref], timeout=timeout)


def image_present(ref: str) -> bool:
    return run(["docker", "image", "inspect", ref], check=False, quiet=True).ok


def tag_image(src: str, dst: str) -> None:
    run(["docker", "tag", src, dst], quiet=True)


def state(name: str) -> dict:
    info = inspect_container(name)
    if not info:
        return {"exists": False}
    st = info["State"]
    return {
        "exists": True,
        "status": st.get("Status"),
        "running": bool(st.get("Running")),
        "restarting": bool(st.get("Restarting")),
        "exit_code": st.get("ExitCode"),
        "health": (st.get("Health") or {}).get("Status"),
        "restart_count": info.get("RestartCount", 0),
        "started_at": st.get("StartedAt"),
        "image_id": info.get("Image"),
        "image_ref": info["Config"].get("Image"),
    }


# ---------- re-create from inspect (Watchtower-style, for containers not managed by compose) ----------
_RUNTIME_ENDPOINT_KEYS = ("IPAddress", "IPPrefixLen", "IPv6Gateway", "GlobalIPv6Address", "GlobalIPv6PrefixLen",
                          "Gateway", "EndpointID", "NetworkID", "DNSNames")


def build_create_body(info: dict, old_image: dict | None, new_image_ref: str) -> dict:
    """Turn `docker inspect <container>` into a /containers/create body for a new image.

    Values that only came from the OLD image (env defaults, labels, cmd, entrypoint, healthcheck, volumes,
    exposed ports, workdir, user) are dropped so the NEW image's defaults apply - exactly like a fresh
    `docker run` with the same options would behave.
    """
    cfg = dict(info["Config"])
    img_cfg = (old_image or {}).get("Config") or {}
    cfg["Image"] = new_image_ref

    img_env = set(img_cfg.get("Env") or [])
    cfg["Env"] = [e for e in (cfg.get("Env") or []) if e not in img_env]
    img_labels = img_cfg.get("Labels") or {}
    cfg["Labels"] = {k: v for k, v in (cfg.get("Labels") or {}).items() if img_labels.get(k) != v}
    for key in ("Cmd", "Entrypoint", "Healthcheck", "WorkingDir", "User", "StopSignal"):
        if cfg.get(key) == img_cfg.get(key):
            cfg.pop(key, None)
    img_vols = img_cfg.get("Volumes") or {}
    if cfg.get("Volumes"):
        cfg["Volumes"] = {k: v for k, v in cfg["Volumes"].items() if k not in img_vols} or None
    img_ports = img_cfg.get("ExposedPorts") or {}
    if cfg.get("ExposedPorts"):
        cfg["ExposedPorts"] = {k: v for k, v in cfg["ExposedPorts"].items() if k not in img_ports} or None
    # The default hostname is the container ID - let Docker pick a new one.
    if cfg.get("Hostname") and info.get("Id", "").startswith(cfg["Hostname"]):
        cfg.pop("Hostname", None)
    if not cfg.get("Domainname"):
        cfg.pop("Domainname", None)

    host = dict(info["HostConfig"])
    nets = info.get("NetworkSettings", {}).get("Networks") or {}
    mode = host.get("NetworkMode", "default")
    endpoints = {}
    for net_name, ep in nets.items():
        if mode in ("host", "none") or mode.startswith("container:"):
            break
        e = {k: v for k, v in ep.items() if k not in _RUNTIME_ENDPOINT_KEYS}
        aliases = [a for a in (e.get("Aliases") or []) if not info.get("Id", "").startswith(a)]
        e["Aliases"] = aliases or None
        e.pop("MacAddress", None)
        endpoints[net_name] = e
    body = {**cfg, "HostConfig": host}
    if endpoints:
        # Only one network can be given at create time; the others are connected afterwards.
        first = mode if mode in endpoints else next(iter(endpoints))
        body["NetworkingConfig"] = {"EndpointsConfig": {first: endpoints[first]}}
        body["_extra_networks"] = {k: v for k, v in endpoints.items() if k != first}
    return body


def create_from_body(name: str, body: dict) -> str:
    extra = body.pop("_extra_networks", {}) or {}
    res = api("POST", f"/containers/create?name={quote(name)}", body)
    cid = res["Id"]
    for net, ep in extra.items():
        api("POST", f"/networks/{quote(net)}/connect", {"Container": cid, "EndpointConfig": ep})
    return cid
