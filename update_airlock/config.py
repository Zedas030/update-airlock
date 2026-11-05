"""Configuration: one commented YAML file plus secrets from an .env file.

Values of the form ${NAME} are replaced by environment variables (loaded from the .env file next to
config.yaml, or the file named by UPDATE_AIRLOCK_ENV). Nothing host-specific is hard-coded: every path,
network, URL and threshold comes from here, so the tool can move to another host by copying the config.
"""

from __future__ import annotations

import copy
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .util import AirlockError

DEFAULT_CONFIG = Path(os.environ.get("UPDATE_AIRLOCK_CONFIG", "/etc/update-airlock/config.yaml"))

POLICY_VALUES = ("auto", "notify", "ignore")
KINDS = ("patch", "minor", "major", "digest")

DEFAULTS: dict = {
    "general": {
        "language": "en",
        "state_dir": "/var/lib/update-airlock",
        "backup_dir": "/var/backups/update-airlock",
        "keep_backups": 3,
        "log_file": "/var/log/update-airlock/update-airlock.log",
        "lock_file": "/run/update-airlock.lock",
        "metrics_file": "/var/lib/prometheus/node-exporter/update_airlock.prom",
        "www_dir": "/var/www/update-airlock",
        "pause_while_active": [],
        "min_free_disk_gb": 5,
        "max_updates_per_night": 3,
        "test_valid_hours": 72,
    },
    "homeassistant": {
        "url": "http://127.0.0.1:8123",
        "token": "",
        "notify_service": "",
        "sensor_prefix": "sensor.update_airlock",
        "verify_tls": True,
        "timeout_seconds": 15,
    },
    "notifications": {
        "events": ["held", "test_failed", "updated", "rolled_back", "rollback_failed", "error",
                   "manual_update_available", "self_check"],
        "repeat_after_hours": 24,
        "repeat_after_hours_by_event": {"held": 168, "manual_update_available": 168},
    },
    "check": {
        "failures_before_alert": 2,
        "github_token": "",
        "http_timeout_seconds": 20,
    },
    "maintenance": {
        "window": "03:40-04:30",
        "days": [],
        "presence": {
            "enabled": False,
            "person": "",
            "activity_sensors": [],
            "quiet_minutes": 20,
        },
    },
    "observe": {
        "minutes": 15,
        "interval_seconds": 30,
        "startup_grace_minutes": 6,
        "unavailable_threshold_pp": 10.0,
        "web_failures_before_rollback": 4,
    },
    "sandbox": {
        "network": "update-airlock-sbx",
        "subnet": "172.30.98.0/24",
        "bridge_name": "ua-sbx",
        "proxy_ip": "172.30.98.2",
        "egress_network": "update-airlock-egress",
        "egress_subnet": "172.30.97.0/24",
        "egress_bridge_name": "ua-egress",
        "proxy_image": "update-airlock/egress-proxy:1",
        "proxy_base_image": "alpine:3.20",
        "proxy_port": 8888,
        "proxy_allow_domains": ["pypi.org", "files.pythonhosted.org", "wheels.home-assistant.io"],
        "probe_image": "alpine:3.20",
        "memory": "1536m",
        "cpus": "2",
        "pids_limit": 1024,
        "work_dir": "",
        "must_be_unreachable": ["@gateway:80", "@host_lan:8123", "@host_lan:22",
                                "@host_bridge:8123", "@host_bridge:1883", "@host_bridge:22",
                                "1.1.1.1:443", "8.8.8.8:53"],
        "proxy_must_deny": ["@gateway:80", "@host_lan:8123", "example.com:443"],
        "proxy_must_allow": ["pypi.org:443"],
    },
    "ui": {
        "home_url": "",
        "home_label": "Dashboard",
    },
    "containers": {},
}

CONTAINER_DEFAULTS: dict = {
    "enabled": True,
    "tester": "generic",            # homeassistant | generic | none
    "notes": "",                    # release-notes provider: homeassistant | "" (none)
    "track": "tag",                 # tag = follow the digest of the current tag; semver = look for newer version tags
    "tag_pattern": r"^v?\d+\.\d+\.\d+$",
    "versioning": "semver",         # semver | calver (YEAR.MONTH.PATCH: a new month counts as "minor")
    "policy": {"patch": "notify", "minor": "notify", "major": "notify", "digest": "notify"},
    "breaking_changes": "hold",     # hold | notify | ignore
    "hold_on_core_changes": False,
    "compose_file": "",             # override; normally read from the compose labels of the container
    "priority": 50,                 # lower = updated first in the night
    "backup": {"exclude": [], "skip_mounts": ["/run", "/var/run", "/etc/localtime", "/etc/timezone",
                                              "/dev", "/proc", "/sys", "/var/run/docker.sock"],
               "max_size_gb": 20},
    "test": {},
    "observe": {},
    "health": {"http_url": "", "ha_unavailable": False},
}


def _deep_merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


_ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")


def _expand(value):
    if isinstance(value, str):
        def sub(m):
            name, default = m.group(1), m.group(2)
            v = os.environ.get(name)
            if v is None or v == "":
                return default if default is not None else ""
            return v
        return _ENV_RE.sub(sub, value)
    if isinstance(value, list):
        return [_expand(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    return value


def load_env_file(path: Path) -> None:
    """Minimal .env parser (KEY=VALUE, # comments, optional quotes). Existing env vars win."""
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip().removeprefix("export ").strip()
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        os.environ.setdefault(k, v)


@dataclass
class ContainerConfig:
    name: str
    raw: dict

    def __getattr__(self, item):
        try:
            return self.raw[item]
        except KeyError as e:
            raise AttributeError(item) from e

    def policy_for(self, kind: str) -> str:
        return self.raw["policy"].get(kind, "notify")


@dataclass
class Config:
    raw: dict
    path: Path | None = None
    containers: dict[str, ContainerConfig] = field(default_factory=dict)

    def __getitem__(self, item):
        return self.raw[item]

    @property
    def general(self) -> dict:
        return self.raw["general"]

    @property
    def ha(self) -> dict:
        return self.raw["homeassistant"]

    @property
    def sandbox(self) -> dict:
        return self.raw["sandbox"]

    def observe_for(self, c: ContainerConfig) -> dict:
        return _deep_merge(self.raw["observe"], c.raw.get("observe") or {})

    @property
    def state_dir(self) -> Path:
        return Path(self.general["state_dir"])

    @property
    def backup_dir(self) -> Path:
        return Path(self.general["backup_dir"])

    @property
    def sandbox_work_dir(self) -> Path:
        wd = self.sandbox.get("work_dir")
        return Path(wd) if wd else self.state_dir / "sandbox"


def parse_config(data: dict, path: Path | None = None) -> Config:
    if not isinstance(data, dict):
        raise AirlockError("Config must be a YAML mapping")
    unknown = set(data) - set(DEFAULTS)
    if unknown:
        raise AirlockError(f"Unknown top-level keys in config: {', '.join(sorted(unknown))}")
    merged = _expand(_deep_merge(DEFAULTS, data))
    cfg = Config(raw=merged, path=path)
    errors: list[str] = []

    lang = merged["general"]["language"]
    if lang not in ("en", "de"):
        errors.append(f"general.language must be 'en' or 'de', not {lang!r}")
    if not re.fullmatch(r"\d{1,2}:\d{2}-\d{1,2}:\d{2}", str(merged["maintenance"]["window"])):
        errors.append("maintenance.window must look like '03:40-04:30'")
    days = merged["maintenance"]["days"] or []
    bad_days = [d for d in days if d not in ("mon", "tue", "wed", "thu", "fri", "sat", "sun")]
    if bad_days:
        errors.append(f"maintenance.days: unknown values {bad_days}")
    pres = merged["maintenance"]["presence"]
    if pres.get("enabled") and not pres.get("person"):
        errors.append("maintenance.presence.enabled needs maintenance.presence.person")
    thr = merged["observe"]["unavailable_threshold_pp"]
    if not isinstance(thr, (int, float)) or thr <= 0:
        errors.append("observe.unavailable_threshold_pp must be a positive number")

    for name, c in (merged.get("containers") or {}).items():
        if c is None:
            c = {}
        cc = _deep_merge(CONTAINER_DEFAULTS, c)
        for k in cc["policy"]:
            if k not in KINDS:
                errors.append(f"containers.{name}.policy: unknown kind {k!r} (allowed: {', '.join(KINDS)})")
            elif cc["policy"][k] not in POLICY_VALUES:
                errors.append(f"containers.{name}.policy.{k}: {cc['policy'][k]!r} is not one of {POLICY_VALUES}")
        if cc["tester"] not in ("homeassistant", "generic", "none"):
            errors.append(f"containers.{name}.tester: unknown tester {cc['tester']!r}")
        if cc["notes"] not in ("", "homeassistant"):
            errors.append(f"containers.{name}.notes: unknown release-notes provider {cc['notes']!r}")
        if cc["track"] not in ("tag", "semver"):
            errors.append(f"containers.{name}.track must be 'tag' or 'semver'")
        if cc["versioning"] not in ("semver", "calver"):
            errors.append(f"containers.{name}.versioning must be 'semver' or 'calver'")
        if cc["breaking_changes"] not in ("hold", "notify", "ignore"):
            errors.append(f"containers.{name}.breaking_changes must be hold, notify or ignore")
        try:
            re.compile(cc["tag_pattern"])
        except re.error as e:
            errors.append(f"containers.{name}.tag_pattern is not a valid regex: {e}")
        cfg.containers[name] = ContainerConfig(name=name, raw=cc)
    if errors:
        raise AirlockError("Config errors:\n  - " + "\n  - ".join(errors))
    return cfg


def load_config(path: Path | None = None) -> Config:
    path = Path(path or DEFAULT_CONFIG)
    if not path.exists():
        raise AirlockError(f"Config file not found: {path}")
    env_file = Path(os.environ.get("UPDATE_AIRLOCK_ENV", str(path.parent / ".env")))
    load_env_file(env_file)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        raise AirlockError(f"Config file {path} is not valid YAML: {e}") from e
    return parse_config(data, path)
