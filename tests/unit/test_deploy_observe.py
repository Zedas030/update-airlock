import datetime as dt
import shutil
import sqlite3

import pytest

from update_airlock import deploy, dockerapi, observe as obsmod
from update_airlock.copying import copy_tree
from update_airlock.deploy import rewrite_compose_image
from update_airlock.util import AirlockError
from update_airlock.window import Presence, in_window, presence

COMPOSE = """# my stack
name: x
services:
  web:
    image: nginx:1.25   # pinned
    restart: unless-stopped
  homeassistant:
    container_name: homeassistant
    image: "ghcr.io/home-assistant/home-assistant:2026.10.4@sha256:aaa"
    network_mode: host
volumes:
  data: {}
"""


def test_rewrite_compose_only_touches_one_service():
    out = rewrite_compose_image(COMPOSE, "homeassistant", "ghcr.io/home-assistant/home-assistant:2026.11.0@sha256:bbb")
    assert '"ghcr.io/home-assistant/home-assistant:2026.11.0@sha256:bbb"' in out
    assert "image: nginx:1.25   # pinned" in out
    assert out.count("\n") == COMPOSE.count("\n")
    out2 = rewrite_compose_image(COMPOSE, "web", "nginx:1.27@sha256:ccc")
    assert "image: nginx:1.27@sha256:ccc   # pinned" in out2
    assert "2026.10.4@sha256:aaa" in out2


def test_rewrite_compose_unknown_service():
    with pytest.raises(AirlockError):
        rewrite_compose_image(COMPOSE, "db", "x")


def test_compose_image_file_refuses_variables(tmp_path):
    f = tmp_path / "c.yml"
    f.write_text("services:\n  a:\n    image: ${IMG}\n")
    with pytest.raises(AirlockError, match="variable"):
        deploy.compose_image_file([str(f)], "a")


def test_build_create_body_drops_image_defaults():
    info = {"Id": "abcdef123456789", "Config": {
        "Hostname": "abcdef123456", "Image": "x:1", "Env": ["PATH=/usr/bin", "TZ=Etc/UTC", "SECRET=1"],
        "Cmd": ["run"], "Entrypoint": ["/init"], "Labels": {"img": "1", "mine": "2"}, "ExposedPorts": {"80/tcp": {}},
        "Volumes": {"/data": {}}, "WorkingDir": "/app", "User": ""},
        "HostConfig": {"NetworkMode": "bridge", "RestartPolicy": {"Name": "unless-stopped"}},
        "NetworkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.5", "Aliases": None, "MacAddress": "x"}}}}
    img = {"Config": {"Env": ["PATH=/usr/bin"], "Cmd": ["run"], "Entrypoint": ["/init"], "Labels": {"img": "1"},
                      "ExposedPorts": {"80/tcp": {}}, "Volumes": {"/data": {}}, "WorkingDir": "/app", "User": ""}}
    body = dockerapi.build_create_body(info, img, "x:2@sha256:new")
    assert body["Image"] == "x:2@sha256:new"
    assert body["Env"] == ["TZ=Etc/UTC", "SECRET=1"]
    assert body["Labels"] == {"mine": "2"}
    for k in ("Cmd", "Entrypoint", "WorkingDir", "Hostname"):
        assert k not in body
    assert body.get("ExposedPorts") is None and body.get("Volumes") is None
    ep = body["NetworkingConfig"]["EndpointsConfig"]["bridge"]
    assert "IPAddress" not in ep and "MacAddress" not in ep
    assert body["HostConfig"]["RestartPolicy"]["Name"] == "unless-stopped"


def test_build_create_body_host_network_has_no_endpoints():
    info = {"Id": "1", "Config": {"Image": "a"}, "HostConfig": {"NetworkMode": "host"},
            "NetworkSettings": {"Networks": {"host": {}}}}
    assert "NetworkingConfig" not in dockerapi.build_create_body(info, {}, "a:2")


def test_copy_tree_excludes_and_copies_sqlite(tmp_path):
    src = tmp_path / "src"
    (src / "backups").mkdir(parents=True)
    (src / "backups" / "big.tar").write_text("x")
    (src / ".ssh").mkdir()
    (src / ".ssh" / "id").write_text("key")
    (src / "configuration.yaml").write_text("a: 1")
    (src / "old.yaml.bak-20261027").write_text("old")
    db = sqlite3.connect(src / "home-assistant_v2.db")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE t(x)")
    db.execute("INSERT INTO t VALUES (42)")
    db.commit()  # stays in the -wal file while the connection is open
    dst = tmp_path / "dst"
    stats = copy_tree(src, dst, ["backups", ".ssh", "*.bak-*"])
    db.close()
    assert (dst / "configuration.yaml").exists()
    assert not (dst / "backups").exists() and not (dst / ".ssh").exists()
    assert not (dst / "old.yaml.bak-20261027").exists()
    assert stats["sqlite"] == 1
    assert sqlite3.connect(dst / "home-assistant_v2.db").execute("SELECT x FROM t").fetchone() == (42,)


@pytest.mark.skipif(not shutil.which("zstd") or not shutil.which("tar"), reason="needs tar + zstd")
def test_backup_and_restore_roundtrip(tmp_path, monkeypatch):
    from update_airlock.inventory import Current, Mount
    from update_airlock.registry import ImageRef
    data = tmp_path / "data"
    (data / "backups").mkdir(parents=True)
    (data / "backups" / "keep-me.tar").write_text("ha backup")
    (data / "config.yaml").write_text("version: 1")
    (data / ".storage").mkdir()
    (data / ".storage" / "core").write_text("old")
    cur = Current(name="svc", ref=ImageRef.parse("x:1"), image_ref="x:1", image_id="sha256:old", digest="sha256:d1",
                  version="1", compose=None, mounts=[Mount("bind", str(data), str(data), "/config", True)],
                  info={"Config": {}})
    bs = deploy.take_backup(tmp_path / "bk", cur, [], ["backups"], "test")
    assert bs.meta["complete"] and (bs.path / "mount0.tar.zst").exists()
    # the "new version" changes things
    (data / "config.yaml").write_text("version: 2")
    (data / ".storage" / "new_file").write_text("created by new version")
    q = tmp_path / "quarantine"
    st = deploy.restore_mounts(bs, q)
    assert (data / "config.yaml").read_text() == "version: 1"
    assert not (data / ".storage" / "new_file").exists()
    assert (q / "mount0" / ".storage" / "new_file").exists()  # nothing lost
    assert (data / "backups" / "keep-me.tar").exists()  # excluded paths are left alone
    assert st["moved"] == 1
    assert [b.path.name for b in deploy.list_backups(tmp_path / "bk", "svc")] == [bs.path.name]


# ---------- observation ----------
class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


OPTS = {"minutes": 10, "interval_seconds": 30, "startup_grace_minutes": 3, "unavailable_threshold_pp": 10,
        "web_failures_before_rollback": 3}


class FakeHA:
    def __init__(self, ok=True, unavailable=10, total=100):
        self.ok, self.unavailable, self.total = ok, unavailable, total

    def api_ok(self):
        return self.ok, "HTTP 200" if self.ok else "HTTP 502"

    def states(self):
        return ([{"entity_id": f"s.u{i}", "state": "unavailable"} for i in range(self.unavailable)]
                + [{"entity_id": f"s.o{i}", "state": "on"} for i in range(self.total - self.unavailable)])


def _patch_state(monkeypatch, states):
    it = iter(states)
    last = {}

    def fake(name):
        nonlocal last
        try:
            last = next(it)
        except StopIteration:
            pass
        return last
    monkeypatch.setattr(obsmod.dockerapi, "state", fake)


RUNNING = {"running": True, "status": "running", "restart_count": 0, "health": None}


def test_observe_healthy(monkeypatch):
    _patch_state(monkeypatch, [RUNNING])
    c = Clock()
    ha = FakeHA(unavailable=12)
    o = obsmod.observe("ha", OPTS, ha, "", ha, baseline_share=10.0, sleep=c.sleep, clock=c)
    assert o.ok, o.reason
    assert o.final_unavailable == 12.0


def test_observe_unavailable_jump_rolls_back(monkeypatch):
    _patch_state(monkeypatch, [RUNNING])
    c = Clock()
    ha = FakeHA(unavailable=40)
    o = obsmod.observe("ha", OPTS, ha, "", ha, baseline_share=20.0, sleep=c.sleep, clock=c)
    assert not o.ok and "40.0%" in o.reason


def test_observe_container_dies(monkeypatch):
    _patch_state(monkeypatch, [RUNNING, RUNNING, {"running": False, "status": "exited", "exit_code": 1}])
    c = Clock()
    o = obsmod.observe("x", OPTS, None, "", None, None, sleep=c.sleep, clock=c)
    assert not o.ok and "not running" in o.reason


def test_observe_restart_detected(monkeypatch):
    _patch_state(monkeypatch, [RUNNING, dict(RUNNING, restart_count=1)])
    c = Clock()
    o = obsmod.observe("x", OPTS, None, "", None, None, sleep=c.sleep, clock=c)
    assert not o.ok and "restarted" in o.reason


def test_observe_web_down(monkeypatch):
    _patch_state(monkeypatch, [RUNNING])
    c = Clock()
    o = obsmod.observe("ha", OPTS, FakeHA(ok=False), "", None, None, sleep=c.sleep, clock=c)
    assert not o.ok and "does not answer" in o.reason


# ---------- window / presence ----------
TZ = dt.timezone(dt.timedelta(hours=1))


def test_window():
    d = dt.datetime(2026, 11, 5, 3, 50, tzinfo=TZ)
    assert in_window(d, "03:40-04:30")
    assert not in_window(d.replace(hour=4, minute=30), "03:40-04:30")
    assert in_window(d.replace(hour=23, minute=30), "23:00-02:00")
    assert in_window(d.replace(hour=1), "23:00-02:00")
    assert not in_window(d.replace(hour=12), "23:00-02:00")
    assert in_window(d, "03:40-04:30", ["thu"]) and not in_window(d, "03:40-04:30", ["mon"])


class PresHA:
    def __init__(self, states):
        self.s = states

    def get_state(self, e):
        if isinstance(self.s, Exception):
            raise self.s
        return self.s.get(e)


PCFG = {"enabled": True, "person": "person.me", "activity_sensors": ["binary_sensor.lr", "binary_sensor.bath"],
        "quiet_minutes": 20}


def test_presence_variants():
    now = dt.datetime(2026, 11, 5, 3, 50, tzinfo=TZ)
    away = PresHA({"person.me": {"state": "not_home"}})
    assert presence(away, PCFG, now) == Presence(True, False, "person.me is not_home")
    on = PresHA({"person.me": {"state": "home"}, "binary_sensor.lr": {"state": "on"}})
    assert presence(on, PCFG, now).active
    recent = PresHA({"person.me": {"state": "home"},
                     "binary_sensor.lr": {"state": "off", "last_changed": "2026-11-05T02:40:00+00:00"}})
    assert presence(recent, PCFG, now).active  # 03:40 local = 10 min ago
    asleep = PresHA({"person.me": {"state": "home"},
                     "binary_sensor.lr": {"state": "off", "last_changed": "2026-11-04T22:00:00+00:00"},
                     "binary_sensor.bath": {"state": "off", "last_changed": "2026-11-04T23:00:00+00:00"}})
    p = presence(asleep, PCFG, now)
    assert p.known and not p.active
    down = PresHA(AirlockError("Home Assistant not reachable"))
    p = presence(down, PCFG, now)
    assert not p.known  # -> fixed window only
    assert not presence(down, dict(PCFG, enabled=False), now).known
