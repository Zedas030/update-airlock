"""Decision logic of the runner with a fake registry, fake container and fake release notes."""

import pytest

from update_airlock import metrics, runner as rmod
from update_airlock.config import parse_config
from update_airlock.inventory import Current
from update_airlock.notes import BreakingChange, NotesProvider
from update_airlock.registry import ImageRef


class FakeRegistry:
    def __init__(self, tags=(), digests=None, labels=None, fail=False):
        self.tags_, self.digests, self.labels, self.fail = list(tags), digests or {}, labels or {}, fail

    def tags(self, ref):
        if self.fail:
            raise rmod.AirlockError("registry down")
        return self.tags_

    def digest(self, ref, tag):
        if self.fail:
            raise rmod.AirlockError("registry down")
        return self.digests[tag]

    def platform_info(self, ref, reference):
        return {"available": True, "labels": self.labels.get(reference, {})}


class FakeNotes(NotesProvider):
    name = "fake"

    def __init__(self, changes=(), used=("zha",), fail=False):
        self.changes, self.used, self.fail = list(changes), set(used), fail

    def breaking_changes(self, old, new):
        if self.fail:
            raise rmod.AirlockError("GitHub down")
        return list(self.changes)

    def used_domains(self):
        return self.used


def make(tmp_path, monkeypatch, container_cfg, current, registry, notes=None):
    cfg = parse_config({"general": {"state_dir": str(tmp_path / "s"), "lock_file": str(tmp_path / "lock"),
                                    "metrics_file": str(tmp_path / "m.prom"), "www_dir": str(tmp_path / "www")},
                        "check": {"failures_before_alert": 2},
                        "containers": {"app": container_cfg}})
    app = rmod.Airlock(cfg)
    app.registry = registry
    monkeypatch.setattr(rmod, "read_current", lambda name, override="": current)
    if notes is not None:
        monkeypatch.setattr(app, "notes_provider", lambda c, cur: notes)
    sent = []
    monkeypatch.setattr(app.ha, "notify", lambda svc, title, msg, data=None: sent.append(msg))
    app.cfg.raw["homeassistant"]["token"] = "t"
    app.cfg.raw["homeassistant"]["notify_service"] = "notify.x"
    app.ha.token = "t"
    monkeypatch.setattr(app.ha, "set_state", lambda *a, **k: None)
    monkeypatch.setattr(app.ha, "get_state", lambda *a, **k: {"state": "ok"})
    return app, sent


def cur(tag="2026.10.4", digest="sha256:old", version=None):
    ref = ImageRef.parse(f"ghcr.io/home-assistant/home-assistant:{tag}")
    return Current(name="app", ref=ref, image_ref=f"ghcr.io/home-assistant/home-assistant:{tag}", image_id="sha256:img",
                   digest=digest, version=version or tag, compose=None, mounts=[], info={}, image_info={})


HA = {"tester": "none", "notes": "homeassistant", "track": "semver", "tag_pattern": r"^\d{4}\.\d{1,2}\.\d+$",
      "versioning": "calver", "policy": {"patch": "auto", "minor": "auto", "major": "notify", "digest": "notify"}}
REG = FakeRegistry(tags=["2026.10.4", "2026.11.0", "2026.11.0b1"], digests={"2026.11.0": "sha256:new"})


def test_breaking_change_holds_and_notifies_once(tmp_path, monkeypatch):
    notes = FakeNotes([BreakingChange("ZHA groups", ["zha"], "2026.11.0", url="u1", key="1"),
                       BreakingChange("Hue", ["hue"], "2026.11.0", key="2")])
    app, sent = make(tmp_path, monkeypatch, HA, cur(), REG, notes)
    app.check(run_tests=False)
    st = app.status_of("app")
    assert st["status"] == "held" and st["held_domains"] == ["zha"]
    assert len(sent) == 1 and "2026.11.0" in sent[0] and "zha" in sent[0]
    app.check(run_tests=False)
    assert len(sent) == 1  # de-duplicated
    assert app.hist.count("held") == 1


def test_ack_releases_the_hold(tmp_path, monkeypatch):
    notes = FakeNotes([BreakingChange("ZHA groups", ["zha"], "2026.11.0", key="1")])
    app, _ = make(tmp_path, monkeypatch, HA, cur(), REG, notes)
    app.ack(app.cfg.containers["app"], "2026.11.0")
    app.check(run_tests=False)
    assert app.status_of("app")["status"] == "ready"  # tester none -> ready without sandbox


def test_no_match_means_candidate(tmp_path, monkeypatch):
    app, _ = make(tmp_path, monkeypatch, HA, cur(), REG, FakeNotes([BreakingChange("Hue", ["hue"], "x", key="2")]))
    assert app.evaluate(app.cfg.containers["app"])["status"] == "candidate"


def test_simulated_breaking_change(tmp_path, monkeypatch):
    app, sent = make(tmp_path, monkeypatch, HA, cur(), REG, FakeNotes([]))
    st = app.evaluate(app.cfg.containers["app"], simulate_breaking=["zha"])
    assert st["status"] == "held" and st["held_domains"] == ["zha"]


def test_notes_unavailable_fails_closed(tmp_path, monkeypatch):
    app, sent = make(tmp_path, monkeypatch, HA, cur(), REG, FakeNotes(fail=True))
    app.check(run_tests=False)
    assert app.status_of("app")["held_reason"] == "notes_unavailable"
    assert any("Release" in m or "release" in m for m in sent)
    app.check(run_tests=False)
    # second consecutive failure -> self-monitoring message
    assert any("2" in m and "release notes" in m for m in sent)


def test_registry_failure_alerts_after_n(tmp_path, monkeypatch):
    app, sent = make(tmp_path, monkeypatch, HA, cur(), FakeRegistry(fail=True), FakeNotes())
    app.check(run_tests=False)
    assert app.status_of("app")["status"] == "error"
    app.check(run_tests=False)
    assert any("registry ghcr.io" in m for m in sent)
    assert app.global_state()["failures"]["registry ghcr.io"] == 2
    app.registry = REG
    monkeypatch.setattr(app, "notes_provider", lambda c, cur: FakeNotes())
    app.check(run_tests=False)
    assert app.global_state()["failures"]["registry ghcr.io"] == 0


def test_minor_notify_only(tmp_path, monkeypatch):
    c = dict(HA, policy={"patch": "auto", "minor": "notify", "major": "notify", "digest": "notify"})
    app, sent = make(tmp_path, monkeypatch, c, cur(), REG, FakeNotes())
    app.check(run_tests=False)
    assert app.status_of("app")["status"] == "notify_only"
    assert "update-airlock update app" in sent[0]


def test_digest_tracking_with_version_labels(tmp_path, monkeypatch):
    c = {"tester": "none", "track": "tag", "policy": {"patch": "auto", "minor": "notify", "digest": "notify"}}
    reg = FakeRegistry(digests={"2": "sha256:new"}, labels={"sha256:new": {"org.opencontainers.image.version": "2.0.3"}})
    app, _ = make(tmp_path, monkeypatch, c, cur(tag="2", version="2.0.2"), reg)
    st = app.evaluate(app.cfg.containers["app"])
    assert st["kind"] == "patch" and st["status"] == "candidate" and st["candidate_ref"].endswith(":2@sha256:new")
    app2, _ = make(tmp_path / "b", monkeypatch, c, cur(tag="2", version=None), FakeRegistry(digests={"2": "sha256:new"}))
    assert app2.evaluate(app2.cfg.containers["app"])["kind"] == "digest"


def test_up_to_date_and_ignored(tmp_path, monkeypatch):
    app, _ = make(tmp_path, monkeypatch, {"track": "tag", "policy": {"digest": "auto"}},
                  cur(tag="1.8", digest="sha256:same"), FakeRegistry(digests={"1.8": "sha256:same"}))
    assert app.evaluate(app.cfg.containers["app"])["status"] == "up_to_date"
    app.cfg.containers["app"].raw["policy"] = {k: "ignore" for k in ("patch", "minor", "major", "digest")}
    assert app.evaluate(app.cfg.containers["app"])["status"] == "ignored"


def test_update_refuses_held_without_force(tmp_path, monkeypatch):
    notes = FakeNotes([BreakingChange("ZHA", ["zha"], "2026.11.0", key="1")])
    app, _ = make(tmp_path, monkeypatch, HA, cur(), REG, notes)
    with pytest.raises(rmod.AirlockError, match="held back"):
        app.update(app.cfg.containers["app"])


def test_update_refuses_when_test_fails(tmp_path, monkeypatch):
    c = dict(HA, tester="generic")
    app, _ = make(tmp_path, monkeypatch, c, cur(), REG, FakeNotes())
    from update_airlock.testers import TestResult

    def fake_test(cc, ref=None, faults=None):
        r = TestResult("app", ref, "sha256:new")
        r.add("config check without errors", False, "broken")
        return r.finish()
    monkeypatch.setattr(app, "test", fake_test)
    called = []
    monkeypatch.setattr(rmod.deploy, "stop", lambda *a: called.append("stop"))
    with pytest.raises(rmod.AirlockError, match="test failed - no update"):
        app.update(app.cfg.containers["app"])
    assert called == []  # production container never touched


def test_apply_outside_window_does_nothing(tmp_path, monkeypatch):
    app, _ = make(tmp_path, monkeypatch, HA, cur(), REG, FakeNotes())
    monkeypatch.setattr(rmod, "in_window", lambda *a, **k: False)
    monkeypatch.setattr(app, "update", lambda *a, **k: pytest.fail("must not update"))
    r = app.apply()
    assert "outside" in r["reason"]


def test_apply_postponed_when_active(tmp_path, monkeypatch):
    app, _ = make(tmp_path, monkeypatch, HA, cur(), REG, FakeNotes())
    monkeypatch.setattr(rmod, "in_window", lambda *a, **k: True)
    monkeypatch.setattr(rmod, "presence", lambda *a, **k: rmod_presence(True, True, "binary_sensor.lr is on"))
    monkeypatch.setattr(app, "update", lambda *a, **k: pytest.fail("must not update"))
    r = app.apply()
    assert "postponed" in r["reason"]


def rmod_presence(known, active, reason):
    from update_airlock.window import Presence
    return Presence(known, active, reason)


def test_metrics_render(tmp_path, monkeypatch):
    notes = FakeNotes([BreakingChange("ZHA", ["zha"], "2026.11.0", key="1")])
    app, _ = make(tmp_path, monkeypatch, HA, cur(), REG, notes)
    app.check(run_tests=False)
    text = (tmp_path / "m.prom").read_text()
    assert 'update_airlock_container_status{container="app",status="held"} 3' in text
    assert "update_airlock_last_run_timestamp_seconds" in text
    assert 'update_airlock_update_available{container="app",kind="minor"' in text
    assert metrics.render({}, {}).endswith("\n")
    # every status the runner can produce has a code (no -1 in Grafana)
    import re
    import update_airlock.runner as r
    src = open(r.__file__, encoding="utf-8").read()
    produced = set(re.findall(r'status"?\]?\s*[=:]\s*"([a-z_]+)"', src)) | set(re.findall(r'status="([a-z_]+)"', src))
    assert produced and produced <= set(metrics.STATUS_CODES), produced - set(metrics.STATUS_CODES)
    assert "2026.11.0" in (tmp_path / "www" / "index.html").read_text(encoding="utf-8")


def test_verify_after_rollback_waits_for_http(tmp_path, monkeypatch):
    c = {"tester": "generic", "track": "tag", "policy": {"digest": "auto"},
         "health": {"http_url": "http://127.0.0.1:9/"}, "observe": {"startup_grace_minutes": 0}}
    app, _ = make(tmp_path, monkeypatch, c, cur(tag="latest"), FakeRegistry())
    monkeypatch.setattr(rmod.dockerapi, "state", lambda n: {"running": True, "status": "running"})
    answers = iter([(False, "ConnectionError"), (False, "ConnectionError"), (True, "HTTP 200")])
    import update_airlock.observe as obs
    monkeypatch.setattr(obs, "web_check", lambda ha, url: next(answers))
    monkeypatch.setattr(rmod.time, "sleep", lambda s: None)
    r = app._verify_after_rollback(app.cfg.containers["app"])
    assert r["ok"] and "HTTP 200" in r["detail"]


def test_inconclusive_generic_test():
    from update_airlock.testers import TestResult
    r = TestResult("x", "img@sha256:a", "sha256:a")
    r.add("container starts and stays up (n/a in the sandbox: fails with the current image too)", True, "")
    r.inconclusive = "does not run in isolation"
    assert r.finish().passed
    r2 = TestResult("x", "img@sha256:a", "sha256:a", require_conclusive=True)
    r2.add("container starts and stays up (n/a ...)", True, "")
    r2.inconclusive = "does not run in isolation"
    assert not r2.finish().passed and "require_conclusive" in r2.error
