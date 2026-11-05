import pytest

from update_airlock.config import parse_config
from update_airlock.util import AirlockError
from update_airlock.versions import Version, candidates, classify, pick, release_lines_between

HA_TAGS = ["2026.10.3", "2026.10.4", "2026.11.0b6", "2026.11.0", "stable", "latest", "dev", "2026.9.9", "2026.10.4-rc1"]
HA_PAT = r"^\d{4}\.\d{1,2}\.\d+$"


def test_parse_and_order():
    assert Version.parse("v1.2.3") == Version(1, 2, 3)
    assert Version.parse("1.8") == Version(1, 8, 0)
    assert Version.parse("2026.11.0b6") is None
    assert Version.parse("latest") is None
    assert Version.parse("2026.10.10") > Version.parse("2026.10.9")


def test_classify_semver_and_calver():
    v = Version.parse
    assert classify(v("1.2.3"), v("1.2.4")) == "patch"
    assert classify(v("1.2.3"), v("1.3.0")) == "minor"
    assert classify(v("1.2.3"), v("2.0.0")) == "major"
    assert classify(v("1.2.3"), v("1.2.3")) is None
    assert classify(v("2026.10.4"), v("2026.11.0"), "calver") == "minor"
    assert classify(v("2026.12.3"), v("2027.1.0"), "calver") == "minor"  # year change is still a monthly release
    assert classify(v("2026.10.4"), v("2026.10.5"), "calver") == "patch"


def test_candidates_ignore_betas_and_floating_tags():
    c = candidates("2026.10.4", HA_TAGS, HA_PAT, "calver")
    assert c == {"minor": "2026.11.0"}
    c = candidates("2026.10.3", HA_TAGS, HA_PAT, "calver")
    assert c == {"patch": "2026.10.4", "minor": "2026.11.0"}
    assert candidates("stable", HA_TAGS, HA_PAT) == {}


def test_pick_respects_policy():
    c = {"patch": "1.2.5", "minor": "1.3.1", "major": "2.0.0"}
    assert pick(c, {"patch": "auto", "minor": "notify", "major": "notify"}) == ("patch", "1.2.5")
    assert pick(c, {"patch": "auto", "minor": "auto", "major": "notify"}) == ("minor", "1.3.1")
    assert pick(c, {"patch": "notify", "minor": "notify", "major": "notify"}) == (None, None)


def test_release_lines():
    assert release_lines_between(Version(2026, 11, 2), Version(2027, 1, 0)) == [(2026, 11), (2026, 12), (2027, 1)]


def test_config_defaults_and_env(monkeypatch):
    monkeypatch.setenv("HA_TOKEN", "abc")
    cfg = parse_config({"homeassistant": {"token": "${HA_TOKEN}"}, "containers": {"x": {"policy": {"patch": "auto"}}}})
    assert cfg.ha["token"] == "abc"
    assert cfg.containers["x"].policy_for("patch") == "auto"
    assert cfg.containers["x"].policy_for("minor") == "notify"
    assert cfg.general["keep_backups"] == 3
    assert cfg.sandbox["subnet"] == "172.30.98.0/24"


def test_config_env_default(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    cfg = parse_config({"check": {"github_token": "${GITHUB_TOKEN:-}"}})
    assert cfg["check"]["github_token"] == ""


@pytest.mark.parametrize("bad, msg", [
    ({"containers": {"x": {"policy": {"patch": "always"}}}}, "is not one of"),
    ({"containers": {"x": {"policy": {"weekly": "auto"}}}}, "unknown kind"),
    ({"containers": {"x": {"tester": "magic"}}}, "unknown tester"),
    ({"maintenance": {"window": "nachts"}}, "maintenance.window"),
    ({"maintenance": {"presence": {"enabled": True}}}, "needs maintenance.presence.person"),
    ({"general": {"language": "fr"}}, "general.language"),
    ({"bogus": 1}, "Unknown top-level"),
    ({"containers": {"x": {"tag_pattern": "("}}}, "not a valid regex"),
])
def test_config_errors(bad, msg):
    with pytest.raises(AirlockError, match=msg):
        parse_config(bad)


def test_load_config_and_env_file(tmp_path, monkeypatch):
    from update_airlock.config import load_config
    monkeypatch.delenv("HA_TOKEN", raising=False)
    (tmp_path / "config.yaml").write_text("homeassistant:\n  token: ${HA_TOKEN}\n")
    (tmp_path / ".env").write_text("# comment\nHA_TOKEN='s3cret'\n")
    monkeypatch.delenv("UPDATE_AIRLOCK_ENV", raising=False)
    cfg = load_config(tmp_path / "config.yaml")
    assert cfg.ha["token"] == "s3cret"


def test_example_config_is_valid():
    from pathlib import Path
    import yaml
    p = Path(__file__).resolve().parents[2] / "config" / "config.example.yaml"
    cfg = parse_config(yaml.safe_load(p.read_text(encoding="utf-8")))
    assert "homeassistant" in cfg.containers
