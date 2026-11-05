import json

from update_airlock import hayaml
from update_airlock.sandbox import Sandbox, filter_lines
from update_airlock.testers.homeassistant import (check_config_errors, error_signatures, neutralize,
                                                  normalize_message)

SEC_OK = {"only_internal_network": True, "networks": ["update-airlock-sbx"], "network_mode": "update-airlock-sbx",
          "published_ports": {}, "port_bindings_runtime": {}, "devices": [], "device_cgroup_rules": [],
          "privileged": False, "cap_drop": ["ALL"], "cap_add": [], "security_opt": ["no-new-privileges"]}


def test_security_ok_accepts_isolated():
    assert Sandbox.security_ok(dict(SEC_OK)) == []


def test_security_ok_rejects_every_escape():
    cases = {
        "networks": {"only_internal_network": False, "networks": ["bridge", "update-airlock-sbx"]},
        "network_mode": {"network_mode": "host"},
        "published ports": {"published_ports": {"8123/tcp": [{"HostPort": "8123"}]}},
        "devices": {"devices": [{"PathOnHost": "/dev/ttyUSB0"}]},
        "privileged": {"privileged": True},
        "capabilities not dropped": {"cap_drop": []},
        "dangerous capability": {"cap_add": ["NET_ADMIN"]},
    }
    for word, patch in cases.items():
        sec = dict(SEC_OK)
        sec.update(patch)
        problems = Sandbox.security_ok(sec)
        assert problems and any(word.split()[0] in p for p in problems), (word, problems)


def test_proxy_filter_is_anchored():
    import re
    rx = [re.compile(x) for x in filter_lines(["pypi.org", "files.pythonhosted.org"]).split()]
    ok = lambda h: any(r.match(h) for r in rx)  # noqa: E731
    assert ok("pypi.org") and ok("www.pypi.org") and ok("files.pythonhosted.org")
    assert not ok("pypi.org.evil.com") and not ok("evilpypi.org") and not ok("10.0.0.1")


def test_normalize_and_signatures():
    a = "2026-11-05 10:00:01.123 ERROR (MainThread) [homeassistant.components.met] Unable to parse 198.51.100.5:80 after 3 tries"
    b = "2026-11-05 11:22:33.999 ERROR (MainThread) [homeassistant.components.met] Unable to parse 10.0.0.1:81 after 7 tries"
    w = "2026-11-05 11:22:33.999 WARNING (MainThread) [x] not counted"
    s = error_signatures("\n".join([a, b, w]))
    assert len(s) == 1
    assert normalize_message("id 0xdeadbeef uuid 123e4567-e89b-12d3-a456-426614174000") == "id <hex> uuid <uuid>"
    assert error_signatures(a, ignore=[r"components\.met"]) == {}


def test_check_config_errors():
    out = ("Testing configuration at /config\nFailed config\n  input_number:\n    - expected float for dictionary value"
           " @ data['min']\n\nSuccessful config (partial)\n  homeassistant:\n")
    errs = check_config_errors(out)
    assert any("input_number" in e for e in errs)
    assert not check_config_errors("Testing configuration at /config\n")


# Real output of HA 2026.10 `--script check_config` for a broken input_number (exit code was 0!)
REAL_CC = (
    "\x1b[1mTesting configuration at /config\x1b[0m\n"
    "\x1b[1;37mIncorrect config\x1b[0m\n"
    "  \x1b[1;33minput_number:\x1b[0m \x1b[33m\x1b[33m\n"
    "    - Invalid config for 'input_number' at configuration.yaml, line 6: expected float for dictionary value "
    "'input_number->update_airlock_fault->min', got 'not-a-number'\n"
    "Invalid config for 'input_number' at configuration.yaml, line 7: expected float for dictionary value "
    "'input_number->update_airlock_fault->max', got [1, 2]\n"
    "    - update_airlock_fault: \x1b[36m[source /config/configuration.yaml:5]\x1b[33m\n"
    "        max: \x1b[36m[source /config/configuration.yaml:7]\x1b[33m\n"
    "          - 1\n"
    "        min: not-a-number \x1b[36m[source /config/configuration.yaml:6]\x1b[33m\n"
    "\x1b[0m\n"
    "\x1b[1;37mSuccessful config (partial)\x1b[0m\n"
    "  \x1b[1minput_number:\x1b[0m\n")


def test_check_config_errors_real_ha_output():
    errs = check_config_errors(REAL_CC)
    assert len(errs) == 2, errs
    assert all("Invalid config for 'input_number'" in e for e in errs)
    ok = "\x1b[1mTesting configuration at /config\x1b[0m\n\x1b[1;37mSuccessful config (partial)\x1b[0m\n  homeassistant:\n"
    assert check_config_errors(ok) == []


def _ha_copy(tmp_path):
    st = tmp_path / ".storage"
    st.mkdir()
    (st / "core.config_entries").write_text(json.dumps({"data": {"entries": [
        {"domain": "zha", "disabled_by": None}, {"domain": "sun", "disabled_by": None},
        {"domain": "tuya", "disabled_by": "user"}]}}))
    (tmp_path / "configuration.yaml").write_text(
        "homeassistant:\n  internal_url: http://x\nautomation: !include automations.yaml\n"
        "shell_command:\n  off: ssh pc\nwake_on_lan:\nswitch:\n  - platform: wake_on_lan\n    mac: aa\n"
        "  - platform: template\n    switches: {}\nsonos:\n  media_player: {hosts: [192.0.2.9]}\n")
    (tmp_path / "automations.yaml").write_text("- id: a\n  alias: A\n  triggers: []\n- id: b\n  alias: B\n  initial_state: true\n")
    return tmp_path


def test_neutralize(tmp_path):
    d = _ha_copy(tmp_path)
    stats = neutralize(d, "172.30.98.0/24", ["sun"], ["shell_command", "wake_on_lan", "sonos"])
    entries = {e["domain"]: e["disabled_by"] for e in json.loads((d / ".storage/core.config_entries").read_text())["data"]["entries"]}
    assert entries == {"zha": "user", "sun": None, "tuya": "user"}
    assert stats["config_entries_disabled"] == 1
    cfg = hayaml.load((d / "configuration.yaml").read_text())
    assert "shell_command" not in cfg and "sonos" not in cfg and "wake_on_lan" not in cfg
    assert [p["platform"] for p in cfg["switch"]] == ["template"]
    assert cfg["automation"].tag == "!include" and cfg["automation"].value == "automations.yaml"
    prov = cfg["homeassistant"]["auth_providers"][0]
    assert prov["type"] == "trusted_networks" and prov["trusted_networks"] == ["172.30.98.0/24"]
    autos = hayaml.load((d / "automations.yaml").read_text())
    assert all(a["initial_state"] is False for a in autos)


def test_in_container_probe_parsing(monkeypatch):
    from update_airlock import sandbox as sbm
    from update_airlock.util import RunResult
    sb = Sandbox({"proxy_ip": "172.30.98.2", "proxy_port": 8888}, "x", None)
    out = "REACH 172.30.98.2:8888\nBLOCK 192.0.2.1:80 TimeoutError\nBLOCK 192.0.2.2:6638 OSError\n"
    monkeypatch.setattr(sbm, "run", lambda *a, **k: RunResult(0, out, ""))
    r = sb.in_container_probe("c", ["192.0.2.1:80", "192.0.2.2:6638"])
    assert all(x["ok"] for x in r)
    out2 = "REACH 172.30.98.2:8888\nREACH 192.0.2.1:80\nBLOCK 192.0.2.2:6638 OSError\n"
    monkeypatch.setattr(sbm, "run", lambda *a, **k: RunResult(0, out2, ""))
    r = sb.in_container_probe("c", ["192.0.2.1:80", "192.0.2.2:6638"])
    assert not all(x["ok"] for x in r)
    # broken probe (control not reachable) must not count as "isolated"
    out3 = "BLOCK 172.30.98.2:8888 x\nBLOCK 192.0.2.1:80 x\nBLOCK 192.0.2.2:6638 x\n"
    monkeypatch.setattr(sbm, "run", lambda *a, **k: RunResult(0, out3, ""))
    assert not all(x["ok"] for x in sb.in_container_probe("c", ["192.0.2.1:80", "192.0.2.2:6638"]))
    monkeypatch.setattr(sbm, "run", lambda *a, **k: RunResult(1, "", "python3: not found"))
    assert not all(x["ok"] for x in sb.in_container_probe("c", ["192.0.2.1:80"]))
