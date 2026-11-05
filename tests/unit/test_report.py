import json

from update_airlock import report


def test_status_page_renders_and_escapes(tmp_path):
    cs = {"homeassistant": {"status": "held", "current_version": "2026.10.4", "available_version": "2026.11.0",
                            "available_tag": "2026.11.0", "kind": "minor", "policy": "auto",
                            "held_reason": "breaking_change", "held_domains": ["zha"],
                            "notes": {"affected": [{"domains": ["zha"], "title": "<script>x</script>", "url": "https://e/1"}]}},
          "kuma": {"status": "up_to_date", "current_version": "2", "last_test": {"passed": True, "finished": "2026-11-05T10:00:00"}}}
    g = {"last_run": {"check": 1762333200}, "isolation_ok": True}
    iso = {"passed": True, "when": "2026-11-05T10:00", "checks": [
        {"from": "probe", "via": "direct", "target": "192.0.2.1:80", "reachable": False, "expected": "blocked", "ok": True},
        {"from": "probe", "via": "control", "target": "172.30.98.2:8888", "reachable": True, "expected": "reachable", "ok": True}]}
    ev = [{"ts": "2026-11-05T10:00:00", "container": "homeassistant", "action": "held", "result": "held",
           "from_version": "2026.10.4", "to_version": "2026.11.0", "summary": "a & b"}]
    report.write(tmp_path, "de", "attention", cs, g, ev, "03:40-04:30", iso, [])
    page = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "Update-Schleuse" in page and "Zurückgehalten" in page
    assert "<script>x</script>" not in page and "&lt;script&gt;" in page
    assert "a &amp; b" in page and "172.30.98.2:8888" in page
    st = json.loads((tmp_path / "status.json").read_text(encoding="utf-8"))
    assert st["containers"]["homeassistant"]["held_domains"] == ["zha"]
    assert "notes" not in st["containers"]["homeassistant"]  # only a public subset
