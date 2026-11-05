import json

import pytest

from update_airlock.hayaml import used_integrations
from update_airlock.notes.homeassistant import HomeAssistantNotes, milestones_for, parse_blog_section
from update_airlock.util import AirlockError
from update_airlock.versions import Version

BLOG = """
<h2>Other noteworthy changes</h2><p>x</p>
<h2>Backward-incompatible changes <a name="backward-incompatible-changes"></a></h2>
<p>intro</p>
<div class="details-block"><details class="details-block-item">
  <summary class="details-block-title"><span>Zigbee Home Automation</span><div>svg</div></summary>
  <div class="details-block-content" id="content_0">
  <p>Groups now get devices &amp; more.</p>
  <p>(<a href="https://github.com/home-assistant/core/pull/188830">#188830</a>) (<a href="/integrations/zha/">ZHA documentation</a>)</p>
  </div></details></div>
<div class="details-block"><details class="details-block-item">
  <summary class="details-block-title"><span>Alert card</span></summary>
  <div class="details-block-content"><p>Frontend only.</p></div></details></div>
<h2>All changes</h2>
<details><summary><span>Not in the section</span></summary><a href="/integrations/hue/">x</a></details>
"""


def test_parse_blog_section():
    ch = parse_blog_section(BLOG, "2026.11.0")
    assert [c.title for c in ch] == ["Zigbee Home Automation", "Alert card"]
    zha = ch[0]
    assert zha.domains == ["zha"]
    assert zha.url.endswith("/pull/188830")
    assert "Groups now get devices & more." in zha.summary
    assert ch[1].domains == []  # no integration -> "core"


def test_parse_blog_without_section():
    with pytest.raises(AirlockError):
        parse_blog_section("<h2>Nothing</h2>", "2026.11.0")


def test_milestones_for_range():
    titles = ["2026.10.3", "2026.10.4", "2026.10.5", "2026.11.0b0", "2026.11.0b6", "2026.11.0", "2026.11.1",
              "2026.11.2", "2026.12.0b0", "2026.9.0"]
    assert milestones_for(titles, Version(2026, 10, 4), Version(2026, 11, 1)) == [
        "2026.10.5", "2026.11.0", "2026.11.0b0", "2026.11.0b6", "2026.11.1"]
    # patch update only: later patches of the same line, never its betas
    assert milestones_for(titles, Version(2026, 10, 3), Version(2026, 10, 4)) == ["2026.10.4"]


def _ha_config(tmp_path):
    st = tmp_path / ".storage"
    st.mkdir()
    (st / "core.config_entries").write_text(json.dumps({"data": {"entries": [
        {"domain": "zha", "disabled_by": None}, {"domain": "tuya"}, {"domain": "growatt_server", "disabled_by": "user"}]}}))
    (tmp_path / "configuration.yaml").write_text(
        "default_config:\nfrontend:\n  themes: !include_dir_merge_named themes\nsonos:\n  media_player: {}\n"
        "sensor:\n  - platform: history_stats\n    name: x\nhomeassistant:\n  name: x\n")
    cc = tmp_path / "custom_components" / "alexa_media"
    cc.mkdir(parents=True)
    (cc / "manifest.json").write_text(json.dumps({"domain": "alexa_media", "version": "1"}))
    return tmp_path


def test_used_integrations(tmp_path):
    u = used_integrations(_ha_config(tmp_path))
    assert u["config_entries"] == ["tuya", "zha"]
    assert u["disabled"] == ["growatt_server"]
    assert "sonos" in u["yaml"] and "history_stats" in u["yaml"] and "sensor" in u["yaml"]
    assert "frontend" not in u["yaml"] and "homeassistant" not in u["yaml"]
    assert u["custom"] == ["alexa_media"]


class FakeNotes(HomeAssistantNotes):
    def __init__(self, cfgdir, changes):
        super().__init__(config_dir=cfgdir)
        self._changes = changes

    def breaking_changes(self, old, new):
        return list(self._changes)


def test_evaluate_matches_used_domains_only(tmp_path):
    from update_airlock.notes import BreakingChange as B
    n = FakeNotes(_ha_config(tmp_path), [B("ZHA", ["zha"], "2026.11.0", key="1"), B("Hue", ["hue"], "2026.11.0", key="2"),
                                          B("Growatt", ["growatt_server"], "2026.11.0", key="3"),
                                          B("Core", [], "2026.11.0", key="4")])
    r = n.evaluate("2026.10.4", "2026.11.0")
    assert r.affected_domains == ["zha"]  # hue not used, growatt disabled
    assert len(r.core) == 1
    n2 = FakeNotes(tmp_path, [B("Growatt", ["growatt_server"], "2026.11.0", key="3")])
    n2.match_disabled = True
    assert n2.evaluate("a", "b").affected_domains == ["growatt_server"]


def test_notes_fail_closed_on_http_error(tmp_path):
    class S:
        headers = {}

        def get(self, *a, **k):
            import requests
            raise requests.ConnectionError("down")
    n = HomeAssistantNotes(config_dir=_ha_config(tmp_path), session=S())
    with pytest.raises(AirlockError, match="not reachable"):
        n.breaking_changes("2026.10.4", "2026.11.0")
