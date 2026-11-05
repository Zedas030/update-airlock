"""Breaking changes of Home Assistant Core between two versions.

Two independent sources, merged by pull-request number:
1. The release blog post (linked from the GitHub release X.Y.0): section "Backward-incompatible changes",
   one <details> block per change, each linking to /integrations/<domain>/ and to the pull request.
2. GitHub: pull requests labelled "breaking-change" in the milestones of the versions in between
   (betas X.Y.0bN, X.Y.0 and patch releases X.Y.Z); the domain comes from the "integration: <domain>" label.
Patch releases have no blog section, so for them only source 2 applies.

Any fetch error raises AirlockError: the caller holds the update back (fail closed) and reports it.
"""

from __future__ import annotations

import html
import json
import logging
import re
from pathlib import Path

import requests

from ..hayaml import used_integrations
from ..util import AirlockError
from ..versions import Version, release_lines_between
from . import BreakingChange, NotesProvider

log = logging.getLogger("update_airlock.notes.ha")

GH = "https://api.github.com/repos/home-assistant/core"


def parse_blog_section(page: str, release: str) -> list[BreakingChange]:
    """Extract the breaking changes from a release blog post."""
    m = re.search(r"<h2[^>]*>\s*Backward-incompatible changes.*?</h2>", page, re.S | re.I)
    if not m:
        raise AirlockError(f"HA {release}: blog post has no 'Backward-incompatible changes' section")
    rest = page[m.end():]
    nxt = re.search(r"<h2[^>]*>", rest)
    section = rest[: nxt.start()] if nxt else rest
    out = []
    for block in re.finditer(r"<details[^>]*>(.*?)</details>", section, re.S):
        b = block.group(1)
        tm = re.search(r"<summary[^>]*>.*?<span>(.*?)</span>", b, re.S)
        title = html.unescape(re.sub(r"<[^>]+>", "", tm.group(1))).strip() if tm else "?"
        domains = sorted(set(re.findall(r'href="/integrations/([a-z0-9_]+)/?"', b)))
        prs = re.findall(r"github\.com/home-assistant/core/pull/(\d+)", b)
        content = re.search(r'<div class="details-block-content"[^>]*>(.*)', b, re.S)
        text = html.unescape(re.sub(r"<[^>]+>", " ", content.group(1) if content else b))
        text = re.sub(r"\s+", " ", text).strip()
        url = f"https://github.com/home-assistant/core/pull/{prs[0]}" if prs else ""
        out.append(BreakingChange(title=title, domains=domains, release=release, url=url, summary=text,
                                  sources=["blog"], key=f"pr{prs[0]}" if prs else f"blog:{release}:{title}"))
    return out


def milestones_for(titles: list[str], old: Version, new: Version) -> list[str]:
    """Milestone titles whose changes lie in (old, new]."""
    lines = set(release_lines_between(old, new))
    out = []
    for t in titles:
        m = re.fullmatch(r"(\d{4})\.(\d{1,2})\.(\d+)(b\d+)?", t)
        if not m:
            continue
        y, mo, p, beta = int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4)
        if (y, mo) not in lines:
            continue
        if (y, mo) == (old.major, old.minor):
            # Same line as the installed version: only later patch releases (betas are long past).
            if beta or p <= old.patch:
                continue
        if (y, mo) == (new.major, new.minor) and not beta and p > new.patch:
            continue
        if beta and p != 0:
            continue
        out.append(t)
    return sorted(out)


class HomeAssistantNotes(NotesProvider):
    name = "homeassistant"

    def __init__(self, config_dir: Path | None = None, cache_dir: Path | None = None, timeout: float = 20,
                 github_token: str = "", session: requests.Session | None = None, match_disabled: bool = False):
        self.config_dir = Path(config_dir) if config_dir else None
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.timeout = timeout
        self.match_disabled = match_disabled
        self.s = session or requests.Session()
        self.s.headers["User-Agent"] = "update-airlock/1.0"
        self.s.headers["Accept"] = "application/vnd.github+json"
        if github_token:
            self.s.headers["Authorization"] = f"Bearer {github_token}"
        self._usage: dict | None = None

    # ---------- usage ----------
    def usage(self) -> dict[str, list[str]]:
        if self._usage is None:
            if not self.config_dir or not self.config_dir.is_dir():
                raise AirlockError(f"HA config directory not readable: {self.config_dir}")
            self._usage = used_integrations(self.config_dir)
        return self._usage

    def used_domains(self) -> set[str]:
        u = self.usage()
        used = set(u["config_entries"]) | set(u["yaml"]) | set(u["custom"])
        if self.match_disabled:
            used |= set(u["disabled"])
        return used

    # ---------- http ----------
    def _get(self, url: str, params: dict | None = None) -> requests.Response:
        try:
            r = self.s.get(url, params=params, timeout=self.timeout)
        except requests.RequestException as e:
            raise AirlockError(f"Release notes not reachable ({url.split('/')[2]}): {type(e).__name__}") from e
        if r.status_code == 403 and "rate limit" in r.text.lower():
            raise AirlockError("GitHub API rate limit reached (set GITHUB_TOKEN in .env for a higher limit)")
        if r.status_code != 200:
            raise AirlockError(f"Release notes: {url.split('?')[0]} answered HTTP {r.status_code}")
        return r

    def _cache_get(self, key: str):
        if not self.cache_dir:
            return None
        f = self.cache_dir / f"{key}.json"
        if f.exists():
            try:
                return json.loads(f.read_text(encoding="utf-8"))
            except ValueError:
                return None
        return None

    def _cache_put(self, key: str, value) -> None:
        if not self.cache_dir:
            return
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        (self.cache_dir / f"{key}.json").write_text(json.dumps(value), encoding="utf-8")

    # ---------- sources ----------
    def blog_changes(self, line: tuple[int, int]) -> list[BreakingChange]:
        release = f"{line[0]}.{line[1]}.0"
        cached = self._cache_get(f"blog-{release}")
        if cached is not None:
            return [BreakingChange(**c) for c in cached]
        rel = self._get(f"{GH}/releases/tags/{release}").json()
        m = re.search(r"https://www\.home-assistant\.io/blog/[^\s)\]]+", rel.get("body") or "")
        if not m:
            raise AirlockError(f"HA {release}: GitHub release has no link to the release notes")
        page = self._get(m.group(0)).text
        changes = parse_blog_section(page, release)
        for c in changes:
            if not c.url:
                c.url = m.group(0) + "#backward-incompatible-changes"
        self._cache_put(f"blog-{release}", [c.__dict__ for c in changes])
        return changes

    def milestones(self) -> list[dict]:
        out = []
        for page in range(1, 6):
            r = self._get(f"{GH}/milestones", params={"state": "all", "per_page": 100, "page": page,
                                                      "sort": "due_on", "direction": "desc"})
            items = r.json()
            out += items
            if len(items) < 100:
                break
        return out

    def milestone_changes(self, ms: dict) -> list[BreakingChange]:
        key = f"ms-{ms['title']}"
        closed = ms.get("state") == "closed"
        if closed:
            cached = self._cache_get(key)
            if cached is not None:
                return [BreakingChange(**c) for c in cached]
        out = []
        for page in range(1, 6):
            items = self._get(f"{GH}/issues", params={"milestone": ms["number"], "labels": "breaking-change",
                                                      "state": "all", "per_page": 100, "page": page}).json()
            for it in items:
                if "pull_request" not in it:
                    continue
                labels = [lb["name"] for lb in it.get("labels", [])]
                domains = sorted(lb.split(":", 1)[1].strip() for lb in labels if lb.startswith("integration:"))
                rel = re.sub(r"b\d+$", "", ms["title"])
                out.append(BreakingChange(title=it["title"], domains=domains, release=rel,
                                          url=it.get("html_url", ""), summary=(it.get("body") or "")[:400],
                                          sources=["github"], key=f"pr{it['number']}"))
            if len(items) < 100:
                break
        if closed:
            self._cache_put(key, [c.__dict__ for c in out])
        return out

    def breaking_changes(self, old: str, new: str) -> list[BreakingChange]:
        vo, vn = Version.parse(old), Version.parse(new)
        if vo is None or vn is None:
            raise AirlockError(f"HA versions not understood: {old!r} -> {new!r}")
        merged: dict[str, BreakingChange] = {}

        def add(c: BreakingChange):
            if c.key in merged:
                m = merged[c.key]
                m.domains = sorted(set(m.domains) | set(c.domains))
                m.sources = sorted(set(m.sources) | set(c.sources))
                if len(c.summary) > len(m.summary) and "blog" in c.sources:
                    m.summary, m.title = c.summary, c.title
            else:
                merged[c.key] = c

        for line in release_lines_between(vo, vn):
            if line != (vo.major, vo.minor):
                for c in self.blog_changes(line):
                    add(c)
        titles = {m["title"]: m for m in self.milestones()}
        for t in milestones_for(list(titles), vo, vn):
            for c in self.milestone_changes(titles[t]):
                add(c)
        return list(merged.values())
