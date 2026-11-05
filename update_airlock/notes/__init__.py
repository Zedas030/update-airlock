"""Release-notes providers. Each provider returns the breaking changes between two versions.

To add a provider for another image: subclass NotesProvider, implement breaking_changes() and register
it in PROVIDERS. The runner matches BreakingChange.domains against the "used" set the provider reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class BreakingChange:
    title: str
    domains: list[str]
    release: str
    url: str = ""
    summary: str = ""
    sources: list[str] = field(default_factory=list)
    key: str = ""

    def to_dict(self) -> dict:
        return {"title": self.title, "domains": self.domains, "release": self.release, "url": self.url,
                "summary": self.summary[:400], "sources": self.sources}


@dataclass
class NotesResult:
    changes: list[BreakingChange]
    used: set[str]
    affected: list[BreakingChange]
    core: list[BreakingChange]
    releases: list[str]

    @property
    def affected_domains(self) -> list[str]:
        return sorted({d for c in self.affected for d in c.domains if d in self.used})


class NotesProvider:
    name = "base"

    def breaking_changes(self, old: str, new: str) -> list[BreakingChange]:  # pragma: no cover
        raise NotImplementedError

    def used_domains(self) -> set[str]:  # pragma: no cover
        raise NotImplementedError

    def evaluate(self, old: str, new: str, extra: list[BreakingChange] | None = None) -> NotesResult:
        changes = self.breaking_changes(old, new) + list(extra or [])
        used = self.used_domains()
        affected = [c for c in changes if set(c.domains) & used]
        core = [c for c in changes if not c.domains]
        releases = sorted({c.release for c in changes})
        return NotesResult(changes=changes, used=used, affected=affected, core=core, releases=releases)


def get_provider(name: str, **kw) -> NotesProvider | None:
    if not name:
        return None
    if name == "homeassistant":
        from .homeassistant import HomeAssistantNotes
        return HomeAssistantNotes(**kw)
    raise ValueError(f"Unknown release-notes provider {name}")
