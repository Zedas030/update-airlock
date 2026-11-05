"""Version tags: parsing, ordering and classifying an update as patch / minor / major.

semver:  1.2.3 -> 1.2.4 patch, 1.3.0 minor, 2.0.0 major (an optional leading "v" is ignored).
calver:  Home Assistant style YEAR.MONTH.PATCH. A new month (also across a year change) is a "minor"
         release, a new last number a "patch". There are no "major" releases in calver mode.
Pre-releases (anything with letters after the numbers, e.g. 2026.11.0b3, 1.2.3-rc1) are never candidates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_NUM_RE = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+))?$")


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, tag: str | None) -> "Version | None":
        if not tag:
            return None
        m = _NUM_RE.match(tag.strip())
        if not m:
            return None
        return cls(int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


def classify(old: Version, new: Version, versioning: str = "semver") -> str | None:
    """Return 'patch' | 'minor' | 'major' for new > old, or None if new is not newer."""
    if new <= old:
        return None
    if versioning == "calver":
        if (new.major, new.minor) != (old.major, old.minor):
            return "minor"
        return "patch"
    if new.major != old.major:
        return "major"
    if new.minor != old.minor:
        return "minor"
    return "patch"


def candidates(current_tag: str, tags: list[str], pattern: str, versioning: str = "semver") -> dict[str, str]:
    """Newest tag per update kind, e.g. {'patch': '1.2.5', 'minor': '1.4.1', 'major': '2.0.3'}.

    'patch' = newest tag in the same minor line, 'minor' = newest in the same major line (calver: any newer
    month), 'major' = newest overall. A kind is only listed if its tag differs from the smaller kinds.
    """
    cur = Version.parse(current_tag)
    if cur is None:
        return {}
    rx = re.compile(pattern)
    parsed: list[tuple[Version, str]] = []
    for t in tags:
        if not rx.match(t):
            continue
        v = Version.parse(t)
        if v is not None and v > cur:
            parsed.append((v, t))
    if not parsed:
        return {}
    parsed.sort()
    best: dict[str, tuple[Version, str]] = {}
    for v, t in parsed:
        kind = classify(cur, v, versioning)
        if kind is None:
            continue
        if kind not in best or v > best[kind][0]:
            best[kind] = (v, t)
    # 'minor' should also cover patch-level improvements inside the new minor line: already the max.
    return {k: t for k, (v, t) in best.items()}


def pick(cands: dict[str, str], policy: dict[str, str]) -> tuple[str | None, str | None]:
    """Pick the biggest candidate that may be installed automatically. Returns (kind, tag) or (None, None)."""
    for kind in ("major", "minor", "patch"):
        if kind in cands and policy.get(kind) == "auto":
            return kind, cands[kind]
    return None, None


def biggest(cands: dict[str, str]) -> tuple[str | None, str | None]:
    for kind in ("major", "minor", "patch"):
        if kind in cands:
            return kind, cands[kind]
    return None, None


def release_lines_between(old: Version, new: Version) -> list[tuple[int, int]]:
    """Calver release lines (year, month) from old's line to new's line inclusive, e.g. for HA notes."""
    out = []
    y, m = old.major, old.minor
    guard = 0
    while (y, m) <= (new.major, new.minor) and guard < 60:
        out.append((y, m))
        m += 1
        if m > 12:
            y, m = y + 1, 1
        guard += 1
    return out
