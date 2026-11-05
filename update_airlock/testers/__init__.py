"""Testers run a candidate image in the sandbox and decide pass / fail.

A tester gets the production container (inventory.Current), the candidate image reference and the
sandbox. It must never touch the production container or its data (it only reads/copies them).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..util import now_iso


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "ok": self.ok, "detail": self.detail[:1500]}


@dataclass
class TestResult:
    __test__ = False  # not a pytest test class
    container: str
    candidate: str
    digest: str
    started: str = field(default_factory=now_iso)
    finished: str = ""
    passed: bool = False
    checks: list[Check] = field(default_factory=list)
    isolation: dict = field(default_factory=dict)
    error: str = ""
    duration_s: float = 0.0
    faults: list[str] = field(default_factory=list)
    # The decisive check could not be evaluated in the sandbox (fails with the current image too, e.g. an exporter
    # that exits without its device). Counts as passed unless test.require_conclusive is set; then only the
    # observation + rollback after the real update protect the update.
    inconclusive: str = ""
    require_conclusive: bool = False
    _t0: float = field(default_factory=time.monotonic, repr=False)

    def add(self, name: str, ok: bool, detail: str = "") -> bool:
        self.checks.append(Check(name, ok, detail))
        return ok

    def finish(self) -> "TestResult":
        self.finished = now_iso()
        self.duration_s = round(time.monotonic() - self._t0, 1)
        self.passed = not self.error and bool(self.checks) and all(c.ok for c in self.checks)
        if self.passed and self.inconclusive and self.require_conclusive:
            self.passed = False
            self.error = f"not testable in the sandbox ({self.inconclusive}) and test.require_conclusive is set"
        return self

    @property
    def failed_checks(self) -> list[Check]:
        return [c for c in self.checks if not c.ok]

    def to_dict(self) -> dict:
        return {"container": self.container, "candidate": self.candidate, "digest": self.digest,
                "started": self.started, "finished": self.finished, "passed": self.passed,
                "checks": [c.to_dict() for c in self.checks], "isolation": self.isolation, "error": self.error,
                "duration_s": self.duration_s, "faults": self.faults, "inconclusive": self.inconclusive}


def get_tester(kind: str):
    if kind == "homeassistant":
        from .homeassistant import HomeAssistantTester
        return HomeAssistantTester
    if kind == "generic":
        from .generic import GenericTester
        return GenericTester
    return None
