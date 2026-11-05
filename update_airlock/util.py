"""Small helpers shared by all modules: subprocess wrapper, deadlines, errors, time helpers."""

from __future__ import annotations

import datetime as dt
import logging
import os
import shlex
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("update_airlock")


class AirlockError(Exception):
    """An expected failure with a message that is safe to show to the user."""


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run(cmd: list[str], *, check: bool = True, timeout: float = 300, quiet: bool = False,
        input_text: str | None = None, env: dict[str, str] | None = None, cwd: str | None = None) -> RunResult:
    """Run a command without a shell. Raises AirlockError on failure when check=True."""
    if not quiet:
        log.debug("run: %s", " ".join(shlex.quote(c) for c in cmd))
    full_env = None
    if env:
        full_env = os.environ.copy()
        full_env.update(env)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input_text,
                           env=full_env, cwd=cwd, errors="replace")
    except subprocess.TimeoutExpired as e:
        raise AirlockError(f"Command timed out after {timeout:.0f}s: {cmd[0]} {cmd[1] if len(cmd) > 1 else ''}") from e
    except FileNotFoundError as e:
        raise AirlockError(f"Command not found: {cmd[0]}") from e
    res = RunResult(p.returncode, p.stdout, p.stderr)
    if check and not res.ok:
        msg = (p.stderr or p.stdout).strip().splitlines()
        tail = " | ".join(msg[-3:])[:400]
        raise AirlockError(f"{' '.join(cmd[:3])} failed (rc {p.returncode}): {tail}")
    return res


class Deadline:
    def __init__(self, seconds: float):
        self.end = time.monotonic() + seconds

    def remaining(self) -> float:
        return max(0.0, self.end - time.monotonic())

    def expired(self) -> bool:
        return time.monotonic() >= self.end


def now() -> dt.datetime:
    return dt.datetime.now().astimezone()


def now_iso() -> str:
    return now().isoformat(timespec="seconds")


def ts_compact() -> str:
    return now().strftime("%Y%m%d-%H%M%S")


def atomic_write(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def short_digest(d: str | None) -> str:
    if not d:
        return "-"
    return d.split(":", 1)[-1][:12]


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TB"
