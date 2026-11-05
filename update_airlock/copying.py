"""Copy data directories for the sandbox: exclude patterns, consistent SQLite copies of live databases."""

from __future__ import annotations

import fnmatch
import os
import shutil
import subprocess
import sys
from pathlib import Path

from .util import AirlockError

SQLITE_MAGIC = b"SQLite format 3\x00"


def _excluded(rel: str, patterns: list[str]) -> bool:
    name = rel.rsplit("/", 1)[-1]
    for p in patterns:
        p = p.strip("/")
        if fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(name, p) or rel == p or rel.startswith(p + "/"):
            return True
    return False


def is_sqlite(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(16) == SQLITE_MAGIC
    except OSError:
        return False


def sqlite_copy(src: Path, dst: Path) -> None:
    """Consistent copy of a database that may be written to right now (SQLite online backup API).

    One single step (pages=-1): copying in chunks restarts from scratch whenever another process writes
    in between - with Home Assistant writing every few seconds it would never finish. In WAL mode the one
    step only holds a read snapshot, so the writer is not blocked.
    """
    # Runs in a child process: the C-level backup cannot be interrupted, a child can be killed at once
    # (SIGTERM / timeout -> subprocess.run kills it and the caller's `finally` cleans up).
    code = ("import sqlite3,sys\n"
            "s=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True,timeout=60)\n"
            "d=sqlite3.connect(sys.argv[2])\n"
            "s.backup(d,pages=-1)\n"
            "d.close();s.close()\n")
    try:
        p = subprocess.run([sys.executable, "-c", code, str(src), str(dst)], capture_output=True, text=True,
                           timeout=3600)
    except subprocess.TimeoutExpired as e:
        raise AirlockError(f"copying {src.name} took longer than 1 h") from e
    if p.returncode != 0:
        raise AirlockError(f"copying database {src.name} failed: {p.stderr.strip()[-300:]}")


def dir_size(path: Path, exclude: list[str]) -> int:
    total = 0
    base = str(path)
    for root, dirs, files in os.walk(path):
        rel_root = os.path.relpath(root, base).replace(os.sep, "/")
        rel_root = "" if rel_root == "." else rel_root + "/"
        dirs[:] = [d for d in dirs if not _excluded(rel_root + d, exclude)]
        for f in files:
            if _excluded(rel_root + f, exclude):
                continue
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
    return total


def copy_tree(src: Path, dst: Path, exclude: list[str], sqlite_online: bool = True) -> dict:
    """Copy src -> dst (dst must not exist). SQLite files (incl. their -wal) are copied via the backup API.

    Returns counters for the test report. Ownership and permissions are preserved (runs as root).
    """
    if not src.exists():
        raise AirlockError(f"Source does not exist: {src}")
    if src.is_file():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        return {"files": 1, "sqlite": 0, "skipped": 0}
    stats = {"files": 0, "sqlite": 0, "skipped": 0}
    base = str(src)
    for root, dirs, files in os.walk(src):
        rel_root = os.path.relpath(root, base).replace(os.sep, "/")
        rel_root = "" if rel_root == "." else rel_root + "/"
        target_root = dst / rel_root
        target_root.mkdir(parents=True, exist_ok=True)
        shutil.copystat(root, target_root, follow_symlinks=False)
        _chown_like(root, target_root)
        keep = []
        for d in dirs:
            if _excluded(rel_root + d, exclude):
                stats["skipped"] += 1
            else:
                keep.append(d)
        dirs[:] = keep
        names = set(files)
        for f in files:
            rel = rel_root + f
            if _excluded(rel, exclude):
                stats["skipped"] += 1
                continue
            sp = Path(root) / f
            tp = target_root / f
            if f.endswith(("-wal", "-shm", "-journal")) and f.rsplit("-", 1)[0] in names and sqlite_online:
                continue  # folded into the database copy
            if sp.is_symlink():
                os.symlink(os.readlink(sp), tp)
                continue
            if sqlite_online and is_sqlite(sp):
                sqlite_copy(sp, tp)
                shutil.copystat(sp, tp)
                _chown_like(sp, tp)
                stats["sqlite"] += 1
            else:
                shutil.copy2(sp, tp, follow_symlinks=False)
                _chown_like(sp, tp)
            stats["files"] += 1
    return stats


def _chown_like(src, dst) -> None:
    try:
        st = os.lstat(src)
        os.lchown(dst, st.st_uid, st.st_gid)
    except (OSError, AttributeError):
        pass


def remove_tree(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
        if path.exists():
            raise AirlockError(f"Could not remove {path}")
