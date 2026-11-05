"""Real updates: backup, switch image, roll back.

Compose-managed containers: the `image:` line of the service in the compose file is rewritten to the
pinned reference (repo:tag@sha256:...), a copy of the file is kept, then `docker compose up -d <service>`.
Other containers: re-created Watchtower-style from their own `docker inspect` data with the new image;
the previous container is kept (renamed, stopped) until the update is confirmed, which makes the rollback
exact.

A backup set is a directory backup_dir/<container>/<timestamp>/ with meta.json, inspect.json, copies of
the compose files and one tar.zst per writable data mount. It is taken while the container is STOPPED,
so databases inside are consistent.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

import yaml

from . import dockerapi
from .copying import _excluded, dir_size
from .inventory import Current, data_mounts
from .util import AirlockError, atomic_write, now_iso, run, ts_compact

log = logging.getLogger("update_airlock.deploy")

KEEP_REPO = "update-airlock-keep"


# ---------- compose file editing ----------
def compose_image_file(files: list[str], service: str) -> tuple[str, str]:
    """(file, image value) of the compose file that defines the service's image (the last one wins)."""
    found = None
    for f in files:
        try:
            data = yaml.safe_load(Path(f).read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as e:
            raise AirlockError(f"compose file {f} not readable: {e}") from e
        svc = (data.get("services") or {}).get(service) or {}
        if "image" in svc:
            found = (f, str(svc["image"]))
    if not found:
        raise AirlockError(f"no compose file defines an image for service {service}")
    if "${" in found[1] or "$" in found[1]:
        raise AirlockError(f"image of {service} in {found[0]} uses a variable ({found[1]}) - pin it literally "
                           "or manage this container with policy 'notify'")
    return found


def rewrite_compose_image(text: str, service: str, new_image: str) -> str:
    """Replace the image of one service, keeping comments, quoting style and everything else."""
    lines = text.splitlines(keepends=True)
    in_services = False
    svc_indent = None
    services_indent = None
    for i, ln in enumerate(lines):
        stripped = ln.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(ln) - len(ln.lstrip(" "))
        if re.match(r"^services:\s*(#.*)?$", stripped) and indent == 0:
            in_services, services_indent = True, indent
            continue
        if in_services and indent == services_indent and not stripped.startswith("-"):
            in_services = False  # next top-level key
        if in_services and svc_indent is None and re.match(rf"^['\"]?{re.escape(service)}['\"]?:\s*(#.*)?$", stripped):
            svc_indent = indent
            continue
        if svc_indent is not None:
            if indent <= svc_indent:
                break
            m = re.match(r"^(\s*image:\s*)(['\"]?)([^'\"#\s]+)(['\"]?)(\s*#.*)?(\r?\n)?$", ln)
            if m:
                lines[i] = f"{m.group(1)}{m.group(2)}{new_image}{m.group(4)}{m.group(5) or ''}{m.group(6) or ''}"
                return "".join(lines)
    raise AirlockError(f"image line of service {service} not found in the compose file")


# ---------- backup ----------
@dataclass
class BackupSet:
    path: Path
    meta: dict

    @classmethod
    def load(cls, path: Path) -> "BackupSet":
        return cls(path, json.loads((path / "meta.json").read_text(encoding="utf-8")))


def backup_root(backup_dir: Path, name: str) -> Path:
    return backup_dir / name


def estimate_backup_bytes(cur: Current, skip: list[str], exclude: list[str]) -> int:
    total = 0
    for m in data_mounts(cur, skip):
        p = Path(m.host_path)
        total += dir_size(p, exclude) if p.is_dir() else p.stat().st_size
    return total


def check_space(path: Path, needed: int, min_free_gb: float) -> None:
    path.mkdir(parents=True, exist_ok=True)
    st = os.statvfs(path)
    free = st.f_bavail * st.f_frsize
    if free - needed < min_free_gb * 1024 ** 3:
        raise AirlockError(f"not enough disk space for the backup: {free / 1024**3:.1f} GB free, "
                           f"~{needed / 1024**3:.1f} GB needed + {min_free_gb} GB reserve")


def take_backup(backup_dir: Path, cur: Current, skip: list[str], exclude: list[str], reason: str) -> BackupSet:
    d = backup_root(backup_dir, cur.name) / ts_compact()
    d.mkdir(parents=True, exist_ok=False)
    os.chmod(d.parent, 0o700)
    os.chmod(d, 0o700)
    meta = {"container": cur.name, "created": now_iso(), "reason": reason, "image_ref": cur.image_ref,
            "image_id": cur.image_id, "digest": cur.digest, "version": cur.version, "tag": cur.tag,
            "compose": cur.compose.__dict__ if cur.compose else None, "mounts": [], "compose_copies": {},
            "complete": False}
    atomic_write(d / "inspect.json", json.dumps(cur.info, indent=1), 0o600)
    if cur.compose:
        for i, f in enumerate(cur.compose.files):
            if Path(f).exists():
                shutil.copy2(f, d / f"compose{i}.yml")
                meta["compose_copies"][f] = f"compose{i}.yml"
    for i, m in enumerate(data_mounts(cur, skip)):
        src = Path(m.host_path)
        archive = f"mount{i}.tar.zst"
        args = ["tar", "--zstd", "--numeric-owner", "--xattrs", "-cf", str(d / archive)]
        for e in exclude:
            args.append(f"--exclude=./{e.strip('/')}" if "/" in e or "*" not in e else f"--exclude={e}")
        if src.is_dir():
            args += ["-C", str(src), "."]
        else:
            args += ["-C", str(src.parent), src.name]
        run(args, timeout=3600)
        meta["mounts"].append({"target": m.target, "host_path": m.host_path, "type": m.type, "archive": archive,
                               "is_dir": src.is_dir(), "exclude": exclude})
    meta["complete"] = True
    atomic_write(d / "meta.json", json.dumps(meta, indent=1), 0o600)
    for f in d.iterdir():
        os.chmod(f, 0o600)
    return BackupSet(d, meta)


def list_backups(backup_dir: Path, name: str) -> list[BackupSet]:
    root = backup_root(backup_dir, name)
    out = []
    if root.is_dir():
        for d in sorted(root.iterdir()):
            if (d / "meta.json").exists():
                try:
                    bs = BackupSet.load(d)
                    if bs.meta.get("complete"):
                        out.append(bs)
                except ValueError:
                    pass
    return out


def prune_backups(backup_dir: Path, name: str, keep: int) -> list[str]:
    sets = list_backups(backup_dir, name)
    removed = []
    for bs in sets[:-keep] if keep > 0 else []:
        shutil.rmtree(bs.path, ignore_errors=True)
        removed.append(bs.path.name)
    return removed


def restore_mounts(bs: BackupSet, quarantine: Path) -> dict:
    """Put the data mounts back to the state of the backup.

    Files that exist now but are not in the backup (and are not excluded from backups) are moved to
    `quarantine` - e.g. files a newer version created - so nothing is lost and the state is exact.
    """
    stats = {"moved": 0, "restored": 0}
    for m in bs.meta["mounts"]:
        arch = bs.path / m["archive"]
        host = Path(m["host_path"])
        exclude = m.get("exclude") or []
        listing = run(["tar", "--zstd", "-tf", str(arch)], timeout=1800, quiet=True).stdout.splitlines()
        if m["is_dir"]:
            members = {ln[2:] if ln.startswith("./") else ln for ln in listing}
            members = {x.rstrip("/") for x in members if x not in (".", "./")}
            if host.exists():
                for root, dirs, files in os.walk(host):
                    rel_root = os.path.relpath(root, host).replace(os.sep, "/")
                    rel_root = "" if rel_root == "." else rel_root + "/"
                    dirs[:] = [x for x in dirs if not _excluded(rel_root + x, exclude)]
                    for f in files:
                        rel = rel_root + f
                        if _excluded(rel, exclude) or rel in members:
                            continue
                        dst = quarantine / m["archive"].replace(".tar.zst", "") / rel
                        dst.parent.mkdir(parents=True, exist_ok=True)
                        shutil.move(os.path.join(root, f), dst)
                        stats["moved"] += 1
            host.mkdir(parents=True, exist_ok=True)
            run(["tar", "--zstd", "--numeric-owner", "--xattrs", "-xpf", str(arch), "-C", str(host)], timeout=3600)
        else:
            run(["tar", "--zstd", "--numeric-owner", "-xpf", str(arch), "-C", str(host.parent)], timeout=3600)
        stats["restored"] += len(listing)
    return stats


# ---------- switching ----------
def stop(cur: Current, timeout: int = 180) -> None:
    if cur.compose:
        run([*cur.compose.cmd(), "stop", "-t", str(timeout), cur.compose.service], timeout=timeout + 60,
            cwd=cur.compose.working_dir or None)
    else:
        run(["docker", "stop", "-t", str(timeout), cur.name], timeout=timeout + 60)


def keep_image(name: str, image_id: str, stamp: str) -> str:
    """Tag the previous image so `docker image prune` cannot remove it while a rollback may need it."""
    tag = f"{KEEP_REPO}/{re.sub(r'[^a-z0-9_.-]', '-', name.lower())}:{stamp}"
    dockerapi.tag_image(image_id, tag)
    return tag


def prune_kept_images(name: str, keep: int) -> None:
    repo = f"{KEEP_REPO}/{re.sub(r'[^a-z0-9_.-]', '-', name.lower())}"
    res = run(["docker", "image", "ls", repo, "--format", "{{.Tag}}"], check=False, quiet=True)
    tags = sorted(t for t in res.stdout.split() if t and t != "<none>")
    for t in tags[:-keep] if keep > 0 else []:
        run(["docker", "rmi", f"{repo}:{t}"], check=False, quiet=True)


def prev_name(name: str) -> str:
    return f"{name}.ua-prev"


def apply_image(cur: Current, new_ref: str, bs: BackupSet) -> dict:
    """Start the container with the new image. Container must be stopped already."""
    if cur.compose:
        f, _old = compose_image_file(cur.compose.files, cur.compose.service)
        text = Path(f).read_text(encoding="utf-8")
        new_text = rewrite_compose_image(text, cur.compose.service, new_ref)
        shutil.copy2(f, f"{f}.bak-{bs.path.name}")
        atomic_write(Path(f), new_text, os.stat(f).st_mode & 0o777)
        run([*cur.compose.cmd(), "up", "-d", "--no-deps", "--pull", "missing", cur.compose.service], timeout=900,
            cwd=cur.compose.working_dir or None)
        return {"mode": "compose", "file": f}
    old = cur.info
    body = dockerapi.build_create_body(old, cur.image_info, new_ref)
    pn = prev_name(cur.name)
    if dockerapi.inspect_container(pn):
        run(["docker", "rm", "-f", pn], quiet=True)
    run(["docker", "rename", cur.name, pn])
    run(["docker", "update", "--restart", "no", pn], check=False, quiet=True)
    try:
        dockerapi.create_from_body(cur.name, body)
        run(["docker", "start", cur.name])
    except AirlockError:
        run(["docker", "rm", "-f", cur.name], check=False, quiet=True)
        run(["docker", "rename", pn, cur.name], check=False, quiet=True)
        raise
    return {"mode": "recreate", "previous_container": pn}


def finalize(cur_name: str, info: dict) -> None:
    """Update confirmed: the kept previous container is no longer needed."""
    if info.get("mode") == "recreate":
        run(["docker", "rm", "-f", info["previous_container"]], check=False, quiet=True)


def rollback(name: str, bs: BackupSet, quarantine: Path, apply_info: dict | None = None) -> dict:
    """Back to the image and data of the backup set. Works after a failed update and later by hand."""
    meta = bs.meta
    old_info = json.loads((bs.path / "inspect.json").read_text(encoding="utf-8"))
    out = {"backup": bs.path.name}
    comp = meta.get("compose")
    # 1. stop whatever runs now
    if dockerapi.inspect_container(name):
        if comp:
            files = comp["files"]
            cmd = ["docker", "compose", "-p", comp["project"]] + sum((["-f", f] for f in files), [])
            run([*cmd, "stop", "-t", "120", comp["service"]], check=False, timeout=300, cwd=comp.get("working_dir") or None)
        else:
            run(["docker", "stop", "-t", "120", name], check=False, timeout=300)
    # 2. data back
    out["restore"] = restore_mounts(bs, quarantine)
    # 3. image back
    if comp:
        files = comp["files"]
        f, _cur = compose_image_file(files, comp["service"])
        copy = meta.get("compose_copies", {}).get(f)
        old_image = None
        if copy:
            data = yaml.safe_load((bs.path / copy).read_text(encoding="utf-8")) or {}
            old_image = ((data.get("services") or {}).get(comp["service"]) or {}).get("image")
        old_image = old_image or meta["image_ref"]
        # if the old reference was floating (e.g. :latest), pin it to the old digest so we really get it back
        if "@" not in old_image and meta.get("digest"):
            old_image = f"{old_image}@{meta['digest']}"
        text = Path(f).read_text(encoding="utf-8")
        atomic_write(Path(f), rewrite_compose_image(text, comp["service"], old_image), os.stat(f).st_mode & 0o777)
        cmd = ["docker", "compose", "-p", comp["project"]] + sum((["-f", x] for x in files), [])
        run([*cmd, "up", "-d", "--no-deps", "--pull", "missing", comp["service"]], timeout=900,
            cwd=comp.get("working_dir") or None)
        out["mode"] = "compose"
        out["image"] = old_image
        return out
    pn = prev_name(name)
    if apply_info and apply_info.get("mode") == "recreate" and dockerapi.inspect_container(pn):
        run(["docker", "rm", "-f", name], check=False, quiet=True)
        run(["docker", "rename", pn, name])
        pol = (old_info.get("HostConfig") or {}).get("RestartPolicy", {}).get("Name") or "no"
        run(["docker", "update", "--restart", pol, name], check=False, quiet=True)
        run(["docker", "start", name])
        out["mode"] = "previous container"
        return out
    # previous container gone (manual rollback days later): re-create from the saved inspect data
    old_img = meta["image_id"]
    if not dockerapi.image_present(old_img):
        raise AirlockError(f"previous image {old_img[:19]} is no longer present - cannot roll back the image")
    img_info = dockerapi.inspect_image(old_img)
    body = dockerapi.build_create_body(old_info, img_info, meta["image_ref"] if "@" in meta["image_ref"] else old_img)
    body["Image"] = old_img
    run(["docker", "rm", "-f", name], check=False, quiet=True)
    dockerapi.create_from_body(name, body)
    run(["docker", "start", name])
    out["mode"] = "re-created from backup"
    return out
