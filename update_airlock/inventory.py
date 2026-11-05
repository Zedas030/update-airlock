"""What is running right now: image reference, tag, digest, version label and how the container is managed."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import dockerapi
from .registry import ImageRef
from .util import AirlockError


@dataclass
class Compose:
    project: str
    service: str
    working_dir: str
    files: list[str]

    def cmd(self) -> list[str]:
        c = ["docker", "compose", "-p", self.project]
        for f in self.files:
            c += ["-f", f]
        return c


@dataclass
class Mount:
    type: str          # bind | volume
    source: str        # host path (bind) or volume name
    host_path: str     # path on the host that holds the data
    target: str
    rw: bool


@dataclass
class Current:
    name: str
    ref: ImageRef
    image_ref: str         # Config.Image as written by the user (e.g. "ghcr.io/x/y:stable")
    image_id: str
    digest: str | None     # registry digest of the running image (index digest)
    version: str | None    # org.opencontainers.image.version label, if any
    compose: Compose | None
    mounts: list[Mount] = field(default_factory=list)
    info: dict = field(default_factory=dict)
    image_info: dict = field(default_factory=dict)

    @property
    def tag(self) -> str | None:
        return self.ref.tag


def _repo_digest(image_info: dict, ref: ImageRef) -> str | None:
    for rd in image_info.get("RepoDigests") or []:
        repo, _, d = rd.partition("@")
        if ImageRef.parse(repo).repository == ref.repository:
            return d
    return None


def read_current(name: str, compose_override: str = "") -> Current:
    info = dockerapi.inspect_container(name)
    if not info:
        raise AirlockError(f"Container {name} does not exist")
    image_ref = info["Config"]["Image"]
    ref = ImageRef.parse(image_ref)
    image_id = info["Image"]
    img = dockerapi.inspect_image(image_id) or {}
    digest = ref.digest or _repo_digest(img, ref)
    labels = (img.get("Config") or {}).get("Labels") or {}
    version = labels.get("org.opencontainers.image.version")
    cl = info["Config"].get("Labels") or {}
    compose = None
    if cl.get("com.docker.compose.project"):
        files = [f for f in (compose_override or cl.get("com.docker.compose.project.config_files", "")).split(",") if f]
        compose = Compose(project=cl["com.docker.compose.project"], service=cl.get("com.docker.compose.service", name),
                          working_dir=cl.get("com.docker.compose.project.working_dir", ""), files=files)
    mounts = []
    for m in info.get("Mounts") or []:
        if m.get("Type") not in ("bind", "volume"):
            continue
        src = m.get("Name") if m["Type"] == "volume" else m.get("Source")
        mounts.append(Mount(type=m["Type"], source=src, host_path=m.get("Source", ""), target=m["Destination"],
                            rw=bool(m.get("RW"))))
    return Current(name=name, ref=ref, image_ref=image_ref, image_id=image_id, digest=digest, version=version,
                   compose=compose, mounts=mounts, info=info, image_info=img)


def data_mounts(cur: Current, skip: list[str]) -> list[Mount]:
    """Writable mounts that hold the container's state (what a backup / sandbox copy must contain)."""
    out = []
    for m in cur.mounts:
        if not m.rw:
            continue
        if any(m.target == s or m.target.startswith(s.rstrip("/") + "/") for s in skip):
            continue
        if any(m.host_path == s or m.host_path.startswith(s.rstrip("/") + "/") for s in skip):
            continue
        if m.host_path and not Path(m.host_path).exists():
            continue
        if m.host_path and Path(m.host_path).is_file():
            # single-file binds (e.g. a config file) are included as files
            pass
        out.append(m)
    return out
