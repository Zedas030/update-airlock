"""Minimal Docker Registry HTTP API v2 client (Docker Hub, ghcr.io, any v2 registry).

Only read access: list tags, resolve a tag to its (multi-arch) digest, read image labels for one
platform. Anonymous by default; optional credentials per registry host ("user:token").
"""

from __future__ import annotations

import logging
import platform as _platform
import re
from dataclasses import dataclass

import requests

from .util import AirlockError

log = logging.getLogger("update_airlock.registry")

ACCEPT_INDEX = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
INDEX_TYPES = ("application/vnd.oci.image.index.v1+json",
               "application/vnd.docker.distribution.manifest.list.v2+json")


@dataclass(frozen=True)
class ImageRef:
    registry: str      # e.g. registry-1.docker.io, ghcr.io
    repository: str    # e.g. library/influxdb, home-assistant/home-assistant
    tag: str | None
    digest: str | None

    @classmethod
    def parse(cls, ref: str) -> "ImageRef":
        digest = None
        if "@" in ref:
            ref, digest = ref.split("@", 1)
        tag = None
        last = ref.rsplit("/", 1)[-1]
        if ":" in last:
            ref, tag = ref.rsplit(":", 1)
        parts = ref.split("/")
        if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
            registry, repo = parts[0], "/".join(parts[1:])
        else:
            registry, repo = "docker.io", ref
        if registry in ("docker.io", "index.docker.io"):
            registry = "registry-1.docker.io"
            if "/" not in repo:
                repo = f"library/{repo}"
        return cls(registry, repo, tag or (None if digest else "latest"), digest)

    @property
    def name(self) -> str:
        """Repository as Docker shows it (without default registry / library prefix)."""
        if self.registry == "registry-1.docker.io":
            return self.repository.removeprefix("library/")
        return f"{self.registry}/{self.repository}"

    def with_tag_digest(self, tag: str | None, digest: str | None) -> str:
        s = self.name
        if tag:
            s += f":{tag}"
        if digest:
            s += f"@{digest}"
        return s


def host_platform() -> tuple[str, str, str | None]:
    m = _platform.machine().lower()
    if m in ("aarch64", "arm64"):
        return "linux", "arm64", None
    if m in ("x86_64", "amd64"):
        return "linux", "amd64", None
    if m.startswith("armv7"):
        return "linux", "arm", "v7"
    return "linux", m, None


class Registry:
    def __init__(self, timeout: float = 20, credentials: dict[str, str] | None = None):
        self.timeout = timeout
        self.credentials = credentials or {}
        self._tokens: dict[tuple[str, str], str] = {}
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "update-airlock/1.0"

    # ---------- auth ----------
    def _auth_header(self, ref: ImageRef) -> dict:
        tok = self._tokens.get((ref.registry, ref.repository))
        return {"Authorization": f"Bearer {tok}"} if tok else {}

    def _authenticate(self, ref: ImageRef, www_auth: str) -> None:
        m = re.match(r"Bearer\s+(.*)", www_auth or "", re.I)
        if not m:
            raise AirlockError(f"{ref.registry}: unsupported auth scheme {www_auth[:60]!r}")
        params = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
        realm = params.pop("realm", None)
        if not realm:
            raise AirlockError(f"{ref.registry}: auth challenge without realm")
        params.setdefault("scope", f"repository:{ref.repository}:pull")
        auth = None
        cred = self.credentials.get(ref.registry)
        if cred and ":" in cred:
            auth = tuple(cred.split(":", 1))
        r = self.session.get(realm, params=params, auth=auth, timeout=self.timeout)
        if r.status_code != 200:
            raise AirlockError(f"{ref.registry}: token request failed (HTTP {r.status_code})")
        j = r.json()
        self._tokens[(ref.registry, ref.repository)] = j.get("token") or j.get("access_token")

    def _request(self, method: str, ref: ImageRef, path: str, headers: dict | None = None,
                 params: dict | None = None) -> requests.Response:
        url = path if path.startswith("http") else f"https://{ref.registry}/v2/{ref.repository}/{path}"
        h = dict(headers or {})
        for attempt in (1, 2):
            try:
                r = self.session.request(method, url, headers={**h, **self._auth_header(ref)},
                                         params=params, timeout=self.timeout)
            except requests.RequestException as e:
                raise AirlockError(f"{ref.registry} not reachable: {type(e).__name__}") from e
            if r.status_code == 401 and attempt == 1:
                self._authenticate(ref, r.headers.get("WWW-Authenticate", ""))
                continue
            return r
        return r

    # ---------- API ----------
    def tags(self, ref: ImageRef, limit_pages: int = 50) -> list[str]:
        out: list[str] = []
        path = "tags/list"
        params: dict | None = {"n": 1000}
        for _ in range(limit_pages):
            r = self._request("GET", ref, path, params=params)
            if r.status_code != 200:
                raise AirlockError(f"{ref.name}: tag list failed (HTTP {r.status_code})")
            out += r.json().get("tags") or []
            link = r.headers.get("Link", "")
            m = re.search(r"<([^>]+)>;\s*rel=\"?next\"?", link)
            if not m:
                break
            nxt = m.group(1)
            path = nxt if nxt.startswith("http") else f"https://{ref.registry}{nxt}"
            params = None
        return out

    def digest(self, ref: ImageRef, tag: str) -> str:
        """Digest of the manifest (list) a tag points to - the value 'docker pull' records."""
        r = self._request("HEAD", ref, f"manifests/{tag}", headers={"Accept": ACCEPT_INDEX})
        if r.status_code == 404:
            raise AirlockError(f"{ref.name}:{tag} does not exist in the registry")
        if r.status_code != 200:
            raise AirlockError(f"{ref.name}:{tag}: manifest lookup failed (HTTP {r.status_code})")
        d = r.headers.get("Docker-Content-Digest")
        if not d:
            r = self._request("GET", ref, f"manifests/{tag}", headers={"Accept": ACCEPT_INDEX})
            import hashlib
            d = "sha256:" + hashlib.sha256(r.content).hexdigest()
        return d

    def platform_info(self, ref: ImageRef, reference: str) -> dict:
        """For a tag/digest: is the host platform available, and which labels does that image carry?"""
        os_, arch, variant = host_platform()
        r = self._request("GET", ref, f"manifests/{reference}", headers={"Accept": ACCEPT_INDEX})
        if r.status_code != 200:
            raise AirlockError(f"{ref.name}@{reference}: manifest GET failed (HTTP {r.status_code})")
        man = r.json()
        mtype = man.get("mediaType") or r.headers.get("Content-Type", "")
        if mtype in INDEX_TYPES or "manifests" in man:
            match = None
            for m in man.get("manifests", []):
                p = m.get("platform") or {}
                if p.get("os") == os_ and p.get("architecture") == arch and (variant is None or p.get("variant") in (None, variant)):
                    match = m
                    break
            if not match:
                return {"available": False, "labels": {}}
            r = self._request("GET", ref, f"manifests/{match['digest']}", headers={"Accept": ACCEPT_INDEX})
            man = r.json()
        cfg = (man.get("config") or {}).get("digest")
        labels: dict = {}
        if cfg:
            b = self._request("GET", ref, f"blobs/{cfg}")
            if b.status_code == 200:
                try:
                    labels = (b.json().get("config") or {}).get("Labels") or {}
                except ValueError:
                    labels = {}
        return {"available": True, "labels": labels}
