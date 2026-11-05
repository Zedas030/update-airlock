"""REST client for the PRODUCTION Home Assistant: notifications, status sensors, presence, health metrics."""

from __future__ import annotations

import logging

import requests

from .util import AirlockError

log = logging.getLogger("update_airlock.ha")


class HAClient:
    def __init__(self, url: str, token: str, timeout: float = 15, verify: bool = True):
        self.url = url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.verify = verify

    @property
    def configured(self) -> bool:
        return bool(self.url and self.token)

    def _h(self) -> dict:
        return {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

    def _req(self, method: str, path: str, json_body=None, timeout: float | None = None):
        if not self.configured:
            raise AirlockError("Home Assistant URL/token not configured (HA_TOKEN in .env)")
        try:
            r = requests.request(method, f"{self.url}{path}", headers=self._h(), json=json_body,
                                 timeout=timeout or self.timeout, verify=self.verify)
        except requests.RequestException as e:
            raise AirlockError(f"Home Assistant not reachable: {type(e).__name__}") from e
        if r.status_code == 401:
            raise AirlockError("Home Assistant rejected the token (HTTP 401) - check HA_TOKEN in .env")
        return r

    def api_ok(self) -> tuple[bool, str]:
        try:
            r = self._req("GET", "/api/", timeout=10)
            return r.status_code == 200, f"HTTP {r.status_code}"
        except AirlockError as e:
            return False, str(e)

    def get_state(self, entity_id: str) -> dict | None:
        r = self._req("GET", f"/api/states/{entity_id}")
        if r.status_code == 404:
            return None
        if r.status_code != 200:
            raise AirlockError(f"HA state {entity_id}: HTTP {r.status_code}")
        return r.json()

    def states(self) -> list[dict]:
        r = self._req("GET", "/api/states", timeout=max(self.timeout, 30))
        if r.status_code != 200:
            raise AirlockError(f"HA /api/states: HTTP {r.status_code}")
        return r.json()

    def config(self) -> dict:
        r = self._req("GET", "/api/config")
        if r.status_code != 200:
            raise AirlockError(f"HA /api/config: HTTP {r.status_code}")
        return r.json()

    def set_state(self, entity_id: str, state: str, attributes: dict) -> None:
        r = self._req("POST", f"/api/states/{entity_id}", {"state": str(state)[:255], "attributes": attributes})
        if r.status_code not in (200, 201):
            raise AirlockError(f"HA set state {entity_id}: HTTP {r.status_code}")

    def notify(self, service: str, title: str, message: str, data: dict | None = None) -> None:
        if not service:
            raise AirlockError("no notify service configured (homeassistant.notify_service)")
        domain, _, name = service.partition(".")
        if domain != "notify" or not name:
            raise AirlockError(f"notify_service must look like notify.<name>, not {service!r}")
        body = {"title": title, "message": message}
        if data:
            body["data"] = data
        r = self._req("POST", f"/api/services/notify/{name}", body, timeout=30)
        if r.status_code not in (200, 201):
            raise AirlockError(f"HA notify.{name}: HTTP {r.status_code} {r.text[:120]}")


def unavailable_share(states: list[dict], ignore_prefixes: tuple[str, ...] = ("sensor.update_airlock",)) -> tuple[float, int, int]:
    """(share in percent, unavailable count, total) over all entities."""
    rel = [s for s in states if not s["entity_id"].startswith(ignore_prefixes)]
    if not rel:
        return 0.0, 0, 0
    bad = sum(1 for s in rel if s.get("state") == "unavailable")
    return round(100.0 * bad / len(rel), 2), bad, len(rel)
