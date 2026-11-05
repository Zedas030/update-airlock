"""Watch a container after a real update and decide: keep or roll back.

Roll back when (any of):
- the container is not running, restarts, or its healthcheck says unhealthy;
- the web interface / API does not answer `web_failures_before_rollback` times in a row after the
  start-up grace period (or never answered at all);
- (Home Assistant) the share of `unavailable` entities at the end is more than
  `unavailable_threshold_pp` percentage points above the share measured right before the update.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

import requests

from . import dockerapi
from .ha import HAClient, unavailable_share
from .util import AirlockError, run

log = logging.getLogger("update_airlock.observe")


@dataclass
class Observation:
    ok: bool = True
    reason: str = ""
    samples: list[dict] = field(default_factory=list)
    web_ok_seen: bool = False
    final_unavailable: float | None = None

    def to_dict(self) -> dict:
        return {"ok": self.ok, "reason": self.reason, "samples": self.samples[-60:], "web_ok_seen": self.web_ok_seen,
                "final_unavailable": self.final_unavailable}


def web_check(ha: HAClient | None, url: str) -> tuple[bool, str]:
    if ha is not None:
        return ha.api_ok()
    if not url:
        return True, "no web check configured"
    try:
        r = requests.get(url, timeout=10)
        return r.status_code < 500, f"HTTP {r.status_code}"
    except requests.RequestException as e:
        return False, type(e).__name__


def observe(name: str, opts: dict, ha_for_web: HAClient | None, http_url: str, ha_for_unavail: HAClient | None,
            baseline_share: float | None, faults: list[str] | None = None, sleep=time.sleep,
            clock=time.monotonic) -> Observation:
    faults = faults or []
    obs = Observation()
    minutes = float(opts["minutes"])
    interval = float(opts["interval_seconds"])
    grace = float(opts["startup_grace_minutes"]) * 60
    max_web_fail = int(opts["web_failures_before_rollback"])
    thr = float(opts["unavailable_threshold_pp"])
    t0 = clock()
    st0 = dockerapi.state(name)
    restarts0 = st0.get("restart_count", 0)
    web_streak = 0
    shares: list[float] = []
    injected = False
    while True:
        elapsed = clock() - t0
        if "unhealthy" in faults and not injected and elapsed >= 30:
            log.warning("FAULT INJECTION: stopping %s to simulate a broken update", name)
            run(["docker", "kill", name], check=False, quiet=True)
            injected = True
        st = dockerapi.state(name)
        sample = {"t": round(elapsed), "status": st.get("status"), "health": st.get("health")}
        if not st.get("running") or st.get("restarting"):
            obs.ok, obs.reason = False, f"container not running (status {st.get('status')}, exit code {st.get('exit_code')})"
            obs.samples.append(sample)
            return obs
        if st.get("health") == "unhealthy":
            obs.ok, obs.reason = False, "healthcheck reports unhealthy"
            obs.samples.append(sample)
            return obs
        if st.get("restart_count", 0) > restarts0:
            obs.ok, obs.reason = False, f"container restarted ({st.get('restart_count')}x)"
            obs.samples.append(sample)
            return obs
        ok, detail = web_check(ha_for_web, http_url)
        sample["web"] = detail
        if ok:
            web_streak = 0
            obs.web_ok_seen = True
        else:
            web_streak += 1
        if elapsed >= grace and web_streak >= max_web_fail:
            obs.ok, obs.reason = False, f"web interface does not answer ({detail}, {web_streak}x in a row)"
            obs.samples.append(sample)
            return obs
        if ha_for_unavail is not None and elapsed >= grace and ok:
            try:
                share, bad, total = unavailable_share(ha_for_unavail.states())
                shares.append(share)
                sample["unavailable"] = f"{bad}/{total} = {share}%"
            except AirlockError as e:
                sample["unavailable"] = f"not measurable: {e}"
        obs.samples.append(sample)
        if elapsed >= minutes * 60:
            break
        sleep(interval)
    if not obs.web_ok_seen:
        obs.ok, obs.reason = False, "web interface never answered during the observation"
        return obs
    if ha_for_unavail is not None and baseline_share is not None:
        if not shares:
            obs.ok, obs.reason = False, "share of unavailable entities could not be measured after the update"
            return obs
        final = min(shares[-3:])
        obs.final_unavailable = final
        if final > baseline_share + thr:
            obs.ok = False
            obs.reason = (f"{final}% of the entities are unavailable, before the update {baseline_share}% "
                          f"(threshold +{thr} percentage points)")
            return obs
    return obs
