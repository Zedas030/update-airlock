"""When may a real update happen? Maintenance window, presence ("at home and active"), busy services."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from .util import AirlockError, run

DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def parse_window(spec: str) -> tuple[dt.time, dt.time]:
    a, b = spec.split("-")
    ta = dt.time(*map(int, a.split(":")))
    tb = dt.time(*map(int, b.split(":")))
    return ta, tb


def in_window(now: dt.datetime, spec: str, days: list[str] | None = None) -> bool:
    start, end = parse_window(spec)
    t = now.time()
    if start <= end:
        inside = start <= t < end
        day = now
    else:  # crosses midnight, e.g. 23:00-02:00
        inside = t >= start or t < end
        day = now if t >= start else now - dt.timedelta(days=1)
    if not inside:
        return False
    if days:
        return DAYS[day.weekday()] in days
    return True


def window_end(now: dt.datetime, spec: str) -> dt.datetime:
    _, end = parse_window(spec)
    e = now.replace(hour=end.hour, minute=end.minute, second=0, microsecond=0)
    if e <= now:
        e += dt.timedelta(days=1)
    return e


@dataclass
class Presence:
    known: bool
    active: bool
    reason: str


def parse_ts(s: str | None) -> dt.datetime | None:
    if not s:
        return None
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def presence(ha, cfg: dict, now: dt.datetime) -> Presence:
    """At home AND (an activity sensor is on, or was on within quiet_minutes).

    If Home Assistant cannot be asked (down, token missing, entity unknown) the result is known=False and
    the caller falls back to the fixed window only.
    """
    if not cfg.get("enabled"):
        return Presence(False, False, "presence check disabled")
    try:
        p = ha.get_state(cfg["person"])
        if p is None:
            return Presence(False, False, f"{cfg['person']} does not exist")
        if p["state"] != "home":
            return Presence(True, False, f"{cfg['person']} is {p['state']}")
        quiet = dt.timedelta(minutes=float(cfg.get("quiet_minutes", 20)))
        seen_any = False
        for ent in cfg.get("activity_sensors") or []:
            s = ha.get_state(ent)
            if s is None:
                continue
            seen_any = True
            if s["state"] == "on":
                return Presence(True, True, f"{ent} is on")
            lc = parse_ts(s.get("last_changed"))
            if s["state"] == "off" and lc and now - lc < quiet:
                return Presence(True, True, f"{ent} was on until {lc.astimezone(now.tzinfo):%H:%M}")
        if cfg.get("activity_sensors") and not seen_any:
            return Presence(False, False, "none of the activity sensors exists")
        return Presence(True, False, "at home, no activity")
    except AirlockError as e:
        return Presence(False, False, f"presence unknown ({e})")


def busy_units(units: list[str]) -> list[str]:
    out = []
    for u in units or []:
        r = run(["systemctl", "is-active", u], check=False, quiet=True)
        if r.stdout.strip() in ("active", "activating", "reloading"):
            out.append(u)
    return out
