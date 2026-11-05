"""Static status page (index.html + status.json), regenerated on every run and served read-only by a web
server (nginx). Uses the shared homelab theme (assets/homelab-theme.css, inlined - works offline, no CDN).
The only script is the tiny light/dark toggle."""

from __future__ import annotations

import datetime as dt
import html
import json
from pathlib import Path

from .util import atomic_write

THEME_FILE = Path(__file__).resolve().parent / "assets" / "homelab-theme.css"

T = {
    "en": {"title": "Update airlock", "sub": "Tested container updates with rollback",
           "kicker": "Container updates", "lead": "New images are tested in a sealed sandbox against a copy of the "
           "real configuration first. Only then they are installed in the maintenance window, watched, and rolled "
           "back automatically if something breaks.",
           "overview": "Overview", "containers": "Containers", "held": "Held back", "tests": "Tests",
           "isolation": "Isolation", "history": "History", "last_check": "Last check", "window": "Maintenance window",
           "postponed": "last postponed", "iso_tile": "Sandbox isolation", "updates": "Updates (30 days)",
           "rollbacks": "rollbacks", "container": "Container", "status": "Status", "installed": "Installed",
           "available": "Available", "kind": "Kind", "policy": "Policy", "last_test": "Last test",
           "last_update": "Last update", "time": "Time", "action": "Action", "result": "Result",
           "versions": "Versions", "summary": "Summary", "check": "From / via", "target": "Target",
           "expected": "Expected", "observed": "Observed", "reachable": "reachable", "blocked": "blocked",
           "never": "not run yet", "image": "Image", "faults": "Fault injection", "generated": "page generated",
           "ack": "Release after reading the notes:", "no_held": "Nothing held back.",
           "proof_sub": "Proven before every test: the sandbox reaches nothing real (positive controls must work)",
           "ok_all": "Everything up to date", "attention": "Needs attention", "error": "Error",
           "pending": "Tested updates wait for the window", "sealed": "sealed", "broken": "BROKEN",
           "no_tests": "No test yet.", "home": "Dashboard",
           "inconclusive": "not testable in the sandbox - protected by watch + rollback only"},
    "de": {"title": "Update-Schleuse", "sub": "Getestete Container-Updates mit Rollback",
           "kicker": "Container-Updates", "lead": "Neue Images laufen zuerst in einer abgeschotteten Sandbox gegen "
           "eine Kopie der echten Konfiguration. Erst dann werden sie im Wartungsfenster installiert, beobachtet und "
           "bei Problemen automatisch zurückgerollt.",
           "overview": "Übersicht", "containers": "Container", "held": "Zurückgehalten", "tests": "Tests",
           "isolation": "Isolation", "history": "Verlauf", "last_check": "Letzter Check", "window": "Wartungsfenster",
           "postponed": "zuletzt verschoben", "iso_tile": "Sandbox-Isolation", "updates": "Updates (30 Tage)",
           "rollbacks": "Rollbacks", "container": "Container", "status": "Status", "installed": "Installiert",
           "available": "Verfügbar", "kind": "Art", "policy": "Richtlinie", "last_test": "Letzter Test",
           "last_update": "Letztes Update", "time": "Zeit", "action": "Aktion", "result": "Ergebnis",
           "versions": "Versionen", "summary": "Zusammenfassung", "check": "Von / über", "target": "Ziel",
           "expected": "Erwartet", "observed": "Beobachtet", "reachable": "erreichbar", "blocked": "blockiert",
           "never": "noch nicht gelaufen", "image": "Image", "faults": "Fehlerinjektion", "generated": "Seite erzeugt",
           "ack": "Freigeben nach dem Lesen der Hinweise:", "no_held": "Nichts zurückgehalten.",
           "proof_sub": "Vor jedem Test nachgewiesen: Die Sandbox erreicht nichts Echtes (Positivkontrollen müssen klappen)",
           "ok_all": "Alles aktuell", "attention": "Braucht Aufmerksamkeit", "error": "Fehler",
           "pending": "Getestete Updates warten aufs Fenster", "sealed": "dicht", "broken": "GEBROCHEN",
           "no_tests": "Noch kein Test.", "home": "Dashboard",
           "inconclusive": "in der Sandbox nicht prüfbar – nur Beobachtung + Rollback schützen"},
}

STATUS_TEXT = {
    "en": {"ok": "ok", "up_to_date": "up to date", "ready": "tested, ready", "candidate": "update found",
           "update_pending": "update pending", "held": "held back", "attention": "attention", "notify_only": "notify only",
           "test_failed": "test failed", "error": "error", "rolled_back": "rolled back", "ignored": "ignored",
           "failed": "failed", "info": "info", "skipped": "skipped", "passed": "passed"},
    "de": {"ok": "ok", "up_to_date": "aktuell", "ready": "getestet, bereit", "candidate": "Update gefunden",
           "update_pending": "Update steht an", "held": "zurückgehalten", "attention": "Aufmerksamkeit",
           "notify_only": "nur Meldung", "test_failed": "Test fehlgeschlagen", "error": "Fehler",
           "rolled_back": "zurückgerollt", "ignored": "ignoriert", "failed": "fehlgeschlagen", "info": "Info",
           "skipped": "übersprungen", "passed": "bestanden"},
}
TONE = {"ok": "ok", "up_to_date": "ok", "passed": "ok", "ready": "accent", "candidate": "accent",
        "update_pending": "accent", "held": "warn", "attention": "warn", "notify_only": "warn",
        "test_failed": "bad", "error": "bad", "rolled_back": "bad", "failed": "bad"}

_SVG = '<svg class="i" viewBox="0 0 24 24" aria-hidden="true">{}</svg>'
ICON = {
    "brand": '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/><path d="M8.5 12.5l2.5 2.5 4.5-5"/>',
    "shield": '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/>',
    "grid": '<path d="M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    "pause": '<path d="M9 5v14M15 5v14"/>',
    "flask": '<path d="M9 3h6M10 3v6l-5 9a2 2 0 0 0 1.7 3h10.6a2 2 0 0 0 1.7-3l-5-9V3"/>',
    "calendar": '<rect x="3.5" y="5" width="17" height="15" rx="2"/><path d="M3.5 10h17M8 3v4M16 3v4"/>',
    "box": '<path d="M3 7.5l9-4.5 9 4.5v9L12 21l-9-4.5z"/><path d="M3 7.5l9 4.5 9-4.5M12 12v9"/>',
    "home": '<path d="M3 11l9-8 9 8M5 10v10h14V10"/>',
    "moon": '<path d="M12 3a9 9 0 1 0 9 9 7 7 0 0 1-9-9z"/>',
    "file": '<path d="M14 3H6v18h12V7z"/><path d="M14 3v4h4"/>',
    "ok": '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
    "warn": '<path d="M12 3.5l9.5 16.5h-19z"/><path d="M12 10v4.5M12 17.5v.01"/>',
    "bad": '<path d="M6 6l12 12M18 6L6 18"/>',
}
FAVICON_COLOR = {"ok": "#16a34a", "update_pending": "#0891b2", "attention": "#d97706", "error": "#dc2626"}

BOOT_JS = ("(function(){var t;try{t=localStorage.getItem('hl-theme')}catch(e){}"
           "if(t!=='light'&&t!=='dark')t=matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';"
           "document.documentElement.dataset.theme=t})()")
TOGGLE_JS = ("(function(){var r=document.documentElement,t=r.dataset.theme==='dark'?'light':'dark';"
             "r.dataset.theme=t;try{localStorage.setItem('hl-theme',t)}catch(e){}})()")

CSS = """
.top .live{max-width:46vw;overflow:hidden;text-overflow:ellipsis}
.sec{scroll-margin-top:90px}.hero{margin-bottom:16px}.hero h2,.hero p,.tile-val{overflow-wrap:anywhere}
.card-h .ico.ok{color:var(--ok);background:color-mix(in srgb,var(--ok) 14%,transparent)}
.card-h .ico.warn{color:var(--warn);background:color-mix(in srgb,var(--warn) 16%,transparent)}
.card-h .ico.bad{color:var(--bad);background:color-mix(in srgb,var(--bad) 14%,transparent)}
.t td.mono,.t td .mono{overflow-wrap:anywhere}.held-list{margin:8px 0 0 18px;padding:0}.held-list li{margin:4px 0}
.cmd{display:inline-block;margin-top:8px;padding:4px 8px;border-radius:8px;background:var(--surface-3);font-family:var(--mono);font-size:12.5px}
@media (max-width:640px){.top .live{display:none}.card-b .t th,.card-b .t td{padding:8px 10px}.hero{align-items:flex-start;padding:18px}}
"""


def _e(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def _icon(n: str) -> str:
    return _SVG.format(ICON[n])


def _ts(v, fmt: str = "%Y-%m-%d %H:%M") -> str:
    if not v:
        return "–"
    try:
        if isinstance(v, (int, float)):
            return dt.datetime.fromtimestamp(v).strftime(fmt)
        return dt.datetime.fromisoformat(str(v)).strftime(fmt)
    except (ValueError, OSError):
        return str(v)[:16].replace("T", " ")


def _theme_css() -> str:
    try:
        return THEME_FILE.read_text(encoding="utf-8")
    except OSError:
        return ""


def favicon_href(state: str) -> str:
    color = FAVICON_COLOR.get(state, "#64748b")
    svg = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'>"
           f"<rect width='32' height='32' rx='7' fill='{color}'/><g fill='none' stroke='#fff' stroke-linecap='round' "
           "stroke-linejoin='round' stroke-width='2.4'><path d='M16 6l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V9z'/>"
           "<path d='M12.5 16l2.5 2.5 4.5-5'/></g></svg>")
    return "data:image/svg+xml," + svg.replace("<", "%3C").replace(">", "%3E").replace("#", "%23")


class Page:
    def __init__(self, lang: str):
        self.lang = lang if lang in T else "en"
        self.t = T[self.lang]
        self.st = STATUS_TEXT[self.lang]

    def pill(self, status: str | None, text: str | None = None) -> str:
        tone = TONE.get(status or "", "")
        cls = f"pill {tone}" if tone else "pill"
        return f"<span class='{cls}'><span class='d'></span>{_e(text or self.st.get(status or '', status or '–'))}</span>"


def render(lang: str, overall: str, containers: dict, glob: dict, events: list[dict], window: str,
           isolation: dict | None, tests: list[dict], home_url: str = "", home_label: str = "") -> str:
    p = Page(lang)
    t = p.t
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    last_check = (glob.get("last_run") or {}).get("check")
    iso_ok = (isolation or {}).get("passed") if isolation else glob.get("isolation_ok")
    held = {n: s for n, s in containers.items() if s.get("status") == "held"}
    managed = {n: s for n, s in containers.items() if s.get("status") != "ignored"}
    since = (dt.datetime.now().astimezone() - dt.timedelta(days=30)).isoformat()
    upd30 = sum(1 for e in events if e["action"] == "update" and e["result"] == "ok" and e["ts"] >= since)
    rb30 = sum(1 for e in events if e["action"] == "rollback" and e["ts"] >= since)

    # ---- header ----
    tabs = [("#containers", "grid", t["containers"]), ("#held", "pause", t["held"]), ("#tests", "flask", t["tests"]),
            ("#isolation", "shield", t["isolation"]), ("#history", "clock", t["history"])]
    on_attr = ' class="on" aria-current="page"'
    nav = "".join(f"<a{on_attr if i == 0 else ''} href='{h}'>{_icon(ic)}{_e(lb)}</a>"
                  for i, (h, ic, lb) in enumerate(tabs))
    live = (f"<span class='live'><i class='sd {TONE.get(overall, '')}'></i>{_e(p.st.get(overall, overall))} · "
            f"{_e(_ts(last_check, '%d.%m. %H:%M'))}</span>")
    home = (f"<a class='btn cross home-btn' href='{_e(home_url)}' title='{_e(home_label or t['home'])}'>{_icon('home')}"
            f"<span class='lbl'>{_e(home_label or t['home'])}</span></a>") if home_url else ""
    header = ("<header class='top'>"
              f"<a class='brand' href='./'><span class='brand-mark'>{_icon('brand')}</span>"
              f"<span><span class='brand-name'>{_e(t['title'])}</span><span class='brand-sub'>{_e(t['sub'])}</span></span></a>"
              f"<nav class='tabs' aria-label='Sections'>{nav}</nav><div class='top-right'>{live}{home}"
              f"<button class='icon-btn' type='button' onclick=\"{TOGGLE_JS}\" aria-label='Light/dark'>{_icon('moon')}</button>"
              "</div></header>")

    # ---- hero + tiles ----
    hero_tone = {"ok": "ok", "update_pending": "ok", "attention": "warn", "error": "bad"}.get(overall, "warn")
    hero_text = {"ok": t["ok_all"], "update_pending": t["pending"], "attention": t["attention"],
                 "error": t["error"]}.get(overall, overall)
    lines = []
    for n, s in managed.items():
        if s.get("status") in ("held", "test_failed", "rolled_back", "error", "notify_only", "ready"):
            lines.append(f"{n}: {p.st.get(s.get('status'), s.get('status'))}"
                         + (f" ({s.get('available_version')})" if s.get("available_version") else ""))
    hero_line = " · ".join(lines) or f"{len(managed)} {t['containers']}"
    hero = (f"<section class='card hero {hero_tone}'><div class='h-ico'>{_icon(hero_tone)}</div>"
            f"<div><h2>{_e(hero_text)}</h2><p>{_e(hero_line)}</p></div></section>")
    postponed = glob.get("last_postponed") or {}

    def tile(ic, label, val, sub, tone=""):
        return (f"<div class='card tile'><div class='tile-top'>{_icon(ic)}{_e(label)}</div>"
                f"<div class='tile-val {tone}'>{val}</div><div class='tile-sub'>{sub}</div></div>")
    iso_val = (t["sealed"] if iso_ok else t["broken"]) if iso_ok is not None else "–"
    tiles = ("<div class='grid cols-4'>"
             + tile("clock", t["last_check"], _e(_ts(last_check, "%d.%m. %H:%M")),
                    _e(p.st.get("ok") if (glob.get("last_ok") or {}).get("check") else p.st.get("error")))
             + tile("shield", t["iso_tile"], _e(iso_val), _e(_ts((isolation or {}).get("when"))),
                    "ok" if iso_ok else ("bad" if iso_ok is False else ""))
             + tile("calendar", t["window"], _e(window),
                    _e(f"{t['postponed']}: {_ts(postponed.get('ts'), '%d.%m. %H:%M')} {postponed.get('reason') or ''}")
                    if postponed else "&nbsp;")
             + tile("box", t["updates"], f"{upd30}", _e(f"{rb30} {t['rollbacks']}"), "bad" if rb30 else "")
             + "</div>")

    # ---- containers ----
    rows = []
    for n, s in containers.items():
        lt = s.get("last_test") or {}
        lts = "–" if not lt else f"{p.pill('passed' if lt.get('passed') else 'failed')} <span class='small muted'>{_e(_ts(lt.get('finished'), '%d.%m. %H:%M'))}</span>"
        if lt and lt.get("passed") and lt.get("inconclusive"):
            lts += f"<div class='small warn' title='{_e(lt.get('inconclusive'))}'>{_e(t['inconclusive'])}</div>"
        lu = s.get("last_update") or {}
        lus = "–" if not lu else f"{_e(_ts(lu.get('ts'), '%d.%m. %H:%M'))}<div class='small muted'>{_e(lu.get('from'))} → {_e(lu.get('to'))}</div>"
        rows.append(f"<tr><td><b>{_e(n)}</b><div class='small muted'>{_e(s.get('managed_by') or '')}</div></td>"
                    f"<td>{p.pill(s.get('status'))}</td><td class='mono'>{_e(s.get('current_version') or '–')}</td>"
                    f"<td class='mono'>{_e(s.get('available_version') or '–')}</td><td>{_e(s.get('kind') or '–')}</td>"
                    f"<td>{_e(s.get('policy') or '–')}</td><td>{lts}</td><td>{lus}</td></tr>")
    sec_cont = (f"<section class='sec' id='containers'><div class='sec-h'><h2>{_e(t['containers'])}</h2></div>"
                "<div class='card'><div class='tbl-wrap'><table class='t'><thead><tr>"
                + "".join(f"<th>{_e(t[k])}</th>" for k in ("container", "status", "installed", "available", "kind",
                                                           "policy", "last_test", "last_update"))
                + "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div></div></section>")

    # ---- held ----
    if held:
        cards = []
        for n, s in held.items():
            aff = (s.get("notes") or {}).get("affected") or []
            items = "".join(f"<li><b>{_e(', '.join(a.get('domains') or []))}</b> – {_e(a.get('title'))} "
                            f"<a href='{_e(a.get('url'))}' rel='noopener' target='_blank'>{_e(a.get('url'))}</a></li>"
                            for a in aff[:15])
            reason = s.get("held_reason") or ""
            err = f"<div class='note bad'>{_e(s.get('error'))}</div>" if reason == "notes_unavailable" else ""
            cards.append(f"<div class='card tone-warn'><div class='card-h'><span class='ico warn'>{_icon('pause')}</span>"
                         f"<h3>{_e(n)} {_e(s.get('available_version'))}</h3><span class='aside'>{p.pill('held', reason)}</span></div>"
                         f"<div class='card-b'>{err}<ul class='held-list'>{items}</ul>"
                         f"<div class='small muted' style='margin-top:10px'>{_e(t['ack'])}</div>"
                         f"<span class='cmd'>update-airlock ack {_e(n)} {_e(s.get('available_tag'))}</span></div></div>")
        held_html = "<div class='grid'>" + "".join(cards) + "</div>"
    else:
        held_html = f"<div class='card'><div class='card-b muted'>{_e(t['no_held'])}</div></div>"
    sec_held = f"<section class='sec' id='held'><div class='sec-h'><h2>{_e(t['held'])}</h2></div>{held_html}</section>"

    # ---- tests ----
    trs = "".join(
        f"<tr><td>{_e(_ts(r.get('finished'), '%d.%m. %H:%M'))}</td><td><b>{_e(r.get('container'))}</b></td>"
        f"<td class='mono'>{_e(r.get('candidate') or '')}</td><td>{p.pill('passed' if r.get('passed') else 'failed')}</td>"
        f"<td>{_e(', '.join(r.get('faults') or []) or '–')}</td>"
        f"<td class='small'>{_e(r.get('error') or '; '.join(c['name'] for c in r.get('checks', []) if not c.get('ok')) or '–')}</td></tr>"
        for r in tests)
    sec_tests = (f"<section class='sec' id='tests'><div class='sec-h'><h2>{_e(t['tests'])}</h2></div><div class='card'>"
                 + (f"<div class='tbl-wrap'><table class='t'><thead><tr><th>{_e(t['time'])}</th><th>{_e(t['container'])}</th>"
                    f"<th>{_e(t['image'])}</th><th>{_e(t['result'])}</th><th>{_e(t['faults'])}</th><th>{_e(t['summary'])}</th>"
                    f"</tr></thead><tbody>{trs}</tbody></table></div>" if tests else
                    f"<div class='card-b muted'>{_e(t['no_tests'])}</div>") + "</div></section>")

    # ---- isolation ----
    if isolation:
        ok = bool(isolation.get("passed"))
        chk = "".join(
            f"<tr><td>{_e(c.get('from'))}{(' / ' + _e(c.get('via'))) if c.get('via') else ''}</td>"
            f"<td class='mono'>{_e(c.get('target'))}</td>"
            f"<td>{_e(t['reachable'] if c.get('expected') == 'reachable' else t['blocked'])}</td>"
            f"<td>{p.pill('ok' if c.get('ok') else 'failed', t['reachable'] if c.get('reachable') else t['blocked'])}</td></tr>"
            for c in isolation.get("checks", []))
        iso_body = (f"<div class='card tone-{'ok' if ok else 'bad'}'><div class='card-h'><span class='ico {'ok' if ok else 'bad'}'>"
                    f"{_icon('shield')}</span><h3>Sandbox</h3><span class='aside'>{p.pill('ok' if ok else 'failed', t['sealed'] if ok else t['broken'])}"
                    f" <span class='small muted'>{_e(_ts(isolation.get('when')))}</span></span></div>"
                    + (f"<div class='card-b'><div class='note bad'>{_e(isolation.get('error'))}</div></div>" if isolation.get("error") else "")
                    + f"<div class='tbl-wrap'><table class='t'><thead><tr><th>{_e(t['check'])}</th><th>{_e(t['target'])}</th>"
                    f"<th>{_e(t['expected'])}</th><th>{_e(t['observed'])}</th></tr></thead><tbody>{chk}</tbody></table></div></div>")
    else:
        iso_body = f"<div class='card'><div class='card-b muted'>{_e(t['never'])}</div></div>"
    sec_iso = (f"<section class='sec' id='isolation'><div class='sec-h'><h2>{_e(t['isolation'])}</h2>"
               f"<span class='sub'>{_e(t['proof_sub'])}</span></div>{iso_body}</section>")

    # ---- history ----
    ev = "".join(
        f"<tr><td class='nowrap'>{_e(_ts(e['ts'], '%d.%m. %H:%M'))}</td><td>{_e(e['container'])}</td><td>{_e(e['action'])}</td>"
        f"<td>{p.pill(e['result'])}</td><td class='mono'>{_e((e.get('from_version') or '') + (' → ' if e.get('to_version') else '') + (e.get('to_version') or ''))}</td>"
        f"<td class='small'>{_e((e.get('summary') or '')[:200])}</td></tr>" for e in events)
    sec_hist = (f"<section class='sec' id='history'><div class='sec-h'><h2>{_e(t['history'])}</h2></div><div class='card'>"
                f"<div class='tbl-wrap'><table class='t'><thead><tr><th>{_e(t['time'])}</th><th>{_e(t['container'])}</th>"
                f"<th>{_e(t['action'])}</th><th>{_e(t['result'])}</th><th>{_e(t['versions'])}</th><th>{_e(t['summary'])}</th>"
                f"</tr></thead><tbody>{ev}</tbody></table></div></div></section>")

    return ("<!doctype html>\n"
            f"<html lang='{p.lang}' data-theme='dark'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'><meta name='color-scheme' content='light dark'>"
            "<meta http-equiv='refresh' content='300'>"
            f"<link rel='icon' type='image/svg+xml' href=\"{favicon_href(overall)}\">"
            f"<title>{_e(t['overview'])} · {_e(t['title'])}</title>"
            f"<style>{_theme_css()}</style><style>{CSS}</style><script>{BOOT_JS}</script></head><body>"
            + header + "<main class='content'>"
            f"<div class='page-head'><div><div class='kicker'>{_e(t['kicker'])}</div><h1>{_e(t['title'])}</h1>"
            f"<p>{_e(t['lead'])}</p></div><div class='actions'><a class='btn sm' href='status.json'>{_icon('file')}status.json</a></div></div>"
            + hero + tiles + sec_cont + sec_held + sec_tests + sec_iso + sec_hist
            + f"<footer class='foot'>update-airlock · {_e(t['generated'])} {now} · <a href='status.json'>status.json</a></footer>"
            "</main></body></html>\n")


def write(www: Path, lang: str, overall: str, containers: dict, glob: dict, events: list[dict], window: str,
          isolation: dict | None, tests: list[dict], home_url: str = "", home_label: str = "") -> None:
    www.mkdir(parents=True, exist_ok=True)
    www.chmod(0o755)
    atomic_write(www / "index.html", render(lang, overall, containers, glob, events, window, isolation, tests,
                                            home_url, home_label), 0o644)
    public = {"overall": overall, "generated": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
              "global": {k: glob.get(k) for k in ("last_run", "last_ok", "isolation_ok", "failures", "last_postponed")},
              "containers": {n: {k: s.get(k) for k in ("status", "current_version", "available_version", "kind",
                                                       "policy", "held_reason", "held_domains", "last_test",
                                                       "last_update", "last_rollback", "error")}
                             for n, s in containers.items()}}
    atomic_write(www / "status.json", json.dumps(public, indent=1, ensure_ascii=False, default=str), 0o644)
