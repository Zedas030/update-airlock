"""Notification texts in English and German (general.language)."""

from __future__ import annotations

MESSAGES = {
    "en": {
        "title": "Update airlock",
        "held": "{name} {to}: breaking change affects {domains} - update held back. Details: {details}",
        "notes_unavailable": "{name} {to}: release notes could not be read ({error}) - update held back.",
        "test_failed": "{name} {to}: test run in the airlock failed - no update. Failed: {checks}",
        "updated": "{name} updated: {frm} -> {to}. Watched {minutes} min, healthy.",
        "rolled_back": "{name}: update to {to} rolled back to {frm}. Reason: {reason}",
        "rollback_failed": "{name}: ROLLBACK FAILED - please check now. {reason}",
        "manual_update_available": "{name}: update {frm} -> {to} ({kind}) available. Policy says notify only; "
                                   "install with: update-airlock update {name}",
        "error": "Update airlock error: {error}",
        "self_check": "Update airlock: {what} failed {n} times in a row: {error}",
        "unit_failed": "Update airlock: systemd unit {unit} failed - see journalctl -u {unit}",
        "test_notify": "Test message from the update airlock - notifications work.",
        "isolation_failed": "SANDBOX ISOLATION BROKEN - all tests stopped: {error}",
    },
    "de": {
        "title": "Update-Schleuse",
        "held": "{name} {to}: Breaking Change betrifft {domains} – Update zurückgehalten. Details: {details}",
        "notes_unavailable": "{name} {to}: Release Notes nicht abrufbar ({error}) – Update zurückgehalten.",
        "test_failed": "{name} {to}: Testlauf in der Schleuse fehlgeschlagen – kein Update. Fehlgeschlagen: {checks}",
        "updated": "{name} aktualisiert: {frm} → {to}. {minutes} min beobachtet, gesund.",
        "rolled_back": "{name}: Update auf {to} zurückgerollt auf {frm}. Grund: {reason}",
        "rollback_failed": "{name}: ROLLBACK FEHLGESCHLAGEN – bitte sofort prüfen. {reason}",
        "manual_update_available": "{name}: Update {frm} → {to} ({kind}) verfügbar. Richtlinie: nur melden; "
                                   "installieren mit: update-airlock update {name}",
        "error": "Fehler in der Update-Schleuse: {error}",
        "self_check": "Update-Schleuse: {what} {n}× hintereinander fehlgeschlagen: {error}",
        "unit_failed": "Update-Schleuse: systemd-Unit {unit} fehlgeschlagen – siehe journalctl -u {unit}",
        "test_notify": "Testnachricht der Update-Schleuse – Meldungen funktionieren.",
        "isolation_failed": "SANDBOX-ISOLATION GEBROCHEN – alle Tests gestoppt: {error}",
    },
}


def t(lang: str, key: str, **kw) -> str:
    table = MESSAGES.get(lang) or MESSAGES["en"]
    text = table.get(key) or MESSAGES["en"][key]
    return text.format(**kw)
