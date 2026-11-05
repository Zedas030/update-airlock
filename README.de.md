# update-airlock – die Update-Schleuse

**Container-Updates zuerst gegen eine Kopie der echten Konfiguration testen, dann aktualisieren, bei
Problemen automatisch zurückrollen.**

Jede Nacht sucht update-airlock nach neuen Images und liest die Release Notes. Bei Home Assistant gleicht
es die Breaking Changes mit den Integrationen ab, die du tatsächlich nutzt. Danach startet es das neue
Image in einer isolierten Wegwerf-Sandbox mit einer Kopie deiner Daten. Erst wenn das klappt, kommt das
echte Update: im Wartungsfenster, nach einem Backup, mit 15 Minuten Beobachtung und automatischem Rollback.

Gebaut für Home Assistant als Container (ohne Supervisor) auf einem Raspberry Pi; funktioniert auf jedem
Docker-Host. English version: [README.md](README.md)

## Inhalt

1. [Wie es arbeitet](#wie-es-arbeitet)
2. [Isolation der Sandbox](#isolation-der-sandbox)
3. [Installation](#installation)
4. [Secrets (Token, Passwörter)](#secrets)
5. [Betrieb](#betrieb)
6. [Dienste hinzufügen](#dienste-hinzufügen)
7. [Update des Tools](#update-des-tools)
8. [Umzug auf einen anderen Host](#umzug-auf-einen-anderen-host)
9. [Deinstallation](#deinstallation)
10. [Fehlerbehebung](#fehlerbehebung)

## Wie es arbeitet

**1. Prüfen (täglich 00:30, `update-airlock-check.timer`)**

Je Container fragt das Tool die Registry ab (Docker Hub, ghcr.io, jede v2-Registry; arm64-Manifest). Es
gibt zwei Arten, Updates zu verfolgen:

- `track: tag` folgt dem Digest des aktuellen Tags (`:latest`, `:2`, `:1.8`). Hat das Image ein
  Versions-Label, wird daraus Patch, Minor oder Major, sonst „digest“.
- `track: semver` sucht neuere Versions-Tags (`tag_pattern`, keine Betas). Für HA gilt `versioning: calver`:
  Ein neuer Monat zählt als Minor.

Pro Container und Update-Art (`patch`, `minor`, `major`, `digest`) legst du fest: `auto` (testen, dann im
Fenster installieren), `notify` (nur melden) oder `ignore`.

**2. Release Notes (zuerst für HA, erweiterbar)**

Zwei Quellen:
- der Abschnitt „Backward-incompatible changes“ des Release-Blogs,
- die Pull Requests mit dem Label `breaking-change` auf GitHub (Betas, .0 und Patch-Releases dazwischen).

Abgeglichen wird mit deinen aktiven Config-Einträgen (`.storage/core.config_entries`), den
YAML-Integrationen und den Custom Components. Bei einem Treffer bleibt das Update stehen und du bekommst
z. B.: *„homeassistant 2026.11.0: Breaking Change betrifft mqtt, sun, tuya, zha – Update zurückgehalten.
Details: …“*.

Sind die Release Notes nicht abrufbar, wird das Update ebenfalls zurückgehalten und gemeldet. Das Tool
geht also im Zweifel auf Nummer sicher.

**3. Testlauf in der Schleuse**

Die Kopie der Config (inklusive Recorder-Datenbank, konsistent kopiert, während HA läuft) wird
neutralisiert und zweimal gestartet: einmal mit dem **aktuellen** Image (Vergleichslauf), einmal mit dem
**neuen**. Gewertet werden nur Unterschiede. Die Sandbox erzeugt nämlich von sich aus Fehler, etwa
„kein Netz“ oder „Integration deaktiviert“, und die haben mit dem Update nichts zu tun.

Die Prüfungen:
- Der Container startet und erreicht `RUNNING`, und zwar mit der erwarteten Version.
- `check_config` liefert keine neuen Fehler.
- Weboberfläche und API antworten.
- Im Log stehen keine neuen ERROR-Zeilen (normalisiert verglichen).
- Alle Komponenten des Vergleichslaufs sind geladen.
- Jede genutzte Integration lässt sich importieren, samt ihren Python-Paketen. Das gilt auch für die
  Integrationen, die in der Sandbox abgeschaltet sind, etwa ZHA.
- Der Testcontainer erreicht nichts (Verbindungsversuche von innen).

Danach wird alles weggeräumt, auch bei Abbruch.

Für andere Container gibt es den generischen Tester: startet, bleibt oben, Healthcheck, HTTP-Antwort,
ebenfalls mit Vergleichslauf.

Manche Container laufen in der Sandbox grundsätzlich nicht, auch nicht mit dem alten Image; ein Exporter zum
Beispiel beendet sich ohne Fritzbox sofort. Ihr Test heißt dann **„nicht prüfbar“ (inconclusive)**. Er gilt
als bestanden, ist aber kein Beweis: Geschützt sind sie dann nur durch die Beobachtung und den Rollback nach
dem echten Update. Das steht im Bericht, in der Meldung und auf der Statusseite. Wer das nicht will, setzt
`test: {require_conclusive: true}`; dann scheitert so ein Test.

**4. Echtes Update (`update-airlock-apply.timer`, alle 10 min; handelt nur im Fenster)**

Voraussetzungen:
- Der Test für genau diesen Digest ist bestanden (höchstens 72 h alt).
- Es ist Wartungsfenster, Standard 03:40–04:30.
- Keiner der Dienste unter `pause_while_active` läuft, z. B. raspiBackup.
- Niemand ist „zu Hause aktiv“: Person zu Hause UND ein Aktivitätsmelder belegt oder in den letzten
  20 min belegt gewesen. Ist HA nicht erreichbar, gilt nur das feste Fenster.

Ablauf:
1. Container stoppen.
2. Backup von Config und Volumes (`tar.zst`), dazu `docker inspect`, die Compose-Datei und das alte Image
   (gesichert per Tag `update-airlock-keep/…`).
3. Neues Image starten. Compose-Dateien bekommen eine feste Zeile `image: repo:tag@sha256:…`; andere
   Container werden aus ihrem eigenen `docker inspect` neu erzeugt, und der alte bleibt bis zur Bestätigung
   gestoppt liegen.

**5. Kontrolle danach (15 min)**

Rollback auf den alten Digest **und** das Daten-Backup, wenn eines davon eintritt:
- Der Container läuft nicht, startet neu oder ist `unhealthy`.
- Weboberfläche oder API antworten nach der Anlaufzeit mehrmals hintereinander nicht.
- Der Anteil der `unavailable`-Entitäten liegt am Ende mehr als `unavailable_threshold_pp` Prozentpunkte
  über dem Wert vor dem Update (Standard: 10).

Dateien, die die neue Version angelegt hat, werden beim Rollback nicht gelöscht, sondern nach
`/var/lib/update-airlock/quarantine/` verschoben.

**Statusseite**

Nach jedem Lauf wird eine statische Seite neu erzeugt: Status aller Container, zurückgehaltene Updates mit
Links auf die Hinweise, Testberichte, Isolationsnachweis und Verlauf, dazu `status.json`. nginx liefert sie
auf Port **8100** aus (`sudo ./scripts/install.sh --nginx`, Vorlage `web/nginx-update-airlock.conf`). Mit
`ui.home_url` gibt es oben rechts einen Knopf zurück zu deinem Dashboard.

**6. Verlauf**

Welche Version wann, Testergebnisse, zurückgehaltene Updates und Rollbacks stehen in
`/var/lib/update-airlock/history.db`. Anzeigen mit `update-airlock history`.

## Isolation der Sandbox

**Der Testcontainer darf niemals echte Geräte schalten.** Dafür gibt es fünf voneinander unabhängige
Schichten:

1. **Internes Docker-Netz** (`--internal`): kein Gateway, keine Route. DNS zeigt ins Leere (`--dns 0.0.0.0`).
2. **Egress-Proxy** (tinyproxy) als einziges weiteres Mitglied. Er lässt nur HTTPS-`CONNECT` zu PyPI und
   den HA-Wheels durch; die braucht HA, um Pakete für Integrationen zu installieren. Ziele mit IP-Adresse
   und alle anderen Hosts lehnt er mit `403` ab.
3. **iptables**, nur für die Dauer eines Tests:
   - Die Bridge des Proxys darf keine privaten oder Link-Local-Netze erreichen (`DOCKER-USER`).
   - Keine Sandbox-Bridge darf neue Verbindungen zum Host aufbauen (`INPUT`).
4. **Container-Härtung:** keine Ports nach außen, keine Geräte, `--cap-drop ALL`, `no-new-privileges`,
   Limits für RAM, CPU und Prozesse.
5. **In der Kopie:**
   - Alle Integrationen außerhalb einer harmlosen Positivliste sind deaktiviert (ZHA, Tuya, TP-Link,
     Sonos, MQTT, mobile_app …).
   - `shell_command`, `wake_on_lan`, `notify` und Ähnliches sind entfernt.
   - Alle Automationen haben `initial_state: false`.
   - `.ssh` und die Backups werden gar nicht erst kopiert.

**Nachweis bei jedem Test:**
- Vor jedem Test versucht ein Probe-Container, Router, Host, deine Geräte (Liste
  `sandbox.must_be_unreachable`) und das Internet zu erreichen, direkt und über den Proxy.
- Dazu kommen **Positivkontrollen:** Der Proxy selbst und PyPI über den Proxy müssen erreichbar sein.
  Ein kaputter Test kann also kein „blockiert“ vortäuschen.
- Ist ein einziges Ziel erreichbar, bricht der Test ab, bevor HA startet, und du bekommst eine Meldung.
- Der echte Testcontainer wiederholt die Verbindungsversuche von innen.

`sudo update-airlock isolation-proof` zeigt den Nachweis jederzeit.

## Installation

Voraussetzungen:
- Linux mit systemd, Docker mit Compose-Plugin.
- Python ≥ 3.11 mit `python3-yaml` und `python3-requests` (Debian-Pakete).
- `tar`, `zstd`, `iptables`.
- Root-Rechte (Docker, iptables, Backups).

```bash
git clone https://github.com/Zedas030/update-airlock.git
cd update-airlock
sudo ./scripts/install.sh
sudoedit /etc/update-airlock/config.yaml     # Container, Richtlinien, Fenster, notify-Dienst
sudoedit /etc/update-airlock/.env            # HA_TOKEN eintragen (siehe Secrets)
sudo update-airlock validate
sudo update-airlock isolation-proof          # muss "passed": true zeigen
sudo update-airlock check --no-test          # erster Überblick
sudo ./scripts/install.sh --enable           # Timer einschalten
sudo ./scripts/install.sh --nginx            # optional: Statusseite auf Port 8100
```

Danach in Home Assistant die Automation `ha/automation_dead_mans_switch.yaml` anlegen; sie meldet, wenn
36 h kein Check lief. In Grafana `grafana/update-airlock-dashboard.json` importieren.

Die Metriken schreibt das Tool nach `/var/lib/prometheus/node-exporter/update_airlock.prom`. Der Debian-node-exporter
liest sie mit dem Textfile-Collector, ein neuer Scrape-Job ist nicht nötig.

**Warum systemd statt Docker Compose?** Das Tool braucht auf dem Host ohnehin Root: Docker-Socket,
iptables-Regeln für die Sandbox, root-eigene Datenverzeichnisse, das Neuanlegen anderer Container. Ein
Container mit Docker-Socket wäre genauso mächtig wie Root, könnte die Firewall des Hosts aber nicht sauber
verwalten.

Die Units sind gehärtet (`ProtectSystem=full`, `NoNewPrivileges` …) und begrenzt (`MemoryMax=512M`,
`CPUQuota=50%`); die Testcontainer haben eigene Limits. Autostart nach einem Reboot übernehmen die Timer
(`WantedBy=timers.target`, `Persistent=true`). Die Logs landen im Journal und in
`/var/log/update-airlock/`; logrotate rotiert sie wöchentlich und hebt 8 Wochen auf.

## Secrets

Alle Secrets stehen in **`/etc/update-airlock/.env`** (root, Rechte 600), nie in der `config.yaml`. In der
Config wird nur mit `${NAME}` darauf verwiesen. Vorlage: `config/env.example`.

| Variable | Wofür | Anlegen / ändern / rotieren |
|---|---|---|
| `HA_TOKEN` | Home-Assistant-Token für Meldungen, Sensoren, Präsenz, Kontrolle nach dem Update | HA → Profil → Sicherheit → *Langlebige Zugangstoken* → erstellen, in `.env` eintragen, alten Token in HA löschen |
| `GITHUB_TOKEN` | optional, höheres GitHub-Limit für die HA-Release-Notes | github.com → Settings → Developer settings → Token ohne Berechtigungen |
| frei wählbar | Zugangsdaten privater Registries `user:token`, Verweis in `check.registry_credentials` | bei der Registry |

Bearbeiten mit `sudoedit /etc/update-airlock/.env`. Jeder Lauf liest die Datei neu, ein Neustart ist nicht
nötig. Test danach: `sudo update-airlock notify-test`.

## Betrieb

| Befehl | Was er tut |
|---|---|
| `update-airlock status` | Zustand aller Container; bei zurückgehaltenen Updates die passenden Breaking Changes mit Link |
| `update-airlock check [name] [--no-test]` | jetzt nach Updates suchen (und Kandidaten testen) |
| `update-airlock test <name>` | Testlauf in der Schleuse jetzt (`--image REF` für ein anderes Image) |
| `update-airlock update <name>` | echtes Update jetzt; testet vorher, falls nötig, und ignoriert Fenster und Präsenz |
| `update-airlock rollback <name>` | zurück auf den Stand vor dem letzten erfolgreichen Update (Image + Daten) |
| `update-airlock ack <name> <version>` | Breaking Changes einer Version bestätigen, danach darf sie installiert werden |
| `update-airlock history [name]` | Verlauf |
| `update-airlock isolation-proof` | Sandbox aufbauen, Isolation nachweisen, abbauen |
| `update-airlock cleanup` | Reste von Testläufen entfernen |
| `update-airlock notify-test` | Testmeldung schicken |
| `update-airlock validate` | Config prüfen |

Zum Testen der Schleuse selbst gibt es diese Fehlerinjektionen:
- `test <name> --fault broken-config` baut eine fehlerhafte Config in die Kopie ein.
- `test <name> --fault crash-after-start` lässt den Testcontainer abstürzen.
- `update <name> --fault unhealthy` stoppt den Container nach dem Update; erwartet ist ein Rollback.
- `check --simulate-breaking zha` simuliert einen Breaking-Change-Treffer.

**Zurückgehaltenes Update:** Lies die verlinkten Hinweise und pass dein Setup an, falls nötig. Danach
`sudo update-airlock ack homeassistant 2026.11.0`: Die nächste Nacht installiert die Version (nach einem
Test). Oder sofort mit `sudo update-airlock update homeassistant`.

**Sensoren in Home Assistant:**
- `sensor.update_airlock`: Zustand `ok`, `update_pending`, `attention` oder `error`, mit den Attributen
  `last_check`, `containers` und `isolation_ok`.
- `sensor.update_airlock_<container>`: Status, dazu installierte und verfügbare Version, Richtlinie,
  Grund fürs Zurückhalten, letzter Test, letztes Update, letzter Rollback.

Nach einem HA-Neustart legt der Apply-Timer die Sensoren innerhalb von 10 Minuten wieder an.

**Wo liegt was:**

| Pfad | Inhalt |
|---|---|
| `/etc/update-airlock/config.yaml` | Konfiguration (kommentiert) |
| `/etc/update-airlock/.env` | Secrets (600) |
| `/opt/update-airlock/app` | Programm |
| `/var/lib/update-airlock/history.db` | Verlauf und Zustand |
| `/var/lib/update-airlock/reports/` | Testberichte als JSON |
| `/var/backups/update-airlock/<container>/<zeit>/` | Backups vor jedem Update (je Container die letzten 3) |
| `/var/log/update-airlock/` | Log-Dateien |
| `/var/www/update-airlock/` | Statusseite (`index.html`, `status.json`), nginx-Site `update-airlock` |

Status der Timer: `systemctl list-timers 'update-airlock*'`. Logs: `journalctl -u update-airlock-check -u update-airlock-apply`.

## Dienste hinzufügen

Unter `containers:` in der `config.yaml` einen Eintrag ergänzen; der Schlüssel ist der Docker-Containername:

```yaml
  mein-dienst:
    tester: generic                 # oder homeassistant / none
    policy: {patch: auto, minor: notify, major: notify, digest: auto}
    track: tag                      # tag = Digest des aktuellen Tags verfolgen; semver = neuere Versions-Tags
    health: {http_url: "http://127.0.0.1:8080/health"}   # wird nach dem echten Update geprüft
    test: {http_port: 8080, http_path: /health}          # wird in der Sandbox geprüft (Port im Container)
```

Danach `sudo update-airlock validate` und `sudo update-airlock test mein-dienst`.

- **Compose-Container** erkennt das Tool an ihren Labels. In der Compose-Datei darf das Image keine
  Variable sein.
- **Andere Container** baut das Tool aus `docker inspect` neu auf.
- **Nicht aufgeführte Container** werden nie angefasst.
- **Neue Geräte im Netz** gehören zusätzlich in `sandbox.must_be_unreachable`.

## Update des Tools

```bash
cd update-airlock && git pull && sudo ./scripts/install.sh && sudo update-airlock validate
```

`config.yaml` und `.env` bleiben unverändert. Neue Optionen zeigt `config/config.example.yaml`.

## Umzug auf einen anderen Host

Für einen Umzug (z. B. auf den SFF-Server) liegt alles Host-Spezifische in der Config:
1. Repository klonen und `install.sh` ausführen.
2. `/etc/update-airlock/config.yaml` und `.env` kopieren.
3. `homeassistant.url` und die Geräteliste in `sandbox.must_be_unreachable` anpassen.
4. `isolation-proof` laufen lassen, danach `install.sh --enable`.

Verlauf und Backups (`/var/lib/update-airlock`, `/var/backups/update-airlock`) kann man mitnehmen, nötig
ist es nicht. Auf dem alten Host danach `uninstall.sh` ausführen.

## Deinstallation

```bash
sudo /opt/update-airlock/app/scripts/uninstall.sh            # behält Config, Verlauf, Backups
sudo /opt/update-airlock/app/scripts/uninstall.sh --purge    # entfernt alles inkl. Backups
```

Aktualisierte Container laufen mit ihrem fest eingetragenen Image weiter. Die HA-Automation und das
Grafana-Dashboard entfernst du selbst.

## Fehlerbehebung

| Symptom | Ursache / Abhilfe |
|---|---|
| `another update-airlock run is active` | Ein Check oder Test läuft noch (`systemctl status update-airlock-check`). Der 10-Minuten-Lauf überspringt dann still. |
| Update bleibt `held` mit `notes_unavailable` | GitHub oder Blog nicht erreichbar oder Rate-Limit: `GITHUB_TOKEN` eintragen. Beim nächsten erfolgreichen Check verschwindet es. |
| `isolation proof failed` | Aus der Sandbox ist etwas erreichbar. `isolation-proof` nennt das Ziel; prüfe Docker- und iptables-Änderungen. Bis das behoben ist, läuft kein Test. |
| Test rot: *new errors in the log* | JSON-Bericht in `reports/` ansehen. Harmloses Sandbox-Rauschen per `test.ignore_error_patterns` ausblenden. |
| Test rot: *integrations can be loaded* | Eine Custom Component passt nicht zur neuen Version. Erst die Komponente aktualisieren oder abwarten. |
| `baseline does not start in the sandbox` | Schon die aktuelle Version startet nicht aus der Kopie, z. B. wegen zu wenig RAM: `sandbox.memory` erhöhen. |
| keine Meldungen | `update-airlock notify-test`; `HA_TOKEN` und `homeassistant.notify_service` prüfen. |
| Sensoren fehlen nach HA-Neustart | Sie kommen innerhalb von 10 min wieder; sofort mit `update-airlock publish`. |
| Reste nach Stromausfall | Der nächste Lauf räumt automatisch auf; sofort mit `update-airlock cleanup`. |
| Meldung „ROLLBACK FEHLGESCHLAGEN“ | Backups liegen in `/var/backups/update-airlock/<name>/<zeit>/` (`mount*.tar.zst`, `compose*.yml`, `inspect.json`). Von Hand: Container stoppen, `tar --zstd -xpf mount0.tar.zst -C <Datenpfad>`, alte Compose-Datei zurück, `docker compose up -d`. Dateien der neuen Version liegen in `/var/lib/update-airlock/quarantine/`. |
| Update wird jede Nacht verschoben | `sensor.update_airlock` → Attribut `last_postponed` nennt den Grund (Präsenz, Backup läuft). |

## Tests

```bash
python3 -m pytest -q tests/unit                                       # Unit-Tests
sudo python3 tests/e2e/e2e.py --generic fritz_exporter --ha homeassistant   # gegen das echte System, verändert nichts
# --generic: ein Container, der in der Sandbox läuft; getestet wird sein aktuelles Image
```

## Lizenz

MIT
