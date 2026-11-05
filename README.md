# update-airlock

**Test container updates against a copy of your real configuration before they reach production.**
update-airlock looks for new images every night, reads the release notes (Home Assistant: breaking
changes matched against the integrations you actually use), runs the new image in an isolated throw-away
sandbox with a copy of your data, and only then updates – inside a maintenance window, with a backup, a
15-minute watch and an automatic rollback.

Built for a Home Assistant *Container* install (no Supervisor) on a Raspberry Pi, works for any Docker host.

[Deutsche Anleitung: README.de.md](README.de.md)

```
 daily 00:30                              every 10 min (acts only inside the window, e.g. 03:40-04:30)
 ┌──────────┐  ┌──────────────┐  ┌───────────────┐   ┌──────────────────────────────────────────────┐
 │ registry │→ │ release notes│→ │ sandbox test  │ → │ backup → new image → watch 15 min → keep      │
 │ tags,    │  │ breaking     │  │ baseline vs.  │   │                       └─ unhealthy / web down │
 │ digests  │  │ changes vs.  │  │ candidate on a│   │                          / unavailable ↑ →    │
 │ policy   │  │ used integr. │  │ copy of /config│  │                          ROLLBACK (image+data)│
 └──────────┘  └─────┬────────┘  └──────┬────────┘   └──────────────────────────────────────────────┘
                     └ held + push       └ failed → no update + push
```

## Features

- **Version check** per container: follow the digest of the current tag (`:latest`, `:2`, `:1.8`) or look
  for newer version tags (semver or HA calver). Policy per container and per kind:
  `patch` / `minor` / `major` / `digest` → `auto` · `notify` · `ignore`.
- **Release notes** (Home Assistant, pluggable): blog section *Backward-incompatible changes* plus GitHub
  pull requests labelled `breaking-change`, matched against active config entries, YAML integrations and
  custom components. A hit holds the update back: *"homeassistant 2026.11.0: breaking change affects zha –
  update held back. Details: …"*. Fail-closed: if the notes cannot be read, the update is held too.
- **Sandbox test**: a neutralised copy of the config (incl. the recorder database) runs once with the
  current image (baseline) and once with the new one. Checks: starts and reaches RUNNING, `check_config`
  without new errors, web/API answer, no new ERROR lines in the log, all baseline components loaded, every
  used integration (also the ones disabled in the sandbox) can be imported incl. its requirements.
  Generic tester for other containers (starts, stays up, healthcheck, HTTP) – also with a baseline run; a
  container that cannot run in isolation at all is reported as *inconclusive* (then only the watch and the
  rollback protect it; `test.require_conclusive: true` turns that into a failure).
- **Isolation that is proven on every run** (see below) – the test container can never switch a device.
- **Real update** only after a passed test of exactly that digest, inside the window, not while somebody
  is at home and active (Home Assistant presence; falls back to the fixed window if HA cannot be asked).
- **Backup before every update** (config + volumes, container stopped = consistent), kept image, compose
  file copy. **Rollback** to the previous digest *and* data if the container is not healthy, the web UI
  does not answer, or the share of unavailable entities rises by more than a threshold.
- **History** (SQLite), CLI, **Home Assistant sensors** via REST API, **push notifications** via any
  `notify.*` service, **Prometheus metrics** (node-exporter textfile collector), a Grafana dashboard and a
  static **status page** (containers, held updates with links, tests, isolation proof, history; `status.json`).
- **Self-monitoring**: failed runs, unreachable registries/release notes, stale checks → message.

## Isolation (safety-critical)

The test container must never reach a real device. Five independent layers:

1. Only member of an **internal Docker network** (`--internal`: no gateway, no route). DNS is pointed into
   nothing (`--dns 0.0.0.0`).
2. The only other member is an **egress proxy** (tinyproxy) that allows HTTPS `CONNECT` to an allow-list
   (PyPI and the Home Assistant wheels – needed to install integration requirements). Requests to IP
   addresses or other hosts get `403`.
3. **iptables**: the proxy's outbound bridge may not reach private/link-local ranges (`DOCKER-USER`), no
   sandbox bridge may open new connections to the host (`INPUT`). Rules exist only during a test.
4. **Container hardening**: no published ports, no devices, `--cap-drop ALL`, `no-new-privileges`,
   memory/CPU/PID limits.
5. **In the copy**: every config entry outside a harmless allow-list is disabled (ZHA, Tuya, TP-Link,
   Sonos, MQTT, mobile_app, …), `shell_command`/`wake_on_lan`/`notify`/… are removed, all automations get
   `initial_state: false`, `.ssh` and backups are never copied.

Before every test a probe container tries to reach the router, the host, your devices (configurable) and
the internet – directly and through the proxy – with **positive controls** (the proxy itself and PyPI via
the proxy must work, so a broken probe cannot fake a pass). Any reachable target aborts the test. The
real test container repeats the connect attempts from inside. Everything is labelled and removed after
the run, after an abort (SIGTERM) and at the start of the next run (crash, power loss).
`update-airlock isolation-proof` shows the proof on demand.

## Installation

Requirements: Linux with systemd, Docker with the compose plugin, Python ≥ 3.11 with `python3-yaml` and
`python3-requests` (Debian packages), `tar`, `zstd`, `iptables`. Root is required (Docker, iptables, backups).

```bash
git clone https://github.com/Zedas030/update-airlock.git
cd update-airlock
sudo ./scripts/install.sh
sudoedit /etc/update-airlock/config.yaml     # containers, policies, window, notify service
sudoedit /etc/update-airlock/.env            # HA_TOKEN (see Secrets)
sudo update-airlock validate
sudo update-airlock isolation-proof          # must say "passed": true
sudo update-airlock check --no-test          # first look
sudo ./scripts/install.sh --enable           # start the timers
```

Status page: `sudo ./scripts/install.sh --nginx` installs an nginx site on port **8100** serving
`/var/www/update-airlock` (read-only, GET only; edit `web/nginx-update-airlock.conf` for another port or
web server). `ui.home_url` in the config adds a button back to your dashboard.

Optional: add `ha/automation_dead_mans_switch.yaml` to Home Assistant (alert when no check for 36 h)
and import `grafana/update-airlock-dashboard.json` into Grafana. The metrics land in
`/var/lib/prometheus/node-exporter/update_airlock.prom`; node-exporter must run with its textfile collector
(Debian's `prometheus-node-exporter` does by default) – no new scrape job is needed.

Why systemd and not a container: the tool needs root on the host anyway (Docker socket, iptables rules for
the sandbox, root-owned data directories, re-creating other containers). A container with the Docker
socket would be root-equivalent as well, but could not manage host firewall rules cleanly. The units are
hardened (`ProtectSystem=full`, `NoNewPrivileges`, …) and limited (`MemoryMax=512M`, `CPUQuota=50%`); the
sandbox containers have their own limits.

## Secrets

All secrets live in **`/etc/update-airlock/.env`** (root, mode 600), never in `config.yaml`:

| Variable | What | How to create / rotate |
|---|---|---|
| `HA_TOKEN` | Home Assistant long-lived access token (notifications, sensors, presence, checks) | HA → profile → Security → *Long-lived access tokens* → create; paste it; delete the old one in HA |
| `GITHUB_TOKEN` | optional, higher GitHub API limit for the HA release notes | github.com → Settings → Developer settings → token without scopes |
| any name | private registry credentials `user:token`, referenced in `check.registry_credentials` | at your registry |

Every run reads the file again – no restart needed after a change. Template: `config/env.example`.

## Operation

| Command | What it does |
|---|---|
| `update-airlock status` | state of every container, held updates with the matching breaking changes |
| `update-airlock check [name] [--no-test]` | look for updates now (and test candidates) |
| `update-airlock test <name> [--image REF] [--fault broken-config\|crash-after-start]` | sandbox test now |
| `update-airlock update <name> [--force] [--fault unhealthy]` | real update now (tests first if needed, ignores the window) |
| `update-airlock rollback <name>` | back to the state before the last successful update (image + data) |
| `update-airlock ack <name> <version>` | accept the breaking changes of a version → it may be installed |
| `update-airlock history [name]` | versions, tests, updates, rollbacks |
| `update-airlock isolation-proof` | build the sandbox, prove the isolation, tear down |
| `update-airlock cleanup` | remove sandbox leftovers |
| `update-airlock notify-test` | test the notification path |

Timers: `update-airlock-check.timer` (daily 00:30) and `update-airlock-apply.timer` (every 10 min; acts
only inside the window and re-publishes the HA sensors after an HA restart). Logs: `journalctl -u
update-airlock-check -u update-airlock-apply` and `/var/log/update-airlock/` (rotated weekly). Test reports
(JSON): `/var/lib/update-airlock/reports/`. Backups: `/var/backups/update-airlock/<container>/`.

**Home Assistant sensors:** `sensor.update_airlock` (`ok` / `update_pending` / `attention` / `error`,
attributes `last_check`, `containers`, `isolation_ok`) and `sensor.update_airlock_<container>`
(state = status, attributes installed/available version, policy, held reason, last test/update/rollback).

**A held update** (breaking change): read the linked notes, adapt your setup if needed, then
`update-airlock ack homeassistant 2026.11.0` – the next night installs it (test first), or
`update-airlock update homeassistant` installs it now.

## Adding a container

Add an entry under `containers:` in `config.yaml` (the key is the Docker container name):

```yaml
  my-app:
    tester: generic                 # or homeassistant / none
    policy: {patch: auto, minor: notify, major: notify, digest: auto}
    track: tag                      # tag = follow the digest of the current tag; semver = newer version tags
    health: {http_url: "http://127.0.0.1:8080/health"}   # checked after a real update
    test: {http_port: 8080, http_path: /health}          # checked in the sandbox (container port)
```

Then `update-airlock validate` and `update-airlock test my-app`. Compose-managed containers are found via
their compose labels; the image line of the service is pinned to `repo:tag@sha256:…` on update (the file
must not use a variable for the image). Other containers are re-created from their own `docker inspect`
data (like Watchtower). Containers not listed are never touched. For devices on your network add them to
`sandbox.must_be_unreachable`.

## Moving to another host

Everything host-specific is in the config: copy the repository, run `install.sh`, copy
`/etc/update-airlock/config.yaml` and `.env`, adjust `homeassistant.url` and the device list in
`sandbox.must_be_unreachable`, run `isolation-proof`. History and backups can be copied from
`/var/lib/update-airlock` and `/var/backups/update-airlock` but are not required.

## Updating the tool

```bash
cd update-airlock && git pull && sudo ./scripts/install.sh
```

`config.yaml` and `.env` are kept. Run `update-airlock validate` afterwards.

## Uninstall

```bash
sudo /opt/update-airlock/app/scripts/uninstall.sh            # keeps config, history, backups
sudo /opt/update-airlock/app/scripts/uninstall.sh --purge    # removes everything incl. backups
```

Updated containers keep running with their pinned image. Remove the HA automation and dashboard cards
yourself.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `another update-airlock run is active` | a check/test is still running (`systemctl status update-airlock-check`); the 10-minute apply run skips quietly |
| update stays `held` with `notes_unavailable` | GitHub/blog unreachable or rate limit → set `GITHUB_TOKEN`; it clears on the next successful check |
| `isolation proof failed` | something can be reached from the sandbox → `update-airlock isolation-proof` lists the target; check Docker/iptables changes; no test runs until it passes |
| test fails with *new errors in the log* | open the JSON report (`reports/`); harmless sandbox noise can be ignored with `test.ignore_error_patterns` |
| test fails *integrations can be loaded* | a custom component is not compatible with the new version → update it first, or wait |
| `baseline does not start in the sandbox` | the current version itself cannot start from the copy (e.g. not enough RAM: `sandbox.memory`) |
| no notifications | `update-airlock notify-test`; check `HA_TOKEN` and `homeassistant.notify_service` |
| sensors missing in HA after a restart | they come back within 10 min (apply timer); `update-airlock publish` does it now |
| leftovers after a power loss | removed automatically by the next run; `update-airlock cleanup` does it now |
| rollback failed (push "ROLLBACK FAILED") | backups are in `/var/backups/update-airlock/<name>/<time>/` (`mount*.tar.zst`, `compose*.yml`, `inspect.json`); files the new version created were moved to `/var/lib/update-airlock/quarantine/` |

## Development

```bash
python3 -m pytest -q tests/unit                 # unit tests (no Docker needed except the tar roundtrip)
sudo python3 tests/e2e/e2e.py --generic <name that runs in the sandbox> [--ha homeassistant]   # real host, non-destructive
```

## License

MIT
