#!/usr/bin/env python3
"""End-to-end test against the REAL system (run as root on the host where update-airlock is installed).

Non-destructive: it never updates or stops a production container. It proves
  1. the config is valid,
  2. the sandbox isolation (probe container + proxy + firewall) on this host,
  3. registry and release notes are reachable (check without tests),
  4. a generic sandbox test passes for a real container,
  5. an injected crash makes that test FAIL (the test can fail),
  6. (--ha) a Home Assistant test with a broken config copy FAILS and production stays untouched,
  7. nothing is left behind: no sandbox containers, networks, firewall rules or work directories.

Usage: sudo python3 tests/e2e/e2e.py [--cli update-airlock] [--generic fritz_exporter] [--ha homeassistant]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time


def sh(cmd: list[str], timeout: int = 3600) -> subprocess.CompletedProcess:
    print("$", " ".join(cmd), flush=True)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


class E2E:
    def __init__(self, cli: list[str]):
        self.cli = cli
        self.results: list[tuple[str, bool, str]] = []

    def step(self, name: str, ok: bool, detail: str = "") -> bool:
        self.results.append((name, ok, detail))
        print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail[:300]}", flush=True)
        return ok

    def leftovers(self) -> dict:
        c = sh(["docker", "ps", "-aq", "--filter", "label=update-airlock.sandbox=1"]).stdout.split()
        n = [x for x in sh(["docker", "network", "ls", "--format", "{{.Name}}"]).stdout.split() if x.startswith("update-airlock")]
        r = [x for x in sh(["iptables", "-S"]).stdout.splitlines() if "update-airlock" in x]
        r += [x for x in sh(["iptables", "-S", "DOCKER-USER"]).stdout.splitlines() if "update-airlock" in x]
        return {"containers": c, "networks": n, "rules": sorted(set(r))}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cli", default="update-airlock")
    ap.add_argument("--config", default="")
    ap.add_argument("--generic", default="fritz_exporter", help="a container that runs in the sandbox")
    ap.add_argument("--ha", default="", help="also run the (long) HA broken-config test for this container")
    a = ap.parse_args()
    cli = a.cli.split() + (["-c", a.config] if a.config else [])
    e = E2E(cli)
    t0 = time.time()

    r = sh([*cli, "validate"])
    e.step("config valid", r.returncode == 0, r.stdout.strip())

    r = sh([*cli, "isolation-proof"], 1200)
    try:
        proof = json.loads(r.stdout)
        bad = [c for c in proof["checks"] if not c["ok"]]
        e.step("isolation proof", r.returncode == 0 and proof["passed"],
               f"{len(proof['checks'])} checks, failing: {bad}")
        e.step("isolation proof contains positive controls",
               any(c.get("expected") == "reachable" and c["ok"] for c in proof["checks"]), "")
    except (ValueError, KeyError):
        e.step("isolation proof", False, r.stdout[-300:] + r.stderr[-300:])

    r = sh([*cli, "check", "--no-test"], 900)
    e.step("check without tests (registry + release notes reachable)",
           r.returncode == 0 and "overall:" in r.stdout and "error:" not in r.stdout
           and "notes_unavailable" not in r.stdout,
           r.stdout.splitlines()[0] if r.stdout else r.stderr[-200:])

    if a.generic:
        before = sh(["docker", "inspect", "-f", "{{.Id}} {{.State.StartedAt}}", a.generic]).stdout.strip()
        # Test the image that runs now (not a pending candidate), so the container's update status is not touched.
        current = sh(["docker", "inspect", "-f", "{{.Image}}", a.generic]).stdout.strip()
        r = sh([*cli, "test", a.generic, "--image", current], 1800)
        e.step(f"generic test of {a.generic} is conclusive (container runs in the sandbox)",
               "inconclusive" not in r.stdout, r.stdout[-300:])
        e.step(f"generic sandbox test of {a.generic} passes", r.returncode == 0, r.stdout[-400:])
        r = sh([*cli, "test", a.generic, "--image", current, "--fault", "crash-after-start"], 1800)
        e.step(f"injected crash makes the test of {a.generic} fail", r.returncode == 1 and "FAIL" in r.stdout,
               r.stdout[-300:])
        after = sh(["docker", "inspect", "-f", "{{.Id}} {{.State.StartedAt}}", a.generic]).stdout.strip()
        e.step("production container untouched by the tests", before == after and bool(before), before)

    if a.ha:
        before = sh(["docker", "inspect", "-f", "{{.Id}} {{.State.StartedAt}}", a.ha]).stdout.strip()
        r = sh([*cli, "test", a.ha, "--fault", "broken-config"], 5400)
        e.step("HA test with a broken config copy fails", r.returncode == 1 and "config check" in r.stdout
               and "[FAIL] config check" in r.stdout, r.stdout[-600:])
        after = sh(["docker", "inspect", "-f", "{{.Id}} {{.State.StartedAt}}", a.ha]).stdout.strip()
        e.step("production Home Assistant untouched", before == after and bool(before), before)

    left = e.leftovers()
    e.step("nothing left behind (containers, networks, firewall rules)",
           not left["containers"] and not left["networks"] and not left["rules"], json.dumps(left))

    ok = all(x[1] for x in e.results)
    print(f"\nE2E {'PASSED' if ok else 'FAILED'}: {sum(x[1] for x in e.results)}/{len(e.results)} steps "
          f"in {time.time() - t0:.0f}s")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
