"""Command line: update-airlock status | check | test | update | rollback | ack | history | ..."""

from __future__ import annotations

import argparse
import json
import logging
import logging.handlers
import signal
import sys
from pathlib import Path

from . import __version__
from .config import load_config
from .util import AirlockError, short_digest

log = logging.getLogger("update_airlock")

FAULTS_TEST = ("broken-config", "crash-after-start")
FAULTS_UPDATE = ("unhealthy",)


def setup_logging(cfg, verbose: bool) -> None:
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S")
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    root.addHandler(sh)
    lf = cfg.general.get("log_file") if cfg else None
    if lf:
        try:
            Path(lf).parent.mkdir(parents=True, exist_ok=True)
            fh = logging.handlers.WatchedFileHandler(lf, encoding="utf-8")  # rotated by logrotate
            fh.setFormatter(fmt)
            root.addHandler(fh)
        except OSError:
            pass
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def _term(signum, frame):
    # Turn SIGTERM (systemctl stop, timeout) into an exception so every `finally` cleans up the sandbox.
    raise SystemExit(f"terminated by signal {signum}")


def container(app, name: str):
    c = app.cfg.containers.get(name)
    if not c:
        raise AirlockError(f"{name} is not configured (containers: {', '.join(app.cfg.containers)})")
    return c


def print_status(app) -> None:
    state, cs = app.overall()
    g = app.global_state()
    print(f"overall: {state}")
    lr = g.get("last_run") or {}
    import datetime as dt
    for k, v in sorted(lr.items()):
        print(f"  last {k}: {dt.datetime.fromtimestamp(v):%Y-%m-%d %H:%M}  ({'ok' if (g.get('last_ok') or {}).get(k) else 'ERROR'})")
    if g.get("failures"):
        bad = {k: v for k, v in g["failures"].items() if v}
        if bad:
            print(f"  source failures: {bad}")
    print(f"  isolation proof: {'ok' if g.get('isolation_ok') else 'not passed / not run yet'}")
    print()
    print(f"{'container':28} {'status':13} {'installed':22} {'available':22} {'kind':7} {'policy':7} last test")
    for n, s in cs.items():
        lt = s.get("last_test") or {}
        lts = "-" if not lt else f"{'passed' if lt.get('passed') else 'FAILED'} {str(lt.get('finished', ''))[:16]}"
        print(f"{n:28} {str(s.get('status', '-')):13} {str(s.get('current_version') or '-')[:22]:22} "
              f"{str(s.get('available_version') or '-')[:22]:22} {str(s.get('kind') or '-'):7} "
              f"{str(s.get('policy') or '-'):7} {lts}")
        if s.get("status") == "held":
            print(f"{'':28} held: {s.get('held_reason')} {', '.join(s.get('held_domains') or [])} {s.get('error') or ''}")
            for a in ((s.get("notes") or {}).get("affected") or [])[:6]:
                print(f"{'':30}- {a['release']} [{', '.join(a['domains'])}] {a['title'][:60]} {a['url']}")
        if s.get("status") == "error":
            print(f"{'':28} error: {s.get('error')}")


def print_test(res) -> None:
    print(f"TEST {res.container} {res.candidate}")
    print(f"  result: {'PASSED' if res.passed else 'FAILED'} in {res.duration_s:.0f}s" + (f" - {res.error}" if res.error else ""))
    if res.inconclusive and res.passed:
        print(f"  NOTE: inconclusive - {res.inconclusive}; only the watch + rollback after a real update protect it")
    for ch in res.checks:
        first = (ch.detail or "").splitlines()
        print(f"  [{'ok' if ch.ok else 'FAIL'}] {ch.name}: {first[0][:150] if first else ''}")
        for extra in first[1:6]:
            print(f"         {extra[:150]}")
    probe = (res.isolation or {}).get("probe") or {}
    if probe:
        bad = [c for c in probe.get("checks", []) if not c.get("ok")]
        print(f"  isolation proof: {'passed' if probe.get('passed') else 'FAILED'} "
              f"({len(probe.get('checks', []))} checks{', failing: ' + str(bad) if bad else ''})")
    cl = (res.isolation or {}).get("cleanup")
    if cl:
        print(f"  cleanup: leftover containers {cl.get('leftover_containers_removed')}, "
              f"firewall rules left: {cl.get('firewall_rules_left')}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="update-airlock", description="Tested container updates with automatic rollback")
    p.add_argument("-c", "--config", help="config file (default /etc/update-airlock/config.yaml)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"update-airlock {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="show the current state of all containers")
    sp = sub.add_parser("check", help="look for new versions, read release notes, test candidates")
    sp.add_argument("container", nargs="?")
    sp.add_argument("--no-test", action="store_true", help="only check, do not run sandbox tests")
    sp.add_argument("--simulate-breaking", action="append", metavar="DOMAIN",
                    help="inject a fake breaking change for DOMAIN (acceptance test)")
    sp = sub.add_parser("test", help="run the sandbox test for a container now")
    sp.add_argument("container")
    sp.add_argument("--image", help="test this image reference instead of the found candidate")
    sp.add_argument("--fault", action="append", choices=FAULTS_TEST, help="inject a fault into the test (acceptance)")
    sp = sub.add_parser("update", help="update a container now (tests first if needed)")
    sp.add_argument("container")
    sp.add_argument("--force", action="store_true", help="also if held back by a breaking change")
    sp.add_argument("--fault", action="append", choices=FAULTS_UPDATE,
                    help="simulate a failure after the update (acceptance: must roll back)")
    sp = sub.add_parser("rollback", help="go back to the state before the last update")
    sp.add_argument("container")
    sp = sub.add_parser("ack", help="accept the breaking changes of a version (it may then be installed)")
    sp.add_argument("container")
    sp.add_argument("version")
    sp = sub.add_parser("history", help="show the history")
    sp.add_argument("container", nargs="?")
    sp.add_argument("-n", type=int, default=30)
    sp.add_argument("--json", action="store_true")
    sub.add_parser("apply", help="(timer) install ready updates if inside the maintenance window")
    sub.add_parser("publish", help="push HA sensors and Prometheus metrics again")
    sub.add_parser("cleanup", help="remove sandbox leftovers (containers, networks, firewall rules)")
    sub.add_parser("isolation-proof", help="build the sandbox, prove the isolation, tear it down")
    sub.add_parser("notify-test", help="send a test notification")
    sp = sub.add_parser("unit-failed", help="(systemd OnFailure) report a failed unit")
    sp.add_argument("unit")
    sub.add_parser("validate", help="validate the config file")
    args = p.parse_args(argv)

    cfg = None
    try:
        cfg = load_config(Path(args.config) if args.config else None)
    except AirlockError as e:
        setup_logging(None, args.verbose)
        log.error("%s", e)
        return 2
    setup_logging(cfg, args.verbose)
    signal.signal(signal.SIGTERM, _term)
    if args.cmd == "validate":
        print(f"config OK: {len(cfg.containers)} containers")
        return 0
    from .runner import Airlock
    app = Airlock(cfg)
    try:
        if args.cmd == "status":
            print_status(app)
        elif args.cmd == "history":
            evs = app.hist.events(args.container, args.n)
            if args.json:
                print(json.dumps(evs, indent=1, ensure_ascii=False, default=str))
            for e in reversed(evs) if not args.json else []:
                ver = f"{e['from_version'] or ''} -> {e['to_version'] or ''}" if e["from_version"] or e["to_version"] else ""
                print(f"{e['ts'][:19]}  {e['container']:22} {e['action']:9} {e['result']:7} {ver:30} {e['summary'] or ''}"[:220])
        elif args.cmd == "check":
            with app.lock("check"):
                app.check(run_tests=not args.no_test, only=args.container, simulate_breaking=args.simulate_breaking)
            print_status(app)
        elif args.cmd == "test":
            c = container(app, args.container)
            with app.lock("test"):
                res = app.test(c, args.image, args.fault)
            print_test(res)
            return 0 if res.passed else 1
        elif args.cmd == "update":
            c = container(app, args.container)
            with app.lock("update"):
                r = app.update(c, force=args.force, faults=args.fault)
            print(json.dumps({k: v for k, v in r.items() if k != "details"}, indent=1, default=str, ensure_ascii=False))
            return 0 if r["result"] == "updated" else 1
        elif args.cmd == "rollback":
            c = container(app, args.container)
            with app.lock("rollback"):
                r = app.rollback(c)
            print(json.dumps(r, indent=1, default=str))
            return 0 if r["check"]["ok"] else 1
        elif args.cmd == "ack":
            app.ack(container(app, args.container), args.version)
            print(f"{args.container} {args.version}: breaking changes acknowledged")
        elif args.cmd == "apply":
            try:
                with app.lock("apply"):
                    r = app.apply()
            except AirlockError as e:
                if "another update-airlock run" in str(e):
                    log.info("%s", e)
                    return 0
                raise
            if r.get("updated") or r.get("skipped"):
                print(json.dumps(r, indent=1, default=str))
        elif args.cmd == "publish":
            app.publish()
        elif args.cmd == "cleanup":
            from .sandbox import Sandbox
            with app.lock("cleanup"):
                n = Sandbox.cleanup_stale(cfg.sandbox)
                sb = Sandbox(cfg.sandbox, "cleanup", cfg.sandbox_work_dir)
                sb.teardown()
                left = Sandbox.cleanup_work_dirs(cfg.sandbox_work_dir)
            print(f"removed {len(n)} containers, {len(left)} work dirs; networks and firewall rules removed")
        elif args.cmd == "isolation-proof":
            from .sandbox import Sandbox
            from .util import Deadline, ts_compact
            with app.lock("isolation-proof"):
                sb = Sandbox(cfg.sandbox, "proof" + ts_compact()[-4:], cfg.sandbox_work_dir)
                cfg.sandbox_work_dir.mkdir(parents=True, exist_ok=True)
                try:
                    sb.setup(Deadline(900))
                    r = sb.probe(Deadline(180))
                finally:
                    sb.teardown()
            print(json.dumps(r.to_dict(), indent=1))
            app.save_isolation(r.to_dict())
            app.publish()
            return 0 if r.passed else 1
        elif args.cmd == "notify-test":
            from . import i18n
            ok = app.notify("self_check", "notify-test", i18n.t(app.lang, "test_notify"), force=True)
            print("sent" if ok else "NOT sent - see log")
            return 0 if ok else 1
        elif args.cmd == "unit-failed":
            from . import i18n
            app.notify("error", f"unit:{args.unit}", i18n.t(app.lang, "unit_failed", unit=args.unit), force=True)
            app.mark_run(args.unit.split(".")[0].replace("update-airlock-", ""), False)
            app.publish()
        return 0
    except AirlockError as e:
        log.error("%s", e)
        return 1
    finally:
        app.hist.close()


if __name__ == "__main__":
    sys.exit(main())
