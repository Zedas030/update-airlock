"""Orchestration: check -> release notes -> sandbox test -> update in the window -> observe -> rollback."""

from __future__ import annotations

import datetime as dt
import fcntl
import json
import logging
import os
import re
import time
from contextlib import contextmanager
from pathlib import Path

from . import deploy, dockerapi, i18n, metrics
from .config import Config, ContainerConfig
from .ha import HAClient, unavailable_share
from .history import History
from .inventory import Current, read_current
from .notes import BreakingChange, get_provider
from .observe import observe
from .registry import ImageRef, Registry
from .sandbox import Sandbox
from .testers import TestResult, get_tester
from .util import AirlockError, Deadline, now, now_iso, short_digest, ts_compact
from .versions import Version, biggest, candidates, classify, pick
from .window import busy_units, in_window, presence

log = logging.getLogger("update_airlock")


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9_]", "_", name.lower())


class Airlock:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.lang = cfg.general["language"]
        cfg.state_dir.mkdir(parents=True, exist_ok=True)
        self.hist = History(cfg.state_dir / "history.db")
        h = cfg.ha
        self.ha = HAClient(h["url"], h["token"], h["timeout_seconds"], h["verify_tls"])
        self.registry = Registry(timeout=cfg["check"]["http_timeout_seconds"],
                                 credentials=cfg["check"].get("registry_credentials") or {})

    # ---------- locking ----------
    @contextmanager
    def lock(self, what: str, wait: bool = False):
        path = Path(self.cfg.general["lock_file"])
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            flags = fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB)
            try:
                fcntl.flock(fd, flags)
            except BlockingIOError as e:
                raise AirlockError(f"another update-airlock run is active ({what} not started)") from e
            os.ftruncate(fd, 0)
            os.write(fd, f"{os.getpid()} {what} {now_iso()}\n".encode())
            yield
        finally:
            os.close(fd)

    # ---------- state ----------
    def status_of(self, name: str) -> dict:
        return self.hist.get(f"status:{name}", {}) or {}

    def set_status(self, name: str, st: dict) -> None:
        st["updated"] = now_iso()
        self.hist.put(f"status:{name}", st)

    def global_state(self) -> dict:
        return self.hist.get("global", {}) or {}

    def mark_run(self, kind: str, ok: bool) -> None:
        g = self.global_state()
        g.setdefault("last_run", {})[kind] = int(time.time())
        g.setdefault("last_ok", {})[kind] = bool(ok)
        self.hist.put("global", g)

    def source_result(self, source: str, ok: bool, error: str = "") -> None:
        """Self-monitoring: count consecutive failures of a source and alert after N."""
        g = self.global_state()
        fails = g.setdefault("failures", {})
        if ok:
            if fails.get(source):
                log.info("source %s works again", source)
            fails[source] = 0
        else:
            fails[source] = fails.get(source, 0) + 1
            n = fails[source]
            if n >= int(self.cfg["check"]["failures_before_alert"]):
                self.notify("self_check", f"self:{source}",
                            i18n.t(self.lang, "self_check", what=source, n=n, error=error))
        self.hist.put("global", g)

    # ---------- notifications ----------
    def notify(self, event: str, dedupe_key: str, message: str, force: bool = False) -> bool:
        log.info("notify [%s] %s", event, message)
        if event not in self.cfg["notifications"]["events"] and not force:
            return False
        sent = self.hist.get("sent", {}) or {}
        key = f"{event}:{dedupe_key}"
        last = sent.get(key)
        n = self.cfg["notifications"]
        rep = float((n.get("repeat_after_hours_by_event") or {}).get(event, n["repeat_after_hours"])) * 3600
        if not force and last and time.time() - last["ts"] < rep and last.get("msg") == message:
            log.info("notification suppressed (sent %.1f h ago)", (time.time() - last["ts"]) / 3600)
            return False
        try:
            self.ha.notify(self.cfg.ha["notify_service"], i18n.t(self.lang, "title"), message)
        except AirlockError as e:
            log.error("notification could not be sent: %s", e)
            return False
        sent[key] = {"ts": time.time(), "msg": message}
        self.hist.put("sent", sent)
        return True

    # ---------- check one container ----------
    def ack_for(self, name: str) -> str | None:
        return self.hist.get(f"ack:{name}")

    def evaluate(self, c: ContainerConfig, simulate_breaking: list[str] | None = None) -> dict:
        """Find out what is available and what the policy says. Never changes anything."""
        st: dict = {"container": c.name, "checked": now_iso()}
        if not c.enabled or all(v == "ignore" for v in c.policy.values()):
            st["status"] = "ignored"
            return st
        cur = read_current(c.name, c.compose_file)
        # semver tracking compares tags, so the tag is the version; otherwise the image label is more telling
        shown = cur.tag if c.track == "semver" else (cur.version or cur.tag)
        st.update(current_ref=cur.image_ref, current_digest=cur.digest, current_tag=cur.tag,
                  current_version=shown, managed_by="compose" if cur.compose else "docker run")
        ref = cur.ref
        host = ref.registry
        try:
            cand_tag, kind, cand_digest, new_version = None, None, None, None
            if c.track == "semver":
                if Version.parse(cur.tag) is None:
                    raise AirlockError(f"track: semver needs a version tag, {c.name} runs '{cur.tag}'")
                tags = self.registry.tags(ref)
                cands = candidates(cur.tag, tags, c.tag_pattern, c.versioning)
                st["candidates"] = cands
                kind, cand_tag = pick(cands, c.policy)
                if not cand_tag:
                    kind, cand_tag = biggest(cands)
                if cand_tag:
                    cand_digest = self.registry.digest(ref, cand_tag)
                    new_version = cand_tag
            else:
                remote = self.registry.digest(ref, cur.tag)
                if cur.digest and remote != cur.digest:
                    cand_tag, cand_digest, kind = cur.tag, remote, "digest"
                    info = self.registry.platform_info(ref, remote)
                    nv = info["labels"].get("org.opencontainers.image.version")
                    new_version = nv or f"{cur.tag}@{short_digest(remote)}"
                    vo, vn = Version.parse(cur.version), Version.parse(nv)
                    if vo and vn:
                        kind = classify(vo, vn, c.versioning) or "digest"
                elif not cur.digest:
                    raise AirlockError(f"{c.name}: digest of the running image unknown (locally built?)")
            self.source_result(f"registry {host}", True)
        except AirlockError as e:
            self.source_result(f"registry {host}", False, str(e))
            st.update(status="error", error=str(e))
            return st
        if not cand_tag:
            st.update(status="up_to_date", available_version=None, kind=None)
            return st
        platform_ok = True
        try:
            platform_ok = self.registry.platform_info(ref, cand_digest)["available"]
        except AirlockError as e:
            log.warning("platform check failed: %s", e)
        cand_ref = ref.with_tag_digest(cand_tag, cand_digest)
        pol = c.policy_for(kind)
        st.update(available_version=new_version, available_tag=cand_tag, candidate_ref=cand_ref,
                  candidate_digest=cand_digest, kind=kind, policy=pol)
        if not platform_ok:
            st.update(status="error", error=f"{cand_ref} has no image for this platform")
            return st
        if pol == "ignore":
            st["status"] = "ignored"
            return st
        # ---- release notes ----
        provider = None
        if c.notes and c.breaking_changes != "ignore":
            provider = self.notes_provider(c, cur)
        if provider:
            try:
                extra = [BreakingChange(title=f"SIMULATED breaking change ({d})", domains=[d], release=new_version,
                                        url="(simulation)", summary="injected with --simulate-breaking",
                                        sources=["simulation"], key=f"sim-{d}") for d in (simulate_breaking or [])]
                old_v = cur.tag if c.track == "semver" else (cur.version or cur.tag)
                nr = provider.evaluate(old_v, cand_tag, extra)
                self.source_result(f"release notes {provider.name}", True)
                st["notes"] = {"releases": nr.releases, "total": len(nr.changes),
                               "affected": [x.to_dict() for x in nr.affected], "affected_domains": nr.affected_domains,
                               "core": [x.to_dict() for x in nr.core][:10]}
                hold = bool(nr.affected) or (c.hold_on_core_changes and bool(nr.core))
                acked = self.ack_for(c.name) == cand_tag and not simulate_breaking
                if hold and c.breaking_changes == "hold" and not acked:
                    st.update(status="held", held_reason="breaking_change",
                              held_domains=nr.affected_domains)
                    return st
                if hold and acked:
                    st["acknowledged"] = True
            except AirlockError as e:
                self.source_result(f"release notes {provider.name}", False, str(e))
                st.update(status="held", held_reason="notes_unavailable", error=str(e))
                return st
        if pol == "notify" and self.ack_for(c.name) != cand_tag:
            st["status"] = "notify_only"
            return st
        st["status"] = "candidate"
        return st

    def notes_provider(self, c: ContainerConfig, cur: Current):
        kw = {}
        if c.notes == "homeassistant":
            cfgdir = (c.raw.get("test") or {}).get("config_dir") or next(
                (m.host_path for m in cur.mounts if m.target == "/config"), None)
            kw = {"config_dir": Path(cfgdir) if cfgdir else None, "cache_dir": self.cfg.state_dir / "notes-cache",
                  "timeout": self.cfg["check"]["http_timeout_seconds"],
                  "github_token": self.cfg["check"].get("github_token", ""),
                  "match_disabled": bool((c.raw.get("notes_options") or {}).get("match_disabled", False))}
        return get_provider(c.notes, **kw)

    def _announce(self, c: ContainerConfig, st: dict, prev: dict) -> None:
        name, to = c.name, st.get("available_version")
        if st["status"] == "held":
            if st.get("held_reason") == "notes_unavailable":
                self.notify("held", f"{name}:{to}:notes", i18n.t(self.lang, "notes_unavailable", name=name, to=to,
                                                                    error=st.get("error")))
            else:
                aff = (st.get("notes") or {}).get("affected") or []
                details = " | ".join(f"{x['title']}: {x['url']}" for x in aff[:4])
                self.notify("held", f"{name}:{to}", i18n.t(self.lang, "held", name=name, to=to,
                                                            domains=", ".join(st.get("held_domains") or []),
                                                            details=details))
            if prev.get("status") != "held" or prev.get("available_version") != to:
                self.hist.add(name, "held", "held", f"{to}: {st.get('held_reason')} {st.get('held_domains', '')}",
                              st.get("notes") or {"error": st.get("error")}, from_version=st.get("current_version"),
                              to_version=to, from_digest=st.get("current_digest"), to_digest=st.get("candidate_digest"))
        elif st["status"] == "notify_only":
            self.notify("manual_update_available", f"{name}:{to}",
                        i18n.t(self.lang, "manual_update_available", name=name, frm=st.get("current_version"), to=to,
                               kind=st.get("kind")))
        elif st["status"] == "error":
            self.notify("error", f"{name}:error", i18n.t(self.lang, "error", error=f"{name}: {st.get('error')}"))

    # ---------- test ----------
    def last_test(self, name: str, digest: str) -> dict | None:
        return self.hist.get(f"test:{name}:{digest}")

    def test_fresh(self, name: str, digest: str) -> bool:
        t = self.last_test(name, digest)
        if not t or not t.get("passed"):
            return False
        age = (now() - dt.datetime.fromisoformat(t["finished"])).total_seconds() / 3600
        return age <= float(self.cfg.general["test_valid_hours"])

    def test(self, c: ContainerConfig, candidate_ref: str | None = None, faults: list[str] | None = None) -> TestResult:
        cur = read_current(c.name, c.compose_file)
        if not candidate_ref:
            st = self.status_of(c.name)
            candidate_ref = st.get("candidate_ref") or ImageRef.parse(cur.image_ref).with_tag_digest(cur.tag, cur.digest)
        tester_cls = get_tester(c.tester)
        if tester_cls is None:
            raise AirlockError(f"{c.name}: tester 'none' - cannot test")
        if busy := busy_units(self.cfg.general["pause_while_active"]):
            raise AirlockError(f"paused: {', '.join(busy)} is running")
        run_id = ts_compact().replace("-", "")[-10:]
        work_root = self.cfg.sandbox_work_dir
        work_root.mkdir(parents=True, exist_ok=True)
        os.chmod(work_root, 0o700)
        stale = Sandbox.cleanup_work_dirs(work_root)  # we hold the lock: nothing else uses them
        if stale:
            log.info("removed work dirs of interrupted runs: %s", ", ".join(stale))
        sb = Sandbox(self.cfg.sandbox, run_id, work_root)
        digest = candidate_ref.split("@")[-1]
        res = TestResult(container=c.name, candidate=candidate_ref, digest=digest, faults=list(faults or []))
        log.info("TEST %s with %s (faults: %s)", c.name, candidate_ref, faults or "-")
        try:
            if not dockerapi.image_present(candidate_ref):
                log.info("pulling %s", candidate_ref)
                dockerapi.pull(candidate_ref)
            sb.setup(Deadline(900))
            iso = sb.probe(Deadline(180))
            self.save_isolation(iso.to_dict())
            if not iso.passed:
                res.isolation = {"probe": iso.to_dict()}
                res.error = f"sandbox isolation proof failed - test aborted ({iso.error})"
                self.notify("error", "isolation", i18n.t(self.lang, "isolation_failed", error=iso.error or
                            ", ".join(x["target"] for x in iso.checks if not x["ok"])), force=True)
                return res.finish()
            work = work_root / f"run-{run_id}"
            kw = {}
            if c.tester == "homeassistant":
                prov = self.notes_provider(c, cur) if c.notes == "homeassistant" else None
                kw["used_domains"] = sorted(prov.used_domains() | set(prov.usage()["disabled"])) if prov else []
            tester = tester_cls(self.cfg, c, cur, candidate_ref, sb, work, faults=faults, **kw)
            res = tester.run()
            res.isolation["probe"] = iso.to_dict()
        except AirlockError as e:
            res.error = str(e)
            res.finish()
        finally:
            sb.teardown()
            leftovers = Sandbox.cleanup_stale(self.cfg.sandbox)
            res.isolation["cleanup"] = {"leftover_containers_removed": len(leftovers),
                                        "firewall_rules_left": sb.firewall_present()}
        if not res.finished:
            res.finish()
        self.record_test(c, res)
        return res

    def record_test(self, c: ContainerConfig, res: TestResult) -> None:
        d = res.to_dict()
        self.hist.put(f"test:{c.name}:{res.digest}", d)
        reports = self.cfg.state_dir / "reports"
        reports.mkdir(parents=True, exist_ok=True)
        f = reports / f"test-{c.name}-{res.started[:19].replace(':', '')}.json"
        f.write_text(json.dumps(d, indent=1, ensure_ascii=False, default=str), encoding="utf-8")
        failed = "; ".join(f"{x.name}: {x.detail.splitlines()[0][:120] if x.detail else ''}" for x in res.failed_checks)
        summary = "passed" if res.passed else (res.error or failed)
        if res.passed and res.inconclusive:
            summary = f"passed, but not testable in the sandbox: {res.inconclusive}"
        if res.faults:
            summary = f"[fault injection: {', '.join(res.faults)}] {summary}"
        cur_status = self.status_of(c.name)
        self.hist.add(c.name, "test", "ok" if res.passed else "failed", summary[:500],
                      {"report": str(f), "checks": [x.to_dict() for x in res.checks], "error": res.error,
                       "faults": res.faults, "duration_s": res.duration_s},
                      from_version=cur_status.get("current_version"),
                      to_version=(cur_status.get("available_version") if cur_status.get("candidate_digest") == res.digest
                                  else res.candidate.split("@")[0].rsplit(":", 1)[-1]), to_digest=res.digest)
        st = self.status_of(c.name)
        if st.get("candidate_digest") == res.digest or not st:
            st["last_test"] = {"passed": res.passed, "finished": res.finished, "report": str(f), "summary": summary[:300],
                               "inconclusive": res.inconclusive}
            if st.get("status") in ("candidate", "ready", "test_failed"):
                st["status"] = "ready" if res.passed else "test_failed"
            self.set_status(c.name, st)
        if not res.passed:
            ver = res.candidate.split("@")[0].rsplit(":", 1)[-1]
            self.notify("test_failed", f"{c.name}:{res.digest}:{','.join(res.faults)}",
                        i18n.t(self.lang, "test_failed", name=c.name, to=ver, checks=summary[:300]))

    # ---------- daily check ----------
    def check(self, run_tests: bool = True, only: str | None = None, simulate_breaking: list[str] | None = None) -> dict:
        ok = True
        results = {}
        for c in sorted(self.cfg.containers.values(), key=lambda x: (x.priority, x.name)):
            if only and c.name != only:
                continue
            prev = self.status_of(c.name)
            try:
                st = self.evaluate(c, simulate_breaking)
            except AirlockError as e:
                st = {"container": c.name, "status": "error", "error": str(e), "checked": now_iso()}
            if st.get("status") == "error":
                ok = False
            # keep test info if the candidate did not change
            if prev.get("candidate_digest") and prev.get("candidate_digest") == st.get("candidate_digest"):
                st["last_test"] = prev.get("last_test")
            for k in ("last_update", "last_rollback"):
                if prev.get(k):
                    st[k] = prev[k]
            self.set_status(c.name, st)
            self._announce(c, st, prev)
            if st.get("status") == "candidate":
                if self.test_fresh(c.name, st["candidate_digest"]):
                    st["status"] = "ready"
                    self.set_status(c.name, st)
                elif run_tests and c.tester != "none":
                    try:
                        res = self.test(c, st["candidate_ref"])
                        st = self.status_of(c.name)
                        st["status"] = "ready" if res.passed else "test_failed"
                        self.set_status(c.name, st)
                    except AirlockError as e:
                        log.error("test of %s not possible: %s", c.name, e)
                        st["status"], st["error"] = "error", str(e)
                        self.set_status(c.name, st)
                        ok = False
                elif c.tester == "none":
                    st["status"] = "ready"
                    self.set_status(c.name, st)
            results[c.name] = self.status_of(c.name)
        self.mark_run("check", ok)
        self.publish()
        return results

    # ---------- maintenance window ----------
    def may_update_now(self) -> tuple[bool, str]:
        m = self.cfg["maintenance"]
        t = now()
        if not in_window(t, m["window"], m.get("days")):
            return False, f"outside the maintenance window {m['window']}"
        if busy := busy_units(self.cfg.general["pause_while_active"]):
            return False, f"paused while {', '.join(busy)} is running"
        p = presence(self.ha, m["presence"], t)
        if p.known and p.active:
            return False, f"postponed: at home and active ({p.reason})"
        return True, p.reason if m["presence"].get("enabled") else "in the window"

    def apply(self) -> dict:
        """Timer entry (every 10 min): republish sensors; inside the window install ready updates."""
        out = {"updated": [], "skipped": {}}
        self.republish_if_missing()
        ok_now, why = self.may_update_now()
        if not ok_now:
            out["reason"] = why
            if "postponed" in why or "paused" in why:
                log.info(why)
                g = self.global_state()
                g["last_postponed"] = {"ts": now_iso(), "reason": why}
                self.hist.put("global", g)
            return out
        done_tonight = self._updates_tonight()
        limit = int(self.cfg.general["max_updates_per_night"])
        for c in sorted(self.cfg.containers.values(), key=lambda x: (x.priority, x.name)):
            st = self.status_of(c.name)
            if st.get("status") != "ready":
                continue
            if c.policy_for(st.get("kind", "digest")) != "auto" and self.ack_for(c.name) != st.get("available_tag"):
                out["skipped"][c.name] = "policy is not auto"
                continue
            if not self.test_fresh(c.name, st["candidate_digest"]) and c.tester != "none":
                out["skipped"][c.name] = "test too old - next check re-tests"
                continue
            if done_tonight >= limit:
                out["skipped"][c.name] = f"max_updates_per_night ({limit}) reached"
                continue
            ok_now, why = self.may_update_now()
            if not ok_now:
                out["skipped"][c.name] = why
                break
            try:
                r = self.update(c, automatic=True)
                out["updated"].append({c.name: r})
                done_tonight += 1
            except AirlockError as e:
                log.error("update of %s failed: %s", c.name, e)
                out["skipped"][c.name] = str(e)
        not_ready = {n: self.status_of(n).get("status") for n in self.cfg.containers
                     if n not in out["skipped"] and not any(n in u for u in out["updated"])
                     and self.status_of(n).get("status") not in (None, "up_to_date", "ignored")}
        log.info("apply inside the window (%s): updated %s; skipped %s; not ready %s", why,
                 [next(iter(u)) for u in out["updated"]] or "-", out["skipped"] or "-", not_ready or "-")
        out["not_ready"] = not_ready
        self.mark_run("apply", True)
        self.publish()
        return out

    def _updates_tonight(self) -> int:
        since = (now() - dt.timedelta(hours=12)).isoformat(timespec="seconds")
        return sum(1 for e in self.hist.events(action="update", limit=50) if e["ts"] >= since)

    # ---------- real update ----------
    def update(self, c: ContainerConfig, automatic: bool = False, force: bool = False,
               faults: list[str] | None = None) -> dict:
        faults = faults or []
        st = self.evaluate(c)
        prev = self.status_of(c.name)
        for k in ("last_test", "last_update", "last_rollback"):
            if prev.get(k):
                st.setdefault(k, prev[k])
        self.set_status(c.name, st)
        if st["status"] in ("up_to_date", "ignored"):
            raise AirlockError(f"{c.name}: no update available ({st['status']})")
        if st["status"] == "error":
            raise AirlockError(f"{c.name}: {st.get('error')}")
        if st["status"] == "held" and not force:
            raise AirlockError(f"{c.name}: update held back ({st.get('held_reason')}: "
                               f"{', '.join(st.get('held_domains') or [])}). Read the notes, then "
                               f"`update-airlock ack {c.name} {st.get('available_tag')}` or use --force")
        cand = st["candidate_ref"]
        digest = st["candidate_digest"]
        if c.tester != "none" and not self.test_fresh(c.name, digest):
            log.info("no fresh passing test for %s - testing first", cand)
            res = self.test(c, cand)
            if not res.passed:
                raise AirlockError(f"{c.name}: test failed - no update ({res.error or '; '.join(x.name for x in res.failed_checks)})")
        cur = read_current(c.name, c.compose_file)
        skip = c.raw["backup"]["skip_mounts"]
        excl = c.raw["backup"]["exclude"]
        deploy.check_space(self.cfg.backup_dir, deploy.estimate_backup_bytes(cur, skip, excl),
                           float(self.cfg.general["min_free_disk_gb"]))
        if not dockerapi.image_present(cand):
            dockerapi.pull(cand)
        obs_opts = self.cfg.observe_for(c)
        use_ha_unavail = bool(c.raw["health"].get("ha_unavailable"))
        baseline = None
        if use_ha_unavail:
            try:
                baseline, bad, total = unavailable_share(self.ha.states())
                log.info("before the update: %s/%s entities unavailable (%s%%)", bad, total, baseline)
            except AirlockError as e:
                raise AirlockError(f"cannot measure the state before the update ({e}) - not updating") from e
        frm, to = st.get("current_version"), st.get("available_version")
        log.info("UPDATE %s: %s -> %s", c.name, frm, to)
        stamp = ts_compact()
        kept = deploy.keep_image(c.name, cur.image_id, stamp)
        deploy.stop(cur)
        try:
            bs = deploy.take_backup(self.cfg.backup_dir, cur, skip, excl, f"before update to {to}")
        except AirlockError:
            # backup failed: start the old container again, do not update
            if cur.compose:
                from .util import run as _run
                _run([*cur.compose.cmd(), "start", cur.compose.service], check=False, cwd=cur.compose.working_dir or None)
            else:
                from .util import run as _run
                _run(["docker", "start", cur.name], check=False)
            raise
        details = {"backup": str(bs.path), "kept_image": kept, "baseline_unavailable": baseline,
                   "candidate": cand, "automatic": automatic, "faults": faults}
        try:
            apply_info = deploy.apply_image(cur, cand, bs)
        except AirlockError as e:
            return self._rollback_after(c, cur, bs, None, st, f"start with the new image failed: {e}", details)
        details["apply"] = apply_info
        is_ha = c.tester == "homeassistant" or use_ha_unavail
        obs = observe(c.name, obs_opts, self.ha if is_ha else None, c.raw["health"].get("http_url", ""),
                      self.ha if use_ha_unavail else None, baseline, faults)
        details["observation"] = obs.to_dict()
        if not obs.ok:
            return self._rollback_after(c, cur, bs, apply_info, st, obs.reason, details)
        deploy.finalize(c.name, apply_info)
        deploy.prune_backups(self.cfg.backup_dir, c.name, int(self.cfg.general["keep_backups"]))
        deploy.prune_kept_images(c.name, int(self.cfg.general["keep_backups"]))
        self.hist.add(c.name, "update", "ok", f"{frm} -> {to}", details, from_version=frm, to_version=to,
                      from_digest=cur.digest, to_digest=digest)
        new = self.evaluate(c)
        new["last_update"] = {"ts": now_iso(), "from": frm, "to": to, "unix": int(time.time())}
        new["last_test"] = st.get("last_test")
        self.set_status(c.name, new)
        if self.ack_for(c.name):
            self.hist.delete(f"ack:{c.name}")
        self.notify("updated", f"{c.name}:{to}", i18n.t(self.lang, "updated", name=c.name, frm=frm, to=to,
                                                         minutes=obs_opts["minutes"]))
        self.publish()
        return {"result": "updated", "from": frm, "to": to, "observation": obs.to_dict(), "backup": str(bs.path)}

    def _rollback_after(self, c, cur, bs, apply_info, st, reason, details) -> dict:
        frm, to = st.get("current_version"), st.get("available_version")
        log.error("ROLLBACK %s: %s", c.name, reason)
        q = self.cfg.state_dir / "quarantine" / f"{c.name}-{bs.path.name}"
        try:
            rb = deploy.rollback(c.name, bs, q, apply_info)
            details["rollback"] = rb
            check = self._verify_after_rollback(c)
            details["after_rollback"] = check
            if not check["ok"]:
                raise AirlockError(f"old version does not come up again: {check['detail']}")
        except AirlockError as e:
            details["rollback_error"] = str(e)
            self.hist.add(c.name, "rollback", "failed", f"{to} -> {frm} FAILED: {e}", details, from_version=to,
                          to_version=frm)
            self.notify("rollback_failed", f"{c.name}:{to}", i18n.t(self.lang, "rollback_failed", name=c.name,
                                                                     reason=f"{reason} / {e}"), force=True)
            self.publish()
            raise AirlockError(f"{c.name}: rollback failed: {e}") from e
        self.hist.add(c.name, "update", "failed", f"{frm} -> {to}: {reason}", details, from_version=frm, to_version=to,
                      from_digest=cur.digest, to_digest=st.get("candidate_digest"))
        self.hist.add(c.name, "rollback", "ok", f"{to} -> {frm}: {reason}", details, from_version=to, to_version=frm,
                      to_digest=cur.digest)
        new = self.status_of(c.name)
        new["status"] = "rolled_back"
        new["last_rollback"] = {"ts": now_iso(), "from": to, "to": frm, "reason": reason}
        self.set_status(c.name, new)
        # A rolled-back candidate is not tried again automatically.
        t = self.last_test(c.name, st.get("candidate_digest", "")) or {}
        if t:
            t["passed"] = False
            t["note"] = f"rolled back after a real update: {reason}"
            self.hist.put(f"test:{c.name}:{st.get('candidate_digest')}", t)
        self.notify("rolled_back", f"{c.name}:{to}", i18n.t(self.lang, "rolled_back", name=c.name, to=to, frm=frm,
                                                             reason=reason), force=True)
        self.publish()
        return {"result": "rolled_back", "reason": reason, "from": frm, "to": to, "details": details}

    def _verify_after_rollback(self, c: ContainerConfig) -> dict:
        dl = Deadline(float(self.cfg.observe_for(c)["startup_grace_minutes"]) * 60 + 120)
        last = ""
        while not dl.expired():
            s = dockerapi.state(c.name)
            if s.get("running"):
                if c.tester == "homeassistant":
                    ok, last = self.ha.api_ok()
                    if ok:
                        return {"ok": True, "detail": f"running, API {last}"}
                elif c.raw["health"].get("http_url"):
                    from .observe import web_check
                    ok, last = web_check(None, c.raw["health"]["http_url"])
                    if ok:
                        return {"ok": True, "detail": f"running, {c.raw['health']['http_url']} {last}"}
                else:
                    return {"ok": True, "detail": f"running ({s.get('status')})"}
            else:
                last = f"status {s.get('status')}"
            time.sleep(10)
        return {"ok": False, "detail": last}

    def rollback(self, c: ContainerConfig) -> dict:
        """Manual rollback to the state before the last successful update."""
        ev = self.hist.last(c.name, "update", "ok")
        if not ev:
            raise AirlockError(f"{c.name}: no successful update in the history - nothing to roll back")
        bs = deploy.BackupSet.load(Path(ev["details"]["backup"]))
        q = self.cfg.state_dir / "quarantine" / f"{c.name}-manual-{ts_compact()}"
        rb = deploy.rollback(c.name, bs, q, None)
        chk = self._verify_after_rollback(c)
        self.hist.add(c.name, "rollback", "ok" if chk["ok"] else "failed", f"manual: {ev['to_version']} -> "
                      f"{ev['from_version']}", {"rollback": rb, "after_rollback": chk, "backup": str(bs.path)},
                      from_version=ev["to_version"], to_version=ev["from_version"], to_digest=ev["from_digest"])
        st = self.evaluate(c)
        st["last_rollback"] = {"ts": now_iso(), "from": ev["to_version"], "to": ev["from_version"], "reason": "manual"}
        self.set_status(c.name, st)
        self.publish()
        return {"rollback": rb, "check": chk}

    def ack(self, c: ContainerConfig, version: str) -> None:
        self.hist.put(f"ack:{c.name}", version)
        self.hist.add(c.name, "ack", "info", f"breaking changes for {version} acknowledged by the user",
                      to_version=version)

    def save_isolation(self, proof: dict) -> None:
        proof = dict(proof, when=now_iso())
        self.hist.put("isolation_proof", proof)
        g = self.global_state()
        g["isolation_ok"] = bool(proof.get("passed"))
        self.hist.put("global", g)

    # ---------- publishing ----------
    def write_report(self, state: str, cs: dict, g: dict) -> None:
        www = self.cfg.general.get("www_dir")
        if not www:
            return
        from . import report
        tests = []
        for e in self.hist.events(action="test", limit=10):
            d = e.get("details") or {}
            tests.append({"finished": e["ts"], "container": e["container"], "candidate": e.get("to_version"),
                          "passed": e["result"] == "ok", "faults": d.get("faults"), "error": d.get("error"),
                          "checks": d.get("checks") or []})
        try:
            report.write(Path(www), self.lang, state, cs, g, self.hist.events(limit=40),
                         self.cfg["maintenance"]["window"], self.hist.get("isolation_proof"), tests,
                         self.cfg["ui"].get("home_url", ""), self.cfg["ui"].get("home_label", ""))
        except OSError as e:
            log.warning("status page not written: %s", e)

    def overall(self) -> tuple[str, dict]:
        cs = {n: self.status_of(n) for n in self.cfg.containers}
        g = self.global_state()
        statuses = [s.get("status") for s in cs.values()]
        if "error" in statuses or not all((g.get("last_ok") or {}).values() or [True]):
            state = "error"
        elif any(s in ("held", "test_failed", "rolled_back", "notify_only") for s in statuses):
            state = "attention"
        elif any(s in ("ready", "candidate") for s in statuses):
            state = "update_pending"
        else:
            state = "ok"
        return state, cs

    def publish(self) -> None:
        state, cs = self.overall()
        g = self.global_state()
        last_check = (g.get("last_run") or {}).get("check")
        counts = {}
        for r in self.hist.db.execute("SELECT action,result,COUNT(*) FROM events GROUP BY action,result"):
            counts[(r[0], r[1])] = r[2]
        mstate = {"global": g, "containers": {}}
        for n, s in cs.items():
            lt = s.get("last_test") or {}
            mstate["containers"][n] = {"status": s.get("status"), "kind": s.get("kind"),
                                       "current_version": s.get("current_version"),
                                       "available_version": s.get("available_version"),
                                       "last_test_passed": lt.get("passed"),
                                       "last_update_ts": (s.get("last_update") or {}).get("unix")}
        try:
            metrics.write(self.cfg.general["metrics_file"], mstate, counts)
        except OSError as e:
            log.warning("metrics not written: %s", e)
        self.write_report(state, cs, g)
        if not self.ha.configured:
            return
        prefix = self.cfg.ha["sensor_prefix"]
        try:
            summary = {n: f"{s.get('status')} {s.get('current_version') or ''}"
                          + (f" -> {s.get('available_version')}" if s.get("available_version") else "")
                       for n, s in cs.items()}
            self.ha.set_state(prefix, state, {
                "friendly_name": "Update airlock" if self.lang == "en" else "Update-Schleuse",
                "icon": "mdi:shield-sync", "last_check": dt.datetime.fromtimestamp(last_check).astimezone().isoformat()
                if last_check else None, "last_check_ts": last_check, "containers": summary,
                "isolation_ok": g.get("isolation_ok"), "source_failures": g.get("failures"),
                "last_postponed": g.get("last_postponed")})
            for n, s in cs.items():
                lt = s.get("last_test") or {}
                self.ha.set_state(f"{prefix}_{slug(n)}", s.get("status") or "unknown", {
                    "friendly_name": f"{'Update airlock' if self.lang == 'en' else 'Update-Schleuse'} {n}",
                    "icon": "mdi:docker", "installed": s.get("current_version"),
                    "available": s.get("available_version"), "kind": s.get("kind"), "policy": s.get("policy"),
                    "held_reason": s.get("held_reason"), "held_domains": s.get("held_domains"),
                    "last_test": lt.get("finished"), "last_test_passed": lt.get("passed"),
                    "last_update": (s.get("last_update") or {}).get("ts"),
                    "last_rollback": (s.get("last_rollback") or {}).get("ts"), "error": s.get("error"),
                    "managed_by": s.get("managed_by")})
            g["published"] = now_iso()
            self.hist.put("global", g)
        except AirlockError as e:
            log.warning("HA sensors not published: %s", e)

    def republish_if_missing(self) -> None:
        if not self.ha.configured:
            return
        try:
            if self.ha.get_state(self.cfg.ha["sensor_prefix"]) is None:
                log.info("status sensor missing in HA (restart?) - publishing again")
                self.publish()
        except AirlockError as e:
            log.warning("HA not reachable for the sensor check: %s", e)
