"""Persistent state in one SQLite file: event history (versions, tests, updates, rollbacks) and a small
key/value store for the current per-container status and alert de-duplication.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .util import now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  container TEXT NOT NULL,
  action TEXT NOT NULL,          -- check | held | test | update | rollback | error | ack
  result TEXT NOT NULL,          -- ok | failed | held | info | skipped
  from_version TEXT, to_version TEXT, from_digest TEXT, to_digest TEXT,
  summary TEXT,
  details TEXT
);
CREATE INDEX IF NOT EXISTS events_container ON events(container, id);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL, ts TEXT NOT NULL);
"""


class History:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.db = sqlite3.connect(str(path), timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def close(self):
        self.db.close()

    def add(self, container: str, action: str, result: str, summary: str = "", details: dict | None = None,
            from_version: str | None = None, to_version: str | None = None,
            from_digest: str | None = None, to_digest: str | None = None) -> int:
        cur = self.db.execute(
            "INSERT INTO events(ts,container,action,result,from_version,to_version,from_digest,to_digest,summary,details)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (now_iso(), container, action, result, from_version, to_version, from_digest, to_digest, summary,
             json.dumps(details or {}, ensure_ascii=False, default=str)))
        self.db.commit()
        return cur.lastrowid

    def events(self, container: str | None = None, limit: int = 50, action: str | None = None) -> list[dict]:
        q = "SELECT * FROM events"
        cond, args = [], []
        if container:
            cond.append("container=?")
            args.append(container)
        if action:
            cond.append("action=?")
            args.append(action)
        if cond:
            q += " WHERE " + " AND ".join(cond)
        q += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        out = []
        for r in self.db.execute(q, args):
            d = dict(r)
            d["details"] = json.loads(d["details"] or "{}")
            out.append(d)
        return out

    def last(self, container: str, action: str, result: str | None = None) -> dict | None:
        q = "SELECT * FROM events WHERE container=? AND action=?"
        args = [container, action]
        if result:
            q += " AND result=?"
            args.append(result)
        r = self.db.execute(q + " ORDER BY id DESC LIMIT 1", args).fetchone()
        if not r:
            return None
        d = dict(r)
        d["details"] = json.loads(d["details"] or "{}")
        return d

    def count(self, action: str, result: str | None = None, container: str | None = None) -> int:
        q, args = "SELECT COUNT(*) FROM events WHERE action=?", [action]
        if result:
            q += " AND result=?"
            args.append(result)
        if container:
            q += " AND container=?"
            args.append(container)
        return self.db.execute(q, args).fetchone()[0]

    # ---------- key/value ----------
    def get(self, key: str, default=None):
        r = self.db.execute("SELECT v FROM kv WHERE k=?", (key,)).fetchone()
        return json.loads(r[0]) if r else default

    def put(self, key: str, value) -> None:
        self.db.execute("INSERT INTO kv(k,v,ts) VALUES (?,?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v, ts=excluded.ts",
                        (key, json.dumps(value, ensure_ascii=False, default=str), now_iso()))
        self.db.commit()

    def delete(self, key: str) -> None:
        self.db.execute("DELETE FROM kv WHERE k=?", (key,))
        self.db.commit()
