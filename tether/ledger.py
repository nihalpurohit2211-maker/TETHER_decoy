"""Append-only event/decision ledger with a SHA-256 hash chain (SQLite)."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import sqlite3
import time

from tether.events import Event
from tether.types import Decision


class Ledger:
    """Every row stores prev_sha256 and its own sha256 over (prev, body)."""

    def __init__(self, path: str = ":memory:") -> None:
        self.conn = sqlite3.connect(path)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS ledger ("
            " seq INTEGER PRIMARY KEY AUTOINCREMENT,"
            " prev_sha256 TEXT NOT NULL,"
            " sha256 TEXT NOT NULL,"
            " kind TEXT NOT NULL,"
            " ts REAL NOT NULL,"
            " body TEXT NOT NULL)"
        )
        self.conn.commit()
        self._last_sha = "GENESIS"

    # --- appends -----------------------------------------------------------
    def _append(self, kind: str, payload: dict) -> str:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        prev = self._last_sha
        sha = hashlib.sha256((prev + body).encode("utf-8")).hexdigest()
        self.conn.execute(
            "INSERT INTO ledger (prev_sha256, sha256, kind, ts, body) VALUES (?,?,?,?,?)",
            (prev, sha, kind, time.time(), body),
        )
        self.conn.commit()
        self._last_sha = sha
        return sha

    def append_event(self, ev: Event) -> str:
        return self._append("event", {"event": ev.to_dict()})

    def append_decision(self, dec: Decision) -> str:
        return self._append("decision", {"decision": dataclasses.asdict(dec)})

    # --- verification ------------------------------------------------------
    def verify_chain(self) -> bool:
        """Recompute the whole chain; any tampered row (or link) breaks it."""
        prev = "GENESIS"
        cur = self.conn.execute(
            "SELECT prev_sha256, sha256, body FROM ledger ORDER BY seq"
        )
        for row_prev, row_sha, body in cur:
            expect = hashlib.sha256((prev + body).encode("utf-8")).hexdigest()
            if row_prev != prev or row_sha != expect:
                return False
            prev = row_sha
        return True

    def rows_for_session(self, session: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT kind, body FROM ledger ORDER BY seq"
        ).fetchall()
        out = []
        for kind, body in rows:
            payload = json.loads(body)
            blob = payload.get("event") or payload.get("decision") or {}
            if blob.get("session") == session:
                out.append({"kind": kind, **payload})
        return out

    def close(self) -> None:
        self.conn.close()
