"""Tiny SQLite storage. One file (aegis.db) next to the app - no server to install."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone

DB_PATH = os.environ.get("AEGIS_DB", "aegis.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS domains (
    domain      TEXT PRIMARY KEY,
    token       TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    verified_at TEXT
);
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT NOT NULL REFERENCES domains(domain),
    started_at  TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    score       INTEGER NOT NULL,
    result      TEXT NOT NULL
);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str = DB_PATH):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)

    # ---- domains -------------------------------------------------------
    def get_domain(self, domain: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM domains WHERE domain=?", (domain,)).fetchone()
        return dict(row) if row else None

    def add_domain(self, domain: str, token: str) -> dict:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO domains(domain, token, created_at, verified_at) VALUES (?,?,?,NULL)",
                (domain, token, now()),
            )
            self._conn.commit()
        return self.get_domain(domain)

    def mark_verified(self, domain: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE domains SET verified_at=? WHERE domain=?", (now(), domain))
            self._conn.commit()

    def list_domains(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT d.*, s.score AS last_score, s.finished_at AS last_scan
                   FROM domains d
                   LEFT JOIN scans s ON s.id = (SELECT MAX(id) FROM scans WHERE domain=d.domain)
                   ORDER BY d.created_at DESC"""
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_domain(self, domain: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM scans WHERE domain=?", (domain,))
            self._conn.execute("DELETE FROM domains WHERE domain=?", (domain,))
            self._conn.commit()

    # ---- scans ---------------------------------------------------------
    def add_scan(self, domain: str, started_at: str, result: dict) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO scans(domain, started_at, finished_at, score, result) VALUES (?,?,?,?,?)",
                (domain, started_at, now(), result["score"], json.dumps(result)),
            )
            self._conn.commit()
            return cur.lastrowid

    def list_scans(self, domain: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, domain, started_at, finished_at, score FROM scans WHERE domain=? ORDER BY id DESC",
                (domain,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_scan(self, scan_id: int) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["result"] = json.loads(d["result"])
        return d
