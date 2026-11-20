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
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT NOT NULL,
    scan_id     INTEGER,
    created_at  TEXT NOT NULL,
    level       TEXT NOT NULL,          -- 'warning' or 'stopped'
    title       TEXT NOT NULL,
    details     TEXT NOT NULL,          -- JSON list of plain-English lines
    seen_at     TEXT
);
"""

# Migrations: columns added after the first version of the schema.
# CREATE TABLE IF NOT EXISTS never changes an existing table, so an aegis.db
# made by an older Aegis needs these columns added on startup.
_MIGRATIONS = [
    ("domains", "monitor", "INTEGER NOT NULL DEFAULT 1"),   # 1 = weekly scans on
    ("scans", "source", "TEXT NOT NULL DEFAULT 'manual'"),  # 'manual' or 'scheduled'
]


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str = DB_PATH):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            for table, column, decl in _MIGRATIONS:
                self._add_column_if_missing(table, column, decl)
            self._conn.commit()

    def _add_column_if_missing(self, table: str, column: str, decl: str) -> None:
        cols = {r["name"] for r in self._conn.execute(f"PRAGMA table_info({table})")}
        if column not in cols:
            self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")

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

    def mark_unverified(self, domain: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE domains SET verified_at=NULL WHERE domain=?", (domain,))
            self._conn.commit()

    def set_monitor(self, domain: str, on: bool) -> None:
        with self._lock:
            self._conn.execute("UPDATE domains SET monitor=? WHERE domain=?", (1 if on else 0, domain))
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

    def monitored_domains(self) -> list[dict]:
        """Verified domains with monitoring on, plus when they were last scanned."""
        return [d for d in self.list_domains() if d["verified_at"] and d["monitor"]]

    def delete_domain(self, domain: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM alerts WHERE domain=?", (domain,))
            self._conn.execute("DELETE FROM scans WHERE domain=?", (domain,))
            self._conn.execute("DELETE FROM domains WHERE domain=?", (domain,))
            self._conn.commit()

    # ---- scans ---------------------------------------------------------
    def add_scan(self, domain: str, started_at: str, result: dict, source: str = "manual") -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO scans(domain, started_at, finished_at, score, result, source) VALUES (?,?,?,?,?,?)",
                (domain, started_at, now(), result["score"], json.dumps(result), source),
            )
            self._conn.commit()
            return cur.lastrowid

    def list_scans(self, domain: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, domain, started_at, finished_at, score, source FROM scans WHERE domain=? ORDER BY id DESC",
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

    def latest_scan(self, domain: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT MAX(id) AS id FROM scans WHERE domain=?", (domain,)).fetchone()
        return self.get_scan(row["id"]) if row and row["id"] else None

    # ---- alerts --------------------------------------------------------
    def add_alert(self, domain: str, level: str, title: str, details: list[str],
                  scan_id: int | None = None) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO alerts(domain, scan_id, created_at, level, title, details) VALUES (?,?,?,?,?,?)",
                (domain, scan_id, now(), level, title, json.dumps(details)),
            )
            self._conn.commit()
            return cur.lastrowid

    def list_alerts(self, limit: int = 50) -> list[dict]:
        """Newest first; unseen alerts have seen_at = None."""
        with self._lock:
            rows = self._conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["details"] = json.loads(d["details"])
            out.append(d)
        return out

    def mark_alerts_seen(self, domain: str | None = None) -> None:
        with self._lock:
            if domain:
                self._conn.execute("UPDATE alerts SET seen_at=? WHERE seen_at IS NULL AND domain=?", (now(), domain))
            else:
                self._conn.execute("UPDATE alerts SET seen_at=? WHERE seen_at IS NULL", (now(),))
            self._conn.commit()
