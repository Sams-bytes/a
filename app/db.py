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
CREATE TABLE IF NOT EXISTS subdomains (
    parent      TEXT NOT NULL,          -- the verified root domain, e.g. dam-bv.com
    name        TEXT NOT NULL,          -- e.g. www.dam-bv.com
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    sources     TEXT NOT NULL,          -- JSON list: certificates / dns / guess
    ips         TEXT NOT NULL,          -- JSON list
    cname       TEXT,
    provider    TEXT,                   -- who hosts it (None = probably your own)
    status      TEXT NOT NULL,          -- ok / no_address / takeover_risk
    PRIMARY KEY (parent, name)
);
CREATE TABLE IF NOT EXISTS netscans (
    cidr        TEXT PRIMARY KEY,       -- the local network, e.g. 192.168.1.0/24
    scanned_at  TEXT NOT NULL,
    admin       INTEGER NOT NULL,       -- was the scan run with admin rights?
    result      TEXT NOT NULL           -- JSON map (devices etc.)
);
CREATE TABLE IF NOT EXISTS known_devices (
    cidr        TEXT NOT NULL,
    mac         TEXT NOT NULL,
    name        TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    PRIMARY KEY (cidr, mac)
);
CREATE TABLE IF NOT EXISTS cve_cache (
    key         TEXT PRIMARY KEY,       -- e.g. a CPE name like cpe:2.3:a:apache:http_server:2.4.49:...
    fetched_at  TEXT NOT NULL,
    data        TEXT NOT NULL           -- JSON answer from NVD
);
"""

# Migrations: columns added after the first version of the schema.
# CREATE TABLE IF NOT EXISTS never changes an existing table, so an aegis.db
# made by an older Aegis needs these columns added on startup.
_MIGRATIONS = [
    ("domains", "monitor", "INTEGER NOT NULL DEFAULT 1"),   # 1 = weekly scans on
    ("scans", "source", "TEXT NOT NULL DEFAULT 'manual'"),  # 'manual' or 'scheduled'
    ("domains", "parent", "TEXT"),                          # set for monitored subdomains
    ("domains", "hosting", "TEXT NOT NULL DEFAULT 'auto'"), # auto / own / shared
    ("domains", "hosting_provider", "TEXT"),                # e.g. 'Hostinger'
    ("domains", "hosting_confirmed_at", "TEXT"),            # when the owner said "my own server"
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

    def add_domain(self, domain: str, token: str, parent: str | None = None) -> dict:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO domains(domain, token, created_at, verified_at, parent) VALUES (?,?,?,NULL,?)",
                (domain, token, now(), parent),
            )
            self._conn.commit()
        return self.get_domain(domain)

    def set_hosting(self, domain: str, hosting: str | None = None, provider: str | None = None,
                    confirmed: bool = False) -> None:
        """hosting: 'auto' / 'own' / 'shared' (None = leave as is); provider: what RDAP said."""
        with self._lock:
            if hosting is not None:
                self._conn.execute("UPDATE domains SET hosting=?, hosting_confirmed_at=? WHERE domain=?",
                                   (hosting, now() if confirmed else None, domain))
            if provider is not None:
                self._conn.execute("UPDATE domains SET hosting_provider=? WHERE domain=?", (provider, domain))
            self._conn.commit()

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
        """Delete a domain, its scans and alerts - and its monitored subdomains too."""
        with self._lock:
            children = [r["domain"] for r in self._conn.execute("SELECT domain FROM domains WHERE parent=?", (domain,))]
            for d in [*children, domain]:
                self._conn.execute("DELETE FROM alerts WHERE domain=?", (d,))
                self._conn.execute("DELETE FROM scans WHERE domain=?", (d,))
                self._conn.execute("DELETE FROM domains WHERE domain=?", (d,))
            self._conn.execute("DELETE FROM subdomains WHERE parent=?", (domain,))
            self._conn.commit()

    # ---- discovered subdomains -----------------------------------------
    def save_subdomains(self, parent: str, rows: list[dict]) -> list[str]:
        """Insert/update discovered subdomains. Returns names seen for the FIRST time."""
        new = []
        with self._lock:
            for r in rows:
                exists = self._conn.execute("SELECT 1 FROM subdomains WHERE parent=? AND name=?",
                                            (parent, r["name"])).fetchone()
                if exists:
                    self._conn.execute(
                        """UPDATE subdomains SET last_seen=?, sources=?, ips=?, cname=?, provider=?, status=?
                           WHERE parent=? AND name=?""",
                        (now(), json.dumps(r["sources"]), json.dumps(r["ips"]), r.get("cname"),
                         r.get("provider"), r["status"], parent, r["name"]))
                else:
                    new.append(r["name"])
                    self._conn.execute(
                        """INSERT INTO subdomains(parent, name, first_seen, last_seen, sources, ips, cname, provider, status)
                           VALUES (?,?,?,?,?,?,?,?,?)""",
                        (parent, r["name"], now(), now(), json.dumps(r["sources"]), json.dumps(r["ips"]),
                         r.get("cname"), r.get("provider"), r["status"]))
            self._conn.commit()
        return new

    def list_subdomains(self, parent: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT s.*, d.domain IS NOT NULL AS monitored FROM subdomains s
                   LEFT JOIN domains d ON d.domain = s.name AND d.parent = s.parent
                   WHERE s.parent=? ORDER BY s.status != 'takeover_risk', s.name""", (parent,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["sources"], d["ips"], d["monitored"] = json.loads(d["sources"]), json.loads(d["ips"]), bool(d["monitored"])
            out.append(d)
        return out

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

    # ---- network map ---------------------------------------------------
    def save_netscan(self, cidr: str, admin: bool, result: dict) -> None:
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO netscans(cidr, scanned_at, admin, result) VALUES (?,?,?,?)",
                               (cidr, now(), 1 if admin else 0, json.dumps(result)))
            self._conn.commit()

    def get_netscan(self, cidr: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT result FROM netscans WHERE cidr=?", (cidr,)).fetchone()
        return json.loads(row["result"]) if row else None

    def save_devices(self, cidr: str, devices: list[dict]) -> list[str]:
        """Remember devices by MAC. Returns MACs seen on this network for the FIRST time."""
        new = []
        with self._lock:
            for d in devices:
                mac = d.get("mac")
                if not mac:
                    continue
                row = self._conn.execute("SELECT 1 FROM known_devices WHERE cidr=? AND mac=?", (cidr, mac)).fetchone()
                if row:
                    self._conn.execute("UPDATE known_devices SET last_seen=?, name=COALESCE(name, ?) WHERE cidr=? AND mac=?",
                                       (now(), d.get("hostname"), cidr, mac))
                else:
                    new.append(mac)
                    self._conn.execute(
                        "INSERT INTO known_devices(cidr, mac, name, first_seen, last_seen) VALUES (?,?,?,?,?)",
                        (cidr, mac, d.get("hostname"), now(), now()))
            self._conn.commit()
        return new

    # ---- CVE cache -----------------------------------------------------
    def get_cache(self, key: str, max_age_s: float):
        """Cached JSON for `key`, or None if missing or older than max_age_s."""
        with self._lock:
            row = self._conn.execute("SELECT fetched_at, data FROM cve_cache WHERE key=?", (key,)).fetchone()
        if not row:
            return None
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(row["fetched_at"])).total_seconds()
        return json.loads(row["data"]) if age <= max_age_s else None

    def set_cache(self, key: str, data) -> None:
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO cve_cache(key, fetched_at, data) VALUES (?,?,?)",
                               (key, now(), json.dumps(data)))
            self._conn.commit()

    def mark_alerts_seen(self, domain: str | None = None) -> None:
        with self._lock:
            if domain:
                self._conn.execute("UPDATE alerts SET seen_at=? WHERE seen_at IS NULL AND domain=?", (now(), domain))
            else:
                self._conn.execute("UPDATE alerts SET seen_at=? WHERE seen_at IS NULL", (now(),))
            self._conn.commit()
