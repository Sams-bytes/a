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
CREATE TABLE IF NOT EXISTS app_secret (     -- tiny key/value: the server's session-signing key
    name        TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT NOT NULL UNIQUE,
    pw_hash     TEXT NOT NULL,          -- scrypt hash (hex); never the password itself
    pw_salt     TEXT NOT NULL,          -- per-user random salt (hex)
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS orgs (           -- a customer organisation = one locked drawer (tenant)
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS memberships (    -- which user belongs to which org, and their role
    org_id      INTEGER NOT NULL REFERENCES orgs(id),
    user_id     INTEGER NOT NULL REFERENCES users(id),
    role        TEXT NOT NULL,          -- admin | member | viewer
    created_at  TEXT NOT NULL,
    PRIMARY KEY (org_id, user_id)
);
CREATE TABLE IF NOT EXISTS projects (       -- an assessment engagement: a scope + who authorised it
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id        INTEGER NOT NULL,
    name          TEXT NOT NULL,
    authorized_by TEXT,                 -- the person who signed off on scanning this scope
    scope_note    TEXT,                 -- free text: what is in scope, caveats, ticket ref…
    authorized_at TEXT,
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ir_cases (        -- incident-response case: a tracked investigation
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id      INTEGER NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,          -- low | medium | high | critical
    status      TEXT NOT NULL,          -- open | investigating | contained | closed
    domain      TEXT,
    source      TEXT,                   -- what opened it (a finding key, an alert, 'manual')
    created_by  INTEGER,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS case_events (     -- the timeline: notes, status changes, actions
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     INTEGER NOT NULL,
    org_id      INTEGER NOT NULL,
    at          TEXT NOT NULL,
    user_id     INTEGER,
    kind        TEXT NOT NULL,          -- created | note | status | action
    text        TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS case_actions (    -- a response action that needs approval before it is taken
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     INTEGER NOT NULL,
    org_id      INTEGER NOT NULL,
    action      TEXT NOT NULL,
    status      TEXT NOT NULL,          -- proposed | approved | rejected | done
    proposed_by INTEGER,
    decided_by  INTEGER,
    note        TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS compliance_answers (  -- NIS2/GDPR self-assessment answers, per org
    org_id      INTEGER NOT NULL,
    key         TEXT NOT NULL,          -- "<measure>:<question>", e.g. "c:backups"
    answer      TEXT NOT NULL,          -- yes | no | na
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (org_id, key)
);
CREATE TABLE IF NOT EXISTS finding_status (  -- remediation workflow: the state of one finding
    org_id      INTEGER NOT NULL,
    domain      TEXT NOT NULL,
    finding_key TEXT NOT NULL,
    status      TEXT NOT NULL,          -- open | fixed | accepted | false_positive
    note        TEXT,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (org_id, domain, finding_key)
);
CREATE TABLE IF NOT EXISTS audit_events (   -- who did what, when: a tamper-evident trail per org
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id      INTEGER NOT NULL,
    user_id     INTEGER,
    at          TEXT NOT NULL,
    action      TEXT NOT NULL,          -- e.g. login, scan, add_domain, delete_domain
    target      TEXT,                   -- what it acted on (a domain, a project…)
    detail      TEXT                    -- optional extra note
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
    # Tenant isolation (Phase 1): every piece of customer data belongs to one org.
    # DEFAULT 1 migrates any data from the pre-accounts version into "org 1"; the
    # first organisation created also gets id 1, so that first customer inherits it.
    ("domains", "org_id", "INTEGER NOT NULL DEFAULT 1"),
    ("scans", "org_id", "INTEGER NOT NULL DEFAULT 1"),
    ("alerts", "org_id", "INTEGER NOT NULL DEFAULT 1"),
    ("subdomains", "org_id", "INTEGER NOT NULL DEFAULT 1"),
    ("netscans", "org_id", "INTEGER NOT NULL DEFAULT 1"),
    ("known_devices", "org_id", "INTEGER NOT NULL DEFAULT 1"),
    ("domains", "project_id", "INTEGER"),   # which engagement a domain belongs to (optional)
]

# Single-tenant / test convenience: calls that don't name an org act on org 1.
# Application code always passes an explicit org_id (via OrgStore), so this default
# never widens access in production - it only keeps single-org callers simple.
DEFAULT_ORG = 1


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
    # Every method takes an org_id and filters on it: a domain is reachable only
    # through the org that owns it. org_id defaults to DEFAULT_ORG for single-org
    # callers; application code passes it explicitly (OrgStore).
    def get_domain(self, domain: str, org_id: int = DEFAULT_ORG) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM domains WHERE domain=? AND org_id=?", (domain, org_id)).fetchone()
        return dict(row) if row else None

    def add_domain(self, domain: str, token: str, parent: str | None = None,
                   org_id: int = DEFAULT_ORG) -> dict:
        with self._lock:
            # A domain belongs to one organisation at a time. Refuse to re-home a
            # domain another org already registered (would otherwise leak/overwrite).
            owner = self._conn.execute("SELECT org_id FROM domains WHERE domain=?", (domain,)).fetchone()
            if owner and owner["org_id"] != org_id:
                raise ValueError(f"{domain} is already registered to another organisation.")
            self._conn.execute(
                """INSERT OR REPLACE INTO domains(domain, token, created_at, verified_at, parent, org_id)
                   VALUES (?,?,?,NULL,?,?)""",
                (domain, token, now(), parent, org_id),
            )
            self._conn.commit()
        return self.get_domain(domain, org_id)

    def set_hosting(self, domain: str, hosting: str | None = None, provider: str | None = None,
                    confirmed: bool = False, org_id: int = DEFAULT_ORG) -> None:
        """hosting: 'auto' / 'own' / 'shared' (None = leave as is); provider: what RDAP said."""
        with self._lock:
            if hosting is not None:
                self._conn.execute("UPDATE domains SET hosting=?, hosting_confirmed_at=? WHERE domain=? AND org_id=?",
                                   (hosting, now() if confirmed else None, domain, org_id))
            if provider is not None:
                self._conn.execute("UPDATE domains SET hosting_provider=? WHERE domain=? AND org_id=?",
                                   (provider, domain, org_id))
            self._conn.commit()

    def mark_verified(self, domain: str, org_id: int = DEFAULT_ORG) -> None:
        with self._lock:
            self._conn.execute("UPDATE domains SET verified_at=? WHERE domain=? AND org_id=?", (now(), domain, org_id))
            self._conn.commit()

    def mark_unverified(self, domain: str, org_id: int = DEFAULT_ORG) -> None:
        with self._lock:
            self._conn.execute("UPDATE domains SET verified_at=NULL WHERE domain=? AND org_id=?", (domain, org_id))
            self._conn.commit()

    def set_monitor(self, domain: str, on: bool, org_id: int = DEFAULT_ORG) -> None:
        with self._lock:
            self._conn.execute("UPDATE domains SET monitor=? WHERE domain=? AND org_id=?",
                               (1 if on else 0, domain, org_id))
            self._conn.commit()

    def list_domains(self, org_id: int = DEFAULT_ORG) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT d.*, s.score AS last_score, s.finished_at AS last_scan
                   FROM domains d
                   LEFT JOIN scans s ON s.id = (SELECT MAX(id) FROM scans WHERE domain=d.domain AND org_id=d.org_id)
                   WHERE d.org_id=?
                   ORDER BY d.created_at DESC""", (org_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def monitored_domains(self, org_id: int = DEFAULT_ORG) -> list[dict]:
        """Verified domains with monitoring on, plus when they were last scanned."""
        return [d for d in self.list_domains(org_id) if d["verified_at"] and d["monitor"]]

    def all_monitored(self) -> list[dict]:
        """Every monitored domain across ALL orgs (for the background scheduler)."""
        with self._lock:
            org_ids = [r["org_id"] for r in self._conn.execute("SELECT DISTINCT org_id FROM domains")]
        out = []
        for oid in org_ids:
            out += self.monitored_domains(oid)
        return out

    def org_ids_with_domains(self) -> list[int]:
        with self._lock:
            return [r["org_id"] for r in self._conn.execute("SELECT DISTINCT org_id FROM domains ORDER BY org_id")]

    def delete_domain(self, domain: str, org_id: int = DEFAULT_ORG) -> None:
        """Delete a domain, its scans and alerts - and its monitored subdomains too."""
        with self._lock:
            children = [r["domain"] for r in self._conn.execute(
                "SELECT domain FROM domains WHERE parent=? AND org_id=?", (domain, org_id))]
            for d in [*children, domain]:
                self._conn.execute("DELETE FROM alerts WHERE domain=? AND org_id=?", (d, org_id))
                self._conn.execute("DELETE FROM scans WHERE domain=? AND org_id=?", (d, org_id))
                self._conn.execute("DELETE FROM domains WHERE domain=? AND org_id=?", (d, org_id))
            self._conn.execute("DELETE FROM subdomains WHERE parent=? AND org_id=?", (domain, org_id))
            self._conn.commit()

    # ---- discovered subdomains -----------------------------------------
    def save_subdomains(self, parent: str, rows: list[dict], org_id: int = DEFAULT_ORG) -> list[str]:
        """Insert/update discovered subdomains. Returns names seen for the FIRST time."""
        new = []
        with self._lock:
            for r in rows:
                exists = self._conn.execute("SELECT 1 FROM subdomains WHERE parent=? AND name=? AND org_id=?",
                                            (parent, r["name"], org_id)).fetchone()
                if exists:
                    self._conn.execute(
                        """UPDATE subdomains SET last_seen=?, sources=?, ips=?, cname=?, provider=?, status=?
                           WHERE parent=? AND name=? AND org_id=?""",
                        (now(), json.dumps(r["sources"]), json.dumps(r["ips"]), r.get("cname"),
                         r.get("provider"), r["status"], parent, r["name"], org_id))
                else:
                    new.append(r["name"])
                    self._conn.execute(
                        """INSERT INTO subdomains(parent, name, first_seen, last_seen, sources, ips, cname, provider, status, org_id)
                           VALUES (?,?,?,?,?,?,?,?,?,?)""",
                        (parent, r["name"], now(), now(), json.dumps(r["sources"]), json.dumps(r["ips"]),
                         r.get("cname"), r.get("provider"), r["status"], org_id))
            self._conn.commit()
        return new

    def list_subdomains(self, parent: str, org_id: int = DEFAULT_ORG) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT s.*, d.domain IS NOT NULL AS monitored FROM subdomains s
                   LEFT JOIN domains d ON d.domain = s.name AND d.parent = s.parent AND d.org_id = s.org_id
                   WHERE s.parent=? AND s.org_id=? ORDER BY s.status != 'takeover_risk', s.name""",
                (parent, org_id)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["sources"], d["ips"], d["monitored"] = json.loads(d["sources"]), json.loads(d["ips"]), bool(d["monitored"])
            out.append(d)
        return out

    # ---- scans ---------------------------------------------------------
    def add_scan(self, domain: str, started_at: str, result: dict, source: str = "manual",
                 org_id: int = DEFAULT_ORG) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO scans(domain, started_at, finished_at, score, result, source, org_id) VALUES (?,?,?,?,?,?,?)",
                (domain, started_at, now(), result["score"], json.dumps(result), source, org_id),
            )
            self._conn.commit()
            return cur.lastrowid

    def list_scans(self, domain: str, org_id: int = DEFAULT_ORG) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, domain, started_at, finished_at, score, source FROM scans WHERE domain=? AND org_id=? ORDER BY id DESC",
                (domain, org_id),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_scan(self, scan_id: int, org_id: int = DEFAULT_ORG) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM scans WHERE id=? AND org_id=?", (scan_id, org_id)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["result"] = json.loads(d["result"])
        return d

    def latest_scan(self, domain: str, org_id: int = DEFAULT_ORG) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT MAX(id) AS id FROM scans WHERE domain=? AND org_id=?",
                                     (domain, org_id)).fetchone()
        return self.get_scan(row["id"], org_id) if row and row["id"] else None

    # ---- alerts --------------------------------------------------------
    def add_alert(self, domain: str, level: str, title: str, details: list[str],
                  scan_id: int | None = None, org_id: int = DEFAULT_ORG) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO alerts(domain, scan_id, created_at, level, title, details, org_id) VALUES (?,?,?,?,?,?,?)",
                (domain, scan_id, now(), level, title, json.dumps(details), org_id),
            )
            self._conn.commit()
            return cur.lastrowid

    def list_alerts(self, limit: int = 50, org_id: int = DEFAULT_ORG) -> list[dict]:
        """Newest first; unseen alerts have seen_at = None."""
        with self._lock:
            rows = self._conn.execute("SELECT * FROM alerts WHERE org_id=? ORDER BY id DESC LIMIT ?",
                                      (org_id, limit)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["details"] = json.loads(d["details"])
            out.append(d)
        return out

    # ---- network map ---------------------------------------------------
    def save_netscan(self, cidr: str, admin: bool, result: dict, org_id: int = DEFAULT_ORG) -> None:
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO netscans(cidr, scanned_at, admin, result, org_id) VALUES (?,?,?,?,?)",
                               (cidr, now(), 1 if admin else 0, json.dumps(result), org_id))
            self._conn.commit()

    def get_netscan(self, cidr: str, org_id: int = DEFAULT_ORG) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT result FROM netscans WHERE cidr=? AND org_id=?",
                                     (cidr, org_id)).fetchone()
        return json.loads(row["result"]) if row else None

    def save_devices(self, cidr: str, devices: list[dict], org_id: int = DEFAULT_ORG) -> list[str]:
        """Remember devices by MAC. Returns MACs seen on this network for the FIRST time."""
        new = []
        with self._lock:
            for d in devices:
                mac = d.get("mac")
                if not mac:
                    continue
                row = self._conn.execute("SELECT 1 FROM known_devices WHERE cidr=? AND mac=? AND org_id=?",
                                         (cidr, mac, org_id)).fetchone()
                if row:
                    self._conn.execute("UPDATE known_devices SET last_seen=?, name=COALESCE(name, ?) WHERE cidr=? AND mac=? AND org_id=?",
                                       (now(), d.get("hostname"), cidr, mac, org_id))
                else:
                    new.append(mac)
                    self._conn.execute(
                        "INSERT INTO known_devices(cidr, mac, name, first_seen, last_seen, org_id) VALUES (?,?,?,?,?,?)",
                        (cidr, mac, d.get("hostname"), now(), now(), org_id))
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

    # ---- app secret (session signing key) ------------------------------
    def get_or_create_secret(self, name: str, make) -> str:
        """Return a stored secret, creating it once with make() if absent.

        Used for the session-signing key: generated on first run and kept in
        aegis.db so login cookies survive a server restart.
        """
        with self._lock:
            row = self._conn.execute("SELECT value FROM app_secret WHERE name=?", (name,)).fetchone()
            if row:
                return row["value"]
            value = make()
            self._conn.execute("INSERT INTO app_secret(name, value) VALUES (?,?)", (name, value))
            self._conn.commit()
            return value

    # ---- users / orgs / memberships ------------------------------------
    def create_user(self, email: str, pw_hash: str, pw_salt: str) -> dict:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO users(email, pw_hash, pw_salt, created_at) VALUES (?,?,?,?)",
                (email, pw_hash, pw_salt, now()))
            self._conn.commit()
            uid = cur.lastrowid
        return self.get_user(uid)

    def get_user(self, user_id: int) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return dict(row) if row else None

    def get_user_by_email(self, email: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        return dict(row) if row else None

    def create_org(self, name: str) -> dict:
        with self._lock:
            cur = self._conn.execute("INSERT INTO orgs(name, created_at) VALUES (?,?)", (name, now()))
            self._conn.commit()
            oid = cur.lastrowid
            row = self._conn.execute("SELECT * FROM orgs WHERE id=?", (oid,)).fetchone()
        return dict(row)

    def add_membership(self, org_id: int, user_id: int, role: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO memberships(org_id, user_id, role, created_at) VALUES (?,?,?,?)",
                (org_id, user_id, role, now()))
            self._conn.commit()

    def memberships_for_user(self, user_id: int) -> list[dict]:
        """Every org this user belongs to, with their role, newest first."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT o.id AS org_id, o.name AS org_name, m.role
                   FROM memberships m JOIN orgs o ON o.id = m.org_id
                   WHERE m.user_id=? ORDER BY o.id""", (user_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_membership(self, org_id: int, user_id: int) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM memberships WHERE org_id=? AND user_id=?", (org_id, user_id)).fetchone()
        return dict(row) if row else None

    def mark_alerts_seen(self, domain: str | None = None, org_id: int = DEFAULT_ORG) -> None:
        with self._lock:
            if domain:
                self._conn.execute("UPDATE alerts SET seen_at=? WHERE seen_at IS NULL AND domain=? AND org_id=?",
                                   (now(), domain, org_id))
            else:
                self._conn.execute("UPDATE alerts SET seen_at=? WHERE seen_at IS NULL AND org_id=?", (now(), org_id))
            self._conn.commit()

    def list_orgs(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM orgs ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    # ---- projects (assessment engagements) -----------------------------
    def create_project(self, name: str, authorized_by: str | None = None,
                       scope_note: str | None = None, org_id: int = DEFAULT_ORG) -> dict:
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO projects(org_id, name, authorized_by, scope_note, authorized_at, created_at)
                   VALUES (?,?,?,?,?,?)""",
                (org_id, name, authorized_by, scope_note, now() if authorized_by else None, now()))
            self._conn.commit()
            pid = cur.lastrowid
        return self.get_project(pid, org_id)

    def get_project(self, project_id: int, org_id: int = DEFAULT_ORG) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM projects WHERE id=? AND org_id=?",
                                     (project_id, org_id)).fetchone()
        return dict(row) if row else None

    def list_projects(self, org_id: int = DEFAULT_ORG) -> list[dict]:
        """Projects in this org, each with how many domains it holds."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT p.*, (SELECT COUNT(*) FROM domains d WHERE d.project_id=p.id AND d.org_id=p.org_id)
                       AS domain_count
                   FROM projects p WHERE p.org_id=? ORDER BY p.id DESC""", (org_id,)).fetchall()
        return [dict(r) for r in rows]

    # ---- incident-response cases ---------------------------------------
    def create_case(self, title: str, severity: str, domain: str | None, source: str,
                    created_by: int | None, org_id: int = DEFAULT_ORG) -> dict:
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO ir_cases(org_id, title, severity, status, domain, source, created_by, created_at, updated_at)
                   VALUES (?,?,?,'open',?,?,?,?,?)""",
                (org_id, title, severity, domain, source, created_by, now(), now()))
            cid = cur.lastrowid
            self._conn.execute(
                "INSERT INTO case_events(case_id, org_id, at, user_id, kind, text) VALUES (?,?,?,?,'created',?)",
                (cid, org_id, now(), created_by, f"Case opened (severity {severity})"))
            self._conn.commit()
        return self.get_case(cid, org_id)

    def list_cases(self, org_id: int = DEFAULT_ORG) -> list[dict]:
        """Open cases first, then by recency."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT c.*, (SELECT COUNT(*) FROM case_actions a
                        WHERE a.case_id=c.id AND a.status='proposed') AS pending_actions
                   FROM ir_cases c WHERE c.org_id=?
                   ORDER BY c.status='closed', c.updated_at DESC""", (org_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_case(self, case_id: int, org_id: int = DEFAULT_ORG) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM ir_cases WHERE id=? AND org_id=?",
                                     (case_id, org_id)).fetchone()
            if not row:
                return None
            case = dict(row)
            case["events"] = [dict(r) for r in self._conn.execute(
                """SELECT e.*, u.email AS user_email FROM case_events e
                   LEFT JOIN users u ON u.id=e.user_id
                   WHERE e.case_id=? ORDER BY e.id""", (case_id,))]
            case["actions"] = [dict(r) for r in self._conn.execute(
                "SELECT * FROM case_actions WHERE case_id=? ORDER BY id", (case_id,))]
        return case

    def add_case_event(self, case_id: int, user_id: int | None, kind: str, text: str,
                       org_id: int = DEFAULT_ORG) -> None:
        with self._lock:
            owned = self._conn.execute("SELECT 1 FROM ir_cases WHERE id=? AND org_id=?",
                                       (case_id, org_id)).fetchone()
            if not owned:
                raise ValueError("No such case in this organisation.")
            self._conn.execute(
                "INSERT INTO case_events(case_id, org_id, at, user_id, kind, text) VALUES (?,?,?,?,?,?)",
                (case_id, org_id, now(), user_id, kind, text))
            self._conn.execute("UPDATE ir_cases SET updated_at=? WHERE id=?", (now(), case_id))
            self._conn.commit()

    def set_case_status(self, case_id: int, status: str, user_id: int | None,
                        org_id: int = DEFAULT_ORG) -> None:
        with self._lock:
            owned = self._conn.execute("SELECT 1 FROM ir_cases WHERE id=? AND org_id=?",
                                       (case_id, org_id)).fetchone()
            if not owned:
                raise ValueError("No such case in this organisation.")
            self._conn.execute("UPDATE ir_cases SET status=?, updated_at=? WHERE id=?", (status, now(), case_id))
            self._conn.execute(
                "INSERT INTO case_events(case_id, org_id, at, user_id, kind, text) VALUES (?,?,?,?,'status',?)",
                (case_id, org_id, now(), user_id, f"Status changed to {status}"))
            self._conn.commit()

    def add_action(self, case_id: int, action: str, proposed_by: int | None, note: str | None,
                   org_id: int = DEFAULT_ORG) -> dict:
        with self._lock:
            owned = self._conn.execute("SELECT 1 FROM ir_cases WHERE id=? AND org_id=?",
                                       (case_id, org_id)).fetchone()
            if not owned:
                raise ValueError("No such case in this organisation.")
            cur = self._conn.execute(
                """INSERT INTO case_actions(case_id, org_id, action, status, proposed_by, note, created_at, updated_at)
                   VALUES (?,?,?,'proposed',?,?,?,?)""",
                (case_id, org_id, action, proposed_by, note, now(), now()))
            self._conn.execute(
                "INSERT INTO case_events(case_id, org_id, at, user_id, kind, text) VALUES (?,?,?,?,'action',?)",
                (case_id, org_id, now(), proposed_by, f"Response action proposed: {action}"))
            self._conn.execute("UPDATE ir_cases SET updated_at=? WHERE id=?", (now(), case_id))
            self._conn.commit()
            aid = cur.lastrowid
            return dict(self._conn.execute("SELECT * FROM case_actions WHERE id=?", (aid,)).fetchone())

    def decide_action(self, action_id: int, status: str, decided_by: int | None,
                      note: str | None, org_id: int = DEFAULT_ORG) -> dict:
        with self._lock:
            row = self._conn.execute("SELECT * FROM case_actions WHERE id=? AND org_id=?",
                                     (action_id, org_id)).fetchone()
            if not row:
                raise ValueError("No such action in this organisation.")
            # Approval gate: a disruptive action can only be carried out after approval.
            if status == "done" and row["status"] != "approved":
                raise ValueError("This action must be approved before it can be marked done.")
            if status in ("approved", "rejected") and row["status"] != "proposed":
                raise ValueError("This action has already been decided.")
            self._conn.execute(
                "UPDATE case_actions SET status=?, decided_by=?, note=COALESCE(?, note), updated_at=? WHERE id=?",
                (status, decided_by, note, now(), action_id))
            self._conn.execute(
                "INSERT INTO case_events(case_id, org_id, at, user_id, kind, text) VALUES (?,?,?,?,'action',?)",
                (row["case_id"], org_id, now(), decided_by, f"Action '{row['action']}' marked {status}"))
            self._conn.execute("UPDATE ir_cases SET updated_at=? WHERE id=?", (now(), row["case_id"]))
            self._conn.commit()
            return dict(self._conn.execute("SELECT * FROM case_actions WHERE id=?", (action_id,)).fetchone())

    # ---- compliance self-assessment ------------------------------------
    def set_compliance_answer(self, key: str, answer: str, org_id: int = DEFAULT_ORG) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO compliance_answers(org_id, key, answer, updated_at) VALUES (?,?,?,?)",
                (org_id, key, answer, now()))
            self._conn.commit()

    def compliance_answers(self, org_id: int = DEFAULT_ORG) -> dict:
        with self._lock:
            rows = self._conn.execute("SELECT key, answer FROM compliance_answers WHERE org_id=?",
                                      (org_id,)).fetchall()
        return {r["key"]: r["answer"] for r in rows}

    # ---- remediation status --------------------------------------------
    def set_finding_status(self, domain: str, finding_key: str, status: str,
                           note: str | None = None, org_id: int = DEFAULT_ORG) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO finding_status(org_id, domain, finding_key, status, note, updated_at)
                   VALUES (?,?,?,?,?,?)""", (org_id, domain, finding_key, status, note, now()))
            self._conn.commit()

    def finding_statuses(self, domain: str, org_id: int = DEFAULT_ORG) -> dict:
        """{finding_key: {status, note, updated_at}} for one domain."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT finding_key, status, note, updated_at FROM finding_status WHERE org_id=? AND domain=?",
                (org_id, domain)).fetchall()
        return {r["finding_key"]: {"status": r["status"], "note": r["note"], "updated_at": r["updated_at"]}
                for r in rows}

    def set_domain_project(self, domain: str, project_id: int | None, org_id: int = DEFAULT_ORG) -> None:
        with self._lock:
            # Only assign a project that belongs to the same org (never cross-org).
            if project_id is not None:
                ok = self._conn.execute("SELECT 1 FROM projects WHERE id=? AND org_id=?",
                                        (project_id, org_id)).fetchone()
                if not ok:
                    raise ValueError("No such project in this organisation.")
            self._conn.execute("UPDATE domains SET project_id=? WHERE domain=? AND org_id=?",
                               (project_id, domain, org_id))
            self._conn.commit()

    # ---- audit log -----------------------------------------------------
    def add_audit(self, org_id: int, user_id: int | None, action: str,
                  target: str | None = None, detail: str | None = None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit_events(org_id, user_id, at, action, target, detail) VALUES (?,?,?,?,?,?)",
                (org_id, user_id, now(), action, target, detail))
            self._conn.commit()

    def list_audit(self, org_id: int, limit: int = 100) -> list[dict]:
        """Newest first, with the acting user's email joined in."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT a.*, u.email AS user_email FROM audit_events a
                   LEFT JOIN users u ON u.id = a.user_id
                   WHERE a.org_id=? ORDER BY a.id DESC LIMIT ?""", (org_id, limit)).fetchall()
        return [dict(r) for r in rows]


class OrgStore:
    """A Store locked to one organisation.

    Hands verification.py, monitor.py and netmap.py a store whose domain/scan/
    alert/subdomain/network methods are already scoped to one org, so those
    modules need no changes to become multi-tenant: they just receive this
    instead of the raw Store. Account-level methods (users, orgs, cve cache,
    the session secret) are reached on the underlying `.store` directly.
    """

    # Methods whose last argument is the org to scope to. Everything else is
    # delegated unchanged to the raw Store.
    _SCOPED = {
        "get_domain", "add_domain", "set_hosting", "mark_verified", "mark_unverified",
        "set_monitor", "list_domains", "monitored_domains", "delete_domain",
        "save_subdomains", "list_subdomains", "add_scan", "list_scans", "get_scan",
        "latest_scan", "add_alert", "list_alerts", "save_netscan", "get_netscan",
        "save_devices", "mark_alerts_seen",
        "create_project", "get_project", "list_projects", "set_domain_project",
        "set_finding_status", "finding_statuses",
        "create_case", "list_cases", "get_case", "add_case_event", "set_case_status",
        "add_action", "decide_action",
        "set_compliance_answer", "compliance_answers",
    }

    def __init__(self, store: Store, org_id: int):
        self.store = store
        self.org_id = org_id

    def __getattr__(self, name):
        attr = getattr(self.store, name)
        if name in self._SCOPED:
            def scoped(*args, **kwargs):
                kwargs.setdefault("org_id", self.org_id)
                return attr(*args, **kwargs)
            return scoped
        return attr
