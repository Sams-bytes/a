import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app import monitor, scanner
from app.db import Store
from app.verification import DNSUnavailable, VerificationService

WEEK = timedelta(days=7)


class FakeDNS(dict):
    """domain -> list of TXT records; set .down = True to simulate no internet."""
    down = False

    def __call__(self, domain):
        if self.down:
            raise DNSUnavailable("offline")
        return self.get(domain, [])


@pytest.fixture
def env(tmp_path, monkeypatch):
    store = Store(str(tmp_path / "m.db"))
    dns = FakeDNS()
    verifier = VerificationService(store, txt_lookup=dns)
    open_ports = {"ports": [80]}  # what the fake scanner "finds"; tests change it

    def fake_scan(domain, **_):
        ports = [{"port": p, "service": f"svc{p}", "banner": ""} for p in open_ports["ports"]]
        return {"domain": domain, "ips": ["203.0.113.5"], "open_ports": ports,
                "findings": [], "score": 100}

    monkeypatch.setattr(scanner, "scan", fake_scan)
    return store, dns, verifier, open_ports


def verified(store, dns, verifier, domain="devries-logistics.nl"):
    row = verifier.start(domain)
    dns[domain] = [f"aegis-verify={row['token']}"]
    verifier.check(domain)
    return domain


def test_due_logic(env):
    store, dns, verifier, _ = env
    d = verified(store, dns, verifier)
    assert monitor.due_domains(store, WEEK) == [d]            # never scanned -> due
    monitor.run_scan(store, d, "manual")
    assert monitor.due_domains(store, WEEK) == []             # just scanned
    later = datetime.now(timezone.utc) + timedelta(days=8)
    assert monitor.due_domains(store, WEEK, at=later) == [d]  # a week later -> due again
    store.set_monitor(d, False)
    assert monitor.due_domains(store, WEEK, at=later) == []   # monitoring off


def test_unverified_domains_are_never_scheduled(env):
    store, _, verifier, _ = env
    verifier.start("someone-else.nl")
    assert monitor.due_domains(store, WEEK) == []
    assert monitor.run_due(store, verifier, WEEK, force=True) == []


def test_scheduled_scan_with_new_port_raises_alert(env):
    store, dns, verifier, ports = env
    d = verified(store, dns, verifier)
    monitor.run_due(store, verifier, WEEK)          # first scan: baseline, no alert
    assert store.list_alerts() == []
    ports["ports"] = [80, 3389]                      # someone opened Remote Desktop
    report = monitor.run_due(store, verifier, WEEK, force=True)
    assert report[0]["status"] == "scanned"
    alerts = store.list_alerts()
    assert len(alerts) == 1 and alerts[0]["level"] == "warning"
    assert any("New open port 3389" in line for line in alerts[0]["details"])
    assert store.get_scan(alerts[0]["scan_id"])["source"] == "scheduled"


def test_manual_scan_never_alerts(env):
    store, dns, verifier, ports = env
    d = verified(store, dns, verifier)
    monitor.run_scan(store, d, "manual")
    ports["ports"] = [80, 3389]
    scan = monitor.run_scan(store, d, "manual")
    assert [p["port"] for p in scan["result"]["changes"]["new_ports"]] == [3389]
    assert store.list_alerts() == []


def test_lost_ownership_stops_monitoring_without_scanning(env):
    store, dns, verifier, _ = env
    d = verified(store, dns, verifier)
    dns[d] = []                                      # owner removed the TXT record
    report = monitor.run_due(store, verifier, WEEK, force=True)
    assert report == [{"domain": d, "status": "stopped"}]
    assert store.list_scans(d) == []                 # no scan happened
    assert store.get_domain(d)["verified_at"] is None
    assert store.list_alerts()[0]["level"] == "stopped"


def test_dns_outage_skips_but_keeps_verification(env):
    store, dns, verifier, _ = env
    d = verified(store, dns, verifier)
    dns.down = True
    report = monitor.run_due(store, verifier, WEEK, force=True)
    assert report[0]["status"] == "skipped"
    assert store.get_domain(d)["verified_at"] is not None   # NOT treated as "record gone"
    assert store.list_scans(d) == [] and store.list_alerts() == []


def test_localhost_is_never_reverified(env):
    store, dns, verifier, _ = env
    verifier.start("localhost")
    dns.down = True                                  # would raise if DNS were asked
    assert monitor.run_due(store, verifier, WEEK)[0]["status"] == "scanned"


def test_migration_upgrades_an_old_database(tmp_path):
    path = str(tmp_path / "old.db")
    old = sqlite3.connect(path)                      # the schema from the first Aegis version
    old.executescript("""
        CREATE TABLE domains (domain TEXT PRIMARY KEY, token TEXT NOT NULL,
                              created_at TEXT NOT NULL, verified_at TEXT);
        CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL,
                            started_at TEXT NOT NULL, finished_at TEXT NOT NULL,
                            score INTEGER NOT NULL, result TEXT NOT NULL);
        INSERT INTO domains VALUES ('localhost', 't', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00');
        INSERT INTO scans(domain, started_at, finished_at, score, result)
            VALUES ('localhost', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:05+00:00', 75, '{"score": 75}');
    """)
    old.commit()
    old.close()

    store = Store(path)                              # opening it runs the migration
    assert store.get_domain("localhost")["monitor"] == 1
    assert store.list_scans("localhost")[0]["source"] == "manual"
    assert store.monitored_domains()[0]["domain"] == "localhost"   # old data kept
