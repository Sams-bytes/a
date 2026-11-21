"""Phase 2c: the printable client report."""

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app import report
from app.accounts import Accounts
from app.db import OrgStore, Store

SCAN = {"result": {"score": 55, "findings": [
    {"key": "cve:apache", "title": "Apache: known vulnerabilities", "severity": "high",
     "cvss": 7.5, "epss": 0.6, "fix": "Update Apache.", "cves": [{"kev": True}]},
    {"key": "note", "title": "SSH is open", "severity": "info", "cvss": 0.0, "fix": "Use keys."},
]}, "finished_at": "2026-02-01T12:00:00+00:00"}


def test_render_contains_key_facts_and_escapes():
    html = report.render("Acme BV", "acme.nl", SCAN, {"cve:apache": {"status": "accepted", "note": "WAF"}})
    assert "acme.nl" in html and "Acme BV" in html
    assert "Apache: known vulnerabilities" in html and "55" in html
    assert "SSH is open" not in html          # info rows are left off the report
    assert "KEV" in html and "EPSS" in html
    assert "Accepted" in html and "WAF" in html


def test_scored_findings_orders_open_first_and_drops_info():
    rows = report.scored_findings(SCAN, {})
    assert len(rows) == 1 and rows[0]["key"] == "cve:apache"
    assert rows[0]["risk"] > 0 and rows[0]["status"] == "open"


@pytest.fixture
def client(tmp_path, monkeypatch):
    store = Store(str(tmp_path / "t.db"))
    monkeypatch.setattr(main, "store", store)
    monkeypatch.setattr(main, "accounts", Accounts(store))
    c = TestClient(main.app)
    c.post("/api/signup", json={"email": "a@acme.nl", "password": "password123"})
    uid = store.get_user_by_email("a@acme.nl")["id"]
    s = OrgStore(store, store.memberships_for_user(uid)[0]["org_id"])
    s.add_domain("acme.nl", "tok"); s.mark_verified("acme.nl")
    s.add_scan("acme.nl", "2026-02-01T00:00:00+00:00", SCAN["result"])
    return c


def test_report_endpoint(client):
    r = client.get("/report/acme.nl")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    assert "Security report" in r.text and "acme.nl" in r.text


def test_report_404_without_scan(client):
    client.post("/api/domains", json={"domain": "localhost"})   # added, never scanned
    assert client.get("/report/localhost").status_code == 404
