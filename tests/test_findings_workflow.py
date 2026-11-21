"""Phase 2b: risk scoring + the org-wide findings worklist with remediation status."""

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app import risk
from app.accounts import Accounts
from app.db import Store


# ---- risk scoring ----------------------------------------------------------
def test_likelihood_prefers_kev_then_epss_then_severity():
    assert risk.likelihood({"cves": [{"kev": True}], "severity": "low"}) == 1.0
    assert risk.likelihood({"epss": 0.4, "severity": "low"}) == 0.4
    assert risk.likelihood({"severity": "critical"}) == 0.5   # no CVE -> severity guess


def test_risk_score_combines_impact_and_likelihood():
    quiet = {"cvss": 9.0, "severity": "critical"}             # severe, not known-exploited
    hot = {"cvss": 7.0, "severity": "high", "cves": [{"kev": True}]}  # exploited now
    assert risk.risk_score(hot) > risk.risk_score(quiet)      # likelihood wins the tie-break
    assert risk.risk_score({"cvss": 0, "severity": "info"}) == 0
    assert 0 <= risk.risk_score({"cvss": 10, "severity": "critical", "cves": [{"kev": True}]}) <= 100


def test_risk_tier_bands():
    assert risk.risk_tier(85) == "critical" and risk.risk_tier(50) == "high"
    assert risk.risk_tier(25) == "medium" and risk.risk_tier(5) == "low"


# ---- the worklist API ------------------------------------------------------
@pytest.fixture
def client(tmp_path, monkeypatch):
    store = Store(str(tmp_path / "t.db"))
    monkeypatch.setattr(main, "store", store)
    monkeypatch.setattr(main, "accounts", Accounts(store))
    c = TestClient(main.app)
    c.post("/api/signup", json={"email": "a@acme.nl", "password": "password123"})
    # Seed a verified domain with a saved scan straight through the org-scoped store.
    org = main.store.memberships_for_user(main.store.get_user_by_email("a@acme.nl")["id"])[0]["org_id"]
    from app.db import OrgStore
    s = OrgStore(store, org)
    s.add_domain("acme.nl", "tok"); s.mark_verified("acme.nl")
    s.add_scan("acme.nl", "2026-01-01T00:00:00+00:00", {"score": 50, "open_ports": [], "findings": [
        {"key": "cve:apache:x", "title": "Apache: 3 known vulns", "severity": "high", "cvss": 7.5,
         "epss": 0.6, "cves": [{"kev": True}]},
        {"key": "rule:tcp:443:hsts-header-missing", "title": "HSTS header missing", "severity": "low", "cvss": 3.7},
        {"key": "note", "title": "SSH is open", "severity": "info", "cvss": 0.0},
    ]})
    return c


def test_findings_worklist_scored_and_sorted(client):
    data = client.get("/api/findings").json()
    titles = [f["title"] for f in data["findings"]]
    assert "SSH is open" not in titles                        # info rows are left off the worklist
    assert data["findings"][0]["title"].startswith("Apache")  # highest risk first
    assert data["findings"][0]["risk"] > data["findings"][1]["risk"]
    assert data["findings"][0]["kev"] is True
    assert data["counts"]["open"] == 2


def test_set_and_reflect_status(client):
    client.post("/api/findings/status", json={"domain": "acme.nl", "key": "cve:apache:x",
                                              "status": "accepted", "note": "mitigated by WAF"})
    data = client.get("/api/findings").json()
    apache = next(f for f in data["findings"] if f["key"] == "cve:apache:x")
    assert apache["status"] == "accepted" and apache["note"] == "mitigated by WAF"
    assert data["counts"]["accepted"] == 1
    # Accepted/fixed drop below open in the worklist ordering.
    assert data["findings"][-1]["key"] == "cve:apache:x"


def test_bad_status_rejected(client):
    assert client.post("/api/findings/status",
                       json={"domain": "acme.nl", "key": "x", "status": "whatever"}).status_code == 422
