"""NIS2 / GDPR readiness: evidence from scans + self-assessment -> readiness score."""

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app import compliance, report
from app.accounts import Accounts
from app.db import OrgStore, Store


def test_finding_letter():
    assert compliance.finding_letter({"nis2": "Art. 21(2)(h) cryptography & encryption"}) == "h"
    assert compliance.finding_letter({"nis2": "something else"}) is None


def test_assess_marks_gap_on_serious_finding_and_on_no_answer():
    findings = [{"title": "Weak HTTPS encryption", "severity": "high",
                 "nis2": "Art. 21(2)(h) cryptography & encryption", "domain": "acme.nl"}]
    data = compliance.assess(findings, answers={})
    h = next(m for m in data["measures"] if m["id"] == "h")
    assert h["status"] == "gap" and h["findings"]           # serious crypto finding -> gap
    a = next(m for m in data["measures"] if m["id"] == "a")
    assert a["status"] == "unknown"                          # organisational, unanswered
    assert 0 <= data["score"] <= 100 and data["total"] == 10


def test_answers_lift_a_measure_to_met():
    data = compliance.assess([], answers={"c:backups": "yes", "c:backups_tested": "yes",
                                          "c:backups_offline": "yes"})
    c = next(m for m in data["measures"] if m["id"] == "c")
    assert c["status"] == "met"
    # A single 'no' drops it back to a gap.
    data2 = compliance.assess([], answers={"c:backups": "yes", "c:backups_tested": "no",
                                           "c:backups_offline": "yes"})
    assert next(m for m in data2["measures"] if m["id"] == "c")["status"] == "gap"


def test_compliance_report_renders():
    data = compliance.assess([], answers={"c:backups": "yes"})
    html = report.render_compliance("Acme BV", data)
    assert "NIS2 / GDPR readiness" in html and "Acme BV" in html and "Art. 21(2)(c)" in html
    assert "readiness aid" in html                           # the honesty note is present


# ---- API -------------------------------------------------------------------
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
    s.add_scan("acme.nl", "2026-02-01T00:00:00+00:00", {"score": 50, "findings": [
        {"key": "tls", "title": "Weak HTTPS encryption", "severity": "high",
         "nis2": "Art. 21(2)(h) cryptography & encryption", "cvss": 7.0}]})
    return c


def test_compliance_api_and_answering(client):
    data = client.get("/api/compliance").json()
    assert data["total"] == 10
    assert next(m for m in data["measures"] if m["id"] == "h")["status"] == "gap"

    before = client.get("/api/compliance").json()["score"]
    updated = client.post("/api/compliance/answer",
                          json={"measure_id": "g", "question_id": "training", "answer": "yes"}).json()
    g = next(m for m in updated["measures"] if m["id"] == "g")
    assert g["questions"][0]["answer"] == "yes"
    assert "compliance_answer" in [e["action"] for e in client.get("/api/audit").json()]
    assert client.post("/api/compliance/answer",
                       json={"measure_id": "g", "question_id": "training", "answer": "maybe"}).status_code == 422


def test_compliance_report_endpoint(client):
    r = client.get("/report/compliance")
    assert r.status_code == 200 and "NIS2 / GDPR readiness" in r.text
