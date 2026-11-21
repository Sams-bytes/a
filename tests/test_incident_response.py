"""Phase 4: incident-response cases, timeline, and approval-gated response actions."""

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.accounts import Accounts, hash_password
from app.db import Store


@pytest.fixture
def client(tmp_path, monkeypatch):
    store = Store(str(tmp_path / "t.db"))
    monkeypatch.setattr(main, "store", store)
    monkeypatch.setattr(main, "accounts", Accounts(store))
    c = TestClient(main.app)
    c.post("/api/signup", json={"email": "admin@acme.nl", "password": "password123"})
    c.store = store
    return c


def test_case_lifecycle_and_timeline(client):
    case = client.post("/api/cases", json={"title": "Exposed RDP on server", "severity": "high",
                                           "domain": "acme.nl", "source": "finding:rdp"}).json()
    assert case["status"] == "open" and case["events"][0]["kind"] == "created"

    client.post(f"/api/cases/{case['id']}/note", json={"text": "Confirmed RDP open from outside."})
    client.post(f"/api/cases/{case['id']}/status", json={"status": "investigating"})
    got = client.get(f"/api/cases/{case['id']}").json()
    assert got["status"] == "investigating"
    kinds = [e["kind"] for e in got["events"]]
    assert kinds == ["created", "note", "status"]
    assert client.get("/api/cases").json()[0]["id"] == case["id"]


def test_action_needs_approval_before_done(client):
    case = client.post("/api/cases", json={"title": "Case", "severity": "medium"}).json()
    client.post(f"/api/cases/{case['id']}/actions", json={"action": "Close RDP at the firewall"})
    action_id = client.get(f"/api/cases/{case['id']}").json()["actions"][0]["id"]

    # Cannot jump straight to done - approval gate.
    assert client.post(f"/api/actions/{action_id}/decision", json={"status": "done"}).status_code == 409
    # Approve, then done works.
    assert client.post(f"/api/actions/{action_id}/decision", json={"status": "approved"}).status_code == 200
    assert client.post(f"/api/actions/{action_id}/decision", json={"status": "done"}).status_code == 200
    # Deciding an already-decided action is a conflict.
    assert client.post(f"/api/actions/{action_id}/decision", json={"status": "rejected"}).status_code == 409
    action = client.get(f"/api/cases/{case['id']}").json()["actions"][0]
    assert action["status"] == "done"


def test_only_admin_can_approve(client):
    # Add a non-admin member to the same org and log them into a second client.
    org = client.store.list_orgs()[0]["id"]
    member = client.store.create_user("member@acme.nl", *hash_password("password123"))
    client.store.add_membership(org, member["id"], "member")
    member_cli = TestClient(main.app)
    member_cli.post("/api/login", json={"email": "member@acme.nl", "password": "password123"})

    case = client.post("/api/cases", json={"title": "Case", "severity": "low"}).json()
    member_cli.post(f"/api/cases/{case['id']}/actions", json={"action": "Disable the account"})
    aid = client.get(f"/api/cases/{case['id']}").json()["actions"][0]["id"]
    # Member proposed it but cannot approve it.
    assert member_cli.post(f"/api/actions/{aid}/decision", json={"status": "approved"}).status_code == 403
    assert client.post(f"/api/actions/{aid}/decision", json={"status": "approved"}).status_code == 200


def test_cases_are_org_scoped(client, monkeypatch):
    client.post("/api/cases", json={"title": "A's case", "severity": "high"})
    other = TestClient(main.app)
    other.post("/api/signup", json={"email": "b@beta.nl", "password": "password123"})
    assert other.get("/api/cases").json() == []


def test_validation(client):
    assert client.post("/api/cases", json={"title": "  ", "severity": "high"}).status_code == 422
    assert client.post("/api/cases", json={"title": "x", "severity": "nope"}).status_code == 422
    case = client.post("/api/cases", json={"title": "x"}).json()
    assert client.post(f"/api/cases/{case['id']}/status", json={"status": "weird"}).status_code == 422
    assert client.post("/api/cases/999/note", json={"text": "hi"}).status_code == 404
