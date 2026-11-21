"""The login gate and tenant isolation, exercised through the real HTTP API."""

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.accounts import Accounts
from app.db import Store


@pytest.fixture
def app_env(tmp_path, monkeypatch):
    """A fresh app with a clean db and NO logged-in client (tests sign in themselves)."""
    store = Store(str(tmp_path / "t.db"))
    monkeypatch.setattr(main, "store", store)
    monkeypatch.setattr(main, "accounts", Accounts(store))
    return store


def test_endpoints_require_login(app_env):
    c = TestClient(main.app)
    for path in ["/api/domains", "/api/me", "/api/alerts", "/api/audit"]:
        assert c.get(path).status_code == 401
    assert c.post("/api/domains", json={"domain": "localhost"}).status_code == 401


def test_signup_login_logout_cycle(app_env):
    c = TestClient(main.app)
    r = c.post("/api/signup", json={"email": "a@acme.nl", "password": "password123", "org_name": "Acme"})
    assert r.status_code == 200 and r.json()["org_name"] == "Acme"
    assert c.get("/api/me").json()["email"] == "a@acme.nl"      # cookie now set
    c.post("/api/logout")
    assert c.get("/api/me").status_code == 401                  # cookie cleared
    # Wrong password is refused; right one works again.
    assert c.post("/api/login", json={"email": "a@acme.nl", "password": "nope"}).status_code == 401
    assert c.post("/api/login", json={"email": "a@acme.nl", "password": "password123"}).status_code == 200


def test_weak_or_duplicate_signup_rejected(app_env):
    c = TestClient(main.app)
    assert c.post("/api/signup", json={"email": "x@y.nl", "password": "short"}).status_code == 400
    c.post("/api/signup", json={"email": "x@y.nl", "password": "password123"})
    assert c.post("/api/signup", json={"email": "x@y.nl", "password": "password123"}).status_code == 400


def test_two_accounts_cannot_see_each_other(app_env):
    a = TestClient(main.app)
    a.post("/api/signup", json={"email": "a@acme.nl", "password": "password123"})
    a.post("/api/domains", json={"domain": "localhost"})
    assert [d["domain"] for d in a.get("/api/domains").json()] == ["localhost"]

    b = TestClient(main.app)   # a separate browser/account
    b.post("/api/signup", json={"email": "b@beta.nl", "password": "password123"})
    assert b.get("/api/domains").json() == []                  # sees nothing of A's
    # B cannot scan or delete A's localhost either (it's not in B's org).
    assert b.post("/api/domains/localhost/scan").status_code == 403
    b.delete("/api/domains/localhost")                         # no-op in B's org
    assert [d["domain"] for d in a.get("/api/domains").json()] == ["localhost"]


def test_audit_records_actions(app_env):
    c = TestClient(main.app)
    c.post("/api/signup", json={"email": "a@acme.nl", "password": "password123"})
    c.post("/api/domains", json={"domain": "localhost"})
    actions = [e["action"] for e in c.get("/api/audit").json()]
    assert "add_domain" in actions and "signup" in actions
