"""Projects = assessment engagements with a written authorisation, org-scoped."""

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.accounts import Accounts
from app.db import OrgStore, Store


# ---- storage layer ---------------------------------------------------------
def test_projects_are_org_scoped(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    a, b = OrgStore(store, 11), OrgStore(store, 22)
    p = a.create_project("Acme pentest", authorized_by="CISO Jane", scope_note="web only")
    assert p["authorized_by"] == "CISO Jane" and p["authorized_at"]
    assert [x["name"] for x in a.list_projects()] == ["Acme pentest"]
    assert b.list_projects() == []                      # other org sees nothing
    assert b.get_project(p["id"]) is None


def test_domain_cannot_join_another_orgs_project(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    a, b = OrgStore(store, 11), OrgStore(store, 22)
    p = a.create_project("Acme")
    b.add_domain("b.example", "tok")
    with pytest.raises(ValueError):
        b.set_domain_project("b.example", p["id"])      # p belongs to org A


# ---- API -------------------------------------------------------------------
@pytest.fixture
def app_env(tmp_path, monkeypatch):
    store = Store(str(tmp_path / "t.db"))
    monkeypatch.setattr(main, "store", store)
    monkeypatch.setattr(main, "accounts", Accounts(store))
    c = TestClient(main.app)
    c.post("/api/signup", json={"email": "a@acme.nl", "password": "password123"})
    return c


def test_create_and_assign_project_via_api(app_env):
    c = app_env
    p = c.post("/api/projects", json={"name": "Q1 assessment", "authorized_by": "Jane",
                                      "scope_note": "externally facing only"}).json()
    assert p["name"] == "Q1 assessment" and p["authorized_by"] == "Jane"
    assert c.get("/api/projects").json()[0]["domain_count"] == 0
    c.post("/api/domains", json={"domain": "localhost"})
    row = c.post("/api/domains/localhost/project", json={"project_id": p["id"]}).json()
    assert row["project_id"] == p["id"]
    assert c.get("/api/projects").json()[0]["domain_count"] == 1
    # Detach again.
    row = c.post("/api/domains/localhost/project", json={"project_id": None}).json()
    assert row["project_id"] is None


def test_create_project_is_audited_and_needs_a_name(app_env):
    c = app_env
    assert c.post("/api/projects", json={"name": "  "}).status_code == 422
    c.post("/api/projects", json={"name": "Engagement 1", "authorized_by": "Jane"})
    assert "create_project" in [e["action"] for e in c.get("/api/audit").json()]
