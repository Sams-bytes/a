"""Phase 5: the AI security analyst - opt-in, offline fallback, guardrails."""

import json

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app import ai
from app.accounts import Accounts
from app.db import OrgStore, Store

CTX = {"domains": [{"domain": "acme.nl", "score": 45, "findings": [
    {"title": "Apache: known vulnerabilities", "severity": "critical", "risk": 90, "status": "open",
     "epss": 0.6, "kev": True},
    {"title": "HSTS header missing", "severity": "low", "risk": 10, "status": "open"},
]}], "open_cases": 1}


# ---- opt-in + offline fallback ---------------------------------------------
def test_analyst_disabled_without_key():
    a = ai.Analyst(api_key="")
    assert a.available() is False
    assert a.status() == {"enabled": False, "provider": None, "model": None}
    out = a.summary(CTX)
    assert out["mode"] == "offline" and "Apache" in out["text"] and "without AI" in out["text"]


def test_offline_summary_is_deterministic_and_prioritised():
    text = ai.offline_summary(CTX)
    assert "1 critical" in text and "Apache" in text
    assert text == ai.offline_summary(CTX)             # deterministic


def test_offline_ask_explains_it_is_off():
    out = ai.Analyst(api_key="").ask("what is my biggest risk?", CTX)
    assert out["mode"] == "offline" and "not enabled" in out["text"].lower()


# ---- the provider call (faked, never real network) -------------------------
def test_ai_path_builds_a_guarded_request():
    seen = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        seen["url"], seen["headers"], seen["json"] = url, headers, json

        class R:
            def raise_for_status(self): pass
            def json(self): return {"content": [{"type": "text", "text": "Your top risk is Apache."}]}
        return R()

    a = ai.Analyst(api_key="sk-test", model="claude-sonnet-5-5", http_post=fake_post)
    assert a.available() is True
    out = a.summary(CTX)
    assert out["mode"] == "ai" and out["text"] == "Your top risk is Apache."
    assert seen["headers"]["x-api-key"] == "sk-test"
    assert seen["json"]["model"] == "claude-sonnet-5-5"
    assert "untrusted" in seen["json"]["system"].lower()          # prompt-injection guard present
    assert "acme.nl" in seen["json"]["messages"][0]["content"]    # the org data was sent
    assert "not instructions" in seen["json"]["messages"][0]["content"]


# ---- context builder is isolation-safe -------------------------------------
def test_build_context_only_sees_the_given_store(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    a = OrgStore(store, 1)
    a.add_domain("acme.nl", "tok"); a.mark_verified("acme.nl")
    a.add_scan("acme.nl", "2026-01-01T00:00:00+00:00", {"score": 70, "findings": [
        {"key": "x", "title": "SMBv1 is enabled", "severity": "critical", "cvss": 9.3},
        {"key": "y", "title": "SSH is open", "severity": "info", "cvss": 0.0}]})
    ctx = ai.build_context(a)
    assert [d["domain"] for d in ctx["domains"]] == ["acme.nl"]
    titles = [f["title"] for f in ctx["domains"][0]["findings"]]
    assert "SMBv1 is enabled" in titles and "SSH is open" not in titles   # info dropped
    assert ai.build_context(OrgStore(store, 999))["domains"] == []        # other org sees nothing


# ---- API -------------------------------------------------------------------
@pytest.fixture
def client(tmp_path, monkeypatch):
    store = Store(str(tmp_path / "t.db"))
    monkeypatch.setattr(main, "store", store)
    monkeypatch.setattr(main, "accounts", Accounts(store))
    c = TestClient(main.app)
    c.post("/api/signup", json={"email": "a@acme.nl", "password": "password123"})
    return c


def test_ai_endpoints_offline(client):
    assert client.get("/api/ai/status").json()["enabled"] is False
    s = client.post("/api/ai/summary").json()
    assert s["mode"] == "offline"
    a = client.post("/api/ai/ask", json={"question": "biggest risk?"}).json()
    assert a["mode"] == "offline"
    assert "ai_summary" in [e["action"] for e in client.get("/api/audit").json()]
    assert client.post("/api/ai/ask", json={"question": "  "}).status_code == 422
