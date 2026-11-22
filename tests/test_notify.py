"""Email alerts: build the message, send only when enabled, stay tenant-isolated.

The network send (notify._transport) is replaced with a fake in every test, so
no real email is ever sent.
"""

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app import monitor, notify
from app.accounts import Accounts
from app.db import OrgStore, Store


@pytest.fixture
def outbox(monkeypatch):
    """A configured outbox whose 'send' just records the EmailMessage."""
    sent = []
    monkeypatch.setenv("AEGIS_SMTP_HOST", "smtp.test")
    monkeypatch.setenv("AEGIS_SMTP_FROM", "alerts@aegis.test")
    monkeypatch.setenv("AEGIS_BASE_URL", "http://aegis.test")
    monkeypatch.setattr(notify, "_transport", lambda cfg, msg: sent.append(msg))
    return sent


# ---- the notify module -----------------------------------------------------
def test_configured_reflects_env(monkeypatch):
    monkeypatch.delenv("AEGIS_SMTP_HOST", raising=False)
    monkeypatch.setattr(notify, "ENV_FILE", notify.Path("does-not-exist.env"))
    assert notify.configured() is False
    monkeypatch.setenv("AEGIS_SMTP_HOST", "smtp.test")
    monkeypatch.setenv("AEGIS_SMTP_FROM", "a@b.c")
    assert notify.configured() is True


def test_send_alert_builds_message(outbox):
    notify.send_alert("owner@acme.nl", "acme.nl", "warning",
                      "Something changed on acme.nl", ["New open port 3389", "Score dropped"])
    assert len(outbox) == 1
    msg = outbox[0]
    assert msg["To"] == "owner@acme.nl"
    assert msg["From"] == "alerts@aegis.test"
    assert "acme.nl" in msg["Subject"]
    body = msg.get_content()
    assert "New open port 3389" in body and "Score dropped" in body
    assert "http://aegis.test" in body               # dashboard link included


def test_send_test_email(outbox):
    notify.send_test("owner@acme.nl")
    assert "Test alert" in outbox[0]["Subject"]


def test_send_without_outbox_raises(monkeypatch):
    monkeypatch.delenv("AEGIS_SMTP_HOST", raising=False)
    monkeypatch.setattr(notify, "ENV_FILE", notify.Path("does-not-exist.env"))
    with pytest.raises(RuntimeError):
        notify.send_test("owner@acme.nl")


# ---- the monitor hook (where alerts actually trigger email) ----------------
def _org_store(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    return store, OrgStore(store, 1)


def test_email_alert_only_when_enabled_and_addressed(tmp_path, monkeypatch):
    _, s = _org_store(tmp_path)
    sent = []
    monkeypatch.setattr(notify, "send_alert", lambda *a: sent.append(a))

    # No address, not enabled -> nothing.
    monitor.email_alert(s, "acme.nl", "warning", "t", ["x"])
    assert sent == []

    # Address set but alerts off -> still nothing.
    s.set_org_settings(alert_email="owner@acme.nl", alerts_enabled=False)
    monitor.email_alert(s, "acme.nl", "warning", "t", ["x"])
    assert sent == []

    # Enabled with an address -> sent.
    s.set_org_settings(alerts_enabled=True)
    monitor.email_alert(s, "acme.nl", "warning", "t", ["x"])
    assert len(sent) == 1


def test_email_alert_swallows_send_errors(tmp_path, monkeypatch):
    _, s = _org_store(tmp_path)
    s.set_org_settings(alert_email="owner@acme.nl", alerts_enabled=True)

    def boom(*a):
        raise RuntimeError("smtp down")
    monkeypatch.setattr(notify, "send_alert", boom)
    monitor.email_alert(s, "acme.nl", "warning", "t", ["x"])   # must not raise


def test_email_alert_is_tenant_isolated(tmp_path, monkeypatch):
    store = Store(str(tmp_path / "t.db"))
    a, b = OrgStore(store, 1), OrgStore(store, 2)
    a.set_org_settings(alert_email="a@a.nl", alerts_enabled=True)
    sent = []
    monkeypatch.setattr(notify, "send_alert", lambda to, *a: sent.append(to))
    # Org B has no settings of its own, so B's alert must not reach A's address.
    monitor.email_alert(b, "b.nl", "warning", "t", ["x"])
    assert sent == []


# ---- the API ---------------------------------------------------------------
@pytest.fixture
def client(tmp_path, monkeypatch):
    store = Store(str(tmp_path / "t.db"))
    monkeypatch.setattr(main, "store", store)
    monkeypatch.setattr(main, "accounts", Accounts(store))
    c = TestClient(main.app)
    c.post("/api/signup", json={"email": "a@acme.nl", "password": "password123"})
    return c


def test_settings_roundtrip_and_validation(client):
    assert client.get("/api/alerts/settings").json()["alert_email"] is None
    saved = client.post("/api/alerts/settings",
                        json={"alert_email": "owner@acme.nl", "alerts_enabled": True}).json()
    assert saved["alert_email"] == "owner@acme.nl" and saved["alerts_enabled"] is True
    assert client.get("/api/alerts/settings").json()["alert_email"] == "owner@acme.nl"
    assert client.post("/api/alerts/settings", json={"alert_email": "not-an-email"}).status_code == 422


def test_test_button_sends(client, outbox):
    client.post("/api/alerts/settings", json={"alert_email": "owner@acme.nl", "alerts_enabled": True})
    r = client.post("/api/alerts/test")
    assert r.status_code == 200 and r.json()["sent"] is True
    assert len(outbox) == 1 and outbox[0]["To"] == "owner@acme.nl"
    assert "alert_test" in [e["action"] for e in client.get("/api/audit").json()]


def test_test_button_needs_address(client, outbox):
    assert client.post("/api/alerts/test").status_code == 422
