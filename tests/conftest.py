import pytest

TEST_LOGIN = {"email": "tester@example.com", "password": "password123"}


@pytest.fixture
def make_client(monkeypatch):
    """Factory: point the app at a fresh Store (with a matching Accounts), optionally
    with fake DNS, and return a TestClient already logged in as a test user."""
    from fastapi.testclient import TestClient

    import app.main as main
    from app.accounts import Accounts

    def _make(store, txt_lookup=None):
        monkeypatch.setattr(main, "store", store)
        monkeypatch.setattr(main, "accounts", Accounts(store))
        if txt_lookup is not None:
            monkeypatch.setattr(main, "TXT_LOOKUP", txt_lookup)
        client = TestClient(main.app)
        client.post("/api/signup", json=TEST_LOGIN)   # sets the session cookie on the client
        return client

    return _make


@pytest.fixture(autouse=True)
def predictable_engines(monkeypatch):
    """Tests use the built-in port scanner and no live NVD calls, even when Nmap is
    installed or the laptop is online. Tests that need Nmap/NVD behaviour fake it."""
    monkeypatch.setenv("AEGIS_ENGINE", "builtin")
    monkeypatch.setenv("AEGIS_CVE_LIVE", "0")
    # No live hosting (RDAP) lookups or subdomain discovery: tests fake them where needed.
    from app import monitor
    monkeypatch.setattr(monitor, "lookup_provider", lambda domain, store=None: None)
    monkeypatch.setattr(monitor, "discover_subdomains", lambda domain, store=None: {"subdomains": [], "sources": {}})
