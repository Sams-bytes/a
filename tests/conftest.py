import pytest


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
