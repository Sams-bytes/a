import pytest


@pytest.fixture(autouse=True)
def predictable_engines(monkeypatch):
    """Tests use the built-in port scanner and no live NVD calls, even when Nmap is
    installed or the laptop is online. Tests that need Nmap/NVD behaviour fake it."""
    monkeypatch.setenv("AEGIS_ENGINE", "builtin")
    monkeypatch.setenv("AEGIS_CVE_LIVE", "0")
