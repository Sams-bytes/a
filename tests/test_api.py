import socket
import threading

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.db import Store
from app.verification import VerificationService


class FakeDNS(dict):
    def __call__(self, domain):
        return self.get(domain, [])


@pytest.fixture
def client(tmp_path, monkeypatch):
    store = Store(str(tmp_path / "t.db"))
    dns = FakeDNS()
    monkeypatch.setattr(main, "store", store)
    monkeypatch.setattr(main, "verifier", VerificationService(store, txt_lookup=dns))
    c = TestClient(main.app)
    c.dns = dns
    return c


def test_dashboard_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "Aegis" in r.text


def test_verify_flow(client):
    d = client.post("/api/domains", json={"domain": "devries-logistics.nl"}).json()
    assert d["verified"] is False and d["record_value"].startswith("aegis-verify=")
    assert client.post("/api/domains/devries-logistics.nl/verify").json()["verified"] is False
    client.dns["devries-logistics.nl"] = [d["record_value"]]
    assert client.post("/api/domains/devries-logistics.nl/verify").json()["verified"] is True
    assert client.get("/api/domains").json()[0]["verified"] is True


def test_scan_refused_when_unverified(client):
    client.post("/api/domains", json={"domain": "someone-else.nl"})
    r = client.post("/api/domains/someone-else.nl/scan")
    assert r.status_code == 403


def test_errors(client):
    assert client.post("/api/domains", json={"domain": "not a domain"}).status_code == 422
    assert client.post("/api/domains/never-added.nl/verify").status_code == 404


def test_real_scan_of_localhost(client, monkeypatch):
    """Open a real port on this machine (pretending to be FTP) and check Aegis finds it."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.1", 21))
    except OSError:
        pytest.skip("port 21 not bindable here (needs admin rights)")
    srv.listen()

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            conn.sendall(b"220 FakeFTP 1.0 ready\r\n")
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    try:
        client.post("/api/domains", json={"domain": "localhost"})
        scan = client.post("/api/domains/localhost/scan").json()
    finally:
        srv.close()

    result = scan["result"]
    ftp = [p for p in result["open_ports"] if p["port"] == 21]
    assert ftp and "FakeFTP" in ftp[0]["banner"]
    # Local scan: FTP is reported as info, with "high if exposed" kept for context.
    assert result["local"] is True
    assert any(f["port"] == 21 and f["severity"] == "info" and f["exposed_severity"] == "high"
               for f in result["findings"])
    assert client.get("/api/domains/localhost/scans").json()[0]["score"] == result["score"]
