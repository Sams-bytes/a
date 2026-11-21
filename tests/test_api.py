import socket
import threading

import pytest
from fastapi.testclient import TestClient

from app.db import Store


class FakeDNS(dict):
    def __call__(self, domain):
        return self.get(domain, [])


@pytest.fixture
def client(tmp_path, make_client):
    dns = FakeDNS()
    c = make_client(Store(str(tmp_path / "t.db")), txt_lookup=dns)
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
    try:  # something already on port 21 (e.g. tools/fake_service.py) would answer instead of us
        socket.create_connection(("127.0.0.1", 21), timeout=0.5).close()
        pytest.skip("port 21 is already in use on this computer")
    except OSError:
        pass
    srv = socket.socket()  # no SO_REUSEADDR: on Windows it lets two programs share a port
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


def test_monitoring_api(client, monkeypatch):
    from app import scanner
    ports = {"list": [80]}
    monkeypatch.setattr(scanner, "scan", lambda d, **_: {
        "domain": d, "ips": ["127.0.0.1"], "findings": [], "score": 100,
        "open_ports": [{"port": p, "service": "x", "banner": ""} for p in ports["list"]]})

    d = client.post("/api/domains", json={"domain": "localhost"}).json()
    assert d["monitor"] is True and d["next_scan_due"] is None   # never scanned -> due now

    assert client.post("/api/monitor/run-now").json()[0]["status"] == "scanned"
    ports["list"] = [80, 5432]
    client.post("/api/monitor/run-now")
    alerts = client.get("/api/alerts").json()
    assert len(alerts) == 1 and alerts[0]["seen_at"] is None
    assert "New open port 5432" in alerts[0]["details"][0]

    client.post("/api/alerts/seen?domain=localhost")
    assert client.get("/api/alerts").json()[0]["seen_at"] is not None

    row = client.get("/api/domains").json()[0]
    assert row["next_scan_due"] is not None                      # scanned -> due in 7 days
    assert client.patch("/api/domains/localhost", json={"monitor": False}).json()["monitor"] is False
    assert client.post("/api/monitor/run-now").json() == []      # monitoring off -> nothing scanned
    assert client.patch("/api/domains/nope.nl", json={"monitor": True}).status_code == 404
