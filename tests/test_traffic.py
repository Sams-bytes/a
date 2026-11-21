import pytest
from fastapi.testclient import TestClient

import app.main as main
from app import traffic
from app.db import Store

NETSTAT = """
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    192.168.1.144:1298     3.115.218.185:9443     ESTABLISHED     6900
  TCP    192.168.1.144:1299     3.115.218.185:9443     ESTABLISHED     6900
  TCP    192.168.1.144:4027     57.144.223.32:5222     ESTABLISHED     5672
  TCP    127.0.0.1:3000         127.0.0.1:49281        ESTABLISHED     33720
  TCP    100.86.72.43:443       100.86.72.43:19912     ESTABLISHED     17280
  TCP    192.168.1.144:5000     8.8.8.8:443            ESTABLISHED     6900
  UDP    0.0.0.0:5353           *:*                                    999
"""

TASKLIST = '''"chrome.exe","6900","Console","1","200,000 K"
"WhatsApp.exe","5672","Console","1","100,000 K"
"node.exe","33720","Console","1","50,000 K"
'''


def test_parse_netstat():
    rows = parse = traffic.parse_netstat(NETSTAT)
    est = [r for r in rows if r["state"] == "ESTABLISHED"]
    assert len(est) == 6
    r = est[0]
    assert r["remote_ip"] == "3.115.218.185" and r["remote_port"] == "9443" and r["pid"] == "6900"


def test_parse_tasklist():
    assert traffic.parse_tasklist(TASKLIST) == {"6900": "chrome.exe", "5672": "WhatsApp.exe", "33720": "node.exe"}


def test_is_public():
    assert traffic.is_public("3.115.218.185") and traffic.is_public("8.8.8.8")
    for priv in ["127.0.0.1", "192.168.1.1", "10.0.0.5", "100.86.72.43", "169.254.1.1", "::1"]:
        assert not traffic.is_public(priv)


def test_snapshot_groups_public_only(monkeypatch):
    monkeypatch.setattr(traffic, "_collect_windows", lambda: (traffic.parse_netstat(NETSTAT), traffic.parse_tasklist(TASKLIST)))
    monkeypatch.setattr(traffic, "_collect_posix", lambda: (traffic.parse_netstat(NETSTAT), traffic.parse_tasklist(TASKLIST)))
    monkeypatch.setattr(traffic.hosting, "lookup", lambda ip, store=None, http_get=None:
                        {"org": "Amazon AWS" if ip.startswith("3.") else "Google" if ip == "8.8.8.8" else "Meta"})
    snap = traffic.snapshot()
    flows = {(f["program"], f["remote_ip"]): f for f in snap["flows"]}
    # localhost, LAN and Tailscale/CGNAT dropped; node.exe (localhost only) gone.
    assert set(flows) == {("chrome.exe", "3.115.218.185"), ("chrome.exe", "8.8.8.8"), ("WhatsApp.exe", "57.144.223.32")}
    assert flows[("chrome.exe", "3.115.218.185")]["count"] == 2        # two connections grouped
    assert flows[("chrome.exe", "3.115.218.185")]["org"] == "Amazon AWS"
    assert flows[("WhatsApp.exe", "57.144.223.32")]["ports"] == ["5222"]
    assert all("node" not in f["program"] for f in snap["flows"])


def test_endpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "store", Store(str(tmp_path / "t.db")))
    monkeypatch.setattr(main.traffic, "snapshot", lambda store: {"captured_at": "now", "flows": [], "connections": 0})
    r = TestClient(main.app).get("/api/traffic").json()
    assert r["connections"] == 0 and r["flows"] == []
