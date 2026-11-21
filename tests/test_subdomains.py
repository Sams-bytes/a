import httpx
import pytest
from fastapi.testclient import TestClient

import app.main as main
from app import monitor, scanner, subdomains
from app.db import Store
from app.verification import VerificationService


class FakeDNS:
    """records: {(name, type): [answers]}; names in `nx` don't exist; wildcard answers any other A query."""

    def __init__(self, records, nx=(), wildcard=None):
        self.records, self.nx, self.wildcard = records, set(nx), wildcard

    def query(self, name, rtype):
        if (name, rtype) in self.records:
            return self.records[(name, rtype)]
        if name in self.nx:
            return None
        if rtype == "A" and self.wildcard and name.endswith(".example.nl"):
            return [self.wildcard]
        return None if rtype == "A" and not any(k[0] == name for k in self.records) else []


def fake_ct(names_crt, names_spot):
    def get(url, params=None, **kw):
        req = httpx.Request("GET", url)
        if "crt.sh" in url:
            return httpx.Response(200, json=[{"name_value": "\n".join(names_crt)}], request=req)
        return httpx.Response(200, json=[{"dns_names": names_spot}], request=req)
    return get


RECORDS = {
    ("www.example.nl", "A"): ["198.51.100.1"],
    ("mail.example.nl", "A"): ["198.51.100.2"],
    ("example.nl", "MX"): ["10 mail.example.nl"],
    ("vpn.example.nl", "A"): ["198.51.100.3"],
    ("shop.example.nl", "CNAME"): ["oldshop.myshopify.com"],
    ("blog.example.nl", "CNAME"): ["example.github.io"],
    ("blog.example.nl", "A"): ["185.199.108.153"],
    ("example.github.io", "A"): ["185.199.108.153"],
}


def classify(ips):
    return "GitHub" if "185.199.108.153" in ips else None


def test_discovery_finds_merges_and_labels():
    dns = FakeDNS(RECORDS, nx={"oldshop.myshopify.com", "legacy.example.nl"})
    http = fake_ct(["example.nl", "*.example.nl", "WWW.example.nl", "legacy.example.nl", "evil.com"],
                   ["www.example.nl", "shop.example.nl"])
    res = subdomains.discover("example.nl", resolver=dns, http_get=http, classify=classify)
    rows = {r["name"]: r for r in res["subdomains"]}
    assert set(rows) == {"www.example.nl", "mail.example.nl", "vpn.example.nl", "shop.example.nl",
                         "blog.example.nl", "legacy.example.nl"}
    assert rows["www.example.nl"]["sources"] == ["certificates", "guess"]
    assert "dns" in rows["mail.example.nl"]["sources"]
    assert rows["vpn.example.nl"]["sources"] == ["guess"]
    assert rows["shop.example.nl"]["status"] == "takeover_risk" and rows["shop.example.nl"]["provider"] == "Shopify"
    assert res["subdomains"][0]["name"] == "shop.example.nl"           # takeover risks first
    assert rows["blog.example.nl"]["status"] == "ok" and rows["blog.example.nl"]["provider"] == "GitHub Pages"
    assert rows["legacy.example.nl"]["status"] == "no_address"          # from old certificates, gone now
    assert res["sources"]["crt.sh"] and res["sources"]["certspotter"] and not res["sources"]["wildcard_dns"]


def test_wildcard_dns_does_not_create_120_fake_subdomains():
    dns = FakeDNS({("www.example.nl", "A"): ["198.51.100.1"]}, wildcard="203.0.113.99")
    res = subdomains.discover("example.nl", resolver=dns, http_get=fake_ct([], []), classify=lambda ips: None)
    assert res["sources"]["wildcard_dns"] is True
    assert [r["name"] for r in res["subdomains"]] == ["www.example.nl"]


def test_certificate_logs_offline_still_uses_dns():
    def down(url, **kw):
        raise httpx.ConnectError("offline")
    res = subdomains.discover("example.nl", resolver=FakeDNS(RECORDS), http_get=down, classify=lambda ips: None)
    assert res["sources"]["crt.sh"] is False and any(r["name"] == "www.example.nl" for r in res["subdomains"])


# ---- API + rules ------------------------------------------------------------------
@pytest.fixture
def client(tmp_path, monkeypatch):
    store = Store(str(tmp_path / "s.db"))
    dns = {}
    monkeypatch.setattr(main, "store", store)
    monkeypatch.setattr(main, "verifier", VerificationService(store, txt_lookup=lambda d: dns.get(d, [])))
    c = TestClient(main.app)
    d = c.post("/api/domains", json={"domain": "dam-bv.com"}).json()
    dns["dam-bv.com"] = [d["record_value"]]
    c.post("/api/domains/dam-bv.com/verify")
    c.store, c.dns = store, dns
    return c


def fake_discovery(rows):
    return lambda domain, store=None: {"subdomains": rows, "sources": {"crt.sh": True}}


WWW = {"name": "www.dam-bv.com", "sources": ["certificates"], "ips": ["77.37.83.28"], "cname": None,
       "provider": "Hostinger", "status": "ok"}
OLD = {"name": "old.dam-bv.com", "sources": ["dns"], "ips": [], "cname": "dam.herokuapp.com",
       "provider": "Heroku", "status": "takeover_risk"}


def test_discover_and_monitor_flow(client, monkeypatch):
    monkeypatch.setattr(monitor, "discover_subdomains", fake_discovery([WWW, OLD]))
    r = client.post("/api/domains/dam-bv.com/discover").json()
    assert [s["name"] for s in r["subdomains"]] == ["old.dam-bv.com", "www.dam-bv.com"]
    assert r["new"] == []                                     # first discovery is the baseline

    assert client.post("/api/domains/dam-bv.com/subdomains/old.dam-bv.com/monitor").status_code == 409
    child = client.post("/api/domains/dam-bv.com/subdomains/www.dam-bv.com/monitor").json()
    assert child["parent"] == "dam-bv.com" and child["verified"] and child["scan_mode"] == "light"
    assert client.get("/api/domains/dam-bv.com/subdomains").json()[1]["monitored"] is True

    client.delete("/api/domains/dam-bv.com")                  # parent removed -> child + list gone
    assert client.get("/api/domains").json() == []
    assert client.get("/api/domains/dam-bv.com/subdomains").json() == []


def test_discovery_needs_verified_root(client):
    client.post("/api/domains", json={"domain": "someone-else.nl"})
    assert client.post("/api/domains/someone-else.nl/discover").status_code == 403
    client.post("/api/domains", json={"domain": "localhost"})
    assert client.post("/api/domains/localhost/discover").status_code == 400


def test_new_subdomain_raises_alert_on_automatic_run(client, monkeypatch):
    monkeypatch.setattr(monitor, "discover_subdomains", fake_discovery([WWW]))
    monitor.run_discovery(client.store, "dam-bv.com", alert=True)
    assert client.store.list_alerts() == []                   # baseline
    monkeypatch.setattr(monitor, "discover_subdomains", fake_discovery([WWW, {**WWW, "name": "test2.dam-bv.com"}, OLD]))
    res = monitor.run_discovery(client.store, "dam-bv.com", alert=True)
    assert sorted(res["new"]) == ["old.dam-bv.com", "test2.dam-bv.com"]
    lines = client.store.list_alerts()[0]["details"]
    assert "New subdomain appeared: test2.dam-bv.com" in lines
    assert any("takeover risk: old.dam-bv.com" in l for l in lines)


def test_hosting_decides_light_or_full(client, monkeypatch):
    calls = []
    monkeypatch.setattr(scanner, "scan", lambda d, **kw: calls.append(kw["mode"]) or
                        {"domain": d, "ips": [], "open_ports": [], "findings": [], "score": 100})
    monkeypatch.setattr(monitor, "lookup_provider", lambda d, store=None: "Hostinger")
    client.post("/api/domains/dam-bv.com/scan")
    assert calls[-1] == "light"                               # shared hosting -> no port scan
    assert client.get("/api/domains").json()[0]["hosting_provider"] == "Hostinger"

    r = client.patch("/api/domains/dam-bv.com", json={"hosting": "own"})
    assert r.status_code == 400                               # must confirm explicitly
    r = client.patch("/api/domains/dam-bv.com", json={"hosting": "own", "confirm": True}).json()
    assert r["scan_mode"] == "full" and r["hosting_confirmed_at"]
    client.post("/api/domains/dam-bv.com/scan")
    assert calls[-1] == "full"

    monkeypatch.setattr(monitor, "lookup_provider", lambda d, store=None: None)
    client.patch("/api/domains/dam-bv.com", json={"hosting": "shared"})
    client.post("/api/domains/dam-bv.com/scan")
    assert calls[-1] == "light"                               # owner said shared -> light


def test_light_scan_never_port_scans(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("port scanner must not run in light mode")
    monkeypatch.setattr(scanner, "collect_ports", boom)
    monkeypatch.setattr(scanner, "resolve", lambda d: ["77.37.83.28"])
    monkeypatch.setattr(scanner, "probe_port", lambda d, p, t: None)
    r = scanner.scan("dam-bv.com", mode="light", provider="Hostinger")
    assert r["mode"] == "light" and "Hostinger" in r["engine"] and r["open_ports"] == []


def test_child_ownership_follows_parent(client):
    store = client.store
    store.save_subdomains("dam-bv.com", [WWW])
    client.post("/api/domains/dam-bv.com/subdomains/www.dam-bv.com/monitor")
    v = main.verifier
    assert v.reverify("www.dam-bv.com") is True
    client.dns["dam-bv.com"] = []                             # parent's TXT record removed
    assert v.reverify("www.dam-bv.com") is False              # -> child loses permission too
