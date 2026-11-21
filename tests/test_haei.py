"""Phase 3: Historical Attack Exposure Intelligence."""

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app import haei
from app.accounts import Accounts
from app.db import OrgStore, Store


# ---- the incident library is well-formed -----------------------------------
def test_incident_library_is_sourced_and_tagged():
    incidents = haei.load_incidents()
    assert len(incidents) >= 12
    for inc in incidents:
        assert inc["source"].startswith("http")           # every entry cites a source
        assert inc["confidence"] in ("confirmed", "reported")
        assert isinstance(inc["signals"], list)           # may be empty (library-only)
        for s in inc["signals"]:
            assert s in haei.SIGNAL_LABELS                 # no stray signal names


# ---- signal derivation -----------------------------------------------------
def test_finding_signals():
    assert "smb_v1" in haei.finding_signals({"key": "nse:smbv1:445", "title": "SMBv1 enabled"})
    cve = {"kind": "cve", "title": "Apache: vulns", "cves": [{"kev": True}]}
    assert haei.finding_signals(cve) == {"exploit_public_app", "known_exploited_cve"}
    assert "exposed_rdp" in haei.finding_signals({"title": "Port 3389 open", "port": 3389})
    assert "exposed_database" in haei.finding_signals({"title": "Port 5432", "port": 5432})
    assert haei.finding_signals({"title": "HSTS header missing", "port": 443}) == set()


def test_match_surfaces_wannacry_on_smbv1_and_nothing_on_clean():
    signals = haei.collect_signals([("srv.nl", {"key": "nse:smbv1:445", "title": "SMBv1 enabled"})])
    names = [m["name"] for m in haei.match(signals)]
    assert "WannaCry" in names and "NotPetya" in names
    assert haei.match(haei.collect_signals([])) == []     # no signals -> no matches
    # Phishing/supply-chain incidents never match from an external scan.
    assert "Maastricht University" not in names and "SolarWinds (SUNBURST)" not in names


def test_match_ranks_by_number_of_shared_signals():
    signals = haei.collect_signals([
        ("a.nl", {"kind": "cve", "title": "x", "cves": [{"kev": True}]}),   # 2 signals
        ("a.nl", {"title": "Port 3389", "port": 3389}),                      # rdp
    ])
    matches = haei.match(signals)
    assert matches[0]["shared_signals"]                                      # best match first
    assert all("evidence" in m for m in matches)


# ---- API -------------------------------------------------------------------
@pytest.fixture
def client(tmp_path, monkeypatch):
    store = Store(str(tmp_path / "t.db"))
    monkeypatch.setattr(main, "store", store)
    monkeypatch.setattr(main, "accounts", Accounts(store))
    c = TestClient(main.app)
    c.post("/api/signup", json={"email": "a@acme.nl", "password": "password123"})
    uid = store.get_user_by_email("a@acme.nl")["id"]
    s = OrgStore(store, store.memberships_for_user(uid)[0]["org_id"])
    s.add_domain("acme.nl", "tok"); s.mark_verified("acme.nl")
    s.add_scan("acme.nl", "2026-02-01T00:00:00+00:00", {"score": 40, "open_ports": [], "findings": [
        {"key": "nse:smbv1:445", "title": "SMBv1 is enabled", "severity": "critical", "cvss": 9.3},
    ]})
    return c


def test_haei_endpoint_matches_and_library(client):
    data = client.get("/api/haei").json()
    assert any(s["id"] == "smb_v1" for s in data["signals"])
    names = [m["name"] for m in data["matches"]]
    assert "WannaCry" in names
    wanna = next(m for m in data["matches"] if m["name"] == "WannaCry")
    assert wanna["evidence"][0]["domain"] == "acme.nl" and wanna["controls"]
    assert len(client.get("/api/incidents").json()) >= 12


def test_haei_skips_fixed_findings(client):
    client.post("/api/findings/status", json={"domain": "acme.nl", "key": "nse:smbv1:445", "status": "fixed"})
    assert client.get("/api/haei").json()["matches"] == []
