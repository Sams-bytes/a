import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.verification import InvalidDomain, VerificationService, normalize_domain


class FakeDNS:
    """Pretend DNS: a dict of domain -> list of TXT strings."""

    def __init__(self):
        self.records: dict[str, list[str]] = {}

    def __call__(self, domain):
        return self.records.get(domain, [])


@pytest.mark.parametrize("raw,expected", [
    ("example.nl", "example.nl"),
    ("  WWW.Example.NL  ", "www.example.nl"),
    ("https://shop.example.de/login?x=1", "shop.example.de"),
    ("example.com.", "example.com"),
    ("example.com:8443", "example.com"),
])
def test_normalize_ok(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "localhost", "-bad.com", "a..b.com", "10.0.0.1", "no spaces.com"])
def test_normalize_rejects(raw):
    with pytest.raises(InvalidDomain):
        normalize_domain(raw)


def test_token_must_be_in_dns():
    dns = FakeDNS()
    svc = VerificationService(txt_lookup=dns)
    ch = svc.start("devries-logistics.nl")
    assert not svc.check("devries-logistics.nl").verified

    dns.records["devries-logistics.nl"] = ["v=spf1 -all", "aegis-verify=wrongtoken"]
    assert not svc.check("devries-logistics.nl").verified

    dns.records["devries-logistics.nl"].append(ch.record_value)
    assert svc.check("devries-logistics.nl").verified
    assert svc.is_verified("DEVRIES-LOGISTICS.NL")


def test_start_twice_keeps_same_token():
    svc = VerificationService(txt_lookup=FakeDNS())
    assert svc.start("a.nl").token == svc.start("a.nl").token


def test_tokens_are_unique_per_domain():
    svc = VerificationService(txt_lookup=FakeDNS())
    assert svc.start("a.nl").token != svc.start("b.nl").token


def test_api_flow(monkeypatch):
    dns = FakeDNS()
    monkeypatch.setattr(main, "service", VerificationService(txt_lookup=dns))
    client = TestClient(main.app)

    r = client.post("/verify/start", json={"domain": "devries-logistics.nl"})
    assert r.status_code == 200
    value = r.json()["record_value"]
    assert value.startswith("aegis-verify=")

    assert client.post("/verify/check", json={"domain": "devries-logistics.nl"}).json()["verified"] is False
    dns.records["devries-logistics.nl"] = [value]
    assert client.post("/verify/check", json={"domain": "devries-logistics.nl"}).json()["verified"] is True


def test_api_errors():
    client = TestClient(main.app)
    assert client.post("/verify/start", json={"domain": "not a domain"}).status_code == 422
    assert client.post("/verify/check", json={"domain": "never-started.nl"}).status_code == 404
