import pytest

from app.db import Store
from app.verification import (InvalidDomain, NotVerified, VerificationService,
                              normalize_domain, record_value)


class FakeDNS:
    """Pretend DNS: a dict of domain -> list of TXT strings."""

    def __init__(self):
        self.records: dict[str, list[str]] = {}

    def __call__(self, domain):
        return self.records.get(domain, [])


@pytest.fixture
def dns():
    return FakeDNS()


@pytest.fixture
def svc(dns, tmp_path):
    return VerificationService(Store(str(tmp_path / "t.db")), txt_lookup=dns)


@pytest.mark.parametrize("raw,expected", [
    ("example.nl", "example.nl"),
    ("  WWW.Example.NL  ", "www.example.nl"),
    ("https://shop.example.de/login?x=1", "shop.example.de"),
    ("example.com.", "example.com"),
    ("example.com:8443", "example.com"),
    ("LOCALHOST", "localhost"),
])
def test_normalize_ok(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "-bad.com", "a..b.com", "10.0.0.1", "no spaces.com", "intranet"])
def test_normalize_rejects(raw):
    with pytest.raises(InvalidDomain):
        normalize_domain(raw)


def test_token_must_be_in_dns(svc, dns):
    row = svc.start("devries-logistics.nl")
    assert not svc.check("devries-logistics.nl")["verified_at"]

    dns.records["devries-logistics.nl"] = ["v=spf1 -all", "aegis-verify=wrongtoken"]
    assert not svc.check("devries-logistics.nl")["verified_at"]

    dns.records["devries-logistics.nl"].append(record_value(row["token"]))
    assert svc.check("devries-logistics.nl")["verified_at"]
    assert svc.require_verified("DEVRIES-LOGISTICS.NL") == "devries-logistics.nl"


def test_unverified_cannot_be_scanned(svc):
    svc.start("a.nl")
    with pytest.raises(NotVerified):
        svc.require_verified("a.nl")
    with pytest.raises(NotVerified):
        svc.require_verified("never-added.nl")


def test_localhost_is_auto_verified(svc):
    assert svc.start("localhost")["verified_at"]


def test_start_twice_keeps_same_token(svc):
    assert svc.start("a.nl")["token"] == svc.start("a.nl")["token"]


def test_tokens_are_unique(svc):
    assert svc.start("a.nl")["token"] != svc.start("b.nl")["token"]
