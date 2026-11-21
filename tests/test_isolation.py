"""Tenant isolation: one organisation can never see or touch another's data.

This is SentinelSec 360's key acceptance test (spec section 15.11). We prove it
at the database layer (Store + OrgStore), because that is where isolation must
live - never only in the UI.
"""

import pytest

from app.db import OrgStore, Store
from app.verification import VerificationService

A, B = 101, 202  # two organisation ids


@pytest.fixture
def store(tmp_path):
    return Store(str(tmp_path / "t.db"))


def _seed(store, org_id, domain):
    store.add_domain(domain, "tok", org_id=org_id)
    store.mark_verified(domain, org_id=org_id)
    sid = store.add_scan(domain, "2026-01-01T00:00:00+00:00",
                         {"score": 70, "open_ports": []}, org_id=org_id)
    store.add_alert(domain, "warning", f"something on {domain}", ["line"], org_id=org_id)
    return sid


def test_list_domains_is_scoped(store):
    _seed(store, A, "a.example")
    _seed(store, B, "b.example")
    assert [d["domain"] for d in store.list_domains(A)] == ["a.example"]
    assert [d["domain"] for d in store.list_domains(B)] == ["b.example"]


def test_cannot_read_other_orgs_domain_or_scan(store):
    sid = _seed(store, A, "a.example")
    # Org B asks for A's domain and A's scan by its real id -> nothing.
    assert store.get_domain("a.example", org_id=B) is None
    assert store.get_scan(sid, org_id=B) is None
    assert store.list_scans("a.example", org_id=B) == []
    assert store.list_alerts(org_id=B) == []
    # Its real owner still sees them.
    assert store.get_domain("a.example", org_id=A)["domain"] == "a.example"
    assert store.get_scan(sid, org_id=A)["score"] == 70


def test_delete_in_one_org_cannot_touch_another(store):
    _seed(store, A, "a.example")
    _seed(store, B, "b.example")
    store.delete_domain("a.example", org_id=B)          # wrong org: no effect
    assert store.get_domain("a.example", org_id=A) is not None
    store.delete_domain("a.example", org_id=A)          # right org: gone
    assert store.get_domain("a.example", org_id=A) is None
    assert store.get_domain("b.example", org_id=B) is not None


def test_domain_cannot_be_hijacked_by_another_org(store):
    store.add_domain("shared.example", "tok", org_id=A)
    with pytest.raises(ValueError):
        store.add_domain("shared.example", "tok2", org_id=B)
    # Still owned by A, token unchanged.
    assert store.get_domain("shared.example", org_id=A)["token"] == "tok"


def test_orgstore_bakes_in_the_org(store):
    a = OrgStore(store, A)
    b = OrgStore(store, B)
    a.add_domain("a.example", "tok")
    a.mark_verified("a.example")
    assert [d["domain"] for d in a.list_domains()] == ["a.example"]
    assert b.list_domains() == []
    assert b.get_domain("a.example") is None
    # Non-scoped methods still reach through (e.g. account helpers, orgs list).
    assert a.list_orgs() == store.list_orgs()


def test_verification_service_honours_orgstore(store):
    """VerificationService given an OrgStore verifies within that org only."""
    a = VerificationService(OrgStore(store, A))
    a.start("localhost")                      # localhost auto-verifies
    assert a.require_verified("localhost") == "localhost"
    # Org A's localhost row exists under A, not under B.
    assert store.get_domain("localhost", org_id=A) is not None
    assert store.get_domain("localhost", org_id=B) is None
