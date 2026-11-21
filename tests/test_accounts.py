import time

import pytest

from app import accounts
from app.accounts import Accounts, AuthError
from app.db import Store


@pytest.fixture
def acc(tmp_path):
    return Accounts(Store(str(tmp_path / "t.db")))


# ---- password hashing ------------------------------------------------------
def test_hash_is_not_the_password():
    h, salt = accounts.hash_password("correct horse battery")
    assert "correct" not in h and h != "correct horse battery"
    assert len(salt) == 32  # 16 random bytes, hex


def test_verify_password_roundtrip():
    h, salt = accounts.hash_password("s3cret-pass")
    assert accounts.verify_password("s3cret-pass", h, salt)
    assert not accounts.verify_password("wrong-pass", h, salt)


def test_same_password_different_salt_gives_different_hash():
    h1, s1 = accounts.hash_password("same")
    h2, s2 = accounts.hash_password("same")
    assert s1 != s2 and h1 != h2  # salts stop two equal passwords looking equal


# ---- session cookies -------------------------------------------------------
def test_session_roundtrip():
    token = accounts.issue_session(42, "server-secret")
    assert accounts.read_session(token, "server-secret") == 42


def test_tampered_or_wrong_secret_rejected():
    token = accounts.issue_session(42, "server-secret")
    assert accounts.read_session(token, "other-secret") is None
    assert accounts.read_session("99." + token.split(".", 1)[1], "server-secret") != 99
    assert accounts.read_session("garbage", "server-secret") is None
    assert accounts.read_session(None, "server-secret") is None


def test_expired_session_rejected():
    token = accounts.issue_session(7, "server-secret", max_age=-1)
    assert accounts.read_session(token, "server-secret") is None


# ---- register / authenticate ----------------------------------------------
def test_register_creates_user_org_and_admin_membership(acc):
    user = acc.register("alice@example.com", "password123", "Acme BV")
    assert user["email"] == "alice@example.com"
    mems = acc.store.memberships_for_user(user["id"])
    assert len(mems) == 1 and mems[0]["role"] == "admin" and mems[0]["org_name"] == "Acme BV"


def test_register_rejects_bad_input(acc):
    with pytest.raises(AuthError):
        acc.register("not-an-email", "password123")
    with pytest.raises(AuthError):
        acc.register("bob@example.com", "short")        # < 8 chars
    acc.register("bob@example.com", "password123")
    with pytest.raises(AuthError):
        acc.register("bob@example.com", "password123")  # duplicate email


def test_authenticate(acc):
    acc.register("carol@example.com", "password123")
    assert acc.authenticate("carol@example.com", "password123")["email"] == "carol@example.com"
    with pytest.raises(AuthError):
        acc.authenticate("carol@example.com", "nope")
    with pytest.raises(AuthError):
        acc.authenticate("ghost@example.com", "password123")


def test_cookie_resolves_back_to_user(acc):
    user = acc.register("dave@example.com", "password123")
    cookie = acc.cookie_for(user["id"])
    assert acc.user_from_cookie(cookie)["email"] == "dave@example.com"
    assert acc.user_from_cookie("bad.cookie.value") is None


def test_secret_persists_across_restart(tmp_path):
    path = str(tmp_path / "t.db")
    a1 = Accounts(Store(path))
    cookie = a1.cookie_for(a1.register("e@example.com", "password123")["id"])
    a2 = Accounts(Store(path))                 # new server, same db file
    assert a2.user_from_cookie(cookie) is not None
