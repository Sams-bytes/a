"""Customer accounts: passwords, login sessions, organisations (tenants).

Why this exists (Phase 1 foundation): until now Aegis was single-user - one
shared pile of domains and scans. A real product gives every customer their own
locked drawer. This module builds the lock:

  * Passwords are never stored. We keep a one-way SCRAMBLE (a scrypt hash) plus a
    random salt. Logging in re-scrambles what you typed and compares - so a stolen
    aegis.db reveals no passwords.
  * A login is remembered with a SIGNED COOKIE: "<user_id>.<expiry>.<signature>".
    The signature is an HMAC made with a server-only secret, so the browser cannot
    forge or change it. No cookie, bad signature or past expiry -> not logged in.
  * An ORGANISATION is the tenant (the drawer). A user belongs to one or more orgs
    via a membership with a role (admin / member / viewer). All customer data in
    the rest of Aegis is scoped to an org id.

Pure standard library (hashlib, hmac, secrets) - no new dependency, so the
double-click launcher still needs no setup.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time

from app.db import Store

SESSION_COOKIE = "aegis_session"
SESSION_MAX_AGE = 14 * 24 * 3600          # 14 days
_SCRYPT = dict(n=2 ** 14, r=8, p=1, dklen=32)   # cost parameters for hashlib.scrypt
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class AuthError(ValueError):
    """Bad sign-up / login input (duplicate email, wrong password, weak password…)."""


# ---- passwords -------------------------------------------------------------
def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """Return (hash_hex, salt_hex). A fresh random salt unless one is given."""
    salt = salt or secrets.token_hex(16)
    h = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt), **_SCRYPT)
    return h.hex(), salt


def verify_password(password: str, pw_hash: str, pw_salt: str) -> bool:
    calc, _ = hash_password(password, pw_salt)
    return hmac.compare_digest(calc, pw_hash)   # constant-time: no timing leak


# ---- session cookies -------------------------------------------------------
def _sign(secret: str, message: str) -> str:
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def issue_session(user_id: int, secret: str, max_age: int = SESSION_MAX_AGE) -> str:
    """A signed cookie value proving this is user_id, valid for max_age seconds."""
    expiry = int(time.time()) + max_age
    message = f"{user_id}.{expiry}"
    return f"{message}.{_sign(secret, message)}"


def read_session(cookie: str | None, secret: str) -> int | None:
    """The user id inside a valid, unexpired, correctly-signed cookie - else None."""
    if not cookie or cookie.count(".") != 2:
        return None
    user_part, expiry_part, sig = cookie.split(".")
    message = f"{user_part}.{expiry_part}"
    if not hmac.compare_digest(sig, _sign(secret, message)):
        return None                       # forged or tampered
    try:
        if int(expiry_part) < time.time():
            return None                   # expired
        return int(user_part)
    except ValueError:
        return None


# ---- the accounts service --------------------------------------------------
class Accounts:
    """Sign up, log in, and resolve the user behind a cookie. Wraps the Store."""

    def __init__(self, store: Store):
        self.store = store
        # One server secret, generated once and kept in aegis.db so logins survive
        # restarts. AEGIS_SECRET (env) overrides it for multi-server deployments.
        import os
        self.secret = os.environ.get("AEGIS_SECRET") or store.get_or_create_secret(
            "session_key", lambda: secrets.token_hex(32))

    def register(self, email: str, password: str, org_name: str | None = None) -> dict:
        """Create a user + their first organisation (they become its admin)."""
        email = (email or "").strip().lower()
        if not _EMAIL_RE.match(email):
            raise AuthError("Enter a valid email address.")
        if len(password or "") < 8:
            raise AuthError("Password must be at least 8 characters.")
        if self.store.get_user_by_email(email):
            raise AuthError("That email already has an account. Try logging in.")
        pw_hash, pw_salt = hash_password(password)
        user = self.store.create_user(email, pw_hash, pw_salt)
        org = self.store.create_org(org_name or f"{email.split('@')[0]}'s organisation")
        self.store.add_membership(org["id"], user["id"], "admin")
        return user

    def authenticate(self, email: str, password: str) -> dict:
        """Return the user row for correct credentials, else raise AuthError."""
        email = (email or "").strip().lower()
        user = self.store.get_user_by_email(email)
        # Always run a hash even when the user is unknown, so timing doesn't reveal
        # which emails exist.
        if user is None:
            hash_password(password or "")
            raise AuthError("Wrong email or password.")
        if not verify_password(password or "", user["pw_hash"], user["pw_salt"]):
            raise AuthError("Wrong email or password.")
        return user

    def user_from_cookie(self, cookie: str | None) -> dict | None:
        uid = read_session(cookie, self.secret)
        return self.store.get_user(uid) if uid is not None else None

    def cookie_for(self, user_id: int) -> str:
        return issue_session(user_id, self.secret)
