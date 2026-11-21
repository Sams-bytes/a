"""Domain ownership verification via a DNS TXT token.

Why this exists: Aegis must only ever scan domains the customer actually owns.
Scanning someone else's servers without permission is illegal in the EU
(e.g. Dutch Criminal Code art. 138ab, German StGB §202c). So before any scan,
the customer proves ownership the same way Google Search Console does:

  1. We generate a random token for their domain.
  2. They add a DNS TXT record:  aegis-verify=<token>
  3. We look up the domain's TXT records. If the token is there, only someone
     controlling the domain's DNS could have put it there -> verified.

Exception: "localhost" (your own computer) is always allowed, so you can
practise on your own machine.
"""

from __future__ import annotations

import re
import secrets
from typing import Callable, Iterable

import dns.exception
import dns.resolver

from app.db import Store

TOKEN_PREFIX = "aegis-verify="
SELF_TEST_HOSTS = {"localhost"}

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")


class InvalidDomain(ValueError):
    pass


class NotVerified(PermissionError):
    pass


class DNSUnavailable(RuntimeError):
    """DNS could not be asked (offline, timeout). NOT the same as 'record missing'."""


def normalize_domain(raw: str) -> str:
    """Turn user input like 'https://WWW.Example.nl/path' into 'www.example.nl'."""
    d = raw.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)
    d = d.split("/")[0].split(":")[0].rstrip(".")
    if d in SELF_TEST_HOSTS:
        return d
    if not _DOMAIN_RE.match(d):
        raise InvalidDomain(f"'{raw}' is not a valid domain name")
    return d


def new_token() -> str:
    return secrets.token_hex(16)  # 128 random bits - impossible to guess


def lookup_txt(domain: str) -> list[str]:
    """All TXT record strings for a domain ([] if it has none).

    Raises DNSUnavailable when DNS could not be reached, so callers never mistake
    "my Wi-Fi is down" for "the owner removed the record".
    """
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as e:
        raise DNSUnavailable(str(e)) from e
    return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]


def record_value(token: str) -> str:
    return f"{TOKEN_PREFIX}{token}"


class VerificationService:
    def __init__(self, store: Store, txt_lookup: Callable[[str], Iterable[str]] = lookup_txt):
        self.store = store
        self._lookup = txt_lookup

    def start(self, raw_domain: str) -> dict:
        domain = normalize_domain(raw_domain)
        existing = self.store.get_domain(domain)
        if existing:
            return existing  # same token if asked twice, so instructions stay valid
        row = self.store.add_domain(domain, new_token())
        if domain in SELF_TEST_HOSTS:
            self.store.mark_verified(domain)
            row = self.store.get_domain(domain)
        return row

    def check(self, raw_domain: str) -> dict:
        domain = normalize_domain(raw_domain)
        row = self.store.get_domain(domain)
        if row is None:
            raise KeyError(domain)
        if not row["verified_at"]:
            try:
                records = [r.strip() for r in self._lookup(domain)]
            except DNSUnavailable:
                return row  # couldn't check right now; stays unverified, user can retry
            if record_value(row["token"]) in records:
                self.store.mark_verified(domain)
                row = self.store.get_domain(domain)
        return row

    def reverify(self, domain: str) -> bool:
        """Is the TXT record STILL there? Asked before every automatic scan.

        Consent can expire: a domain gets sold, or the owner removes the record.
        Returns False only when DNS answered and the record is gone.
        Raises DNSUnavailable when DNS could not be asked at all.
        """
        if domain in SELF_TEST_HOSTS:
            return True
        row = self.store.get_domain(domain)
        if not row:
            return False
        if row.get("parent"):  # a monitored subdomain is covered by its parent's record
            return self.reverify(row["parent"])
        records = [r.strip() for r in self._lookup(domain)]
        return record_value(row["token"]) in records

    def require_verified(self, raw_domain: str) -> str:
        domain = normalize_domain(raw_domain)
        row = self.store.get_domain(domain)
        if not row or not row["verified_at"]:
            raise NotVerified(domain)
        return domain
