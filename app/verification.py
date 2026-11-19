"""Domain ownership verification via a DNS TXT token.

Why this exists: Aegis must only ever scan domains the customer actually owns.
Scanning someone else's servers without permission is illegal in the EU
(e.g. Dutch Criminal Code art. 138ab, German StGB §202c). So before any scan,
the customer proves ownership the same way Google Search Console does:

  1. We generate a random token for their domain.
  2. They add a DNS TXT record:  aegis-verify=<token>
  3. We look up the domain's TXT records. If the token is there, only someone
     controlling the domain's DNS could have put it there -> verified.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterable

import dns.exception
import dns.resolver

TOKEN_PREFIX = "aegis-verify="

# Letters, digits, hyphens; labels separated by dots; must end in a TLD.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$"
)


class InvalidDomain(ValueError):
    pass


def normalize_domain(raw: str) -> str:
    """Turn user input like 'https://WWW.Example.nl/path' into 'www.example.nl'."""
    d = raw.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)  # drop scheme
    d = d.split("/")[0].split(":")[0]  # drop path and port
    d = d.rstrip(".")
    if not _DOMAIN_RE.match(d):
        raise InvalidDomain(f"'{raw}' is not a valid domain name")
    return d


def new_token() -> str:
    """32 random hex characters (128 bits). Impossible to guess."""
    return secrets.token_hex(16)


def lookup_txt(domain: str) -> list[str]:
    """Return all TXT record strings for a domain ([] if none / not found)."""
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout,
            dns.resolver.NoNameservers):
        return []
    out = []
    for rdata in answers:
        # A TXT record can be split into several <=255-byte chunks; join them.
        out.append(b"".join(rdata.strings).decode("utf-8", errors="replace"))
    return out


@dataclass
class Challenge:
    domain: str
    token: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    verified_at: datetime | None = None

    @property
    def record_value(self) -> str:
        return f"{TOKEN_PREFIX}{self.token}"

    @property
    def verified(self) -> bool:
        return self.verified_at is not None


class VerificationService:
    """Keeps challenges in memory. (A database replaces this later.)

    `txt_lookup` is injectable so tests can fake DNS without the internet.
    """

    def __init__(self, txt_lookup: Callable[[str], Iterable[str]] = lookup_txt):
        self._lookup = txt_lookup
        self._challenges: dict[str, Challenge] = {}

    def start(self, raw_domain: str) -> Challenge:
        domain = normalize_domain(raw_domain)
        existing = self._challenges.get(domain)
        if existing and not existing.verified:
            return existing  # same token if they ask twice, so instructions stay valid
        ch = Challenge(domain=domain, token=new_token())
        self._challenges[domain] = ch
        return ch

    def check(self, raw_domain: str) -> Challenge:
        domain = normalize_domain(raw_domain)
        ch = self._challenges.get(domain)
        if ch is None:
            raise KeyError(domain)
        if not ch.verified:
            records = [r.strip() for r in self._lookup(domain)]
            if ch.record_value in records:
                ch.verified_at = datetime.now(timezone.utc)
        return ch

    def is_verified(self, raw_domain: str) -> bool:
        ch = self._challenges.get(normalize_domain(raw_domain))
        return bool(ch and ch.verified)
