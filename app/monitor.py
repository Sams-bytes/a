"""Automatic weekly scans + change alerts.

How it works:
  * A background thread (a second worker inside the server) wakes up at start
    and then every 15 minutes, and asks: which monitored domains were last
    scanned longer ago than the interval (7 days by default)?
  * For each such domain it FIRST re-checks the DNS ownership record. If the
    owner removed it, we stop - consent can expire, and scanning without it is
    illegal. Only then does it scan.
  * Every scan is compared with the previous one (app/changes.py). If something
    got worse - a new open port, a new finding, a lower score - an alert is
    stored and shown in the dashboard.

Limitation: the thread lives inside the Aegis server, so it only runs while
Aegis is running. Because it checks at startup, a laptop that was closed for a
week catches up as soon as Aegis starts again.

Settings (environment variables):
  AEGIS_SCAN_INTERVAL_HOURS   default 168 (= 7 days)
  AEGIS_SCHEDULER=0           turn the background thread off
"""

from __future__ import annotations

import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Callable

from app import cve, hosting, scanner, subdomains
from app.changes import compare, describe, is_bad
from app.db import Store, now
from app.verification import DNSUnavailable, VerificationService

CHECK_EVERY_S = 15 * 60


def interval_from_env() -> timedelta:
    return timedelta(hours=float(os.environ.get("AEGIS_SCAN_INTERVAL_HOURS", "168")))


def scheduler_enabled() -> bool:
    return os.environ.get("AEGIS_SCHEDULER", "1") != "0"


def log(msg: str) -> None:
    print(f"[monitor] {msg}", flush=True)


# One lock per domain, so a manual scan and an automatic scan of the same
# domain never run at the same time (their "what changed" would get mixed up).
_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


def _lock_for(domain: str) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(domain, threading.Lock())


# Indirections so tests can swap in fakes without touching the real modules.
def lookup_provider(domain: str, store: Store) -> str | None:
    return hosting.classify(scanner.resolve(domain), store)


discover_subdomains = subdomains.discover


def check_hosting(store: Store, domain: str) -> str:
    """Look up who hosts `domain` and remember it. Returns '' when no provider was found."""
    provider = lookup_provider(domain, store) or ""
    store.set_hosting(domain, provider=provider)
    return provider


def decide_mode(store: Store, domain: str) -> tuple[str, str | None]:
    """'full' only for localhost, servers the owner confirmed as their own, or IPs that
    belong to no known hosting provider. Everything else gets a light scan."""
    if domain == "localhost":
        return "full", None
    row = store.get_domain(domain) or {}
    if row.get("hosting") == "own":
        return "full", row.get("hosting_provider")
    provider = check_hosting(store, domain)
    if row.get("hosting") == "shared" or provider:
        return "light", provider or row.get("hosting_provider")
    return "full", None


def run_discovery(store: Store, domain: str, alert: bool = False) -> dict:
    """Discover subdomains, save them, and (for automatic runs) alert on anything new."""
    before = {s["name"]: s["status"] for s in store.list_subdomains(domain)}
    res = discover_subdomains(domain, store)
    new = store.save_subdomains(domain, res["subdomains"])
    new_takeovers = [s["name"] for s in res["subdomains"]
                     if s["status"] == "takeover_risk" and before.get(s["name"]) != "takeover_risk"]
    lines = [f"New subdomain appeared: {n}" for n in new] if before else []
    lines += [f"Subdomain takeover risk: {n} points to a service that no longer exists" for n in new_takeovers]
    if alert and lines:
        store.add_alert(domain, "warning", f"Subdomain changes on {domain}", lines)
    return {**res, "new": new if before else []}


def run_scan(store: Store, domain: str, source: str = "manual") -> dict:
    """The one place scans happen: scan, compare with last time, save, alert."""
    with _lock_for(domain):
        previous = store.latest_scan(domain)
        started = now()
        mode, provider = decide_mode(store, domain)
        result = scanner.scan(domain, matcher=cve.Matcher(store), mode=mode, provider=provider)
        changes = compare(previous["result"] if previous else None, result)
        result["changes"] = changes
        scan_id = store.add_scan(domain, started, result, source)
        # Manual scans: you're looking at the screen already. Automatic scans
        # happen while nobody watches, so bad changes become an alert.
        if source == "scheduled" and is_bad(changes):
            store.add_alert(domain, "warning", f"Something changed on {domain}",
                            describe(changes), scan_id)
        return store.get_scan(scan_id)


def next_due(domain_row: dict, interval: timedelta) -> datetime | None:
    """When the next automatic scan is due (None = due now, never scanned)."""
    last = domain_row.get("last_scan")
    if not last:
        return None
    return datetime.fromisoformat(last) + interval


def due_domains(store: Store, interval: timedelta, at: datetime | None = None) -> list[str]:
    at = at or datetime.now(timezone.utc)
    out = []
    for d in store.monitored_domains():
        due = next_due(d, interval)
        if due is None or due <= at:
            out.append(d["domain"])
    return out


def run_due(store: Store, verifier: VerificationService, interval: timedelta,
            force: bool = False) -> list[dict]:
    """Scan every domain that is due (or every monitored domain when force=True)."""
    domains = ([d["domain"] for d in store.monitored_domains()] if force
               else due_domains(store, interval))
    report = []
    for domain in domains:
        try:
            still_owned = verifier.reverify(domain)
        except DNSUnavailable:
            log(f"{domain}: DNS unreachable, will try again later")
            report.append({"domain": domain, "status": "skipped", "reason": "DNS unreachable"})
            continue
        if not still_owned:
            log(f"{domain}: ownership record is gone - monitoring stopped, NOT scanning")
            store.mark_unverified(domain)
            store.add_alert(domain, "stopped", f"Monitoring stopped for {domain}", [
                "The DNS TXT record that proves ownership (aegis-verify=...) is no longer there.",
                "Aegis only scans domains with proven ownership, so automatic scans have stopped.",
                "If you still own this domain, add the record again and press Check verification.",
            ])
            report.append({"domain": domain, "status": "stopped"})
            continue
        log(f"{domain}: scanning")
        scan = run_scan(store, domain, "scheduled")
        row = store.get_domain(domain) or {}
        if domain != "localhost" and not row.get("parent"):
            try:
                found = run_discovery(store, domain, alert=True)
                log(f"{domain}: {len(found['subdomains'])} subdomains known, {len(found['new'])} new")
            except Exception as e:  # discovery problems must not stop monitoring
                log(f"{domain}: subdomain discovery failed: {e!r}")
        lines = describe(scan["result"]["changes"])
        log(f"{domain}: score {scan['score']}" + (f" - {'; '.join(lines)}" if lines else " - no changes"))
        report.append({"domain": domain, "status": "scanned", "scan_id": scan["id"], "score": scan["score"]})
    return report


class Scheduler:
    """Background thread that runs run_due() at start and then every CHECK_EVERY_S."""

    def __init__(self, get_store: Callable[[], Store], get_verifier: Callable[[], VerificationService],
                 interval: timedelta, check_every_s: float = CHECK_EVERY_S):
        self._get_store, self._get_verifier = get_store, get_verifier
        self.interval, self.check_every_s = interval, check_every_s
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="aegis-monitor", daemon=True)

    def start(self) -> None:
        log(f"started - automatic scans every {self.interval}, checking every {int(self.check_every_s // 60)} min")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()  # wakes the thread immediately instead of waiting 15 min
        self._thread.join(timeout=5)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                run_due(self._get_store(), self._get_verifier(), self.interval)
            except Exception as e:  # never let one bad scan kill the scheduler
                log(f"error: {e!r}")
            self._stop.wait(self.check_every_s)
