"""Aegis - one app: web dashboard + API + scanner.

Run:   start.bat   (Windows, double-click)
  or:  uvicorn app.main:app
Open:  http://127.0.0.1:8000
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app import monitor
from app.db import Store
from app.verification import (InvalidDomain, NotVerified, VerificationService, new_token,
                              normalize_domain, record_value)

STATIC = Path(__file__).parent / "static"

store = Store()
verifier = VerificationService(store)
INTERVAL = monitor.interval_from_env()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Runs when the server starts / stops. Lambdas so tests can swap store/verifier.
    sched = None
    if monitor.scheduler_enabled():
        sched = monitor.Scheduler(lambda: store, lambda: verifier, INTERVAL)
        sched.start()
    yield
    if sched:
        sched.stop()


app = FastAPI(title="Aegis", version="0.3.0", lifespan=lifespan,
              description="Attack-surface monitoring for EU SMEs. Scans only verified domains.")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


class DomainIn(BaseModel):
    domain: str


class DomainSettings(BaseModel):
    monitor: bool | None = None
    hosting: str | None = None      # 'own' | 'shared' | 'auto'
    confirm: bool = False           # required to set hosting='own'


def scan_mode(row: dict) -> str:
    """What the next scan will be: full / light / unknown (hosting not checked yet)."""
    if row["domain"] == "localhost" or row.get("hosting") == "own":
        return "full"
    if row.get("hosting") == "shared":
        return "light"
    provider = row.get("hosting_provider")
    return "unknown" if provider is None else ("light" if provider else "full")


def _domain_out(row: dict) -> dict:
    due = monitor.next_due(row, INTERVAL) if row["verified_at"] and row.get("monitor", 1) else None
    return {
        "parent": row.get("parent"),
        "hosting": row.get("hosting", "auto"),
        "hosting_provider": row.get("hosting_provider"),
        "hosting_confirmed_at": row.get("hosting_confirmed_at"),
        "scan_mode": scan_mode(row),
        "monitor": bool(row.get("monitor", 1)),
        "next_scan_due": due.isoformat(timespec="seconds") if due else None,
        "domain": row["domain"],
        "verified": bool(row["verified_at"]),
        "verified_at": row["verified_at"],
        "record_type": "TXT",
        "record_name": row["domain"],
        "record_value": record_value(row["token"]),
        "last_score": row.get("last_score"),
        "last_scan": row.get("last_scan"),
    }


def _bad_domain(e: InvalidDomain):
    raise HTTPException(status_code=422, detail=str(e))


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/domains")
def list_domains():
    return [_domain_out(r) for r in store.list_domains()]


@app.post("/api/domains")
def add_domain(body: DomainIn):
    try:
        return _domain_out(verifier.start(body.domain))
    except InvalidDomain as e:
        _bad_domain(e)


@app.delete("/api/domains/{domain}")
def delete_domain(domain: str):
    store.delete_domain(domain)
    return {"deleted": domain}


@app.post("/api/domains/{domain}/verify")
def verify_domain(domain: str):
    try:
        return _domain_out(verifier.check(domain))
    except InvalidDomain as e:
        _bad_domain(e)
    except KeyError:
        raise HTTPException(status_code=404, detail="Add this domain first.")


@app.post("/api/domains/{domain}/scan")
def scan_domain(domain: str):
    try:
        domain = verifier.require_verified(domain)
    except InvalidDomain as e:
        _bad_domain(e)
    except NotVerified:
        raise HTTPException(status_code=403,
                            detail="Domain not verified. Aegis only scans domains you have proven you own.")
    return monitor.run_scan(store, domain, "manual")


@app.patch("/api/domains/{domain}")
def update_domain(domain: str, body: DomainSettings):
    try:
        domain = normalize_domain(domain)
    except InvalidDomain as e:
        _bad_domain(e)
    if not store.get_domain(domain):
        raise HTTPException(status_code=404, detail="Add this domain first.")
    if body.monitor is not None:
        store.set_monitor(domain, body.monitor)
    if body.hosting is not None:
        if body.hosting not in ("own", "shared", "auto"):
            raise HTTPException(status_code=422, detail="hosting must be own, shared or auto")
        if body.hosting == "own" and not body.confirm:
            raise HTTPException(status_code=400, detail=(
                "Confirm that this server is yours alone (VPS or dedicated). On shared hosting a port "
                "scan would scan the provider's machine, which you are not allowed to do."))
        store.set_hosting(domain, body.hosting, confirmed=body.hosting == "own")
    return _domain_row_out(domain)


def _domain_row_out(domain: str) -> dict:
    return next(_domain_out(r) for r in store.list_domains() if r["domain"] == domain)


def _verified_root(domain: str) -> str:
    try:
        domain = normalize_domain(domain)
    except InvalidDomain as e:
        _bad_domain(e)
    row = store.get_domain(domain)
    if not row or not row["verified_at"]:
        raise HTTPException(status_code=403, detail="Verify this domain first.")
    if domain == "localhost" or row.get("parent"):
        raise HTTPException(status_code=400, detail="Subdomain discovery works on your verified main domain.")
    return domain


@app.post("/api/domains/{domain}/hosting-check")
def hosting_check(domain: str):
    """Who hosts this domain? (RDAP lookup of its IP addresses.)"""
    try:
        domain = verifier.require_verified(domain)
    except (InvalidDomain, NotVerified):
        raise HTTPException(status_code=403, detail="Verify this domain first.")
    if domain != "localhost":
        monitor.check_hosting(store, domain)
    return _domain_row_out(domain)


# ---- subdomains ------------------------------------------------------------
@app.post("/api/domains/{domain}/discover")
def discover(domain: str):
    domain = _verified_root(domain)
    res = monitor.run_discovery(store, domain, alert=False)
    return {"subdomains": store.list_subdomains(domain), "new": res["new"], "sources": res["sources"]}


@app.get("/api/domains/{domain}/subdomains")
def list_subdomains(domain: str):
    try:
        return store.list_subdomains(normalize_domain(domain))
    except InvalidDomain as e:
        _bad_domain(e)


@app.post("/api/domains/{domain}/subdomains/{sub}/monitor")
def monitor_subdomain(domain: str, sub: str):
    """Start monitoring a discovered subdomain. Ownership is covered by the parent's TXT record."""
    domain = _verified_root(domain)
    sub = normalize_domain(sub)
    found = next((s for s in store.list_subdomains(domain) if s["name"] == sub), None)
    if not found:
        raise HTTPException(status_code=404, detail="Discover subdomains first.")
    if found["status"] == "takeover_risk":
        raise HTTPException(status_code=409, detail=(
            f"{sub} points to a service that no longer exists. Remove or fix that DNS record first - "
            f"there is nothing of yours to scan there, and an attacker could claim it."))
    if not store.get_domain(sub):
        store.add_domain(sub, new_token(), parent=domain)
        store.mark_verified(sub)
        if found.get("provider"):
            store.set_hosting(sub, provider=found["provider"])
    return _domain_row_out(sub)


# ---- monitoring & alerts ---------------------------------------------------
@app.get("/api/monitor")
def monitor_status():
    return {"scheduler": monitor.scheduler_enabled(),
            "interval_hours": INTERVAL.total_seconds() / 3600,
            "check_every_minutes": monitor.CHECK_EVERY_S // 60,
            "due_now": monitor.due_domains(store, INTERVAL)}


@app.post("/api/monitor/run-now")
def monitor_run_now():
    """Run the automatic check now for every monitored domain (for demos/testing)."""
    return monitor.run_due(store, verifier, INTERVAL, force=True)


@app.get("/api/alerts")
def list_alerts():
    return store.list_alerts()


@app.post("/api/alerts/seen")
def alerts_seen(domain: str | None = None):
    store.mark_alerts_seen(domain)
    return {"ok": True}


@app.get("/api/domains/{domain}/scans")
def list_scans(domain: str):
    return store.list_scans(domain)


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int):
    s = store.get_scan(scan_id)
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    return s
