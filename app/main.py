"""Aegis - one app: web dashboard + API + scanner.

Run:   start.bat   (Windows, double-click)
  or:  uvicorn app.main:app
Open:  http://127.0.0.1:8000
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app import scanner
from app.db import Store, now
from app.verification import InvalidDomain, NotVerified, VerificationService, record_value

STATIC = Path(__file__).parent / "static"

app = FastAPI(title="Aegis", version="0.2.0",
              description="Attack-surface monitoring for EU SMEs. Scans only verified domains.")
app.mount("/static", StaticFiles(directory=STATIC), name="static")

store = Store()
verifier = VerificationService(store)


class DomainIn(BaseModel):
    domain: str


def _domain_out(row: dict) -> dict:
    return {
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
    started = now()
    result = scanner.scan(domain)
    scan_id = store.add_scan(domain, started, result)
    return store.get_scan(scan_id)


@app.get("/api/domains/{domain}/scans")
def list_scans(domain: str):
    return store.list_scans(domain)


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int):
    s = store.get_scan(scan_id)
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    return s
