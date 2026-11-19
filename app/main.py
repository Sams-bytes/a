"""Aegis API.

Run locally:   uvicorn app.main:app --reload
Then open:     http://127.0.0.1:8000/docs
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.verification import InvalidDomain, VerificationService

app = FastAPI(
    title="Aegis",
    description="Attack-surface monitoring for EU SMEs. Scans only verified domains.",
    version="0.1.0",
)

service = VerificationService()


class DomainIn(BaseModel):
    domain: str


class ChallengeOut(BaseModel):
    domain: str
    verified: bool
    record_type: str = "TXT"
    record_name: str
    record_value: str
    instructions: str


def _to_out(ch) -> ChallengeOut:
    return ChallengeOut(
        domain=ch.domain,
        verified=ch.verified,
        record_name=ch.domain,
        record_value=ch.record_value,
        instructions=(
            "Verified - this domain may be scanned."
            if ch.verified
            else f"Add a DNS TXT record on {ch.domain} with value "
                 f"'{ch.record_value}', wait a few minutes, then call /verify/check."
        ),
    )


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/verify/start", response_model=ChallengeOut)
def verify_start(body: DomainIn):
    try:
        return _to_out(service.start(body.domain))
    except InvalidDomain as e:
        raise HTTPException(status_code=422, detail=str(e))


@app.post("/verify/check", response_model=ChallengeOut)
def verify_check(body: DomainIn):
    try:
        return _to_out(service.check(body.domain))
    except InvalidDomain as e:
        raise HTTPException(status_code=422, detail=str(e))
    except KeyError:
        raise HTTPException(status_code=404, detail="Call /verify/start for this domain first.")
