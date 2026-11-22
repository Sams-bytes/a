"""Aegis - one app: web dashboard + API + scanner.

Run:   start.bat   (Windows, double-click)
  or:  uvicorn app.main:app
Open:  http://127.0.0.1:8000

Accounts (Phase 1): every request is tied to a logged-in user and their
organisation. All customer data is reached through an OrgStore scoped to that
org, so one customer never sees another's. See app/accounts.py.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app import ai, compliance, haei, jobs, monitor, netmap, notify, report, risk, traffic
from app.accounts import SESSION_COOKIE, Accounts, AuthError
from app.db import OrgStore, Store
from app.verification import (InvalidDomain, NotVerified, VerificationService, lookup_txt,
                              new_token, normalize_domain, record_value)

STATIC = Path(__file__).parent / "static"

store = Store()
accounts = Accounts(store)
INTERVAL = monitor.interval_from_env()

# How the per-request verifier looks up DNS TXT records. Indirection so tests can
# swap in fake DNS (monkeypatch main.TXT_LOOKUP).
TXT_LOOKUP = lookup_txt


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Runs when the server starts / stops. The scheduler scans every org's domains.
    sched = None
    if monitor.scheduler_enabled():
        sched = monitor.Scheduler(lambda: store, INTERVAL)
        sched.start()
    yield
    if sched:
        sched.stop()


app = FastAPI(title="Aegis", version="0.4.0", lifespan=lifespan,
              description="Attack-surface monitoring for EU SMEs. Scans only verified domains.")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


# ---- request context: who is logged in, and their org-scoped store ---------
@dataclass
class Ctx:
    user: dict
    org_id: int
    org_name: str
    role: str
    store: OrgStore
    verifier: VerificationService

    def audit(self, action: str, target: str | None = None, detail: str | None = None) -> None:
        store.add_audit(self.org_id, self.user["id"], action, target, detail)


def get_ctx(request: Request) -> Ctx:
    """FastAPI dependency: resolve the logged-in user + their active organisation,
    or refuse with 401. Every data endpoint depends on this."""
    user = accounts.user_from_cookie(request.cookies.get(SESSION_COOKIE))
    if not user:
        raise HTTPException(status_code=401, detail="Please log in.")
    mems = store.memberships_for_user(user["id"])
    if not mems:
        raise HTTPException(status_code=403, detail="Your account has no organisation.")
    m = mems[0]   # one org per user for now; org switching comes later
    org_store = OrgStore(store, m["org_id"])
    return Ctx(user=user, org_id=m["org_id"], org_name=m["org_name"], role=m["role"],
               store=org_store, verifier=VerificationService(org_store, txt_lookup=TXT_LOOKUP))


class DomainIn(BaseModel):
    domain: str


class DomainSettings(BaseModel):
    monitor: bool | None = None
    hosting: str | None = None      # 'own' | 'shared' | 'auto'
    confirm: bool = False           # required to set hosting='own'


class Credentials(BaseModel):
    email: str
    password: str
    org_name: str | None = None     # only used on sign-up


class ProjectIn(BaseModel):
    name: str
    authorized_by: str | None = None
    scope_note: str | None = None


class ProjectAssign(BaseModel):
    project_id: int | None = None   # null detaches the domain from any project


class FindingStatusIn(BaseModel):
    domain: str
    key: str
    status: str                     # open | fixed | accepted | false_positive
    note: str | None = None


class CaseIn(BaseModel):
    title: str
    severity: str = "medium"        # low | medium | high | critical
    domain: str | None = None
    source: str = "manual"


class NoteIn(BaseModel):
    text: str


class CaseStatusIn(BaseModel):
    status: str                     # open | investigating | contained | closed


class ActionIn(BaseModel):
    action: str
    note: str | None = None


class DecisionIn(BaseModel):
    status: str                     # approved | rejected | done
    note: str | None = None


class AskIn(BaseModel):
    question: str


class ComplianceAnswerIn(BaseModel):
    measure_id: str
    question_id: str
    answer: str                     # yes | no | na


class AlertSettingsIn(BaseModel):
    alert_email: str | None = None      # where alert emails go ("" clears it)
    alerts_enabled: bool | None = None  # master on/off switch


CASE_STATUSES = ("open", "investigating", "contained", "closed")
SEVERITIES = ("low", "medium", "high", "critical")

analyst = ai.Analyst()


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
        "project_id": row.get("project_id"),
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


def _domain_row_out(ctx: Ctx, domain: str) -> dict:
    return next(_domain_out(r) for r in ctx.store.list_domains() if r["domain"] == domain)


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok"}


# ---- accounts: sign up / log in / who am I --------------------------------
def _session_cookie(response: Response, user_id: int) -> None:
    response.set_cookie(SESSION_COOKIE, accounts.cookie_for(user_id), max_age=14 * 24 * 3600,
                        httponly=True, samesite="lax")


@app.post("/api/signup")
def signup(body: Credentials, response: Response):
    try:
        user = accounts.register(body.email, body.password, body.org_name)
    except AuthError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _session_cookie(response, user["id"])
    org = store.memberships_for_user(user["id"])[0]
    store.add_audit(org["org_id"], user["id"], "signup", body.email)
    return {"email": user["email"], "org_name": org["org_name"], "role": org["role"]}


@app.post("/api/login")
def login(body: Credentials, response: Response):
    try:
        user = accounts.authenticate(body.email, body.password)
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))
    _session_cookie(response, user["id"])
    mems = store.memberships_for_user(user["id"])
    if mems:
        store.add_audit(mems[0]["org_id"], user["id"], "login", body.email)
    return {"email": user["email"],
            "org_name": mems[0]["org_name"] if mems else None,
            "role": mems[0]["role"] if mems else None}


@app.post("/api/logout")
def logout(response: Response, request: Request):
    user = accounts.user_from_cookie(request.cookies.get(SESSION_COOKIE))
    if user:
        mems = store.memberships_for_user(user["id"])
        if mems:
            store.add_audit(mems[0]["org_id"], user["id"], "logout", user["email"])
    response.delete_cookie(SESSION_COOKIE)
    return {"ok": True}


@app.get("/api/me")
def me(ctx: Ctx = Depends(get_ctx)):
    return {"email": ctx.user["email"], "org_name": ctx.org_name, "role": ctx.role}


@app.get("/api/audit")
def audit_log(ctx: Ctx = Depends(get_ctx)):
    return store.list_audit(ctx.org_id)


# ---- projects (assessment engagements + authorised scope) ------------------
@app.get("/api/projects")
def list_projects(ctx: Ctx = Depends(get_ctx)):
    return ctx.store.list_projects()


@app.post("/api/projects")
def create_project(body: ProjectIn, ctx: Ctx = Depends(get_ctx)):
    name = (body.name or "").strip()
    if not name:
        raise HTTPException(status_code=422, detail="A project needs a name.")
    p = ctx.store.create_project(name, body.authorized_by, body.scope_note)
    ctx.audit("create_project", name, body.authorized_by)
    return p


# ---- exposure management: all findings, risk-ranked, with remediation status --
@app.get("/api/findings")
def all_findings(ctx: Ctx = Depends(get_ctx)):
    """Every finding across this org's domains, scored by risk and tagged with its
    remediation status. The exposure-management worklist."""
    rows = []
    counts = {"open": 0, "fixed": 0, "accepted": 0, "false_positive": 0}
    for d in ctx.store.list_domains():
        scan = ctx.store.latest_scan(d["domain"])
        if not scan:
            continue
        statuses = ctx.store.finding_statuses(d["domain"])
        for f in scan["result"].get("findings", []):
            if f.get("severity") == "info":
                continue                         # the worklist is about real risk, not notes
            st = statuses.get(f["key"], {"status": "open", "note": None})
            score = risk.risk_score(f)
            rows.append({
                "domain": d["domain"], "key": f["key"], "title": f["title"],
                "severity": f["severity"], "cvss": f.get("cvss"), "epss": f.get("epss"),
                "kev": any(c.get("kev") for c in f.get("cves", [])),
                "risk": score, "risk_tier": risk.risk_tier(score),
                "status": st["status"], "note": st.get("note"), "scan_id": scan["id"],
            })
            counts[st["status"]] = counts.get(st["status"], 0) + 1
    rows.sort(key=lambda r: (r["status"] != "open", -r["risk"]))
    return {"findings": rows, "counts": counts}


# ---- incident response: cases, timeline, approval-gated actions -----------
@app.get("/api/cases")
def list_cases(ctx: Ctx = Depends(get_ctx)):
    return ctx.store.list_cases()


@app.post("/api/cases")
def create_case(body: CaseIn, ctx: Ctx = Depends(get_ctx)):
    if not (body.title or "").strip():
        raise HTTPException(status_code=422, detail="A case needs a title.")
    if body.severity not in SEVERITIES:
        raise HTTPException(status_code=422, detail=f"severity must be one of {', '.join(SEVERITIES)}")
    case = ctx.store.create_case(body.title.strip(), body.severity, body.domain, body.source, ctx.user["id"])
    ctx.audit("open_case", f"#{case['id']} {body.title.strip()}")
    return case


@app.get("/api/cases/{case_id}")
def get_case(case_id: int, ctx: Ctx = Depends(get_ctx)):
    case = ctx.store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    return case


def _case_or_404(ctx: Ctx, fn, *args):
    try:
        return fn(*args)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/cases/{case_id}/note")
def add_case_note(case_id: int, body: NoteIn, ctx: Ctx = Depends(get_ctx)):
    if not (body.text or "").strip():
        raise HTTPException(status_code=422, detail="Note text is required.")
    _case_or_404(ctx, ctx.store.add_case_event, case_id, ctx.user["id"], "note", body.text.strip())
    return ctx.store.get_case(case_id)


@app.post("/api/cases/{case_id}/status")
def set_case_status(case_id: int, body: CaseStatusIn, ctx: Ctx = Depends(get_ctx)):
    if body.status not in CASE_STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of {', '.join(CASE_STATUSES)}")
    _case_or_404(ctx, ctx.store.set_case_status, case_id, body.status, ctx.user["id"])
    ctx.audit("case_status", f"#{case_id}", body.status)
    return ctx.store.get_case(case_id)


@app.post("/api/cases/{case_id}/actions")
def propose_action(case_id: int, body: ActionIn, ctx: Ctx = Depends(get_ctx)):
    if not (body.action or "").strip():
        raise HTTPException(status_code=422, detail="Describe the response action.")
    _case_or_404(ctx, ctx.store.add_action, case_id, body.action.strip(), ctx.user["id"], body.note)
    return ctx.store.get_case(case_id)


@app.post("/api/actions/{action_id}/decision")
def decide_action(action_id: int, body: DecisionIn, ctx: Ctx = Depends(get_ctx)):
    if body.status not in ("approved", "rejected", "done"):
        raise HTTPException(status_code=422, detail="decision must be approved, rejected or done")
    # Disruptive actions need an authorised approver: only an org admin may approve/reject.
    if body.status in ("approved", "rejected") and ctx.role != "admin":
        raise HTTPException(status_code=403, detail="Only an organisation admin can approve or reject an action.")
    try:
        action = ctx.store.decide_action(action_id, body.status, ctx.user["id"], body.note)
    except ValueError as e:
        # "already decided" / "must be approved first" are 409 conflicts; unknown is 404.
        code = 404 if "No such action" in str(e) else 409
        raise HTTPException(status_code=code, detail=str(e))
    ctx.audit("action_decision", action["action"], body.status)
    return ctx.store.get_case(action["case_id"])


# ---- NIS2 / GDPR readiness ------------------------------------------------
def _org_open_findings(ctx: Ctx) -> list[dict]:
    """This org's current open, non-info findings (for compliance mapping)."""
    out = []
    for d in ctx.store.list_domains():
        scan = ctx.store.latest_scan(d["domain"])
        if not scan:
            continue
        statuses = ctx.store.finding_statuses(d["domain"])
        for f in scan["result"].get("findings", []):
            if f.get("severity") == "info":
                continue
            if statuses.get(f["key"], {}).get("status") in ("fixed", "accepted", "false_positive"):
                continue
            out.append({"title": f["title"], "severity": f["severity"],
                        "nis2": f.get("nis2"), "domain": d["domain"]})
    return out


def _assess(ctx: Ctx) -> dict:
    caps = {"incidents": bool(ctx.store.list_cases()),
            "monitoring": any(d.get("monitor") for d in ctx.store.list_domains())}
    return compliance.assess(_org_open_findings(ctx), ctx.store.compliance_answers(), caps)


@app.get("/api/compliance")
def compliance_status(ctx: Ctx = Depends(get_ctx)):
    return _assess(ctx)


@app.post("/api/compliance/answer")
def compliance_answer(body: ComplianceAnswerIn, ctx: Ctx = Depends(get_ctx)):
    if body.answer not in ("yes", "no", "na"):
        raise HTTPException(status_code=422, detail="answer must be yes, no or na")
    if not any(m["id"] == body.measure_id for m in compliance.MEASURES):
        raise HTTPException(status_code=404, detail="Unknown measure.")
    ctx.store.set_compliance_answer(f"{body.measure_id}:{body.question_id}", body.answer)
    ctx.audit("compliance_answer", f"{body.measure_id}:{body.question_id}", body.answer)
    return _assess(ctx)


@app.get("/report/compliance", response_class=HTMLResponse, include_in_schema=False)
def compliance_report(ctx: Ctx = Depends(get_ctx)):
    ctx.audit("compliance_report")
    return report.render_compliance(ctx.org_name, _assess(ctx))


# ---- email alerts ----------------------------------------------------------
def _alerts_payload(ctx: Ctx) -> dict:
    s = ctx.store.get_org_settings()
    # `outbox_ready` tells the UI whether the operator has configured an SMTP
    # outbox at all - without one, no email can be sent no matter the settings.
    return {"alert_email": s["alert_email"], "alerts_enabled": s["alerts_enabled"],
            "outbox_ready": notify.configured()}


@app.get("/api/alerts/settings")
def alerts_settings(ctx: Ctx = Depends(get_ctx)):
    return _alerts_payload(ctx)


@app.post("/api/alerts/settings")
def alerts_settings_save(body: AlertSettingsIn, ctx: Ctx = Depends(get_ctx)):
    email = body.alert_email
    if email is not None:
        email = email.strip()
        if email and "@" not in email:
            raise HTTPException(status_code=422, detail="That does not look like an email address.")
    ctx.store.set_org_settings(alert_email=email, alerts_enabled=body.alerts_enabled)
    ctx.audit("alert_settings", ctx.store.get_org_settings()["alert_email"],
              "on" if ctx.store.get_org_settings()["alerts_enabled"] else "off")
    return _alerts_payload(ctx)


@app.post("/api/alerts/test")
def alerts_test(ctx: Ctx = Depends(get_ctx)):
    to = ctx.store.get_org_settings()["alert_email"]
    if not to:
        raise HTTPException(status_code=422, detail="Add an email address first, then send a test.")
    try:
        notify.send_test(to)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))
    ctx.audit("alert_test", to)
    return {"sent": True, "to": to}


# ---- AI security analyst (opt-in, guarded) --------------------------------
@app.get("/api/ai/status")
def ai_status(ctx: Ctx = Depends(get_ctx)):
    return analyst.status()


@app.post("/api/ai/summary")
def ai_summary(ctx: Ctx = Depends(get_ctx)):
    result = _ai_call(ctx, analyst.summary, ai.build_context(ctx.store))
    ctx.audit("ai_summary", None, result["mode"])
    return result


@app.post("/api/ai/ask")
def ai_ask(body: AskIn, ctx: Ctx = Depends(get_ctx)):
    if not (body.question or "").strip():
        raise HTTPException(status_code=422, detail="Ask a question.")
    result = _ai_call(ctx, lambda c: analyst.ask(body.question.strip(), c), ai.build_context(ctx.store))
    ctx.audit("ai_ask", body.question.strip()[:80], result["mode"])
    return result


def _ai_call(ctx: Ctx, fn, context):
    try:
        return fn(context)
    except Exception as e:   # provider down / bad key: fail gracefully, never 500 the UI
        raise HTTPException(status_code=502, detail=f"The AI analyst could not be reached: {e}")


# ---- Historical Attack Intelligence (HAEI) --------------------------------
@app.get("/api/incidents")
def incident_library(ctx: Ctx = Depends(get_ctx)):
    """The library of documented historical breaches (reference data)."""
    return haei.load_incidents()


@app.get("/api/haei")
def attack_intelligence(ctx: Ctx = Depends(get_ctx)):
    """Compare this org's current findings to how real breaches began."""
    pairs = []
    for d in ctx.store.list_domains():
        scan = ctx.store.latest_scan(d["domain"])
        if not scan:
            continue
        statuses = ctx.store.finding_statuses(d["domain"])
        for f in scan["result"].get("findings", []):
            # Skip findings the team has already dealt with.
            if statuses.get(f["key"], {}).get("status") in ("fixed", "false_positive"):
                continue
            pairs.append((d["domain"], f))
    signals = haei.collect_signals(pairs)
    return {"signals": [{"id": s, "label": haei.SIGNAL_LABELS.get(s, s), "evidence": ev}
                        for s, ev in signals.items()],
            "matches": haei.match(signals)}


@app.get("/report/{domain}", response_class=HTMLResponse, include_in_schema=False)
def domain_report(domain: str, ctx: Ctx = Depends(get_ctx)):
    """A printable client report for one domain (open it, then Print -> Save as PDF)."""
    try:
        domain = normalize_domain(domain)
    except InvalidDomain as e:
        _bad_domain(e)
    scan = ctx.store.latest_scan(domain)
    if not ctx.store.get_domain(domain) or not scan:
        raise HTTPException(status_code=404, detail="No scan to report on yet. Run a scan first.")
    ctx.audit("report", domain)
    return report.render(ctx.org_name, domain, scan, ctx.store.finding_statuses(domain))


@app.post("/api/findings/status")
def set_finding_status(body: FindingStatusIn, ctx: Ctx = Depends(get_ctx)):
    if body.status not in risk.STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of {', '.join(risk.STATUSES)}")
    domain = normalize_domain(body.domain)
    if not ctx.store.get_domain(domain):
        raise HTTPException(status_code=404, detail="Unknown domain.")
    ctx.store.set_finding_status(domain, body.key, body.status, body.note)
    ctx.audit("finding_status", f"{domain} {body.key}", body.status)
    return {"ok": True}


@app.post("/api/domains/{domain}/project")
def assign_project(domain: str, body: ProjectAssign, ctx: Ctx = Depends(get_ctx)):
    try:
        domain = normalize_domain(domain)
    except InvalidDomain as e:
        _bad_domain(e)
    if not ctx.store.get_domain(domain):
        raise HTTPException(status_code=404, detail="Add this domain first.")
    try:
        ctx.store.set_domain_project(domain, body.project_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    ctx.audit("assign_project", domain, str(body.project_id) if body.project_id else "none")
    return _domain_row_out(ctx, domain)


# ---- domains ---------------------------------------------------------------
@app.get("/api/domains")
def list_domains(ctx: Ctx = Depends(get_ctx)):
    return [_domain_out(r) for r in ctx.store.list_domains()]


@app.post("/api/domains")
def add_domain(body: DomainIn, ctx: Ctx = Depends(get_ctx)):
    try:
        row = ctx.verifier.start(body.domain)
    except InvalidDomain as e:
        _bad_domain(e)
    except ValueError as e:   # domain already registered to another organisation
        raise HTTPException(status_code=409, detail=str(e))
    ctx.audit("add_domain", row["domain"])
    return _domain_out(row)


@app.delete("/api/domains/{domain}")
def delete_domain(domain: str, ctx: Ctx = Depends(get_ctx)):
    ctx.store.delete_domain(domain)
    ctx.audit("delete_domain", domain)
    return {"deleted": domain}


@app.post("/api/domains/{domain}/verify")
def verify_domain(domain: str, ctx: Ctx = Depends(get_ctx)):
    try:
        row = ctx.verifier.check(domain)
    except InvalidDomain as e:
        _bad_domain(e)
    except KeyError:
        raise HTTPException(status_code=404, detail="Add this domain first.")
    if row["verified_at"]:
        ctx.audit("verify_domain", domain)
    return _domain_out(row)


@app.post("/api/domains/{domain}/scan")
def scan_domain(domain: str, live: bool = False, ctx: Ctx = Depends(get_ctx)):
    try:
        domain = ctx.verifier.require_verified(domain)
    except InvalidDomain as e:
        _bad_domain(e)
    except NotVerified:
        raise HTTPException(status_code=403,
                            detail="Domain not verified. Aegis only scans domains you have proven you own.")
    ctx.audit("scan", domain)
    if live:   # run in the background and let the browser watch via /api/jobs/<id>
        return {"job_id": jobs.start(lambda report: monitor.run_scan(ctx.store, domain, "manual", report=report))}
    return monitor.run_scan(ctx.store, domain, "manual")


@app.get("/api/jobs/{job_id}")
def job_status(job_id: str, ctx: Ctx = Depends(get_ctx)):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="No such job (it may have expired).")
    return job


@app.patch("/api/domains/{domain}")
def update_domain(domain: str, body: DomainSettings, ctx: Ctx = Depends(get_ctx)):
    try:
        domain = normalize_domain(domain)
    except InvalidDomain as e:
        _bad_domain(e)
    if not ctx.store.get_domain(domain):
        raise HTTPException(status_code=404, detail="Add this domain first.")
    if body.monitor is not None:
        ctx.store.set_monitor(domain, body.monitor)
    if body.hosting is not None:
        if body.hosting not in ("own", "shared", "auto"):
            raise HTTPException(status_code=422, detail="hosting must be own, shared or auto")
        if body.hosting == "own" and not body.confirm:
            raise HTTPException(status_code=400, detail=(
                "Confirm that this server is yours alone (VPS or dedicated). On shared hosting a port "
                "scan would scan the provider's machine, which you are not allowed to do."))
        ctx.store.set_hosting(domain, body.hosting, confirmed=body.hosting == "own")
        if body.hosting == "own":
            ctx.audit("confirm_own_server", domain)
    return _domain_row_out(ctx, domain)


def _verified_root(ctx: Ctx, domain: str) -> str:
    try:
        domain = normalize_domain(domain)
    except InvalidDomain as e:
        _bad_domain(e)
    row = ctx.store.get_domain(domain)
    if not row or not row["verified_at"]:
        raise HTTPException(status_code=403, detail="Verify this domain first.")
    if domain == "localhost" or row.get("parent"):
        raise HTTPException(status_code=400, detail="Subdomain discovery works on your verified main domain.")
    return domain


@app.post("/api/domains/{domain}/hosting-check")
def hosting_check(domain: str, ctx: Ctx = Depends(get_ctx)):
    """Who hosts this domain? (RDAP lookup of its IP addresses.)"""
    try:
        domain = ctx.verifier.require_verified(domain)
    except (InvalidDomain, NotVerified):
        raise HTTPException(status_code=403, detail="Verify this domain first.")
    if domain != "localhost":
        monitor.check_hosting(ctx.store, domain)
    return _domain_row_out(ctx, domain)


# ---- subdomains ------------------------------------------------------------
@app.post("/api/domains/{domain}/discover")
def discover(domain: str, ctx: Ctx = Depends(get_ctx)):
    domain = _verified_root(ctx, domain)
    res = monitor.run_discovery(ctx.store, domain, alert=False)
    return {"subdomains": ctx.store.list_subdomains(domain), "new": res["new"], "sources": res["sources"]}


@app.get("/api/domains/{domain}/subdomains")
def list_subdomains(domain: str, ctx: Ctx = Depends(get_ctx)):
    try:
        return ctx.store.list_subdomains(normalize_domain(domain))
    except InvalidDomain as e:
        _bad_domain(e)


@app.post("/api/domains/{domain}/subdomains/{sub}/monitor")
def monitor_subdomain(domain: str, sub: str, ctx: Ctx = Depends(get_ctx)):
    """Start monitoring a discovered subdomain. Ownership is covered by the parent's TXT record."""
    domain = _verified_root(ctx, domain)
    sub = normalize_domain(sub)
    found = next((s for s in ctx.store.list_subdomains(domain) if s["name"] == sub), None)
    if not found:
        raise HTTPException(status_code=404, detail="Discover subdomains first.")
    if found["status"] == "takeover_risk":
        raise HTTPException(status_code=409, detail=(
            f"{sub} points to a service that no longer exists. Remove or fix that DNS record first - "
            f"there is nothing of yours to scan there, and an attacker could claim it."))
    if not ctx.store.get_domain(sub):
        ctx.store.add_domain(sub, new_token(), parent=domain)
        ctx.store.mark_verified(sub)
        if found.get("provider"):
            ctx.store.set_hosting(sub, provider=found["provider"])
        ctx.audit("monitor_subdomain", sub)
    return _domain_row_out(ctx, sub)


# ---- monitoring & alerts ---------------------------------------------------
@app.get("/api/monitor")
def monitor_status(ctx: Ctx = Depends(get_ctx)):
    return {"scheduler": monitor.scheduler_enabled(),
            "interval_hours": INTERVAL.total_seconds() / 3600,
            "check_every_minutes": monitor.CHECK_EVERY_S // 60,
            "due_now": monitor.due_domains(ctx.store, INTERVAL)}


@app.post("/api/monitor/run-now")
def monitor_run_now(ctx: Ctx = Depends(get_ctx)):
    """Run the automatic check now for this organisation's monitored domains."""
    return monitor.run_due(ctx.store, ctx.verifier, INTERVAL, force=True)


@app.get("/api/alerts")
def list_alerts(ctx: Ctx = Depends(get_ctx)):
    return ctx.store.list_alerts()


@app.post("/api/alerts/seen")
def alerts_seen(domain: str | None = None, ctx: Ctx = Depends(get_ctx)):
    ctx.store.mark_alerts_seen(domain)
    return {"ok": True}


# ---- network map (your own local network) ----------------------------------
class NetworkScan(BaseModel):
    cidr: str
    confirm: bool = False       # "this network is mine and I'm allowed to scan it"
    deep: bool = False          # also detect open ports + OS (slower; OS needs admin)
    live: bool = False          # run as a background job the browser can watch


@app.get("/api/network/interfaces")
def network_interfaces(ctx: Ctx = Depends(get_ctx)):
    nmap = netmap.find_nmap()
    nets = netmap.local_networks(nmap) if nmap else []
    for n in nets:
        n["scanned"] = ctx.store.get_netscan(n["cidr"]) is not None
    return {"nmap": bool(nmap), "admin": netmap.is_admin(), "networks": nets}


@app.post("/api/network/scan")
def network_scan(body: NetworkScan, ctx: Ctx = Depends(get_ctx)):
    if not netmap.find_nmap():
        raise HTTPException(status_code=400, detail="Nmap is not installed. Install it from https://nmap.org to map your network.")
    try:
        netmap.validate_cidr(body.cidr)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not body.confirm:
        raise HTTPException(status_code=400, detail=(
            "Confirm this is your own network (home or office) that you are allowed to scan. "
            "Scanning someone else's network without permission is illegal."))
    ctx.audit("network_scan", body.cidr)
    if body.live:
        return {"job_id": jobs.start(lambda report: netmap.run(body.cidr, ctx.store, deep=body.deep, report=report))}
    try:
        return netmap.run(body.cidr, ctx.store, deep=body.deep)
    except netmap.NmapError as e:
        raise HTTPException(status_code=502, detail=f"Network scan failed: {e}")


@app.get("/api/network/last")
def network_last(cidr: str, ctx: Ctx = Depends(get_ctx)):
    scan = ctx.store.get_netscan(cidr)
    if not scan:
        raise HTTPException(status_code=404, detail="This network hasn't been scanned yet.")
    return scan


@app.get("/api/traffic")
def traffic_snapshot(ctx: Ctx = Depends(get_ctx)):
    """What this computer is currently connected to (its own connection table)."""
    return traffic.snapshot(ctx.store)


@app.get("/api/domains/{domain}/scans")
def list_scans(domain: str, ctx: Ctx = Depends(get_ctx)):
    return ctx.store.list_scans(domain)


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int, ctx: Ctx = Depends(get_ctx)):
    s = ctx.store.get_scan(scan_id)
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    return s
