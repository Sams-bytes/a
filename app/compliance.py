"""NIS2 / GDPR readiness - the deliverable an EU SME actually buys.

NIS2 Article 21(2) lists ten security measures essential/important entities must
take. For each one we combine two things:

  * What Aegis can SEE from scans (tagged findings already carry the article,
    e.g. "Art. 21(2)(h) cryptography" on a weak-TLS finding).
  * A short SELF-ASSESSMENT for the organisational parts no scanner can check
    (backups, training, MFA, incident plan...).

The result is a readiness score and, via report.py, an exportable readiness
report mapping evidence to each article.

Honest framing (and we say so in the output): this is a readiness aid, NOT a
certification or legal compliance conclusion. "No findings" means Aegis saw no
problem in what it can scan - not that the measure is fully met.
"""

from __future__ import annotations

import re

# Each measure: id = the Article 21(2) letter; tag = the finding letter Aegis can
# scan for it (None = organisational only); self = yes/no questions for the owner.
MEASURES = [
    {"id": "a", "title": "Risk management & security policies", "tag": None,
     "self": [("policy", "Do you have a written information-security policy?"),
              ("riskassess", "Do you review security risks regularly?")]},
    {"id": "b", "title": "Incident handling", "tag": None, "capability": "incidents",
     "self": [("ir_plan", "Do you have a written incident-response plan?"),
              ("ir_contact", "Is there a clear way for staff to report an incident?")]},
    {"id": "c", "title": "Backups, continuity & disaster recovery", "tag": None,
     "self": [("backups", "Do you take regular backups?"),
              ("backups_tested", "Have you test-restored a backup in the last year?"),
              ("backups_offline", "Is at least one backup offline or immutable (ransomware-safe)?")]},
    {"id": "d", "title": "Supply-chain security", "tag": None,
     "self": [("vendor_review", "Do you check the security of key suppliers and software?")]},
    {"id": "e", "title": "Secure systems & vulnerability handling", "tag": "e",
     "self": [("patching", "Do you apply security updates promptly?")]},
    {"id": "f", "title": "Measuring effectiveness of measures", "tag": None, "capability": "monitoring",
     "self": [("review", "Do you review whether your security measures actually work?")]},
    {"id": "g", "title": "Basic cyber hygiene & training", "tag": None,
     "self": [("training", "Do staff get basic security-awareness training?"),
              ("phishing", "Are staff warned about phishing?")]},
    {"id": "h", "title": "Cryptography & encryption", "tag": "h",
     "self": [("disk_enc", "Are laptops and servers disk-encrypted?")]},
    {"id": "i", "title": "Access control & asset management", "tag": "i",
     "self": [("least_priv", "Are admin rights limited to those who need them?"),
              ("offboard", "Is access removed promptly when someone leaves?")]},
    {"id": "j", "title": "Multi-factor authentication & secure comms", "tag": None,
     "self": [("mfa", "Is MFA enabled on email, VPN and admin accounts?")]},
]

GDPR_NOTE = ("GDPR Article 32 (security of processing) overlaps heavily with the above: encryption "
             "(h), confidentiality/integrity/availability and resilience (i, c), the ability to "
             "restore after an incident (b, c) and regular testing (f). Meeting these NIS2 measures "
             "is strong evidence towards Article 32.")

_LETTER = re.compile(r"21\(2\)\(([a-j])\)")


def finding_letter(f: dict) -> str | None:
    m = _LETTER.search(f.get("nis2", "") or "")
    return m.group(1) if m else None


def assess(open_findings: list[dict], answers: dict, capabilities: dict | None = None) -> dict:
    """Per-measure status + a readiness score.

    open_findings: the org's current open, non-info findings (each with nis2 + severity).
    answers: {"<measure>:<question>": "yes"|"no"|"na"}.
    capabilities: {"incidents": bool, "monitoring": bool} - Aegis features in use.
    """
    capabilities = capabilities or {}
    by_letter: dict[str, list[dict]] = {}
    for f in open_findings:
        letter = finding_letter(f)
        if letter:
            by_letter.setdefault(letter, []).append(f)

    measures_out = []
    met = 0
    for m in MEASURES:
        findings = by_letter.get(m["tag"], []) if m["tag"] else []
        worst = _worst_severity(findings)
        questions = [{"id": q, "text": t, "answer": answers.get(f"{m['id']}:{q}", "unknown")}
                     for q, t in m["self"]]
        status = _measure_status(worst, questions)
        if status == "met":
            met += 1
        measures_out.append({
            "id": m["id"], "article": f"Art. 21(2)({m['id']})", "title": m["title"],
            "status": status, "scanned": bool(m["tag"]),
            "findings": [{"title": f["title"], "severity": f["severity"], "domain": f.get("domain")}
                         for f in findings],
            "worst_finding": worst, "questions": questions,
            "capability": m.get("capability"),
            "capability_in_use": bool(capabilities.get(m.get("capability"))) if m.get("capability") else None,
        })
    score = round(100 * met / len(MEASURES))
    return {"score": score, "met": met, "total": len(MEASURES), "measures": measures_out, "gdpr_note": GDPR_NOTE}


def _worst_severity(findings: list[dict]) -> str | None:
    order = ["critical", "high", "medium", "low"]
    for sev in order:
        if any(f["severity"] == sev for f in findings):
            return sev
    return None


def _measure_status(worst: str | None, questions: list[dict]) -> str:
    """met / gap / partial / unknown, combining scan evidence and self-answers."""
    if worst in ("critical", "high"):
        return "gap"                                   # a serious open finding in this area
    ans = [q["answer"] for q in questions]
    if any(a == "no" for a in ans):
        return "gap"                                   # the owner says a control is missing
    positives = [a for a in ans if a in ("yes", "na")]
    if any(a == "unknown" for a in ans):
        # Something still unanswered: partial if we already have some positive signal, else not assessed.
        return "partial" if positives or worst is not None else "unknown"
    # everything answered yes/na and no serious finding
    return "met" if worst is None else "partial"
