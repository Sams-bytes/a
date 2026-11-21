"""Risk scoring: turn a finding into one sortable number, so a team fixes the
RIGHT things first instead of just the highest-CVSS things.

The idea every security team uses:  Risk = Impact x Likelihood.

  * Impact     - how bad if exploited. We use the finding's CVSS (0-10).
  * Likelihood - how probable an attack is. Best signal is EPSS (the exploit
                 probability we fetch per CVE). If a CVE is on CISA's KEV list it
                 is being exploited right now, so likelihood = 1. With no CVE we
                 fall back to a severity-based guess.

risk_score returns 0-100 so it reads like a percentage of "maximum nastiness".
A floor keeps a severe-but-not-yet-exploited hole from scoring zero.
"""

from __future__ import annotations

STATUSES = ("open", "fixed", "accepted", "false_positive")

_SEVERITY_LIKELIHOOD = {"critical": 0.5, "high": 0.3, "medium": 0.15, "low": 0.05, "info": 0.0}


def likelihood(f: dict) -> float:
    """0-1 chance this gets attacked."""
    if any(c.get("kev") for c in f.get("cves", [])):
        return 1.0                              # on CISA KEV: exploited in the wild now
    if f.get("epss") is not None:
        return float(f["epss"])                 # FIRST.org exploit prediction
    return _SEVERITY_LIKELIHOOD.get(f.get("severity", "info"), 0.1)


def risk_score(f: dict) -> int:
    """0-100. Impact (CVSS/10) x Likelihood, with a 0.25 floor on likelihood so a
    serious hole still ranks even before anyone is known to exploit it."""
    impact = (f.get("cvss") or 0) * 10          # CVSS 0-10 -> 0-100
    return round(impact * (0.25 + 0.75 * likelihood(f)))


def risk_tier(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 20:
        return "medium"
    if score > 0:
        return "low"
    return "info"
