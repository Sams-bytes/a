"""Historical Attack Exposure Intelligence (HAEI).

The differentiator: don't just list findings - compare them to HOW REAL BREACHES
ACTUALLY STARTED. Each documented incident (app/data/incidents.json) is tagged
with the externally-observable condition attackers used to get in (a "signal").
We derive the same signals from the customer's current findings and look for
overlaps.

Discipline (from the spec, and common sense): resembling a victim is NOT proof of
vulnerability. We say "you share an entry condition with X" and recommend the
control - never "you will be breached". Signals we cannot see from an external
scan (phishing, supply chain, stolen cloud creds) make those incidents
library-only: they never produce a false match.
"""

from __future__ import annotations

import json
from pathlib import Path

INCIDENTS_FILE = Path(__file__).parent / "data" / "incidents.json"

# Ports that mean "a database is exposed" / "remote access is exposed".
DB_PORTS = {1433, 1521, 3306, 5432, 5984, 6379, 9042, 9200, 11211, 27017}
REMOTE_PORTS = {22, 3389, 5900}        # SSH, RDP, VNC

# Plain-English name for each signal, shown in the UI.
SIGNAL_LABELS = {
    "smb_v1": "Legacy SMBv1 file sharing is enabled",
    "exploit_public_app": "Internet-facing software with known vulnerabilities",
    "known_exploited_cve": "A vulnerability that is being exploited in the wild (CISA KEV)",
    "exposed_rdp": "Remote Desktop (RDP) is reachable",
    "exposed_remote_access": "A remote-access service (RDP/SSH/VPN) is reachable",
    "exposed_database": "A database port is reachable",
    "weak_tls": "Weak or misconfigured TLS/HTTPS encryption",
}


def load_incidents() -> list[dict]:
    return json.loads(INCIDENTS_FILE.read_text(encoding="utf-8"))["incidents"]


def finding_signals(f: dict) -> set[str]:
    """Which attack entry-conditions does this one finding represent?"""
    sig: set[str] = set()
    key = f.get("key", "")
    title = (f.get("title") or "").lower()
    port = f.get("port")

    if key.startswith("nse:smbv1") or "smbv1" in title:
        sig.add("smb_v1")
    if f.get("kind") == "cve":
        sig.add("exploit_public_app")
        if any(c.get("kev") for c in f.get("cves", [])):
            sig.add("known_exploited_cve")
    if port == 3389:
        sig.add("exposed_rdp")
    if port in REMOTE_PORTS or "vpn" in title:
        sig.add("exposed_remote_access")
    if port in DB_PORTS:
        sig.add("exposed_database")
    if key.startswith("nse:tls") or "tls 1.0" in title or "certificate is not trusted" in title:
        sig.add("weak_tls")
    return sig


def collect_signals(domain_findings: list[tuple[str, dict]]) -> dict[str, list[dict]]:
    """From (domain, finding) pairs -> {signal: [evidence {domain, finding}]}."""
    out: dict[str, list[dict]] = {}
    for domain, f in domain_findings:
        for s in finding_signals(f):
            out.setdefault(s, []).append({"domain": domain, "finding": f.get("title")})
    return out


def match(signals: dict[str, list[dict]], incidents: list[dict] | None = None) -> list[dict]:
    """Incidents whose entry condition you currently share, worst (most signals) first."""
    incidents = incidents if incidents is not None else load_incidents()
    present = set(signals)
    matches = []
    for inc in incidents:
        shared = [s for s in inc.get("signals", []) if s in present]
        if not shared:
            continue
        evidence = []
        for s in shared:
            evidence += signals[s]
        matches.append({
            "id": inc["id"], "name": inc["name"], "org": inc["org"], "country": inc["country"],
            "date": inc["date"], "category": inc["category"], "initial_access": inc["initial_access"],
            "techniques": inc.get("techniques", []), "controls": inc.get("controls", []),
            "source": inc.get("source"), "confidence": inc.get("confidence"),
            "shared_signals": [{"id": s, "label": SIGNAL_LABELS.get(s, s)} for s in shared],
            "evidence": evidence,
        })
    matches.sort(key=lambda m: -len(m["shared_signals"]))
    return matches
