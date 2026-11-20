"""Compare two scans: what changed since last time?

This is the heart of *monitoring*. A single scan says "these ports are open".
Monitoring says "port 3389 opened since last week" - that is the moment to act,
because attackers scan the whole internet non-stop and find new openings within
hours.
"""

from __future__ import annotations


def _key(f: dict) -> tuple:
    """A finding is 'the same' in two scans when title and port match."""
    return (f.get("title"), f.get("port"))


def compare(old: dict | None, new: dict) -> dict:
    """Differences between the previous scan result `old` and the new one."""
    if not old:
        return {"first_scan": True, "new_ports": [], "closed_ports": [], "new_findings": [],
                "fixed_findings": [], "score_before": None, "score_after": new.get("score")}

    old_ports = {p["port"]: p for p in old.get("open_ports", [])}
    new_ports = {p["port"]: p for p in new.get("open_ports", [])}
    old_f = {_key(f): f for f in old.get("findings", [])}
    new_f = {_key(f): f for f in new.get("findings", [])}

    return {
        "first_scan": False,
        "new_ports": [new_ports[p] for p in sorted(new_ports.keys() - old_ports.keys())],
        "closed_ports": [old_ports[p] for p in sorted(old_ports.keys() - new_ports.keys())],
        "new_findings": [f for k, f in new_f.items() if k not in old_f],
        "fixed_findings": [f for k, f in old_f.items() if k not in new_f],
        "score_before": old.get("score"),
        "score_after": new.get("score"),
    }


def is_bad(ch: dict) -> bool:
    """Worth an alert? Any newly opened port, a new real finding, or a lower score."""
    if ch.get("first_scan"):
        return False
    if ch["new_ports"]:
        return True
    if any(f["severity"] != "info" for f in ch["new_findings"]):
        return True
    return (ch["score_before"] is not None and ch["score_after"] is not None
            and ch["score_after"] < ch["score_before"])


def describe(ch: dict) -> list[str]:
    """Plain-English lines for an alert."""
    lines = []
    for p in ch["new_ports"]:
        lines.append(f"New open port {p['port']} ({p.get('service', '?')})")
    for f in ch["new_findings"]:
        if f["severity"] != "info":
            lines.append(f"New {f['severity']} finding: {f['title']}")
    if ch["score_before"] is not None and ch["score_after"] is not None and ch["score_after"] != ch["score_before"]:
        lines.append(f"Score {ch['score_before']} -> {ch['score_after']}")
    for p in ch["closed_ports"]:
        lines.append(f"Closed since last scan: port {p['port']}")
    return lines
