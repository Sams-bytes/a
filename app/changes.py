"""Compare two scans: what changed since last time?

This is the heart of *monitoring*. A single scan says "these ports are open".
Monitoring says "port 3389 opened since last week" - that is the moment to act,
because attackers scan the whole internet non-stop and find new openings within
hours.
"""

from __future__ import annotations


def _key(f: dict) -> tuple:
    """A finding is 'the same' in two scans when title and port match.

    CVE findings carry their own key (product + version + CVE ids), so a NEW
    CVE published for software you run counts as a new finding -> alert.
    """
    return f.get("key") or (f.get("title"), f.get("port"))


def _engine_family(r: dict) -> str:
    if r.get("mode") == "light":
        return "light"
    return "nmap" if str(r.get("engine", "")).startswith("Nmap") else "builtin"


def _label(p: dict) -> str:
    return f"{'UDP' if p.get('proto') == 'udp' else 'port'} {p['port']}"


def compare(old: dict | None, new: dict) -> dict:
    """Differences between the previous scan result `old` and the new one."""
    if not old:
        return {"first_scan": True, "new_ports": [], "closed_ports": [], "new_findings": [],
                "fixed_findings": [], "score_before": None, "score_after": new.get("score")}

    # Compare like with like: switching from the 25-port built-in scan to Nmap's
    # 1,000+ ports would otherwise look like "20 new ports opened!".
    engine_changed = _engine_family(old) != _engine_family(new)
    # UDP only counts when BOTH scans could scan UDP (it needs admin rights).
    both_udp = old.get("udp") == "ok" and new.get("udp") == "ok"

    def ports(r):
        return {(p.get("proto", "tcp"), p["port"]): p for p in r.get("open_ports", [])
                if p.get("proto", "tcp") == "tcp" or both_udp}

    old_ports, new_ports = ports(old), ports(new)
    old_f = {_key(f): f for f in old.get("findings", [])}
    new_f = {_key(f): f for f in new.get("findings", [])}

    return {
        "first_scan": False,
        "engine_changed": engine_changed,
        "new_ports": [new_ports[p] for p in sorted(new_ports.keys() - old_ports.keys())],
        "closed_ports": [old_ports[p] for p in sorted(old_ports.keys() - new_ports.keys())],
        "new_findings": [f for k, f in new_f.items() if k not in old_f],
        "fixed_findings": [f for k, f in old_f.items() if k not in new_f],
        "score_before": old.get("score"),
        "score_after": new.get("score"),
    }


def is_bad(ch: dict) -> bool:
    """Worth an alert? Any newly opened port, a new real finding, or a lower score."""
    if ch.get("first_scan") or ch.get("engine_changed"):
        return False  # a new baseline, not a change on the server
    if ch["new_ports"]:
        return True
    if any(f["severity"] != "info" for f in ch["new_findings"]):
        return True
    return (ch["score_before"] is not None and ch["score_after"] is not None
            and ch["score_after"] < ch["score_before"])


def describe(ch: dict) -> list[str]:
    """Plain-English lines for an alert."""
    lines = []
    if ch.get("engine_changed"):
        lines.append("Scan type changed (e.g. Nmap installed, or light <-> full scan): this scan is the new baseline, "
                     "differences below are from looking more closely, not from changes on the server")
    for p in ch["new_ports"]:
        lines.append(f"New open {_label(p)} ({p.get('service', '?')})")
    for f in ch["new_findings"]:
        if f["severity"] != "info":
            lines.append(f"New {f['severity']} finding: {f['title']}")
    if ch["score_before"] is not None and ch["score_after"] is not None and ch["score_after"] != ch["score_before"]:
        lines.append(f"Score {ch['score_before']} -> {ch['score_after']}")
    for p in ch["closed_ports"]:
        lines.append(f"Closed since last scan: {_label(p)}")
    return lines
