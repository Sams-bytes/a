"""Live traffic view: what is YOUR OWN computer talking to right now?

This answers the question people really mean by "watch the network": which of
my programs are connected to which servers on the internet. It reads your
computer's own connection table (like Task Manager's network tab) - the active
connections and which program owns each - and labels every remote server with
its owner (Amazon, Google, Meta…) via the same public RDAP registry the hosting
check uses.

Honest scope: this is connection metadata, NOT packet contents. It shows that
Chrome is connected to a Google server, not what was sent. Reading the actual
packets is Wireshark's job; Aegis deliberately stays out of your data.

Privacy/safety: reads only this machine's own connection list (no special
rights, no other computers). Only remote IP addresses are sent to rdap.org.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
from datetime import datetime, timezone

from app import hosting
from app.db import Store
from app.nmap_engine import _no_window

CGNAT = ipaddress.ip_network("100.64.0.0/10")   # carrier-grade NAT / Tailscale


def is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
                or a.is_unspecified or a.is_reserved or a in CGNAT)


def _split_hostport(s: str) -> tuple[str, str]:
    """'1.2.3.4:443' -> ('1.2.3.4','443'); '[::1]:443' -> ('::1','443')."""
    if s.startswith("["):
        host, _, port = s[1:].partition("]:")
        return host, port
    host, _, port = s.rpartition(":")
    return host, port


def parse_netstat(text: str) -> list[dict]:
    """Windows `netstat -ano` → connection rows."""
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] not in ("TCP", "UDP"):
            continue
        proto = parts[0]
        local, foreign = parts[1], parts[2]
        if proto == "TCP":
            state, pid = parts[3], parts[4] if len(parts) > 4 else "0"
        else:
            state, pid = "", parts[3]
        rip, rport = _split_hostport(foreign)
        rows.append({"proto": proto, "remote_ip": rip, "remote_port": rport, "state": state, "pid": pid})
    return rows


def parse_tasklist(text: str) -> dict[str, str]:
    """`tasklist /fo csv /nh` → {pid: program}."""
    names = {}
    for line in text.splitlines():
        m = re.match(r'"([^"]*)","(\d+)"', line)
        if m:
            names[m.group(2)] = m.group(1)
    return names


def _collect_windows() -> tuple[list[dict], dict[str, str]]:
    ns = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=15, **_no_window())
    tl = subprocess.run(["tasklist", "/fo", "csv", "/nh"], capture_output=True, text=True, timeout=15, **_no_window())
    return parse_netstat(ns.stdout), parse_tasklist(tl.stdout)


def _collect_posix() -> tuple[list[dict], dict[str, str]]:
    out = subprocess.run(["ss", "-tunp"], capture_output=True, text=True, timeout=15).stdout
    rows, names = [], {}
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = "TCP" if parts[0].startswith("tcp") else "UDP"
        rip, rport = _split_hostport(parts[4])
        prog = (re.search(r'\("([^"]+)",pid=(\d+)', line) or [None, "?", "0"])
        pid = prog[2] if prog != [None, "?", "0"] else "0"
        rows.append({"proto": proto, "remote_ip": rip, "remote_port": rport, "state": "ESTAB", "pid": pid})
        if prog != [None, "?", "0"]:
            names[pid] = prog[1]
    return rows, names


def snapshot(store: Store | None = None, http_get=None, max_lookups: int = 25) -> dict:
    """One look at this computer's connections to public servers, grouped per app+server."""
    conns, names = (_collect_windows() if sys.platform == "win32" else _collect_posix())
    public = [c for c in conns if (c["state"] in ("ESTABLISHED", "ESTAB") or c["proto"] == "UDP")
              and is_public(c["remote_ip"])]

    org_cache: dict[str, dict] = {}

    def label(ip: str) -> dict:
        if ip not in org_cache:
            if len(org_cache) < max_lookups:
                info = hosting.lookup(ip, store, http_get) if http_get else hosting.lookup(ip, store)
            else:
                info = {"org": "", "provider": None}
            org_cache[ip] = info
        return org_cache[ip]

    flows: dict[tuple, dict] = {}
    for c in public:
        program = names.get(c["pid"], f"PID {c['pid']}")
        key = (program, c["remote_ip"])
        f = flows.setdefault(key, {"program": program, "remote_ip": c["remote_ip"],
                                   "ports": set(), "count": 0, "proto": c["proto"]})
        f["ports"].add(c["remote_port"])
        f["count"] += 1

    def org_label(info: dict) -> str:
        # Prefer a short name: the keyword provider, else the network name, else the first contact.
        name = info.get("provider") or info.get("network") or (info.get("org") or "").split(";")[0].strip() or "—"
        return name if len(name) <= 40 else name[:38] + "…"

    out = []
    for f in flows.values():
        info = label(f["remote_ip"])
        out.append({"program": f["program"], "remote_ip": f["remote_ip"],
                    "org": org_label(info),
                    "ports": sorted(f["ports"], key=lambda p: int(p) if p.isdigit() else 0),
                    "count": f["count"], "proto": f["proto"]})
    out.sort(key=lambda f: (-f["count"], f["program"].lower()))
    return {"captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "flows": out, "connections": len(public)}
