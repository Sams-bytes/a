"""Professional port scanning with Nmap - the industry-standard scanner.

What we ask Nmap to do (three runs in parallel):
  1. TCP: the 1,000 most common ports (Nmap's list, built from internet-wide
     scans) with version detection (-sV: "which software is behind this port?").
  2. TCP: Aegis's own high-risk ports, so they are always checked.
  3. UDP: ~17 important UDP services, each probed in its own protocol.

UDP lesson: a closed TCP port says "go away". A UDP port often says nothing at
all - silence can mean open OR blocked by a firewall. Nmap reports that as
"open|filtered". We only call a UDP port open when the service ANSWERED; the
silent ones are listed separately as "uncertain".

Safety:
  * No shell. Nmap gets a Python list of arguments, so a "domain" like
    "x.nl & del C:\\*" can never become a second command (command injection).
    The target is validated again right here, as a second line of defence.
  * No NSE scripts (--script): some guess passwords or run exploits.
    Aegis only uses non-intrusive scan types: -sT, -sV, -sU.
  * UDP scanning needs administrator rights (raw network access). Without
    them we still return the TCP results and say why UDP was skipped.

Settings: AEGIS_NMAP = full path to nmap.exe (optional).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

# Aegis's high-risk TCP ports: always scanned, even when not in Nmap's top 1,000.
TCP_EXTRAS = [21, 23, 445, 1433, 2049, 2375, 2376, 3306, 3389, 4786, 5432, 5900, 5985, 5986,
              6379, 8291, 9200, 10000, 11211, 27017]

UDP_SERVICES = {
    53: "DNS", 67: "DHCP", 69: "TFTP (file transfer, no login)", 123: "NTP (time)",
    137: "NetBIOS name service", 161: "SNMP (device management)", 389: "CLDAP (directory)",
    500: "IKE (IPsec VPN)", 623: "IPMI (server management chip)", 1194: "OpenVPN",
    1434: "MS SQL Browser", 1900: "SSDP / UPnP", 4500: "IPsec NAT-T (VPN)", 5060: "SIP (VoIP)",
    5353: "mDNS (Bonjour)", 11211: "memcached", 51820: "WireGuard VPN",
}

COMMON = ["-Pn", "-n", "-T4", "--host-timeout", "10m", "--stats-every", "2s", "-oX", "-"]
#  -Pn  don't ping first (many firewalls drop pings, the host would look "down")
#  -n   don't do reverse-DNS lookups of the IPs
#  -T4  faster timing, normal for a single host
#  --stats-every 2s  emit <taskprogress percent=".."> into the XML so we can show live progress
#  -oX -  write machine-readable XML to the output, which we parse

_SAFE_TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]*$")
# Nmap's live progress element, e.g. <taskprogress task="Connect Scan" percent="45.87" remaining="5"/>
TASK_RE = re.compile(r'<taskprogress task="([^"]*)"[^>]*percent="([\d.]+)"[^>]*remaining="(\d+)"')
_PRIV_WORDS = ("root privileges", "requires root", "administrator", "privileged", "dnet:", "npcap")


class NmapError(RuntimeError):
    pass


def find_nmap() -> str | None:
    candidates = [os.environ.get("AEGIS_NMAP"), shutil.which("nmap"),
                  r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"]
    return next((c for c in candidates if c and os.path.isfile(c)), None)


def nmap_version(nmap: str) -> str:
    try:
        out = subprocess.run([nmap, "--version"], capture_output=True, text=True, timeout=20,
                             **_no_window()).stdout
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    m = re.search(r"Nmap version (\S+)", out)
    return m.group(1) if m else "unknown"


def check_target(target: str) -> str:
    """Second line of defence: only plain host names / IPv4 addresses reach Nmap."""
    if not _SAFE_TARGET.match(target or ""):
        raise ValueError(f"refusing to pass {target!r} to nmap")
    return target


def build_commands(target: str, nmap: str) -> dict[str, list[str]]:
    target = check_target(target)
    return {
        "tcp_top": [nmap, "-sT", "-sV", "--top-ports", "1000", *COMMON, target],
        "tcp_extra": [nmap, "-sT", "-sV", "-p", ",".join(map(str, TCP_EXTRAS)), *COMMON, target],
        "udp": [nmap, "-sU", "-sV", "--version-intensity", "0",
                "-p", "U:" + ",".join(map(str, UDP_SERVICES)), *COMMON, target],
    }


def _no_window() -> dict:
    # On Windows, don't flash a black console window for every Nmap run.
    return {"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}


def parse_xml(xml: str) -> list[dict]:
    """Every scanned port Nmap reported (open, open|filtered, ...)."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        raise NmapError(f"could not read nmap output: {e}") from e
    out = []
    for port in root.iter("port"):
        state = port.find("state")
        svc = port.find("service")
        s = svc.attrib if svc is not None else {}
        out.append({
            "port": int(port.get("portid")),
            "proto": port.get("protocol", "tcp"),
            "state": state.get("state") if state is not None else "unknown",
            "nmap_service": s.get("name", ""),
            "product": s.get("product", ""),
            "version": s.get("version", ""),
            "extrainfo": s.get("extrainfo", ""),
            "cpe": [c.text for c in (svc.findall("cpe") if svc is not None else []) if c.text],
        })
    return out


def _run_streaming(cmd: list[str], on_progress=None) -> tuple[str, str, int]:
    """Like _run, but read stdout as it arrives and report Nmap's live % via on_progress."""
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, encoding="utf-8", errors="replace", **_no_window())
    except OSError as e:
        return "", str(e), -1
    out = []
    try:
        for line in p.stdout:                       # streams line by line until Nmap exits
            out.append(line)
            if on_progress:
                m = TASK_RE.search(line)
                if m:
                    on_progress(m.group(1), float(m.group(2)), int(m.group(3)))
        err = p.stderr.read()
        p.wait(timeout=900)
    except subprocess.TimeoutExpired:
        p.kill()
        return "".join(out), "nmap timed out", -1
    return "".join(out), err, p.returncode


def _run(cmd: list[str]) -> tuple[str, str, int]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=900, **_no_window())
        return p.stdout, p.stderr, p.returncode
    except subprocess.TimeoutExpired:
        return "", "nmap timed out after 15 minutes", -1
    except OSError as e:
        return "", str(e), -1


def _service_name(p: dict, tcp_names: dict[int, str]) -> str:
    known = tcp_names.get(p["port"]) if p["proto"] == "tcp" else UDP_SERVICES.get(p["port"])
    return known or p["nmap_service"] or "unknown"


def _software_text(p: dict) -> str:
    return " ".join(x for x in (p["product"], p["version"], f"({p['extrainfo']})" if p["extrainfo"] else "") if x)


def run(target: str, nmap: str, tcp_names: dict[int, str] | None = None, log=lambda m: None,
        on_progress=None) -> dict:
    """Scan one target with Nmap. Returns the same shape as Aegis's built-in scanner, plus extras.
    on_progress(task, percent, remaining) receives Nmap's live progress for the slow scans."""
    tcp_names = tcp_names or {}
    cmds = build_commands(target, nmap)
    log("Nmap: scanning top 1,000 TCP ports + high-risk extras + UDP services")
    runner = (lambda cmd: _run_streaming(cmd, on_progress)) if on_progress else _run
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = dict(zip(cmds, pool.map(runner, cmds.values())))

    ports: dict[tuple[str, int], dict] = {}
    tcp_ok = False
    for name in ("tcp_top", "tcp_extra"):
        xml, err, rc = results[name]
        if rc == 0 and xml.strip():
            tcp_ok = True
            for p in parse_xml(xml):
                if p["state"] == "open":
                    ports[(p["proto"], p["port"])] = p
    if not tcp_ok:
        raise NmapError((results["tcp_top"][1] or "nmap failed").strip().splitlines()[0])

    uncertain = []
    xml, err, rc = results["udp"]
    if rc == 0 and xml.strip():
        udp_status = "ok"
        for p in parse_xml(xml):
            if p["state"] == "open":
                ports[(p["proto"], p["port"])] = p
            elif p["state"] == "open|filtered":
                uncertain.append({"port": p["port"], "proto": "udp", "service": UDP_SERVICES.get(p["port"], "")})
    elif any(w in err.lower() for w in _PRIV_WORDS):
        udp_status = "skipped: UDP scanning needs administrator rights"
    else:
        udp_status = "skipped: " + ((err.strip().splitlines() or ["nmap UDP scan failed"])[0])[:160]

    open_ports = [{
        "port": p["port"], "proto": p["proto"], "service": _service_name(p, tcp_names),
        "banner": _software_text(p), "product": p["product"], "version": p["version"],
        "extrainfo": p["extrainfo"], "cpe": p["cpe"],
    } for p in sorted(ports.values(), key=lambda p: (p["proto"], p["port"]))]
    return {"engine": f"Nmap {nmap_version(nmap)}", "open_ports": open_ports,
            "uncertain_udp": uncertain, "udp": udp_status}
