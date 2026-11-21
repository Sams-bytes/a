"""Deeper checks with the Nmap Scripting Engine (NSE) - SAFE scripts only.

NSE scripts are little plug-ins that ask a service detailed questions. Nmap
groups them by category; some ("intrusive", "brute", "exploit", "dos") attack a
service. Aegis uses ONLY a fixed allowlist of non-intrusive, read-only checks -
the same thing a careful auditor inspects by hand:

  ssl-enum-ciphers       grade a site's HTTPS encryption A-F, list weak ciphers
  ssh2-enum-algos        list an SSH server's algorithms (spot broken ones)
  smb-protocols          which SMB versions - is ancient SMBv1 (WannaCry) on?
  smb2-security-mode     is SMB message signing required?
  http-security-headers  which protective HTTP headers are set
  http-title             the web page's title (context, harmless)

Safety: the allowlist is a constant. No caller value is ever passed to
`--script`, so an attacker can't make Aegis run a dangerous script. And these
scripts only read - they never guess passwords or exploit anything.
"""

from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET

from app.nmap_engine import NmapError, _run, _run_streaming, check_target

# The ONLY scripts Aegis will ever run. A fixed constant - never built from input.
ALLOWLIST = ["ssl-enum-ciphers", "ssh2-enum-algos", "smb-protocols", "smb2-security-mode",
             "http-security-headers", "http-title"]

# Which open ports are worth running the scripts against.
RELEVANT = {22, 80, 443, 445, 993, 995, 8080, 8443}

WEAK_SSH = re.compile(r"diffie-hellman-group1-sha1|group-exchange-sha1|ssh-rsa\b|hmac-md5|hmac-sha1\b|-cbc\b|arcfour|3des", re.I)


def relevant_ports(open_ports: list[dict]) -> list[int]:
    return sorted({p["port"] for p in open_ports if p.get("proto", "tcp") == "tcp" and p["port"] in RELEVANT})


def parse(xml: str) -> list[dict]:
    """Every script result: {port (None=host-level), id, output, elems[]}."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        raise NmapError(f"could not read nmap script output: {e}") from e
    out = []

    def collect(script, port):
        out.append({"port": port, "id": script.get("id", ""), "output": script.get("output", "") or "",
                    "elems": [e.text for e in script.iter("elem") if e.text]})

    for port in root.iter("port"):
        pid = int(port.get("portid"))
        for s in port.findall("script"):
            collect(s, pid)
    for hs in root.iter("hostscript"):
        for s in hs.findall("script"):
            collect(s, None)
    return out


def tls_grade(output: str) -> str | None:
    m = re.search(r"least strength:\s*([A-F])", output)
    return m.group(1) if m else None


def has_legacy_tls(output: str) -> bool:
    return "TLSv1.0" in output or "TLSv1.1" in output or "SSLv3" in output


def smbv1_enabled(script: dict) -> bool:
    text = (script["output"] + " " + " ".join(script["elems"])).lower()
    return "nt lm 0.12" in text or "smbv1" in text


def signing_not_required(script: dict) -> bool:
    return "not required" in script["output"].lower()


def run(target: str, nmap: str, ports: list[int], on_progress=None) -> dict:
    """Run the safe scripts against the given open ports. Returns parsed checks."""
    check_target(target)
    if not ports:
        return {"ran": False, "checks": [], "ports": []}
    cmd = [nmap, "-Pn", "-n", "-sV", "--script", ",".join(ALLOWLIST),   # the fixed allowlist, never input
           "-p", ",".join(map(str, ports)), "--host-timeout", "5m", "--stats-every", "2s", "-oX", "-", target]
    xml, err, rc = (_run_streaming(cmd, on_progress) if on_progress else _run(cmd))
    if rc != 0 and not xml.strip():
        raise NmapError((err or "nmap script scan failed").strip().splitlines()[0])
    return {"ran": True, "checks": parse(xml), "ports": ports}


def should_run() -> bool:
    return os.environ.get("AEGIS_NSE", "1") != "0"
