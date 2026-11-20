"""Fingerprinting: which software (and which version) is this server running?

Many servers introduce themselves when you connect. That greeting is called a
"banner":   SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
            220 ProFTPD 1.3.5 Server
            Server: Apache/2.4.49 (Unix)
We recognise these with patterns and translate them into a CPE name - the
official "address" NIST's vulnerability database uses for a product:
            cpe:2.3:a:<vendor>:<product>:<version>:<update>:...
Naming is messy in real life: nginx is filed under vendor "f5" (the company
that bought it), vsftpd under "vsftpd_project". That's why this table exists.
"""

from __future__ import annotations

import re

# (product id, display name, regex with the version in group 1, cpe vendor, cpe product)
PATTERNS = [
    ("openssh", "OpenSSH", r"OpenSSH[_-](\d+\.\d+(?:p\d+)?)", "openbsd", "openssh"),
    ("apache", "Apache", r"Apache/(\d+\.\d+\.\d+)", "apache", "http_server"),
    ("nginx", "nginx", r"nginx/(\d+\.\d+\.\d+)", "f5", "nginx"),
    ("iis", "Microsoft IIS", r"Microsoft-IIS/(\d+\.\d+)", "microsoft", "internet_information_services"),
    ("proftpd", "ProFTPD", r"ProFTPD (\d+\.\d+\.\d+[a-z]?)", "proftpd", "proftpd"),
    ("vsftpd", "vsftpd", r"vsFTPd (\d+\.\d+\.\d+)", "vsftpd_project", "vsftpd"),
    ("exim", "Exim", r"Exim (\d+\.\d+(?:\.\d+)?)", "exim", "exim"),
    ("openssl", "OpenSSL", r"OpenSSL/(\d+\.\d+\.\d+[a-z]*)", "openssl", "openssl"),
    ("php", "PHP", r"PHP/(\d+\.\d+\.\d+)", "php", "php"),
    ("lighttpd", "lighttpd", r"lighttpd/(\d+\.\d+\.\d+)", "lighttpd", "lighttpd"),
]

# Linux distributions often fix security holes WITHOUT changing the version
# number ("back-porting"), so a match on these is "possibly affected".
_DISTRO = re.compile(r"\b(Ubuntu|Debian|Raspbian|deb\d+u\d+|el\d+|Red Hat|CentOS|Rocky|AlmaLinux|FreeBSD)\b", re.I)


def cpe_name(vendor: str, product: str, version: str) -> str:
    """OpenSSH puts its patch level in CPE's separate 'update' field: 8.2p1 -> 8.2 + p1."""
    update = "*"
    m = re.fullmatch(r"(\d+\.\d+)(p\d+)", version)
    if m:
        version, update = m.groups()
    return f"cpe:2.3:a:{vendor}:{product}:{version}:{update}:*:*:*:*:*:*"


def _texts(scan: dict) -> list[tuple[int | None, str]]:
    """Every place a server talks about itself: (port, text)."""
    out = [(p["port"], p.get("banner") or "") for p in scan.get("open_ports", [])]
    for key, port in (("https", 443), ("http", 80)):
        resp = scan.get(key) or {}
        for header in ("server", "powered_by"):
            if resp.get(header):
                out.append((port, resp[header]))
    return [(port, text) for port, text in out if text]


def detect(scan: dict) -> list[dict]:
    """All software we can recognise, one entry per product+version."""
    found: dict[tuple[str, str], dict] = {}
    for port, text in _texts(scan):
        distro = _DISTRO.search(text)
        for pid, name, rx, vendor, product in PATTERNS:
            m = re.search(rx, text)
            if not m:
                continue
            version = m.group(1)
            sw = found.setdefault((pid, version), {
                "product": pid, "name": name, "version": version, "ports": [],
                "cpe": cpe_name(vendor, product, version), "raw": text[:120], "distro": None})
            if port is not None and port not in sw["ports"]:
                sw["ports"].append(port)
            if distro and not sw["distro"]:
                sw["distro"] = distro.group(1)
    return list(found.values())
