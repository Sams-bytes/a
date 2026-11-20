"""The exposure scanner: what can the internet see on this domain?

Steps (the same ones a professional scanner runs):
  1. Resolve DNS       -> which IP addresses does the domain point to?
  2. Probe ports       -> which "doors" are open? (TCP connect, nothing more)
  3. Grab banners      -> what software answers behind each door?
  4. Check TLS         -> is the HTTPS certificate valid, current, modern?
  5. Check web headers -> does the site use basic browser protections?
  6. Turn it into findings with a severity, CVSS score and a plain-English fix.

Only ever called for verified domains (see verification.py).
This is a gentle scan: one TCP connect per port. No exploits, no password guessing.
"""

from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import httpx

from app.findings import build_findings, is_local_scan, score_findings
from app.fingerprint import detect

# port -> human-readable service name
PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP (mail)", 53: "DNS",
    80: "HTTP (web)", 110: "POP3 (mail)", 143: "IMAP (mail)", 443: "HTTPS (web)",
    445: "SMB (Windows file sharing)", 465: "SMTPS (mail)", 587: "SMTP submission",
    993: "IMAPS (mail)", 995: "POP3S (mail)", 1433: "Microsoft SQL Server",
    3306: "MySQL database", 3389: "Remote Desktop (RDP)", 5432: "PostgreSQL database",
    5900: "VNC remote screen", 6379: "Redis database", 8000: "HTTP (dev server)",
    8080: "HTTP (alt)", 8443: "HTTPS (alt)", 9200: "Elasticsearch", 27017: "MongoDB",
}

BANNER_PORTS = {21, 22, 25, 110, 143, 587}


def resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    return sorted({i[4][0] for i in infos})


def probe_port(host: str, port: int, timeout: float) -> dict | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            banner = ""
            if port in BANNER_PORTS:
                s.settimeout(2)
                try:
                    banner = s.recv(256).decode("utf-8", errors="replace").strip()
                except OSError:
                    pass
            return {"port": port, "service": PORTS.get(port, "unknown"), "banner": banner[:120]}
    except OSError:
        return None


def check_tls(host: str, port: int = 443, timeout: float = 5) -> dict:
    out: dict = {"port": port, "checked": True}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as tls:
                cert = tls.getpeercert()
                out["valid"] = True
                out["version"] = tls.version()
                expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                out["expires"] = expires.date().isoformat()
                out["days_left"] = (expires - datetime.now(timezone.utc)).days
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                out["issuer"] = issuer.get("organizationName", "unknown")
    except ssl.SSLCertVerificationError as e:
        out["valid"] = False
        out["error"] = e.verify_message or str(e)
    except (OSError, ssl.SSLError) as e:
        out["valid"] = False
        out["error"] = str(e)
    out["legacy_tls"] = accepts_legacy_tls(host, port, timeout)
    return out


def accepts_legacy_tls(host: str, port: int, timeout: float) -> bool | None:
    """Does the server still accept TLS 1.0/1.1 (broken, banned by most standards)?
    Returns None if this computer's OpenSSL can't even test it."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host):
                return True
    except ssl.SSLError:
        return False
    except OSError:
        return None


def check_http(host: str, https: bool) -> dict:
    url = f"{'https' if https else 'http'}://{host}/"
    try:
        r = httpx.get(url, timeout=6, follow_redirects=False)
    except httpx.HTTPError as e:
        return {"url": url, "error": str(e)}
    location = r.headers.get("location", "")
    return {
        "url": url,
        "status": r.status_code,
        "redirects_to_https": r.is_redirect and location.startswith("https://"),
        "server": r.headers.get("server", ""),
        "powered_by": r.headers.get("x-powered-by", ""),
        "hsts": "strict-transport-security" in r.headers,
        "csp": "content-security-policy" in r.headers,
        "x_frame": "x-frame-options" in r.headers or "frame-ancestors" in r.headers.get("content-security-policy", ""),
    }


def scan(domain: str, timeout: float = 1.5, log=lambda msg: None, matcher=None) -> dict:
    """matcher: an app.cve.Matcher; when given, detected software is checked for CVEs."""
    started = datetime.now(timezone.utc)
    log(f"Resolving DNS for {domain}")
    ips = resolve(domain)
    result: dict = {"domain": domain, "ips": ips, "open_ports": [], "tls": None, "http": None, "https": None}
    if not ips:
        result["error"] = "Domain does not resolve to any IP address."
        result["findings"] = []
        result["score"] = 100
        return result

    log(f"Probing {len(PORTS)} common ports")
    with ThreadPoolExecutor(max_workers=25) as pool:
        hits = pool.map(lambda p: probe_port(domain, p, timeout), PORTS)
    result["open_ports"] = sorted((h for h in hits if h), key=lambda h: h["port"])
    open_set = {p["port"] for p in result["open_ports"]}

    if 443 in open_set:
        log("Checking TLS certificate")
        result["tls"] = check_tls(domain)
        result["https"] = check_http(domain, https=True)
    if 80 in open_set:
        result["http"] = check_http(domain, https=False)

    result["software"] = detect(result)
    if matcher and result["software"]:
        log("Checking detected software for known vulnerabilities (CVEs)")
        result["vulns"] = matcher.match(result["software"])
    result["local"] = is_local_scan(result)
    result["findings"] = build_findings(result)
    result["score"] = score_findings(result["findings"])
    result["duration_s"] = round((datetime.now(timezone.utc) - started).total_seconds(), 1)
    return result
