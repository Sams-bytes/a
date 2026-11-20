"""Turn raw scan data into findings a business owner can act on.

Every finding has:
  severity  critical / high / medium / low / info
  cvss      0-10 industry severity number (approximate base score for this class of issue)
  what      what's wrong, in plain English
  fix       what to do about it
  nis2      which NIS2 Article 21(2) measure it relates to
"""

from __future__ import annotations

import ipaddress

NIS2_ACCESS = "Art. 21(2)(i) access control"
NIS2_CRYPTO = "Art. 21(2)(h) cryptography & encryption"
NIS2_VULN = "Art. 21(2)(e) secure systems & vulnerability handling"

# port -> (severity, cvss, title, what, fix, nis2)
RISKY_PORTS = {
    23: ("critical", 9.8, "Telnet is open",
         "Telnet is a 1970s remote login that sends everything, including passwords, unencrypted.",
         "Turn Telnet off. Use SSH with keys instead.", NIS2_CRYPTO),
    445: ("critical", 9.8, "Windows file sharing (SMB) exposed to the internet",
          "SMB is how WannaCry spread worldwide. It should never be reachable from the internet.",
          "Block port 445 at the firewall. Share files through a VPN or cloud storage.", NIS2_ACCESS),
    3389: ("critical", 9.0, "Remote Desktop (RDP) is open to the internet",
           "Exposed RDP is the #1 way ransomware gangs get into small businesses: they guess or buy passwords.",
           "Put RDP behind a VPN, turn on multi-factor authentication, and close port 3389.", NIS2_ACCESS),
    27017: ("critical", 9.1, "MongoDB database reachable from the internet",
            "Databases exposed like this are regularly found and copied or wiped by automated bots.",
            "Bind the database to localhost or a private network and firewall the port.", NIS2_ACCESS),
    6379: ("critical", 9.1, "Redis database reachable from the internet",
           "Redis often has no password by default; attackers use it to take over the server.",
           "Bind Redis to localhost, set a password, and firewall port 6379.", NIS2_ACCESS),
    9200: ("high", 8.6, "Elasticsearch reachable from the internet",
           "Exposed Elasticsearch is a top source of large data leaks.",
           "Firewall port 9200 and enable authentication.", NIS2_ACCESS),
    3306: ("high", 8.6, "MySQL database reachable from the internet",
           "Your database login page is visible to the whole internet and can be brute-forced.",
           "Only allow your own app servers to connect. Firewall port 3306.", NIS2_ACCESS),
    5432: ("high", 8.6, "PostgreSQL database reachable from the internet",
           "Your database login is visible to the whole internet and can be brute-forced.",
           "Only allow your own app servers to connect. Firewall port 5432.", NIS2_ACCESS),
    1433: ("high", 8.6, "Microsoft SQL Server reachable from the internet",
           "Your database login is visible to the whole internet and can be brute-forced.",
           "Only allow your own app servers to connect. Firewall port 1433.", NIS2_ACCESS),
    5900: ("high", 8.8, "VNC remote screen is open",
           "VNC gives full control of a computer's screen and often has weak passwords.",
           "Close port 5900 and use a VPN for remote access.", NIS2_ACCESS),
    21: ("high", 7.5, "FTP (unencrypted file transfer) is open",
         "FTP sends usernames, passwords and files in plain text that anyone on the path can read.",
         "Switch to SFTP or FTPS and close port 21.", NIS2_CRYPTO),
    110: ("medium", 5.9, "Unencrypted POP3 mail is open",
          "Mail passwords can be sent unencrypted on this port.",
          "Use POP3S (port 995) only and close port 110.", NIS2_CRYPTO),
    143: ("medium", 5.9, "Unencrypted IMAP mail is open",
          "Mail passwords can be sent unencrypted on this port.",
          "Use IMAPS (port 993) only and close port 143.", NIS2_CRYPTO),
}

SEVERITY_WEIGHT = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _f(severity, cvss, title, what, fix, nis2, port=None):
    return {"severity": severity, "cvss": cvss, "title": title, "what": what,
            "fix": fix, "nis2": nis2, "port": port}


def is_local_scan(scan: dict) -> bool:
    """True when the target is this computer itself (localhost / 127.0.0.1 / ::1).

    A local scan looks at the machine from the INSIDE: it shows which programs
    are listening, but not whether the firewall lets the internet reach them.
    """
    if scan.get("domain") == "localhost":
        return True
    ips = scan.get("ips") or []
    try:
        return bool(ips) and all(ipaddress.ip_address(ip).is_loopback for ip in ips)
    except ValueError:
        return False


def _as_local(f: dict, service: str) -> dict:
    """Rewrite a port finding for a local scan.

    Severity drops to info: from the inside we can only prove the port is OPEN,
    not that it is REACHABLE from outside. We keep what the severity WOULD be
    if exposed, so the owner still learns why this port matters.
    """
    risky = f["severity"] != "info"
    what = "You scanned this computer from the inside, so this shows a program is running, not that the internet can reach it."
    if risky:
        what += f" If this port were reachable from the internet it would be {f['severity']} (CVSS {f['cvss']}): {f['what']}"
        fix = (f"Check that your firewall blocks port {f['port']} from outside (scan your public domain to be sure). "
               f"If it is ever exposed: {f['fix']}")
    else:
        fix = f"Nothing to do if you know what this is. Make sure your firewall blocks port {f['port']} from outside."
    return {**f, "severity": "info", "cvss": 0.0,
            "title": f"Port {f['port']} open on this computer ({service})",
            "what": what, "fix": fix,
            "exposed_severity": f["severity"] if risky else None,
            "exposed_cvss": f["cvss"] if risky else None}


def _cvss_severity(score: float) -> str:
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def cve_findings(scan: dict) -> list[dict]:
    """One finding per detected product with known CVEs (not one per CVE, so 88
    Apache CVEs don't bury everything else or crush the score)."""
    out = []
    for item in (scan.get("vulns") or {}).get("items", []):
        cves = item["cves"]
        if not cves:
            continue
        top = max((c["cvss"] or 0) for c in cves)
        kev = [c for c in cves if c["kev"]]
        severity = _cvss_severity(top)
        if kev and severity in ("medium", "low"):
            severity = "high"  # criminals are using it right now
        n = len(cves)
        title = f"{item['name']} {item['version']}: {n} known vulnerabilit{'y' if n == 1 else 'ies'}"
        if kev:
            title += f" ({len(kev)} actively exploited)"
        worst = cves[0]
        what = (f"This version has publicly known security holes. "
                f"Most urgent: {worst['id']} (CVSS {worst['cvss']}"
                f"{', actively exploited' if worst['kev'] else ''}): {worst['summary']}")
        fix = (f"Update {item['name']} to {item['fix_version']} or newer."
               if item.get("fix_version") else f"Update {item['name']} to the latest version.")
        if item.get("distro"):
            fix += (f" Note: the server says it runs {item['distro']}, which often fixes holes without "
                    f"changing the version number. Check that security updates are installed; "
                    f"some of these may already be fixed.")
        fix += " Also consider hiding the version number in the banner."
        f = _f(severity, top, title, what, fix, NIS2_VULN, port=(item.get("ports") or [None])[0])
        f.update(kind="cve", key=f"cve:{item['product']}:{item['version']}:{','.join(sorted(c['id'] for c in cves))}",
                 cves=[{"id": c["id"], "cvss": c["cvss"], "kev": c["kev"], "summary": c["summary"],
                        "url": f"https://nvd.nist.gov/vuln/detail/{c['id']}"} for c in cves])
        out.append(f)
    return out


def build_findings(scan: dict) -> list[dict]:
    out: list[dict] = []
    open_ports = {p["port"]: p for p in scan.get("open_ports", [])}

    for port, info in RISKY_PORTS.items():
        if port in open_ports:
            out.append(_f(*info, port=port))

    if 22 in open_ports:
        out.append(_f("info", 0.0, "SSH is open",
                      "SSH is normal for server admin, but it attracts constant password-guessing bots.",
                      "Allow key-based login only, disable password login, consider limiting by IP.",
                      NIS2_ACCESS, port=22))

    tls = scan.get("tls")
    if tls:
        if tls.get("valid") is False:
            out.append(_f("high", 7.4, "HTTPS certificate is not trusted",
                          f"Browsers will show a security warning: {tls.get('error', 'invalid certificate')}.",
                          "Install a valid certificate (Let's Encrypt is free and automatic).", NIS2_CRYPTO, 443))
        elif tls.get("days_left") is not None and tls["days_left"] < 14:
            out.append(_f("medium", 5.3, f"HTTPS certificate expires in {tls['days_left']} days",
                          "When it expires, visitors get a scary warning and many will leave.",
                          "Renew now and turn on automatic renewal.", NIS2_CRYPTO, 443))
        if tls.get("legacy_tls"):
            out.append(_f("medium", 5.9, "Old TLS 1.0/1.1 still accepted",
                          "These encryption versions have known weaknesses and are banned by PCI-DSS and BSI guidance.",
                          "Allow only TLS 1.2 and 1.3 in your web server settings.", NIS2_CRYPTO, 443))

    https = scan.get("https") or {}
    if https and "error" not in https:
        if not https.get("hsts"):
            out.append(_f("low", 3.7, "HSTS header missing",
                          "Without HSTS a visitor's first connection can be downgraded to unencrypted HTTP.",
                          "Add the header: Strict-Transport-Security: max-age=31536000", NIS2_CRYPTO, 443))
        if not https.get("x_frame"):
            out.append(_f("low", 3.1, "Clickjacking protection missing",
                          "Other sites can load your pages invisibly in a frame and trick users into clicking.",
                          "Add the header: X-Frame-Options: DENY (or CSP frame-ancestors).", NIS2_VULN, 443))

    for resp in (https, scan.get("http") or {}):
        server = resp.get("server", "") if resp else ""
        if any(ch.isdigit() for ch in server):
            out.append(_f("low", 3.1, f"Web server reveals its version ({server})",
                          "Publishing exact versions helps attackers look up known holes for that version.",
                          "Hide the version number in the server configuration.", NIS2_VULN))
            break

    out.extend(cve_findings(scan))

    http = scan.get("http") or {}
    if http and "error" not in http and not http.get("redirects_to_https"):
        out.append(_f("medium", 5.3, "Website is served without forcing HTTPS",
                      "Visitors on plain http:// send data (logins, forms) unencrypted.",
                      "Redirect all http:// traffic to https://.", NIS2_CRYPTO, 80))

    for p in open_ports.values():
        if p["port"] not in RISKY_PORTS and p["port"] not in (22, 80, 443):
            out.append(_f("info", 0.0, f"Port {p['port']} open ({p['service']})",
                          "Not necessarily a problem, but every open port is something to keep patched.",
                          "Close it if nobody needs it from the internet.", NIS2_VULN, p["port"]))

    if is_local_scan(scan):
        # Only "port X is open" findings change; web/TLS findings (ports 80/443) and
        # CVE findings stay as they are - outdated software is a problem even locally.
        out = [_as_local(f, open_ports[f["port"]]["service"])
               if f["port"] in open_ports and f["port"] not in (80, 443) and f.get("kind") != "cve" else f
               for f in out]

    out.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], -f["cvss"]))
    return out


def score_findings(findings: list[dict]) -> int:
    """100 = nothing found. Each finding subtracts points by severity."""
    return max(0, 100 - sum(SEVERITY_WEIGHT[f["severity"]] for f in findings))
