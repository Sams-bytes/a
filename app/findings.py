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
    # Found mainly by the Nmap engine (top 1,000 ports + Aegis extras):
    2375: ("critical", 9.8, "Docker API open without encryption",
           "Anyone who reaches this port can start containers and take over the whole server.",
           "Never expose the Docker API. Close port 2375; manage Docker over SSH instead.", NIS2_ACCESS),
    2376: ("high", 7.5, "Docker API reachable from the internet",
           "Even with TLS, the Docker API controls the whole server and should not be public.",
           "Close port 2376 to the internet; reach it only through a VPN or SSH.", NIS2_ACCESS),
    11211: ("critical", 9.1, "memcached reachable from the internet",
            "memcached has no login: anyone can read or change cached data, and it can be abused for DDoS attacks.",
            "Bind memcached to localhost and firewall port 11211.", NIS2_ACCESS),
    4786: ("critical", 9.8, "Cisco Smart Install is open",
           "A known-abused Cisco feature that lets attackers rewrite the switch/router configuration.",
           "Disable Smart Install on the device ('no vstack') and block port 4786.", NIS2_ACCESS),
    5985: ("high", 7.5, "Windows Remote Management (WinRM) is open",
           "WinRM gives remote command-line control of Windows. Attackers use it with stolen passwords.",
           "Close port 5985 to the internet; use a VPN for remote administration.", NIS2_ACCESS),
    5986: ("high", 7.5, "Windows Remote Management (WinRM over HTTPS) is open",
           "WinRM gives remote command-line control of Windows. Attackers use it with stolen passwords.",
           "Close port 5986 to the internet; use a VPN for remote administration.", NIS2_ACCESS),
    10000: ("high", 8.1, "Webmin server admin panel is open",
            "A web panel that controls the whole server; it has had several critical vulnerabilities.",
            "Close port 10000 to the internet, or restrict it to your own IP / VPN.", NIS2_ACCESS),
    8291: ("high", 8.1, "MikroTik Winbox router management is open",
           "Router admin access from the internet; old versions were mass-hacked.",
           "Restrict Winbox to your internal network and update RouterOS.", NIS2_ACCESS),
    2049: ("high", 7.5, "NFS file sharing reachable from the internet",
           "Network file shares exposed to the internet can leak or let attackers change files.",
           "Block port 2049; share files through a VPN.", NIS2_ACCESS),
    111: ("medium", 5.3, "RPC portmapper is open",
          "Tells anyone which internal services run on the server and can be abused for DDoS amplification.",
          "Block port 111 at the firewall.", NIS2_ACCESS),
    139: ("high", 7.5, "Windows NetBIOS file sharing exposed",
          "Old Windows file-sharing protocol; should never be reachable from the internet.",
          "Block port 139 at the firewall.", NIS2_ACCESS),
}

_AMPLIFY = ("Can be abused for 'amplification' DDoS attacks: attackers send a tiny request with a faked "
            "sender address and your server sends a much bigger answer to their victim. Your server "
            "becomes a weapon against others, and your provider may cut you off.")

# UDP port -> (severity, cvss, title, what, fix, nis2)
RISKY_UDP = {
    161: ("high", 7.5, "SNMP device management is reachable (UDP 161)",
          "SNMP reveals device and network details and often still uses the default password 'public'.",
          "Block UDP 161 from the internet. If you need SNMP, use SNMPv3 with a strong password.", NIS2_ACCESS),
    623: ("critical", 9.8, "IPMI server management chip is reachable (UDP 623)",
          "IPMI controls the server hardware below the operating system. Known flaws leak password hashes.",
          "Put IPMI/iDRAC/iLO on a separate management network, never on the internet.", NIS2_ACCESS),
    69: ("high", 7.5, "TFTP file transfer is open (UDP 69)",
         "TFTP has no login at all: anyone can download (and sometimes upload) files, e.g. device configs.",
         "Turn TFTP off or block UDP 69.", NIS2_ACCESS),
    11211: ("critical", 9.1, "memcached over UDP is open (UDP 11211)",
            "memcached over UDP enabled record-breaking DDoS attacks (51,000x amplification). " + _AMPLIFY,
            "Disable UDP in memcached (-U 0) and firewall port 11211.", NIS2_VULN),
    123: ("medium", 5.3, "NTP time server is reachable (UDP 123)",
          "Public NTP servers that answer everyone (especially old 'monlist') are abused. " + _AMPLIFY,
          "Only answer your own network, disable monlist, or block UDP 123 if you don't run a time server.", NIS2_VULN),
    1900: ("medium", 5.3, "SSDP / UPnP is reachable (UDP 1900)",
           "SSDP is meant for home networks only. " + _AMPLIFY,
           "Disable UPnP on the router/device and block UDP 1900.", NIS2_VULN),
    389: ("medium", 5.8, "CLDAP directory service is reachable (UDP 389)",
          "Exposed Active Directory CLDAP leaks domain information. " + _AMPLIFY,
          "Block UDP 389 from the internet.", NIS2_VULN),
    53: ("medium", 5.0, "DNS server answers on UDP 53",
         "Fine for your own domain's name server - but if it answers questions about ANY domain "
         "(an 'open resolver'), it is abused. " + _AMPLIFY,
         "Make sure the DNS server only answers for your own domains (disable recursion for the internet).", NIS2_VULN),
    137: ("high", 7.5, "NetBIOS name service is reachable (UDP 137)",
          "Leaks computer and user names from Windows networks; should never be internet-facing.",
          "Block UDP 137-138 at the firewall.", NIS2_ACCESS),
    1434: ("medium", 5.3, "MS SQL Browser is reachable (UDP 1434)",
           "Reveals SQL Server instances and versions to anyone (and was used by the SQL Slammer worm).",
           "Block UDP 1434 from the internet.", NIS2_ACCESS),
    5060: ("medium", 5.3, "SIP (VoIP telephony) is reachable (UDP 5060)",
           "Exposed SIP is targeted for toll fraud: criminals make expensive calls on your account.",
           "Allow SIP only from your VoIP provider's addresses and use strong SIP passwords.", NIS2_ACCESS),
}

# VPN endpoints are GOOD news: that's exactly what we recommend instead of open admin ports.
VPN_UDP = {500: "IPsec VPN (IKE)", 4500: "IPsec VPN (NAT-T)", 1194: "OpenVPN", 51820: "WireGuard VPN"}

SEVERITY_WEIGHT = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _f(severity, cvss, title, what, fix, nis2, port=None, proto="tcp"):
    return {"severity": severity, "cvss": cvss, "title": title, "what": what,
            "fix": fix, "nis2": nis2, "port": port, "proto": proto if port is not None else None}


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
    label = f"{'UDP' if f.get('proto') == 'udp' else 'Port'} {f['port']}"
    what = "You scanned this computer from the inside, so this shows a program is running, not that the internet can reach it."
    if risky:
        what += f" If this port were reachable from the internet it would be {f['severity']} (CVSS {f['cvss']}): {f['what']}"
        fix = (f"Check that your firewall blocks {label.lower()} from outside (scan your public domain to be sure). "
               f"If it is ever exposed: {f['fix']}")
    else:
        fix = f"Nothing to do if you know what this is. Make sure your firewall blocks {label.lower()} from outside."
    return {**f, "severity": "info", "cvss": 0.0,
            "title": f"{label} open on this computer ({service})",
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


_TLS_GRADE = {"C": ("medium", 5.3), "D": ("high", 7.0), "E": ("high", 7.4), "F": ("critical", 9.1)}


def nse_findings(scan: dict) -> list[dict]:
    """Findings from the safe Nmap scripts (app/nse.py)."""
    from app import nse
    out = []
    for c in (scan.get("nse") or {}).get("checks", []):
        port, sid = c["port"], c["id"]
        if sid == "ssl-enum-ciphers":
            grade = nse.tls_grade(c["output"])
            if grade in _TLS_GRADE:
                sev, cvss = _TLS_GRADE[grade]
                legacy = " It also still allows old TLS 1.0/1.1 or SSLv3." if nse.has_legacy_tls(c["output"]) else ""
                f = _f(sev, cvss, f"Weak HTTPS encryption (grade {grade})",
                       f"Nmap graded this server's HTTPS encryption {grade} (A is best, F worst).{legacy} "
                       "Weak encryption can let attackers read or tamper with traffic.",
                       "Allow only TLS 1.2/1.3 and strong ciphers; disable old protocols and weak ciphers "
                       "(Mozilla's SSL Config Generator gives ready settings).", NIS2_CRYPTO, port)
                f.update(kind="nse", key=f"nse:tls:{port}")
                out.append(f)
        elif sid == "smb-protocols" and nse.smbv1_enabled(c):
            port = port or 445   # SMB scripts are reported host-level; the port is always 445
            f = _f("critical", 9.3, "Ancient SMBv1 file sharing is enabled",
                   "SMBv1 is the 1980s protocol WannaCry used to spread worldwide. It should be off everywhere.",
                   "Disable SMBv1 (Windows: turn off the 'SMB 1.0/CIFS' feature) and use SMB 2/3 only.",
                   NIS2_ACCESS, port)
            f.update(kind="nse", key=f"nse:smbv1:{port}")
            out.append(f)
        elif sid == "smb2-security-mode" and nse.signing_not_required(c):
            port = port or 445
            f = _f("medium", 5.3, "SMB message signing is not required",
                   "Without required signing, an attacker on the network can tamper with file-sharing traffic "
                   "(relay attacks).", "Require SMB signing on the server and clients.", NIS2_ACCESS, port)
            f.update(kind="nse", key=f"nse:smbsign:{port}")
            out.append(f)
        elif sid == "ssh2-enum-algos" and nse.WEAK_SSH.search(c["output"]):
            f = _f("medium", 5.3, "SSH offers weak algorithms",
                   "This SSH server still offers outdated key-exchange, cipher or MAC algorithms "
                   "(e.g. SHA-1, CBC, 3DES) that are considered unsafe.",
                   "Limit SSH to modern algorithms (disable SHA-1, CBC and 3DES in sshd_config).", NIS2_CRYPTO, port)
            f.update(kind="nse", key=f"nse:ssh:{port}")
            out.append(f)
    return out


def build_findings(scan: dict) -> list[dict]:
    out: list[dict] = []
    # Key by (protocol, port): TCP 11211 and UDP 11211 are different "doors".
    open_ports = {(p.get("proto", "tcp"), p["port"]): p for p in scan.get("open_ports", [])}

    for port, info in RISKY_PORTS.items():
        if ("tcp", port) in open_ports:
            out.append(_f(*info, port=port))
    for port, info in RISKY_UDP.items():
        if ("udp", port) in open_ports:
            out.append(_f(*info, port=port, proto="udp"))
    for port, name in VPN_UDP.items():
        if ("udp", port) in open_ports:
            out.append(_f("info", 0.0, f"VPN endpoint found: {name} (UDP {port})",
                          "Good news: a VPN is the safe way to reach internal systems, instead of opening admin ports.",
                          "Keep the VPN software updated and require multi-factor login for every VPN user.",
                          NIS2_ACCESS, port=port, proto="udp"))

    if ("tcp", 22) in open_ports:
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
    out.extend(nse_findings(scan))

    http = scan.get("http") or {}
    if http and "error" not in http and not http.get("redirects_to_https"):
        out.append(_f("medium", 5.3, "Website is served without forcing HTTPS",
                      "Visitors on plain http:// send data (logins, forms) unencrypted.",
                      "Redirect all http:// traffic to https://.", NIS2_CRYPTO, 80))

    for (proto, port), p in open_ports.items():
        if proto == "tcp" and port not in RISKY_PORTS and port not in (22, 80, 443):
            out.append(_f("info", 0.0, f"Port {port} open ({p['service']})",
                          "Not necessarily a problem, but every open port is something to keep patched.",
                          "Close it if nobody needs it from the internet.", NIS2_VULN, port))
        elif proto == "udp" and port not in RISKY_UDP and port not in VPN_UDP:
            out.append(_f("info", 0.0, f"UDP {port} open ({p['service']})",
                          "A UDP service answered. Not necessarily a problem, but keep it patched.",
                          "Close it if nobody needs it from the internet.", NIS2_VULN, port, proto="udp"))

    if is_local_scan(scan):
        # Only "port X is open" findings change; web/TLS findings (TCP 80/443) and
        # CVE findings stay as they are - outdated software is a problem even locally.
        def is_port_finding(f):
            key = (f.get("proto") or "tcp", f["port"])
            return (key in open_ports and key not in (("tcp", 80), ("tcp", 443))
                    and f.get("kind") not in ("cve", "nse"))
        out = [_as_local(f, open_ports[(f.get("proto") or "tcp", f["port"])]["service"])
               if is_port_finding(f) else f for f in out]

    out.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], -f["cvss"]))
    return out


def score_findings(findings: list[dict]) -> int:
    """100 = nothing found. Each finding subtracts points by severity."""
    return max(0, 100 - sum(SEVERITY_WEIGHT[f["severity"]] for f in findings))
