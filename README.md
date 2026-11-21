# Aegis

Attack-surface monitoring for EU small businesses (NIS2 / GDPR focused).
**Aegis only scans domains whose owner has proven control via DNS.**

## Run it on Windows (no terminal needed)

1. Install Python once: open PowerShell and run `winget install Python.Python.3.12`
2. Download this project: `git clone https://github.com/Sams-bytes/a.git` then
   `git checkout claude/inspiring-hamilton-jxo3nx` inside the `a` folder
   (or on GitHub: Code -> Download ZIP, and unzip it).
3. **Double-click `start.bat`.** The first run sets everything up (about a minute),
   then your browser opens http://127.0.0.1:8000 with the Aegis dashboard.

Close the black window to stop Aegis. Your domains and scans are saved in `aegis.db`.

Try it right away: add `localhost` (your own computer is always allowed) and press **Run scan**.

Developers: `python -m pytest -q` runs the tests; the API docs are at http://127.0.0.1:8000/docs.

## How domain verification works

1. Add the domain in the dashboard (or `POST /api/domains {"domain": "yourcompany.nl"}`). You get a token like `aegis-verify=3f9a…`.
2. Add it as a **TXT record** on the domain at your DNS provider.
3. Press **Check verification** (or `POST /api/domains/yourcompany.nl/verify`). Once the record is visible, the domain is verified and **Run scan** unlocks.

Only someone who controls the domain's DNS can add that record. That is the
legal boundary: unauthorised scanning is a criminal offence in the EU
(NL Sr. art. 138ab, DE StGB §202c).

## Weekly monitoring

Every verified domain is re-scanned automatically every 7 days (switch it off per
domain in the dashboard). Each scan is compared with the previous one. If a port
opened, a new finding appeared or the score dropped, you get an alert in the
dashboard. The **What changed** card shows the details.

- **Ownership is re-checked before every automatic scan.** If the `aegis-verify`
  TXT record has gone, Aegis does not scan, marks the domain unverified and raises
  an alert. If DNS is simply unreachable (offline), it skips and tries again later.
- The scheduler runs inside the Aegis server, so it only runs while Aegis is
  running. It checks at startup, so overdue scans catch up straight away.
- Settings: `AEGIS_SCAN_INTERVAL_HOURS` (default 168), `AEGIS_SCHEDULER=0` to turn it off.
- Try it: run `.venv\Scripts\python tools\fake_service.py 5432` (a fake database on
  your own computer), then press **Run automatic check now** on localhost.

## Network map (your own network)

Click **My network map** in the dashboard to see every device on your own
Wi-Fi/LAN — router, computers, phones, printers, smart gadgets — drawn as a map
you can click. It uses Nmap host discovery (`-sn`), which on a local network uses
ARP, so it also learns each device's MAC address and maker (Apple, Samsung,
Zyxel…). A device that appears for the first time is flagged, so you notice a
stranger on your Wi-Fi.

- **Only your own network.** Aegis offers only the private ranges this computer
  is on, and scans one only after you tick "this network is mine". Scanning a
  café/hotel/client network without permission is a crime, like scanning a
  stranger's server.
- **Deep scan** (open ports + OS detection) needs administrator rights: run
  `start-admin.bat` (one Windows UAC prompt). Without admin you still get the
  full device list with makers and names.

## Live traffic (what is my computer talking to?)

Click **Live traffic** to see which of your own programs are connected to which
servers on the internet right now, each labelled with who owns the server
(Amazon, Google, Meta…). It reads **this computer's own** connection table
(like Task Manager's network tab) and refreshes every few seconds.

Honest scope: this is connection *metadata*, not packet contents — it shows that
Chrome is talking to a Google server, not what was sent. Deep packet inspection
is Wireshark's job; Aegis stays out of your data. Only your own machine is read;
only remote IP addresses are sent to rdap.org for the owner labels.

## Deeper checks (safe Nmap scripts)

When relevant ports are open, Aegis runs a **fixed allowlist of safe,
non-intrusive Nmap scripts** and shows the results as cards:

- `ssl-enum-ciphers` — grades the HTTPS encryption **A–F** and lists weak ciphers.
- `smb-protocols` / `smb2-security-mode` — is ancient **SMBv1** (WannaCry) on? is signing required?
- `ssh2-enum-algos` — flags outdated SSH algorithms (SHA-1, CBC, 3DES).
- `http-security-headers` / `http-title` — context, harmless.

Grade C/D/E/F, SMBv1, missing SMB signing and weak SSH become findings. Only
these read-only scripts are ever used — never the intrusive, brute-force or
exploit categories, and no caller value is ever passed to `--script`. Turn off
with `AEGIS_NSE=0`.

## Hosting check: light vs full scan

Owning a domain is not owning the server. If a domain's IP addresses belong
to a hosting or cloud company (looked up in the public RDAP registry, e.g.
"HOSTINGER-HOSTING"), Aegis does a **light scan**: the website, its certificate,
headers and software versions, like a browser visit. **No port scan**, because
on shared hosting the machine also serves other customers. If you run your own
VPS or dedicated server there, press **This is my own server**. Aegis records
when you confirmed it and then does the full scan. IPs that belong to no known
hosting company get the full scan; if the lookup fails, Aegis plays safe and scans lightly.

## Subdomain discovery

On a verified main domain, **Discover subdomains** searches public certificate
logs (crt.sh and certspotter: each has gaps, so both are used), DNS records (MX,
SRV) and ~120 common names (vpn, mail, dev, test, old, …).

- **Wildcard DNS** is detected, so guesses that only hit a catch-all record are ignored.
- **Subdomain takeover:** a name that points (CNAME) to a cloud service that no
  longer exists (e.g. a cancelled Shopify/Heroku/GitHub Pages site) is flagged
  red, because an attacker could claim it and show their page on your subdomain.
- Each subdomain shows who hosts it. **Monitor** adds it under its parent (no
  extra TXT record needed: the parent's record covers it, and it is re-checked
  before every automatic scan). Hosted by a provider → light scan.
- Weekly monitoring re-runs discovery and alerts on new subdomains and new takeover risks.
- Privacy: the domain name goes to crt.sh/certspotter (public logs) and IP addresses to rdap.org.

## Professional scanning with Nmap

When [Nmap](https://nmap.org/download.html) is installed, Aegis uses it automatically:

- **TCP:** Nmap's top 1,000 ports plus Aegis's own high-risk ports (Docker API,
  Redis, memcached, WinRM, …), with **version detection** (`-sV`). Nmap's
  product/version/CPE output feeds the CVE matching.
- **UDP:** 17 important services (DNS, NTP, SNMP, IPMI, SSDP, memcached, VPNs…).
  Only services that *answer* count as open. Silent ports are listed as
  "uncertain" (open or blocked: UDP can't tell). Exposed NTP/SSDP/memcached/CLDAP
  are flagged as **DDoS amplification** risks.
- Safe by design: no shell (argument list only, target validated twice), no NSE
  scripts, only `-sT`, `-sV`, `-sU`. UDP may need administrator rights; without
  them Aegis reports "UDP skipped" and still gives the TCP results.
- Without Nmap, Aegis uses its built-in scanner (25 TCP ports). Settings:
  `AEGIS_NMAP` (path to nmap.exe), `AEGIS_ENGINE=builtin` (force the built-in engine).
- The first Nmap scan after the built-in engine is treated as a new baseline
  (no "20 new ports!" alert).

## CVE matching

Many servers announce their software and version (`SSH-2.0-OpenSSH_8.2p1`,
`Server: Apache/2.4.49`). Aegis recognises these (`app/fingerprint.py`) and looks
up known vulnerabilities (CVEs) for that exact version (`app/cve.py`):

1. **Built-in list** (`app/data/known_cves.json`): about 20 famous CVEs. Works offline.
2. **Live NVD lookup**: NIST's National Vulnerability Database, cached for 24 h.
   Only the software identifier (a CPE name such as
   `cpe:2.3:a:apache:http_server:2.4.49:…`) is sent, never your domain.

You get one finding per product ("ProFTPD 1.3.5: 19 known vulnerabilities (1
actively exploited)"), with the version to update to and links to NIST.
**Actively exploited** means the CVE is on CISA's Known Exploited
Vulnerabilities (KEV) list. Version matching gives *possible* matches: Linux
distributions often fix holes without changing the version number, and Aegis
says so when it sees Ubuntu/Debian/RHEL in a banner. Aegis never tries an attack.

- Settings: `NVD_API_KEY` (optional, free from NIST, faster lookups), `AEGIS_CVE_LIVE=0` (built-in list only).
- Try it: `.venv\Scripts\python tools\fake_service.py 21 --banner "220 ProFTPD 1.3.5 Server"`,
  then **Run scan** on localhost.

## Layout

| File | What it does |
|------|--------------|
| `start.bat` | One-click launcher for Windows |
| `start-admin.bat` | Launch as admin (for the network map's deep scan) |
| `app/main.py` | Web server: serves the dashboard and the API |
| `app/verification.py` | Proves domain ownership via a DNS TXT token |
| `app/scanner.py` | Resolves DNS, scans ports (Nmap or built-in), checks TLS and web headers |
| `app/traffic.py` | Live view of this computer's connections to the internet, by app and owner |
| `app/nse.py` | Safe Nmap scripts: TLS grade, SMBv1/signing, weak SSH, headers |
| `app/jobs.py` | Background scan jobs with live progress (phase/percent/log) |
| `app/netmap.py` | Maps your own LAN (device discovery, MAC vendors, OS, rogue-device flag) |
| `app/hosting.py` | Who owns an IP (RDAP) → light or full scan |
| `app/subdomains.py` | Subdomain discovery: certificate logs, DNS, common names, takeover check |
| `app/nmap_engine.py` | Runs Nmap safely (TCP top 1,000 + UDP) and parses its XML |
| `app/findings.py` | Turns scan data into findings: severity, CVSS, plain-English fix, NIS2 article |
| `app/fingerprint.py` | Recognises software + version in banners and headers |
| `app/cve.py`, `app/data/known_cves.json` | CVE matching: built-in list + live NVD (cached) |
| `app/changes.py` | Compares two scans: new/closed ports, new/fixed findings |
| `app/monitor.py` | Weekly automatic scans, ownership re-check, alerts |
| `app/db.py` | Saves domains, scan history and alerts in SQLite (`aegis.db`), with small migrations |
| `app/static/` | The dashboard (HTML/CSS/JS) |
| `tools/fake_service.py` | Opens a fake service on a local port (optionally with a banner), for demos |
| `tests/` | 114 tests, including a real scan of a fake FTP server on localhost |

## Roadmap

- [x] Domain ownership verification
- [x] Exposure scanner: ports, banners, TLS, web headers (verified domains only)
- [x] Findings with CVSS score, fix advice and NIS2 mapping
- [x] Dashboard with score and scan history
- [x] Weekly scans + change alerts in the dashboard
- [ ] Email delivery for alerts
- [x] CVE matching on software versions (built-in list + live NVD)
- [ ] Customer accounts / login
- [ ] NIS2 / GDPR readiness mapping
- [ ] Phishing-awareness training module
