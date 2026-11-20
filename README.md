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
| `app/main.py` | Web server: serves the dashboard and the API |
| `app/verification.py` | Proves domain ownership via a DNS TXT token |
| `app/scanner.py` | Resolves DNS, probes 25 common ports, grabs banners, checks TLS and web headers |
| `app/findings.py` | Turns scan data into findings: severity, CVSS, plain-English fix, NIS2 article |
| `app/fingerprint.py` | Recognises software + version in banners and headers |
| `app/cve.py`, `app/data/known_cves.json` | CVE matching: built-in list + live NVD (cached) |
| `app/changes.py` | Compares two scans: new/closed ports, new/fixed findings |
| `app/monitor.py` | Weekly automatic scans, ownership re-check, alerts |
| `app/db.py` | Saves domains, scan history and alerts in SQLite (`aegis.db`), with small migrations |
| `app/static/` | The dashboard (HTML/CSS/JS) |
| `tools/fake_service.py` | Opens a fake service on a local port (optionally with a banner), for demos |
| `tests/` | 63 tests, including a real scan of a fake FTP server on localhost |

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
