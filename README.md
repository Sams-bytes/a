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

1. `POST /verify/start {"domain": "yourcompany.nl"}` returns a token like `aegis-verify=3f9a…`.
2. Add it as a **TXT record** on the domain at your DNS provider.
3. `POST /verify/check {"domain": "yourcompany.nl"}` returns `verified: true` once the record is visible.

Only someone who controls the domain's DNS can add that record. That is the
legal boundary: unauthorised scanning is a criminal offence in the EU
(NL Sr. art. 138ab, DE StGB §202c).

## Layout

| File | What it does |
|------|--------------|
| `start.bat` | One-click launcher for Windows |
| `app/main.py` | Web server: serves the dashboard and the API |
| `app/verification.py` | Proves domain ownership via a DNS TXT token |
| `app/scanner.py` | Resolves DNS, probes 25 common ports, grabs banners, checks TLS and web headers |
| `app/findings.py` | Turns scan data into findings: severity, CVSS, plain-English fix, NIS2 article |
| `app/db.py` | Saves domains and scan history in SQLite (`aegis.db`) |
| `app/static/` | The dashboard (HTML/CSS/JS) |
| `tests/` | 27 tests, including a real scan of a fake FTP server on localhost |

## Roadmap

- [x] Domain ownership verification
- [x] Exposure scanner: ports, banners, TLS, web headers (verified domains only)
- [x] Findings with CVSS score, fix advice and NIS2 mapping
- [x] Dashboard with score and scan history
- [ ] CVE matching on software versions
- [ ] Scheduled scans + email alerts
- [ ] Customer accounts / login
- [ ] NIS2 / GDPR readiness mapping
- [ ] Phishing-awareness training module
