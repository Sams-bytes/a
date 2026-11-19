# Aegis

Attack-surface monitoring for EU small businesses (NIS2 / GDPR focused).
**Aegis only scans domains whose owner has proven control via DNS.**

## Run it on Windows

```powershell
git clone https://github.com/Sams-bytes/a.git
cd a
git checkout claude/inspiring-hamilton-jxo3nx
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/docs to try the API in your browser.

> If `Activate.ps1` is blocked, run once:
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

Run tests: `python -m pytest -q`

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
| `app/verification.py` | Domain cleanup, token generation, DNS TXT lookup |
| `app/main.py` | FastAPI web API |
| `tests/` | Tests with fake DNS (no internet needed) |

## Roadmap

- [x] Domain ownership verification
- [ ] Exposure scanner: ports, services, TLS (verified domains only)
- [ ] CVE matching + CVSS scoring
- [ ] NIS2 / GDPR readiness mapping
- [ ] Phishing-awareness training module
