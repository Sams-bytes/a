"""CVE matching: which known vulnerabilities affect the software we detected?

Two sources (merged by CVE id):
  1. Built-in list  app/data/known_cves.json - ~20 famous CVEs, works offline.
  2. Live NVD       NIST's National Vulnerability Database - everything else.
                    We send ONLY the software identifier (a CPE name such as
                    cpe:2.3:a:apache:http_server:2.4.49:...), never the
                    customer's domain. Answers are cached for 24 hours.

Words:
  CVE   public ID for one known security hole, e.g. CVE-2021-41773
  CVSS  0-10 severity score (10 = worst)
  KEV   CISA's list of "Known Exploited Vulnerabilities": criminals are
        using this one right now. NVD marks those with "cisaExploitAdd".

Honest limit: matching by version number gives POSSIBLE matches. Linux
distributions often patch a hole without changing the version ("back-porting").

Settings: NVD_API_KEY (optional, faster lookups), AEGIS_CVE_LIVE=0 (offline only).
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path

import httpx

from app.db import Store

BUILTIN_FILE = Path(__file__).parent / "data" / "known_cves.json"
CACHE_S = 24 * 3600
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"


# ---- version comparison -------------------------------------------------------
def vkey(version: str) -> tuple:
    """'8.2p1' -> (8, 2, 16, 1); '1.0.1f' -> (1, 0, 1, 6). Letters count a=1..z=26.

    Comparing tuples works like comparing words letter by letter, so
    1.0.1f < 1.0.1g, 2.4.9 < 2.4.49 and 8.5p1 < 9.8p1 - which plain text
    comparison gets wrong ("2.4.9" > "2.4.49" as text!).
    """
    return tuple(int(p) if p.isdigit() else ord(p) - 96 for p in re.findall(r"\d+|[a-z]", version.lower()))


def in_range(version: str, r: dict) -> bool:
    v = vkey(version)
    if "exact" in r:
        return v == vkey(r["exact"])
    if v < vkey(r.get("introduced", "0")):
        return False
    if "fixed" in r:
        return v < vkey(r["fixed"])
    if "last_affected" in r:
        return v <= vkey(r["last_affected"])
    return True


# ---- source 1: built-in list --------------------------------------------------
def load_builtin() -> list[dict]:
    return json.loads(BUILTIN_FILE.read_text(encoding="utf-8"))["cves"]


def builtin_matches(product: str, version: str, entries: list[dict] | None = None) -> list[dict]:
    out = []
    for e in entries if entries is not None else load_builtin():
        if e["product"] == product and any(in_range(version, r) for r in e["ranges"]):
            fixed = [r["fixed"] for r in e["ranges"] if "fixed" in r and in_range(version, r)]
            out.append({"id": e["id"], "cvss": e["cvss"], "kev": e["kev"], "summary": e["summary"],
                        "fixed_in": fixed, "source": "built-in"})
    return out


# ---- source 2: live NVD -------------------------------------------------------
def parse_nvd_cve(c: dict, vendor_product: str) -> dict:
    """One NVD 'cve' object -> our small dict."""
    metrics = c.get("metrics", {})
    cvss = None
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):  # newest scoring system first
        if metrics.get(k):
            primary = [m for m in metrics[k] if m.get("type") == "Primary"] or metrics[k]
            cvss = primary[0]["cvssData"]["baseScore"]
            break
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    fixed = []
    for conf in c.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable") and f":{vendor_product}:" in m.get("criteria", "") \
                        and m.get("versionEndExcluding"):
                    fixed.append(m["versionEndExcluding"])
    return {"id": c["id"], "cvss": cvss, "kev": "cisaExploitAdd" in c,
            "summary": (desc[:220] + "...") if len(desc) > 220 else desc,
            "fixed_in": fixed, "source": "nvd"}


class NVDClient:
    """Asks NVD which CVEs affect one exact CPE. Returns None when unreachable."""

    _lock = threading.Lock()
    _last = 0.0

    def __init__(self, api_key: str | None = None, http_get=httpx.get):
        self.api_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY")
        self._get = http_get
        # NVD's public limit: 5 requests / 30 s without a key, 50 / 30 s with one.
        self.min_interval = 0.7 if self.api_key else 6.5

    def lookup(self, cpe: str) -> list[dict] | None:
        vendor_product = ":".join(cpe.split(":")[3:5])
        with NVDClient._lock:  # one request at a time, politely spaced
            wait = NVDClient._last + self.min_interval - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            try:
                headers = {"apiKey": self.api_key} if self.api_key else {}
                r = self._get(NVD_URL, params={"cpeName": cpe, "isVulnerable": ""},
                              headers=headers, timeout=20)
                r.raise_for_status()
                data = r.json()
            except (httpx.HTTPError, ValueError):
                return None
            finally:
                NVDClient._last = time.monotonic()
        return [parse_nvd_cve(v["cve"], vendor_product) for v in data.get("vulnerabilities", [])]


# ---- source 3: EPSS (how LIKELY is a CVE to be exploited?) -----------------------
class EPSSClient:
    """FIRST.org's EPSS: a 0-1 probability a CVE will be exploited in the next 30
    days. Free, no key. Only CVE ids leave the machine (never the domain)."""

    def __init__(self, http_get=httpx.get):
        self._get = http_get

    def lookup(self, cve_ids: list[str]) -> dict | None:
        """{cve_id: probability}. None on failure. Unknown CVEs are simply absent."""
        out: dict[str, float] = {}
        ids = sorted(set(cve_ids))
        for i in range(0, len(ids), 100):          # the API takes up to ~100 ids per call
            batch = ids[i:i + 100]
            try:
                r = self._get(EPSS_URL, params={"cve": ",".join(batch)}, timeout=20)
                r.raise_for_status()
                data = r.json()
            except (httpx.HTTPError, ValueError):
                return None
            for row in data.get("data", []):
                try:
                    out[row["cve"]] = float(row["epss"])
                except (KeyError, TypeError, ValueError):
                    pass
        return out


def top_epss(cves: list[dict]) -> float | None:
    """The highest exploit probability among a product's CVEs (None if unknown)."""
    vals = [c["epss"] for c in cves if c.get("epss") is not None]
    return max(vals) if vals else None


# ---- merge both sources ---------------------------------------------------------
def fix_version(version: str, cves: list[dict]) -> str | None:
    """Lowest version that fixes ALL listed CVEs (as far as we know)."""
    needed = []
    for c in cves:
        later = [f for f in c.get("fixed_in", []) if vkey(f) > vkey(version)]
        if later:
            needed.append(min(later, key=vkey))
    return max(needed, key=vkey) if needed else None


class Matcher:
    def __init__(self, store: Store, nvd: NVDClient | None = None, live: bool | None = None,
                 epss: EPSSClient | None = None):
        self.store = store
        self.live = live if live is not None else os.environ.get("AEGIS_CVE_LIVE", "1") != "0"
        self.nvd = nvd or NVDClient()
        self.epss = epss or EPSSClient()
        self.builtin = load_builtin()

    def _live(self, cpe: str) -> list[dict] | None:
        cached = self.store.get_cache(cpe, CACHE_S)
        if cached is not None:
            return cached
        fresh = self.nvd.lookup(cpe)
        if fresh is not None:
            self.store.set_cache(cpe, fresh)
        return fresh

    def _epss(self, cve_ids: list[str]) -> dict:
        """EPSS probabilities for these CVEs, cached per-CVE for 24 h. {} if unreachable."""
        scores, missing = {}, []
        for cid in set(cve_ids):
            cached = self.store.get_cache(f"epss:{cid}", CACHE_S)
            if cached is not None:
                scores[cid] = cached.get("epss")
            else:
                missing.append(cid)
        if missing:
            fresh = self.epss.lookup(missing)
            if fresh is not None:
                for cid in missing:                     # cache a null too, so we don't re-ask daily
                    scores[cid] = fresh.get(cid)
                    self.store.set_cache(f"epss:{cid}", {"epss": fresh.get(cid)})
        return scores

    def match(self, software: list[dict]) -> dict:
        """{'live': True/False/None, 'items': [software + its cves + fix_version]}"""
        live_ok: bool | None = None
        items = []
        for sw in software:
            merged = {c["id"]: c for c in builtin_matches(sw["product"], sw["version"], self.builtin)}
            if self.live:
                nvd = self._live(sw["cpe"])
                live_ok = (live_ok is not False) and nvd is not None
                for c in nvd or []:
                    if c["id"] in merged:  # keep our plain-English summary, take NVD's fresh score/KEV
                        merged[c["id"]].update(cvss=c["cvss"] or merged[c["id"]]["cvss"],
                                               kev=c["kev"] or merged[c["id"]]["kev"],
                                               fixed_in=merged[c["id"]]["fixed_in"] + c["fixed_in"])
                    else:
                        merged[c["id"]] = c
            else:
                live_ok = False  # live lookups switched off: built-in list only
            cves = sorted(merged.values(), key=lambda c: (not c["kev"], -(c["cvss"] or 0), c["id"]))
            items.append({**sw, "cves": cves, "fix_version": fix_version(sw["version"], cves)})
        # Enrich every matched CVE with its EPSS exploit-probability (one batched call).
        if self.live:
            all_ids = [c["id"] for it in items for c in it["cves"]]
            if all_ids:
                scores = self._epss(all_ids)
                for it in items:
                    for c in it["cves"]:
                        c["epss"] = scores.get(c["id"])
        return {"live": live_ok, "items": items}
