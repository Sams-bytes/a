import httpx
import pytest

from app import cve
from app.cve import Matcher, NVDClient, builtin_matches, fix_version, in_range, vkey
from app.db import Store
from app.findings import build_findings, score_findings


def test_version_ordering():
    assert vkey("2.4.9") < vkey("2.4.49")          # as plain text this would be wrong
    assert vkey("1.0.1f") < vkey("1.0.1g")
    assert vkey("1.0.1") < vkey("1.0.1a")
    assert vkey("8.5p1") < vkey("9.7p1") < vkey("9.8p1")
    assert vkey("1.0.2zc") < vkey("1.0.2zd") < vkey("1.0.3")


def test_ranges():
    assert in_range("2.4.49", {"exact": "2.4.49"}) and not in_range("2.4.50", {"exact": "2.4.49"})
    assert in_range("2.4.50", {"introduced": "2.4.49", "fixed": "2.4.51"})
    assert not in_range("2.4.51", {"introduced": "2.4.49", "fixed": "2.4.51"})
    assert in_range("4.91", {"introduced": "4.87", "last_affected": "4.91"})
    assert not in_range("4.86", {"introduced": "4.87", "last_affected": "4.91"})


def test_builtin_list():
    ids = {c["id"] for c in builtin_matches("apache", "2.4.49")}
    assert {"CVE-2021-41773", "CVE-2021-42013"} <= ids
    assert builtin_matches("apache", "2.4.62") == []
    regress = {c["id"] for c in builtin_matches("openssh", "9.7p1")}
    assert "CVE-2024-6387" in regress
    assert "CVE-2024-6387" not in {c["id"] for c in builtin_matches("openssh", "9.8p1")}
    assert "CVE-2024-6387" not in {c["id"] for c in builtin_matches("openssh", "8.2p1")}  # 8.2 is before the regression
    assert {c["id"] for c in builtin_matches("proftpd", "1.3.5")} == {"CVE-2015-3306"}
    assert builtin_matches("proftpd", "1.3.5a") == []


def test_every_builtin_entry_is_well_formed():
    for e in cve.load_builtin():
        assert e["id"].startswith("CVE-") and 0 <= e["cvss"] <= 10 and e["summary"] and e["ranges"]


# ---- live NVD (faked) ----------------------------------------------------------
NVD_ANSWER = {"vulnerabilities": [
    {"cve": {"id": "CVE-2021-41773", "cisaExploitAdd": "2021-11-03",
             "descriptions": [{"lang": "en", "value": "Technical NVD text."}],
             "metrics": {"cvssMetricV31": [{"type": "Secondary", "cvssData": {"baseScore": 7.5}},
                                           {"type": "Primary", "cvssData": {"baseScore": 9.8}}]},
             "configurations": [{"nodes": [{"cpeMatch": [
                 {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}]}]}]}},
    {"cve": {"id": "CVE-2099-0001",
             "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": "Old bug."}],
             "metrics": {"cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 5.0}}]},
             "configurations": [{"nodes": [{"cpeMatch": [
                 {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                  "versionEndExcluding": "2.4.62"},
                 {"vulnerable": True, "criteria": "cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*",
                  "versionEndExcluding": "99.0"}]}]}]}},
]}


class FakeHTTP:
    def __init__(self, answer=NVD_ANSWER, fail=False):
        self.answer, self.fail, self.calls = answer, fail, []

    def __call__(self, url, params=None, headers=None, timeout=None):
        self.calls.append(params)
        if self.fail:
            raise httpx.ConnectError("offline")
        return httpx.Response(200, json=self.answer, request=httpx.Request("GET", url))


@pytest.fixture
def store(tmp_path):
    return Store(str(tmp_path / "c.db"))


def nvd(http):
    c = NVDClient(api_key="", http_get=http)
    c.min_interval = 0  # no politeness delay in tests
    return c


APACHE = {"product": "apache", "name": "Apache", "version": "2.4.49", "ports": [443],
          "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", "distro": None}


def test_nvd_parsing():
    out = nvd(FakeHTTP()).lookup(APACHE["cpe"])
    a, b = out
    assert (a["id"], a["cvss"], a["kev"]) == ("CVE-2021-41773", 9.8, True)   # Primary score wins
    assert (b["cvss"], b["kev"], b["summary"]) == (5.0, False, "Old bug.")    # v2 fallback, English text
    assert b["fixed_in"] == ["2.4.62"]                                        # other products ignored


def test_merge_cache_and_fix_version(store):
    http = FakeHTTP()
    m = Matcher(store, nvd=nvd(http), live=True)
    res = m.match([APACHE])
    assert res["live"] is True
    item = res["items"][0]
    ids = [c["id"] for c in item["cves"]]
    assert len(ids) == len(set(ids))                       # CVE-2021-41773 in both sources -> once
    merged = next(c for c in item["cves"] if c["id"] == "CVE-2021-41773")
    assert merged["summary"].startswith("Path traversal")  # our plain-English text kept
    assert "CVE-2099-0001" in ids                          # NVD-only CVE added
    assert ids[0] in ("CVE-2021-41773", "CVE-2021-42013")  # actively exploited first
    assert item["fix_version"] == "2.4.62"
    Matcher(store, nvd=nvd(http), live=True).match([APACHE])
    assert len(http.calls) == 1                            # second time answered from cache


def test_offline_falls_back_to_builtin(store):
    res = Matcher(store, nvd=nvd(FakeHTTP(fail=True)), live=True).match([APACHE])
    assert res["live"] is False
    assert {"CVE-2021-41773", "CVE-2021-42013"} <= {c["id"] for c in res["items"][0]["cves"]}


def test_findings_one_per_product(store):
    scan = {"domain": "example.nl", "ips": ["203.0.113.5"], "open_ports": [],
            "vulns": Matcher(store, live=False).match([APACHE, {**APACHE, "product": "proftpd", "name": "ProFTPD",
                                                                  "version": "1.3.5", "ports": [21]}])}
    f = [x for x in build_findings(scan) if x.get("kind") == "cve"]
    assert len(f) == 2
    apache = next(x for x in f if "Apache" in x["title"])
    assert apache["severity"] == "critical" and "actively exploited" in apache["title"]
    assert apache["cves"][0]["url"].startswith("https://nvd.nist.gov/vuln/detail/CVE-")
    assert "2.4.60" in apache["fix"]                        # from the built-in ranges
    assert score_findings(f) == 50


def test_actively_exploited_is_at_least_high():
    scan = {"vulns": {"items": [{"product": "x", "name": "X", "version": "1", "ports": [80], "distro": None,
                                 "fix_version": None,
                                 "cves": [{"id": "CVE-1", "cvss": 5.0, "kev": True, "summary": "s"}]}]}}
    [f] = build_findings(scan)
    assert f["severity"] == "high"


def test_cve_finding_on_localhost_is_not_downgraded(store):
    scan = {"domain": "localhost", "ips": ["127.0.0.1"],
            "open_ports": [{"port": 21, "service": "FTP", "banner": "220 ProFTPD 1.3.5 Server"}],
            "vulns": Matcher(store, live=False).match(
                [{**APACHE, "product": "proftpd", "name": "ProFTPD", "version": "1.3.5", "ports": [21]}])}
    f = build_findings(scan)
    assert next(x for x in f if x.get("kind") == "cve")["severity"] == "critical"
    assert next(x for x in f if x.get("kind") != "cve")["severity"] == "info"   # the open port itself


def test_backport_note_for_distros(store):
    sw = {**APACHE, "product": "openssh", "name": "OpenSSH", "version": "9.3p1", "distro": "Ubuntu"}
    [f] = build_findings({"vulns": Matcher(store, live=False).match([sw])})
    assert "Ubuntu" in f["fix"] and "9.8p1" in f["fix"]


def test_fix_version_picks_highest_needed():
    cves = [{"fixed_in": ["2.4.51"]}, {"fixed_in": ["2.4.60", "2.5.0"]}, {"fixed_in": []}]
    assert fix_version("2.4.49", cves) == "2.4.60"
