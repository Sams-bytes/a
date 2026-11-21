"""EPSS enrichment: how LIKELY a CVE is to be exploited (FIRST.org), cached 24h."""

from app import cve
from app.cve import EPSSClient, Matcher, NVDClient, top_epss
from app.db import Store


class FakeResp:
    def __init__(self, payload): self._p = payload
    def raise_for_status(self): pass
    def json(self): return self._p


def test_epss_client_parses_and_batches(monkeypatch):
    calls = []

    def fake_get(url, params=None, **kw):
        calls.append(params["cve"])
        want = params["cve"].split(",")
        return FakeResp({"data": [{"cve": c, "epss": "0.5"} for c in want if c != "CVE-X"]})

    scores = EPSSClient(http_get=fake_get).lookup(["CVE-1", "CVE-2", "CVE-X"])
    assert scores == {"CVE-1": 0.5, "CVE-2": 0.5}          # unknown CVE simply absent
    assert len(calls) == 1                                  # one batched request


def test_epss_client_returns_none_on_failure():
    def boom(*a, **k): raise cve.httpx.HTTPError("down")
    assert EPSSClient(http_get=boom).lookup(["CVE-1"]) is None


def test_top_epss():
    assert top_epss([{"epss": 0.1}, {"epss": 0.92}, {"epss": None}]) == 0.92
    assert top_epss([{"epss": None}]) is None
    assert top_epss([]) is None


def test_matcher_attaches_epss_and_caches(tmp_path, monkeypatch):
    store = Store(str(tmp_path / "t.db"))
    # One built-in CVE match for a known product/version.
    monkeypatch.setattr(cve, "load_builtin", lambda: [{
        "id": "CVE-2021-41773", "product": "apache_http_server", "cvss": 7.5, "kev": True,
        "summary": "path traversal", "ranges": [{"exact": "2.4.49"}]}])

    hits = []

    def fake_get(url, params=None, **kw):
        hits.append(params["cve"])
        return FakeResp({"data": [{"cve": "CVE-2021-41773", "epss": "0.80"}]})

    no_nvd = NVDClient(http_get=lambda *a, **k: FakeResp({"vulnerabilities": []}))
    m = Matcher(store, live=True, nvd=no_nvd, epss=EPSSClient(http_get=fake_get))
    sw = [{"product": "apache_http_server", "version": "2.4.49",
           "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", "name": "Apache"}]
    res = m.match(sw)
    assert res["items"][0]["cves"][0]["epss"] == 0.80

    # Second scan: EPSS is served from cache, no new HTTP call.
    Matcher(store, live=True, nvd=no_nvd, epss=EPSSClient(http_get=fake_get)).match(sw)
    assert len(hits) == 1
