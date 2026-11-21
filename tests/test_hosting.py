import httpx

from app import hosting
from app.db import Store

HOSTINGER = {"name": "HOSTINGER-HOSTING", "entities": [
    {"vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Private Customer"]]]}]}
IPXO = {"name": "IPXO", "entities": [
    {"vcardArray": ["vcard", [["fn", {}, "text", "Internet Utilities Admin/Tech Contact"]]]}]}
UNKNOWN_ISP = {"name": "KPN-ZAKELIJK", "entities": []}


class FakeRDAP:
    def __init__(self, answers=None, fail=False):
        self.answers, self.fail, self.calls = answers or {}, fail, []

    def __call__(self, url, **kw):
        self.calls.append(url)
        if self.fail:
            raise httpx.ConnectError("offline")
        ip = url.rsplit("/", 1)[-1]
        return httpx.Response(200, json=self.answers[ip], request=httpx.Request("GET", url))


def test_parse_and_provider_keywords():
    assert hosting.parse_rdap(HOSTINGER)["provider"] == "Hostinger"
    assert hosting.parse_rdap(IPXO)["provider"].startswith("IPXO")
    assert hosting.parse_rdap(UNKNOWN_ISP)["provider"] is None


def test_classify_real_world_mix(tmp_path):
    http = FakeRDAP({"77.37.83.28": HOSTINGER, "93.127.179.40": IPXO, "198.51.100.7": UNKNOWN_ISP})
    store = Store(str(tmp_path / "h.db"))
    both = hosting.classify(["77.37.83.28", "93.127.179.40"], store, http)
    assert "Hostinger" in both and "IPXO" in both          # dam-bv.com's real situation
    assert hosting.classify(["198.51.100.7"], store, http) is None   # no hosting company -> own
    hosting.classify(["77.37.83.28"], store, http)
    assert http.calls.count("https://rdap.org/ip/77.37.83.28") == 1  # cached


def test_private_ips_never_looked_up():
    http = FakeRDAP(fail=True)
    assert hosting.classify(["127.0.0.1", "192.168.1.10"], None, http) is None
    assert http.calls == []


def test_offline_means_unknown_which_means_light():
    assert hosting.classify(["77.37.83.28"], None, FakeRDAP(fail=True)) == "unknown"
