import pytest

from app import netmap
from app.db import Store

# Real Nmap host-discovery XML (trimmed) from a home Wi-Fi: router, iPhone, a
# randomized-MAC phone, a Tuya smart device, and this laptop (no MAC of its own).
SN_XML = """<?xml version="1.0"?><nmaprun>
<host><status state="up" reason="arp-response"/>
  <address addr="192.168.1.1" addrtype="ipv4"/>
  <address addr="D4:3D:F3:BE:74:58" addrtype="mac" vendor="Zyxel Communications"/>
  <hostnames><hostname name="home" type="PTR"/></hostnames></host>
<host><status state="up" reason="arp-response"/>
  <address addr="192.168.1.33" addrtype="ipv4"/>
  <address addr="F6:3C:8D:73:96:2E" addrtype="mac"/>
  <hostnames><hostname name="iPhone.home" type="PTR"/></hostnames></host>
<host><status state="up" reason="arp-response"/>
  <address addr="192.168.1.146" addrtype="ipv4"/>
  <address addr="F8:17:2D:4B:42:E0" addrtype="mac" vendor="Tuya Smart"/>
  <hostnames></hostnames></host>
<host><status state="down"/><address addr="192.168.1.9" addrtype="ipv4"/></host>
<host><status state="up" reason="localhost-response"/>
  <address addr="192.168.1.144" addrtype="ipv4"/>
  <hostnames><hostname name="Ehetasham.home" type="PTR"/></hostnames></host>
</nmaprun>"""

DEEP_XML = """<?xml version="1.0"?><nmaprun>
<host><status state="up"/><address addr="192.168.1.50" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="9100"><state state="open"/><service name="jetdirect"/></port>
    <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
    <port protocol="tcp" portid="21"><state state="closed"/></port>
  </ports>
  <os><osmatch name="HP Printer" accuracy="95"/></os></host>
</nmaprun>"""

# Real `nmap --iflist` text: one usable Wi-Fi network, plus things to ignore.
IFLIST = """Starting Nmap
************************INTERFACES************************
DEV  (SHORT) IP/MASK                 TYPE     UP   MTU  MAC
unk0 (unk0)  100.86.72.43/32         other    up   1280
eth0 (eth0)  169.254.239.104/16      ethernet down 1500 42:1A:58:BF:B3:9A
eth2 (eth2)  192.168.1.144/24        ethernet up   1500 40:1A:58:BF:B3:9A
lo0  (lo0)   127.0.0.1/8             loopback up   -1
**************************ROUTES**************************
DST/MASK          DEV  METRIC GATEWAY
192.168.1.0/24    eth2 291
0.0.0.0/0         eth2 35     192.168.1.1
"""


def test_parse_hosts_from_arp_sweep():
    hosts = {h["ip"]: h for h in netmap.parse_hosts(SN_XML)}
    assert set(hosts) == {"192.168.1.1", "192.168.1.33", "192.168.1.146", "192.168.1.144"}  # 'down' skipped
    assert hosts["192.168.1.1"]["vendor"] == "Zyxel Communications"
    assert hosts["192.168.1.33"]["hostname"] == "iPhone.home" and hosts["192.168.1.33"]["vendor"] is None
    assert hosts["192.168.1.144"]["mac"] is None   # this laptop, found via localhost-response


def test_parse_hosts_deep_ports_and_os():
    [h] = netmap.parse_hosts(DEEP_XML)
    assert {p["port"] for p in h["open_ports"]} == {"9100", "80"}   # closed port excluded
    assert h["os"] == "HP Printer (95%)"


def test_classify():
    c = netmap.classify
    assert c({"ip": "192.168.1.1"}, "192.168.1.1") == "router"
    assert c({"ip": "192.168.1.33", "hostname": "iPhone.home"}, "192.168.1.1") == "phone"
    assert c({"ip": "192.168.1.146", "vendor": "Tuya Smart"}, "192.168.1.1") == "iot"
    assert c({"ip": "192.168.1.50", "open_ports": [{"port": "9100"}]}, "192.168.1.1") == "printer"
    assert c({"ip": "192.168.1.60", "os": "Linux 5.x general purpose"}, "192.168.1.1") == "computer"
    assert c({"ip": "192.168.1.70"}, "192.168.1.1") == "unknown"


def test_randomized_mac():
    assert netmap.randomized_mac("F6:3C:8D:73:96:2E")       # phone privacy MAC
    assert not netmap.randomized_mac("D4:3D:F3:BE:74:58")   # real vendor MAC
    assert not netmap.randomized_mac(None)


def test_validate_cidr():
    assert str(netmap.validate_cidr("192.168.1.0/24")) == "192.168.1.0/24"
    for bad in ["8.8.8.0/24", "100.64.0.0/24", "10.0.0.0/8", "169.254.0.0/16", "not-a-cidr"]:
        with pytest.raises(ValueError):   # public / CGNAT / too big / link-local / junk
            netmap.validate_cidr(bad)


def test_local_networks_only_private(monkeypatch):
    monkeypatch.setattr(netmap, "_run", lambda cmd: (IFLIST, "", 0))
    nets = netmap.local_networks("nmap")
    assert len(nets) == 1
    assert nets[0]["cidr"] == "192.168.1.0/24" and nets[0]["gateway"] == "192.168.1.1"


def fake_runs(monkeypatch, admin=False, deep_xml=DEEP_XML):
    def fake_run(cmd):
        if "--iflist" in cmd:
            return (IFLIST, "", 0)
        if "-sn" in cmd:
            return (SN_XML, "", 0)
        return (deep_xml, "", 0)
    monkeypatch.setattr(netmap, "_run", fake_run)
    monkeypatch.setattr(netmap, "find_nmap", lambda: "nmap")
    monkeypatch.setattr(netmap, "nmap_version", lambda n: "7.99")
    monkeypatch.setattr(netmap, "is_admin", lambda: admin)


def test_run_builds_map_and_flags_new_devices(tmp_path, monkeypatch):
    fake_runs(monkeypatch)
    store = Store(str(tmp_path / "n.db"))
    r = netmap.run("192.168.1.0/24", store)
    assert r["gateway"] == "192.168.1.1" and r["count"] == 4 and r["admin"] is False
    router = next(d for d in r["devices"] if d["ip"] == "192.168.1.1")
    assert router["type"] == "router" and router["is_gateway"]
    phone = next(d for d in r["devices"] if d["ip"] == "192.168.1.33")
    assert phone["type"] == "phone" and phone["randomized_mac"] and phone["is_new"]
    # Second scan: the known devices are no longer "new".
    r2 = netmap.run("192.168.1.0/24", store)
    assert r2["new_macs"] == [] and not any(d["is_new"] for d in r2["devices"])
    assert store.get_netscan("192.168.1.0/24")["count"] == 4


def test_run_rejects_non_private():
    with pytest.raises(ValueError):
        netmap.run("8.8.8.0/24", None, nmap="nmap")


# ---- API gate --------------------------------------------------------------------
@pytest.fixture
def client(tmp_path, monkeypatch, make_client):
    import app.main as main
    monkeypatch.setattr(main.netmap, "find_nmap", lambda: "nmap")
    return make_client(Store(str(tmp_path / "a.db")))


def test_scan_requires_confirmation_and_private_range(client, monkeypatch):
    import app.main as main
    called = []
    monkeypatch.setattr(main.netmap, "run", lambda cidr, store, deep=False: called.append(cidr) or
                        {"network": cidr, "devices": [], "count": 0, "new_macs": []})

    assert client.post("/api/network/scan", json={"cidr": "192.168.1.0/24"}).status_code == 400  # no confirm
    assert client.post("/api/network/scan", json={"cidr": "8.8.8.0/24", "confirm": True}).status_code == 400  # public
    assert called == []                                                   # nmap never ran for those
    ok = client.post("/api/network/scan", json={"cidr": "192.168.1.0/24", "confirm": True})
    assert ok.status_code == 200 and called == ["192.168.1.0/24"]


def test_interfaces_reports_capabilities(client, monkeypatch):
    import app.main as main
    monkeypatch.setattr(main.netmap, "local_networks", lambda nmap: [{"cidr": "192.168.1.0/24", "gateway": "192.168.1.1"}])
    monkeypatch.setattr(main.netmap, "is_admin", lambda: False)
    r = client.get("/api/network/interfaces").json()
    assert r["nmap"] is True and r["admin"] is False
    assert r["networks"][0]["cidr"] == "192.168.1.0/24" and r["networks"][0]["scanned"] is False
