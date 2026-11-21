import pytest

from app import nmap_engine, scanner
from app.changes import compare, is_bad
from app.findings import build_findings
from app.fingerprint import detect

TCP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95"><host><status state="up"/><ports>
  <port protocol="tcp" portid="21"><state state="open"/>
    <service name="ftp" product="ProFTPD" version="1.3.5"><cpe>cpe:/a:proftpd:proftpd:1.3.5</cpe></service></port>
  <port protocol="tcp" portid="22"><state state="open"/>
    <service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu 4ubuntu0.5" extrainfo="Ubuntu Linux; protocol 2.0">
      <cpe>cpe:/a:openbsd:openssh:8.2p1</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service></port>
  <port protocol="tcp" portid="80"><state state="open"/>
    <service name="http" product="nginx" version="1.18.0"><cpe>cpe:/a:igor_sysoev:nginx:1.18.0</cpe></service></port>
  <port protocol="tcp" portid="2375"><state state="open"/><service name="docker"/></port>
  <port protocol="tcp" portid="8888"><state state="closed"/></port>
</ports></host></nmaprun>"""

UDP_XML = """<?xml version="1.0"?>
<nmaprun><host><ports>
  <port protocol="udp" portid="161"><state state="open"/><service name="snmp"/></port>
  <port protocol="udp" portid="51820"><state state="open"/><service name="wireguard"/></port>
  <port protocol="udp" portid="123"><state state="open|filtered"/><service name="ntp"/></port>
</ports></host></nmaprun>"""


def test_parse_xml():
    ports = {p["port"]: p for p in nmap_engine.parse_xml(TCP_XML)}
    assert ports[21]["product"] == "ProFTPD" and ports[21]["cpe"] == ["cpe:/a:proftpd:proftpd:1.3.5"]
    assert ports[8888]["state"] == "closed"
    with pytest.raises(nmap_engine.NmapError):
        nmap_engine.parse_xml("not xml")


def test_commands_have_no_shell_and_safe_target():
    cmds = nmap_engine.build_commands("devries-logistics.nl", "nmap")
    for c in cmds.values():
        assert c[-1] == "devries-logistics.nl" and "--script" not in " ".join(c)
    assert "-sU" in cmds["udp"] and "--top-ports" in cmds["tcp_top"]
    for evil in ["x.nl & del C:\\*", "--script=brute", "-iL secrets.txt", "a b", "", "x.nl;rm"]:
        with pytest.raises(ValueError):
            nmap_engine.build_commands(evil, "nmap")


def fake_runs(monkeypatch, udp=(UDP_XML, "", 0)):
    def fake_run(cmd):
        return udp if "-sU" in cmd else (TCP_XML if "--top-ports" in cmd else "<nmaprun/>", "", 0)
    monkeypatch.setattr(nmap_engine, "_run", fake_run)
    monkeypatch.setattr(nmap_engine, "nmap_version", lambda n: "7.95")


def test_run_merges_tcp_and_udp(monkeypatch):
    fake_runs(monkeypatch)
    r = nmap_engine.run("example.nl", "nmap", tcp_names={21: "FTP"})
    keys = {(p["proto"], p["port"]) for p in r["open_ports"]}
    assert keys == {("tcp", 21), ("tcp", 22), ("tcp", 80), ("tcp", 2375), ("udp", 161), ("udp", 51820)}
    assert r["udp"] == "ok" and r["engine"] == "Nmap 7.95"
    assert r["uncertain_udp"] == [{"port": 123, "proto": "udp", "service": "NTP (time)"}]
    assert next(p for p in r["open_ports"] if p["port"] == 21)["service"] == "FTP"


def test_udp_without_admin_rights_still_returns_tcp(monkeypatch):
    fake_runs(monkeypatch, udp=("", "You requested a scan type which requires root privileges.\nQUITTING!", 1))
    r = nmap_engine.run("example.nl", "nmap")
    assert r["udp"] == "skipped: UDP scanning needs administrator rights"
    assert all(p["proto"] == "tcp" for p in r["open_ports"]) and r["open_ports"]


def test_scanner_falls_back_without_nmap(monkeypatch):
    monkeypatch.setenv("AEGIS_ENGINE", "auto")
    monkeypatch.setattr(nmap_engine, "find_nmap", lambda: None)
    monkeypatch.setattr(scanner, "builtin_ports", lambda d, t, log: [])
    r = scanner.collect_ports("example.nl", 1, lambda m: None)
    assert r["engine"].startswith("built-in") and "install Nmap" in r["udp"]


def test_scanner_uses_nmap_when_installed(monkeypatch):
    monkeypatch.setenv("AEGIS_ENGINE", "auto")
    monkeypatch.setattr(nmap_engine, "find_nmap", lambda: "nmap")
    fake_runs(monkeypatch)
    assert scanner.collect_ports("example.nl", 1, lambda m: None)["engine"] == "Nmap 7.95"


def test_nmap_cpe_feeds_fingerprinting(monkeypatch):
    fake_runs(monkeypatch)
    r = nmap_engine.run("example.nl", "nmap")
    sw = {(s["product"], s["version"]): s for s in detect(r)}
    assert ("proftpd", "1.3.5") in sw
    assert sw[("openssh", "8.2p1")]["cpe"] == "cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*"
    assert sw[("openssh", "8.2p1")]["distro"] == "Ubuntu"
    assert sw[("nginx", "1.18.0")]["cpe"].startswith("cpe:2.3:a:f5:nginx:1.18.0")   # old vendor name fixed


def test_udp_and_new_tcp_findings(monkeypatch):
    fake_runs(monkeypatch)
    r = {"domain": "example.nl", "ips": ["203.0.113.5"], **nmap_engine.run("example.nl", "nmap")}
    f = {(x["proto"], x["port"]): x for x in build_findings(r) if x["port"]}
    assert f[("tcp", 2375)]["severity"] == "critical"            # Docker API
    assert f[("udp", 161)]["severity"] == "high" and "UDP 161" in f[("udp", 161)]["title"]
    assert f[("udp", 51820)]["severity"] == "info" and "VPN" in f[("udp", 51820)]["title"]


def test_udp_on_localhost_is_inside_view(monkeypatch):
    fake_runs(monkeypatch)
    r = {"domain": "localhost", "ips": ["127.0.0.1"], **nmap_engine.run("localhost", "nmap")}
    snmp = next(x for x in build_findings(r) if x["port"] == 161)
    assert snmp["severity"] == "info" and snmp["exposed_severity"] == "high"
    assert snmp["title"].startswith("UDP 161 open on this computer")


def test_switching_to_nmap_is_a_new_baseline_not_an_alert(monkeypatch):
    fake_runs(monkeypatch)
    old = {"open_ports": [{"port": 80, "proto": "tcp", "service": "http"}], "findings": [], "score": 100,
           "engine": "built-in (25 TCP ports)"}
    new = {**nmap_engine.run("example.nl", "nmap"), "findings": [], "score": 100}
    ch = compare(old, new)
    assert ch["engine_changed"] and not is_bad(ch)
    ch2 = compare(new, {**new, "udp": "skipped: UDP scanning needs administrator rights",
                        "open_ports": [p for p in new["open_ports"] if p["proto"] == "tcp"]})
    assert not ch2["closed_ports"]   # UDP not compared when one scan couldn't do UDP
