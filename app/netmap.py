"""Map YOUR OWN local network: which devices are on your Wi-Fi/LAN?

A domain scan looks at one server from outside. This looks at your own network
from inside: it lists every device (router, laptop, phone, printer, smart plug,
TV) and draws them as a map. Defensive value: an inventory of what's on your
network, and a warning when a device you don't recognise appears (a classic
sign of an intruder or a neighbour on your Wi-Fi).

How it finds devices: Nmap host discovery (`-sn`). On a local network this uses
ARP - the way computers ask "who has IP 192.168.1.33?" on the local wire - so it
also learns each device's MAC address (its hardware ID) and from that the maker
(Apple, Samsung, Zyxel...). A deep scan adds open ports and an OS guess.

LEGAL BOUNDARY (same spirit as the domain rule): Aegis only offers the PRIVATE
networks this computer is actually on, and only scans one after you confirm it
is yours (home/office). Scanning someone else's network - a cafe, a hotel, a
client's office - without written permission is a crime, exactly like scanning a
stranger's server.

Safety: Nmap is run with an argument LIST (no shell), and the target is a
validated private CIDR, so nothing user-typed can become a second command.
"""

from __future__ import annotations

import ipaddress
import re
import sys
import xml.etree.ElementTree as ET

from app.db import Store
from app.nmap_engine import NmapError, _no_window, _run, _run_streaming, find_nmap, nmap_version

CGNAT = ipaddress.ip_network("100.64.0.0/10")  # carrier-grade NAT / Tailscale - not a LAN we scan
MAX_PREFIX = 23  # smallest network (= most hosts) we allow: /23 = 512 addresses


def is_admin() -> bool:
    """Admin/root? ARP host discovery works without it here, but OS detection needs it."""
    try:
        if sys.platform == "win32":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        import os
        return os.geteuid() == 0
    except Exception:
        return False


def _is_scannable(net: ipaddress.IPv4Network) -> bool:
    a = net.network_address
    return net.version == 4 and net.is_private and not net.is_loopback \
        and not net.is_link_local and a not in CGNAT


def local_networks(nmap: str | None = None) -> list[dict]:
    """The private IPv4 networks this computer is connected to (from `nmap --iflist`)."""
    nmap = nmap or find_nmap()
    if not nmap:
        return []
    out, _, _ = _run([nmap, "--iflist"])
    section = ""
    gateways: dict[str, str] = {}   # device -> default gateway
    nets: dict[str, dict] = {}
    for line in out.splitlines():
        if "INTERFACES" in line:
            section = "if"
            continue
        if "ROUTES" in line:
            section = "route"
            continue
        parts = line.split()
        if section == "if" and len(parts) >= 5 and "/" in parts[2] and parts[3] == "ethernet" and parts[4] == "up":
            dev, ipmask = parts[0], parts[2]
            try:
                iface = ipaddress.ip_interface(ipmask)
                net = iface.network
            except ValueError:
                continue
            if _is_scannable(net):
                nets[dev] = {"cidr": str(net), "ip": str(iface.ip), "interface": dev, "gateway": None}
        elif section == "route" and len(parts) >= 4 and parts[0] == "0.0.0.0/0":
            gateways[parts[1]] = parts[3]
    for dev, info in nets.items():
        info["gateway"] = gateways.get(dev)
    return list(nets.values())


def validate_cidr(cidr: str) -> ipaddress.IPv4Network:
    """Only a real, private, not-too-big network is allowed to be scanned."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        raise ValueError(f"{cidr!r} is not a network") from e
    if not isinstance(net, ipaddress.IPv4Network) or not _is_scannable(net):
        raise ValueError(f"{cidr} is not a private local network Aegis may scan")
    if net.prefixlen < MAX_PREFIX:
        raise ValueError(f"{cidr} is too large (max /{MAX_PREFIX}); scan a smaller range")
    return net


# ---- device classification -------------------------------------------------------
HOSTNAME_RULES = [
    ("phone", r"iphone|ipad|galaxy|pixel|oneplus|xiaomi|redmi|huawei|-s\d\d|android|phone|mobile"),
    ("tv", r"\btv\b|roku|chromecast|firetv|fire-tv|bravia|appletv|shield|webos|samsungtv"),
    ("printer", r"printer|officejet|laserjet|deskjet|envy|canon|epson|brother|kyocera"),
    ("network", r"router|gateway|repeater|extender|rangeextender|re\d{3}|deco|eero|orbi|velop|access-?point|\bap\b"),
    ("iot", r"tuya|smart|plug|bulb|hue|nest|echo|alexa|sonoff|shelly|camera|cam\b|doorbell|thermostat|vacuum"),
    ("computer", r"macbook|imac|mac-?mini|desktop|laptop|pc\b|-pc|raspberry|rpi|ubuntu|debian|windows|workstation"),
]
VENDOR_RULES = [
    ("network", r"zyxel|tp-?link|netgear|ubiquiti|mikrotik|cisco|aruba|d-link|asustek|fritz|avm|technicolor|sagemcom|huawei techn"),
    ("printer", r"hewlett|hp inc|canon|epson|brother|lexmark|kyocera|xerox"),
    ("iot", r"tuya|espressif|sonoff|shelly|tplink techno|amazon techno|google|nest|ring|wyze|ezviz|hangzhou"),
    ("phone", r"apple|samsung electro|xiaomi|oneplus|oppo|vivo|motorola|huawei device"),
    ("computer", r"raspberry|intel corp|dell|lenovo|micro-star|gigabyte|asustek comput"),
]
PORT_RULES = [(("9100", "515", "631"), "printer"), (("62078",), "phone"),
              (("554", "8008", "8009", "7000"), "tv"), (("3389", "5900", "22"), "computer")]
OS_RULES = [("router", "network"), ("WAP", "network"), ("switch", "network"), ("printer", "printer"),
            ("phone", "phone"), ("webcam", "iot"), ("general purpose", "computer"), ("specialized", "iot")]


def classify(host: dict, gateway: str | None) -> str:
    if gateway and host.get("ip") == gateway:
        return "router"
    name = (host.get("hostname") or "").lower()
    vendor = (host.get("vendor") or "").lower()
    ports = {p["port"] for p in host.get("open_ports", [])}
    for t, rx in HOSTNAME_RULES:
        if re.search(rx, name):
            return t
    for t, rx in VENDOR_RULES:
        if re.search(rx, vendor):
            return t
    for needed, t in PORT_RULES:
        if ports & set(needed):
            return t
    for needle, t in OS_RULES:
        if needle in (host.get("os") or "").lower():
            return t
    if ports and ports <= {"80", "443"}:
        return "iot"
    return "unknown"


def randomized_mac(mac: str | None) -> bool:
    """Phones use random MACs for privacy; the 2nd hex digit is then 2, 6, A or E."""
    return bool(mac) and len(mac) >= 2 and mac[1].upper() in "26AE"


# ---- running the scan ------------------------------------------------------------
def parse_hosts(xml: str) -> list[dict]:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        raise NmapError(f"could not read nmap output: {e}") from e
    hosts = []
    for h in root.iter("host"):
        st = h.find("status")
        if st is not None and st.get("state") != "up":
            continue
        ip = mac = vendor = hostname = os_guess = None
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                ip = a.get("addr")
            elif a.get("addrtype") == "mac":
                mac, vendor = a.get("addr"), a.get("vendor")
        hn = h.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name")
        ports = [{"port": p.get("portid"),
                  "service": (p.find("service").get("name") if p.find("service") is not None else "")}
                 for p in h.iter("port")
                 if (p.find("state") is not None and p.find("state").get("state") == "open")]
        osm = h.find("os/osmatch")
        if osm is not None:
            os_guess = f"{osm.get('name')} ({osm.get('accuracy')}%)"
        if ip:
            hosts.append({"ip": ip, "mac": mac, "vendor": vendor, "hostname": hostname,
                          "os": os_guess, "open_ports": ports})
    return hosts


def discover(cidr: str, nmap: str, deep: bool = False, admin: bool = False, on_progress=None) -> list[dict]:
    validate_cidr(cidr)
    sweep, err, rc = _run([nmap, "-sn", "-T4", "-oX", "-", cidr])
    if rc != 0 and not sweep.strip():
        raise NmapError((err or "nmap host discovery failed").strip().splitlines()[0])
    hosts = {h["ip"]: h for h in parse_hosts(sweep)}

    if deep and hosts:
        cmd = [nmap, "-sT", "--top-ports", "100", "-T4", "-Pn", "--host-timeout", "3m", "--stats-every", "2s", "-oX", "-"]
        if admin:
            cmd += ["-O", "--osscan-guess"]   # OS detection needs raw packets = admin rights
        xml, _, drc = (_run_streaming([*cmd, *hosts], on_progress) if on_progress else _run([*cmd, *hosts]))
        if drc == 0 and xml.strip():
            for d in parse_hosts(xml):
                if d["ip"] in hosts:
                    hosts[d["ip"]].update(open_ports=d["open_ports"], os=d["os"] or hosts[d["ip"]]["os"])
    return list(hosts.values())


def run(cidr: str, store: Store | None = None, deep: bool = False, nmap: str | None = None, report=None) -> dict:
    nmap = nmap or find_nmap()
    if not nmap:
        raise NmapError("Nmap is not installed")
    rep = report or (lambda **k: None)
    admin = is_admin()
    net = validate_cidr(cidr)
    gateway = self_ip = None
    for n in local_networks(nmap):
        if n["cidr"] == str(net):
            gateway, self_ip = n["gateway"], n["ip"]
    rep(phase=f"Discovering devices on {net}", percent=15)
    on_prog = (lambda task, pct, rem: rep(phase=f"Deep scan — {task}", percent=40 + pct * 0.5)) if report and deep else None
    hosts = discover(cidr, nmap, deep=deep, admin=admin, on_progress=on_prog)
    rep(phase="Identifying devices", percent=95, line=f"{len(hosts)} device(s) up")
    devices = []
    for h in sorted(hosts, key=lambda h: ipaddress.ip_address(h["ip"])):
        is_self = h["ip"] == self_ip
        devices.append({**h, "type": "computer" if is_self else classify(h, gateway),
                        "is_gateway": h["ip"] == gateway, "is_self": is_self,
                        "randomized_mac": randomized_mac(h.get("mac"))})
    new_macs = store.save_devices(cidr, devices) if store else []
    for d in devices:
        d["is_new"] = d.get("mac") in new_macs and bool(d.get("mac"))
    result = {"network": str(net), "gateway": gateway, "engine": f"Nmap {nmap_version(nmap)}",
              "admin": admin, "deep": deep, "count": len(devices), "devices": devices, "new_macs": new_macs}
    if store:
        store.save_netscan(cidr, admin, result)
    return result
