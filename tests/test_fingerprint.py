from app.fingerprint import cpe_name, detect


def ports(*pairs):
    return [{"port": p, "service": "x", "banner": b} for p, b in pairs]


def test_real_world_banners():
    scan = {"open_ports": ports((22, "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"),
                                (21, "220 ProFTPD 1.3.5 Server (Debian) [::ffff:10.0.0.5]"),
                                (25, "220 mail.example.nl ESMTP Exim 4.92 Mon, 01 Jan 2026"),
                                (2121, "220 (vsFTPd 3.0.3)")),
            "https": {"server": "Apache/2.4.49 (Unix) OpenSSL/1.0.1f", "powered_by": "PHP/7.3.10"}}
    found = {(s["product"], s["version"]): s for s in detect(scan)}
    assert set(found) == {("openssh", "8.2p1"), ("proftpd", "1.3.5"), ("exim", "4.92"),
                          ("vsftpd", "3.0.3"), ("apache", "2.4.49"), ("openssl", "1.0.1f"), ("php", "7.3.10")}
    assert found[("openssh", "8.2p1")]["distro"] == "Ubuntu"
    assert found[("proftpd", "1.3.5")]["distro"] == "Debian"
    assert found[("apache", "2.4.49")]["ports"] == [443] and found[("apache", "2.4.49")]["distro"] is None


def test_same_software_on_two_ports_is_one_entry():
    scan = {"open_ports": [], "https": {"server": "nginx/1.18.0"}, "http": {"server": "nginx/1.18.0"}}
    [sw] = detect(scan)
    assert sw["ports"] == [443, 80] and sw["cpe"] == "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"


def test_cpe_names():
    assert cpe_name("openbsd", "openssh", "8.2p1") == "cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*"
    assert cpe_name("apache", "http_server", "2.4.49") == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"


def test_no_banner_no_software():
    assert detect({"open_ports": ports((445, "")), "https": {"server": "cloudflare"}}) == []
