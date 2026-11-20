from app.findings import build_findings, score_findings


def ports(*nums):
    return [{"port": p, "service": "x", "banner": ""} for p in nums]


def test_clean_server_scores_100():
    scan = {"open_ports": ports(443), "tls": {"valid": True, "days_left": 80, "legacy_tls": False},
            "https": {"hsts": True, "x_frame": True, "server": "nginx"}, "http": None}
    assert build_findings(scan) == []
    assert score_findings([]) == 100


def test_rdp_and_database_are_flagged_worst_first():
    f = build_findings({"open_ports": ports(22, 3306, 3389)})
    titles = [x["title"] for x in f]
    assert f[0]["severity"] == "critical" and "Remote Desktop" in titles[0]
    assert any("MySQL" in t for t in titles)
    assert score_findings(f) == 100 - 25 - 15  # critical + high (SSH is info)


def test_tls_problems():
    f = build_findings({"open_ports": ports(443),
                        "tls": {"valid": True, "days_left": 5, "legacy_tls": True},
                        "https": {"hsts": False, "x_frame": False, "server": "Apache/2.4.49"}})
    titles = " | ".join(x["title"] for x in f)
    assert "expires in 5 days" in titles
    assert "TLS 1.0/1.1" in titles
    assert "HSTS" in titles
    assert "Apache/2.4.49" in titles


def test_http_without_redirect():
    f = build_findings({"open_ports": ports(80), "http": {"redirects_to_https": False, "server": ""}})
    assert any("without forcing HTTPS" in x["title"] for x in f)


def test_local_scan_is_detected():
    from app.findings import is_local_scan
    assert is_local_scan({"domain": "localhost"})
    assert is_local_scan({"domain": "x.test", "ips": ["127.0.0.1", "::1"]})
    assert not is_local_scan({"domain": "example.nl", "ips": ["93.184.216.34"]})
    assert not is_local_scan({"domain": "example.nl", "ips": ["127.0.0.1", "93.184.216.34"]})


def test_smb_on_localhost_is_info_not_critical():
    f = build_findings({"domain": "localhost", "ips": ["127.0.0.1"],
                        "open_ports": [{"port": 445, "service": "SMB (Windows file sharing)", "banner": ""}]})
    assert len(f) == 1
    smb = f[0]
    assert smb["severity"] == "info" and smb["cvss"] == 0.0
    assert smb["exposed_severity"] == "critical" and smb["exposed_cvss"] == 9.8
    assert "open on this computer" in smb["title"]
    assert "firewall" in smb["fix"]
    assert score_findings(f) == 100


def test_same_port_on_real_domain_stays_critical():
    f = build_findings({"domain": "example.nl", "ips": ["93.184.216.34"], "open_ports": ports(445)})
    assert f[0]["severity"] == "critical" and "exposed to the internet" in f[0]["title"]


def test_local_scan_keeps_web_findings():
    f = build_findings({"domain": "localhost", "ips": ["127.0.0.1"], "open_ports": ports(80),
                        "http": {"redirects_to_https": False, "server": ""}})
    assert any("without forcing HTTPS" in x["title"] for x in f)


def test_score_never_negative():
    f = build_findings({"open_ports": ports(21, 23, 445, 3389, 27017, 6379)})
    assert score_findings(f) == 0
