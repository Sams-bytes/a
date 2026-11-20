from app.changes import compare, describe, is_bad


def result(ports, findings=(), score=100):
    return {"open_ports": [{"port": p, "service": f"svc{p}", "banner": ""} for p in ports],
            "findings": list(findings), "score": score}


def finding(title, sev="high", port=None):
    return {"title": title, "severity": sev, "port": port, "cvss": 7.0}


def test_first_scan_is_never_an_alert():
    ch = compare(None, result([80]))
    assert ch["first_scan"] and not is_bad(ch)


def test_new_and_closed_ports():
    ch = compare(result([22, 80]), result([80, 3389]))
    assert [p["port"] for p in ch["new_ports"]] == [3389]
    assert [p["port"] for p in ch["closed_ports"]] == [22]
    assert is_bad(ch)
    text = " | ".join(describe(ch))
    assert "New open port 3389" in text and "Closed since last scan: port 22" in text


def test_only_closing_things_is_good_news_not_an_alert():
    old = result([22, 3389], [finding("RDP open", "critical", 3389)], score=75)
    new = result([22], [], score=100)
    ch = compare(old, new)
    assert [f["title"] for f in ch["fixed_findings"]] == ["RDP open"]
    assert not is_bad(ch)


def test_new_real_finding_or_score_drop_alerts():
    assert is_bad(compare(result([443]), result([443], [finding("HSTS missing", "low", 443)], 97)))
    assert is_bad(compare(result([443], score=90), result([443], score=80)))


def test_new_info_finding_alone_is_not_an_alert():
    ch = compare(result([443]), result([443], [finding("Some note", "info", 443)]))
    assert not is_bad(ch)


def test_unchanged_scan_is_quiet():
    r = result([80, 443], [finding("x", "low", 443)], 97)
    ch = compare(r, r)
    assert not is_bad(ch) and not ch["new_ports"] and not ch["fixed_findings"]
