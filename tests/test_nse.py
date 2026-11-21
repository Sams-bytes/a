import pytest

from app import nse
from app.findings import build_findings, nse_findings

SSL_XML = """<nmaprun><host><ports>
<port protocol="tcp" portid="443"><state state="open"/>
<service name="https"/>
<script id="ssl-enum-ciphers" output="  TLSv1.0:
    ciphers:
      TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
  TLSv1.2:
    ciphers:
      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 - A
  least strength: F"/>
<script id="http-title" output="Example Domain"/>
</port></ports></host></nmaprun>"""

# Real smb-protocols with ancient SMBv1 present, and signing not required.
SMB_XML = """<nmaprun><host><ports>
<port protocol="tcp" portid="445"><state state="open"/></port></ports>
<hostscript>
<script id="smb-protocols" output="  dialects: &#xa;    NT LM 0.12 (SMBv1)&#xa;    2.0.2&#xa;    3.1.1">
<table key="dialects"><elem>NT LM 0.12 (SMBv1)</elem><elem>2.0.2</elem><elem>3.1.1</elem></table></script>
<script id="smb2-security-mode" output="  3.1.1: &#xa;    Message signing enabled but not required"/>
</hostscript></host></nmaprun>"""

SSH_XML = """<nmaprun><host><ports>
<port protocol="tcp" portid="22"><state state="open"/>
<script id="ssh2-enum-algos" output="  kex_algorithms:
      diffie-hellman-group1-sha1
  mac_algorithms:
      hmac-sha1"/>
</port></ports></host></nmaprun>"""

# Healthy host: good TLS grade, SMBv1 off, signing required.
GOOD_XML = """<nmaprun><host><ports>
<port protocol="tcp" portid="443"><state state="open"/><script id="ssl-enum-ciphers" output="  TLSv1.3:
    ciphers: ok
  least strength: A"/></port></ports>
<hostscript>
<script id="smb-protocols" output="dialects: 2.0.2 3.1.1"><table key="dialects"><elem>2.0.2</elem><elem>3.1.1</elem></table></script>
<script id="smb2-security-mode" output="Message signing enabled and required"/>
</hostscript></host></nmaprun>"""


def test_parse_locates_port_and_host_scripts():
    checks = {c["id"]: c for c in nse.parse(SMB_XML)}
    assert checks["smb-protocols"]["port"] is None            # host-level
    assert "NT LM 0.12" in " ".join(checks["smb-protocols"]["elems"])
    ssl = {c["id"]: c for c in nse.parse(SSL_XML)}
    assert ssl["ssl-enum-ciphers"]["port"] == 443             # port-level


def test_interpreters():
    assert nse.tls_grade("least strength: F") == "F" and nse.tls_grade("no grade") is None
    assert nse.has_legacy_tls("has TLSv1.0 here") and not nse.has_legacy_tls("TLSv1.2 only")
    [smb] = [c for c in nse.parse(SMB_XML) if c["id"] == "smb-protocols"]
    assert nse.smbv1_enabled(smb)
    [sign] = [c for c in nse.parse(SMB_XML) if c["id"] == "smb2-security-mode"]
    assert nse.signing_not_required(sign)


def test_findings_from_bad_tls_smb_ssh():
    checks = nse.parse(SSL_XML) + nse.parse(SMB_XML) + nse.parse(SSH_XML)
    f = {x["key"]: x for x in nse_findings({"nse": {"checks": checks}})}
    assert f["nse:tls:443"]["severity"] == "critical" and "grade F" in f["nse:tls:443"]["title"]
    assert f["nse:smbv1:445"]["severity"] == "critical"
    assert f["nse:smbsign:445"]["severity"] == "medium"
    assert f["nse:ssh:22"]["severity"] == "medium"


def test_healthy_host_has_no_nse_findings():
    assert nse_findings({"nse": {"checks": nse.parse(GOOD_XML)}}) == []


def test_smbv1_finding_survives_localhost_downgrade():
    scan = {"domain": "localhost", "ips": ["127.0.0.1"],
            "open_ports": [{"port": 445, "proto": "tcp", "service": "smb"}],
            "nse": {"checks": nse.parse(SMB_XML)}}
    smbv1 = next(x for x in build_findings(scan) if x.get("key") == "nse:smbv1:445")
    assert smbv1["severity"] == "critical"    # NOT softened to info just because it's local


def test_allowlist_is_fixed_and_target_validated(monkeypatch):
    seen = {}
    def fake_run(cmd):
        seen["cmd"] = cmd
        return "<nmaprun/>", "", 0
    monkeypatch.setattr(nse, "_run", fake_run)
    nse.run("example.nl", "nmap", [443, 22])
    cmd = seen["cmd"]
    i = cmd.index("--script")
    assert cmd[i + 1] == "ssl-enum-ciphers,ssh2-enum-algos,smb-protocols,smb2-security-mode,http-security-headers,http-title"
    assert cmd[-1] == "example.nl"
    # A malicious "target" can never reach nmap.
    for evil in ["x.nl; rm -rf /", "--script=http-vuln", "-oN out"]:
        with pytest.raises(ValueError):
            nse.run(evil, "nmap", [443])


def test_no_relevant_ports_means_no_run():
    assert nse.relevant_ports([{"port": 3000, "proto": "tcp"}]) == []
    assert nse.run("example.nl", "nmap", [])["ran"] is False
