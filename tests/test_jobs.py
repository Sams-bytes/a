import time

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app import jobs, nmap_engine, scanner
from app.db import Store
from app.verification import VerificationService


def wait(job_id, timeout=3):
    end = time.time() + timeout
    while time.time() < end:
        j = jobs.get(job_id)
        if j and j["state"] != "running":
            return j
        time.sleep(0.02)
    raise AssertionError("job did not finish")


def test_job_runs_and_collects_progress():
    def work(report):
        report(phase="Step one", percent=10, line="hello")
        report(percent=50)
        report(line="nearly there")
        return {"ok": True}
    j = wait(jobs.start(work))
    assert j["state"] == "done" and j["result"] == {"ok": True} and j["percent"] == 100
    assert "hello" in j["lines"] and "nearly there" in j["lines"]


def test_phase_without_line_is_logged():
    def work(report):
        report(phase="Resolving DNS", percent=5)   # no explicit line -> phase itself is logged
        return None
    assert "Resolving DNS" in wait(jobs.start(work))["lines"]


def test_job_surfaces_errors():
    def boom(report):
        raise RuntimeError("nmap exploded")
    j = wait(jobs.start(boom))
    assert j["state"] == "error" and "exploded" in j["error"]


def test_percent_only_moves_forward():
    def work(report):
        report(percent=80)
        report(percent=30)   # a late, lower number must not drag the bar backwards
        return None
    assert wait(jobs.start(work))["percent"] == 100  # done forces 100
    j = jobs.Job()
    j.report(percent=80); j.report(percent=30)
    assert j.snapshot()["percent"] == 80


def test_taskprogress_parser():
    line = '<taskprogress task="Connect Scan" time="1" percent="45.87" remaining="5" etc="2"/>'
    m = nmap_engine.TASK_RE.search(line)
    assert m.group(1) == "Connect Scan" and float(m.group(2)) == 45.87 and int(m.group(3)) == 5


def test_streaming_reports_progress(monkeypatch):
    # Fake an nmap process whose stdout dribbles out progress then the final XML.
    class FakeProc:
        def __init__(self):
            self.stdout = iter(['<taskprogress task="Connect Scan" percent="20.0" remaining="4"/>\n',
                                '<taskprogress task="Connect Scan" percent="90.0" remaining="1"/>\n',
                                '<nmaprun></nmaprun>\n'])

            class E:
                def read(self_inner): return ""
            self.stderr = E()
            self.returncode = 0

        def wait(self, timeout=None): return 0
    monkeypatch.setattr(nmap_engine.subprocess, "Popen", lambda *a, **k: FakeProc())
    seen = []
    out, err, rc = nmap_engine._run_streaming(["nmap"], lambda t, p, r: seen.append(p))
    assert seen == [20.0, 90.0] and rc == 0 and "<nmaprun>" in out


@pytest.fixture
def client(tmp_path, monkeypatch, make_client):
    monkeypatch.setattr(scanner, "scan", lambda d, report=None, **kw: (
        report and report(phase="Scanning ports", percent=40, line="probing")) or
        {"domain": d, "ips": ["127.0.0.1"], "open_ports": [], "findings": [], "score": 100})
    c = make_client(Store(str(tmp_path / "j.db")))
    c.post("/api/domains", json={"domain": "localhost"})
    return c


def test_live_scan_endpoint(client):
    r = client.post("/api/domains/localhost/scan?live=true").json()
    assert "job_id" in r
    end = time.time() + 3
    while time.time() < end:
        j = client.get(f"/api/jobs/{r['job_id']}").json()
        if j["state"] != "running":
            break
        time.sleep(0.02)
    assert j["state"] == "done" and j["result"]["result"]["score"] == 100
    assert client.get("/api/jobs/nope").status_code == 404