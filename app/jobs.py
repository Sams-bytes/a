"""A tiny background-job runner so the browser can watch a scan happen live.

A scan can take a minute. Instead of one frozen request + a spinner, we run the
scan in a background thread (a 'job') that reports its progress as it goes:
which phase it's in, a percentage, and a line of activity. The browser polls
GET /api/jobs/<id> and shows a live progress bar + activity log, then the result.

In-memory only (fine for a single-user local tool); the last ~40 jobs are kept.
"""

from __future__ import annotations

import threading
import uuid
from collections import OrderedDict
from typing import Callable

MAX_JOBS = 40
_jobs: "OrderedDict[str, Job]" = OrderedDict()
_guard = threading.Lock()


class Job:
    def __init__(self):
        self.id = uuid.uuid4().hex[:12]
        self.state = "running"      # running | done | error
        self.percent = 0
        self.phase = "Starting…"
        self.lines: list[str] = []
        self.result = None
        self.error: str | None = None
        self._lock = threading.Lock()

    def report(self, phase: str | None = None, percent: float | None = None, line: str | None = None) -> None:
        """Called by the running scan to publish progress. Percent only moves forward."""
        with self._lock:
            if phase is not None:
                self.phase = phase
                if line is None:
                    line = phase
            if percent is not None:
                self.percent = max(self.percent, min(100, int(percent)))
            if line:
                self.lines.append(line)

    def snapshot(self) -> dict:
        with self._lock:
            return {"id": self.id, "state": self.state, "percent": self.percent, "phase": self.phase,
                    "lines": self.lines[-12:], "result": self.result, "error": self.error}


def start(fn: Callable[[Callable], object]) -> str:
    """Run fn(report) in a background thread. Returns the job id to poll."""
    job = Job()
    with _guard:
        _jobs[job.id] = job
        while len(_jobs) > MAX_JOBS:
            _jobs.popitem(last=False)

    def run():
        try:
            job.result = fn(job.report)
            job.report(phase="Done", percent=100)
            job.state = "done"
        except Exception as e:  # the scan's error becomes the job's error, shown in the UI
            job.error = str(e) or e.__class__.__name__
            job.state = "error"
            job.report(phase="Failed")

    threading.Thread(target=run, name=f"job-{job.id}", daemon=True).start()
    return job.id


def get(job_id: str) -> dict | None:
    with _guard:
        job = _jobs.get(job_id)
    return job.snapshot() if job else None
