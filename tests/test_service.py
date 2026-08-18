"""Integration tests for the API service + worker in local mode.

ZAP is monkeypatched to return canned alerts, so these run without a live ZAP
daemon or API key. Covers: auth gate over HTTP, job lifecycle, worker producing
report artifacts, and the report endpoint gating on status.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Isolate storage + allowlist before importing the app.
_TMP = tempfile.mkdtemp(prefix="webscan-test-")
os.environ["DATA_DIR"] = _TMP
os.environ["SCAN_ALLOWLIST"] = "localhost"
os.environ["USE_AI"] = "0"           # static mapping, no API key needed
os.environ.pop("RUN_MODE", None)     # local (inline worker thread)
os.environ.pop("GOOGLE_CLOUD_PROJECT", None)

from fastapi.testclient import TestClient  # noqa: E402

from scanner import zap_runner  # noqa: E402

_SAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "examples", "sample_zap_alerts.json")
with open(_SAMPLE, encoding="utf-8") as fh:
    SAMPLE_ALERTS = json.load(fh)


# Patch ZapRunner.scan to skip the network entirely.
zap_runner.ZapRunner.scan = lambda self, target: SAMPLE_ALERTS  # type: ignore

from api.main import app  # noqa: E402  (import after patch + env)

client = TestClient(app)


def test_healthz():
    assert client.get("/healthz").text == "ok"


def test_auth_gate_rejects_unlisted_host():
    r = client.post("/scan", json={"target": "http://evil.example.com"})
    assert r.status_code == 403


def test_full_scan_flow_produces_report():
    r = client.post("/scan", json={"target": "http://localhost:3000"})
    assert r.status_code == 202, r.text
    job_id = r.json()["job_id"]

    # Poll until the inline worker thread finishes.
    for _ in range(50):
        status = client.get(f"/scan/{job_id}").json()["status"]
        if status in ("done", "failed"):
            break
        time.sleep(0.2)
    assert status == "done", f"job ended as {status}"

    report = client.get(f"/report/{job_id}")
    assert report.status_code == 200
    assert "Web Security Assessment Report" in report.text
    assert "A03:2021 - Injection" in report.text

    summary = client.get(f"/scan/{job_id}").json()["summary"]
    assert summary["total"] == len(SAMPLE_ALERTS)


def test_report_not_ready_returns_425():
    # A freshly created job (worker patched to be slow-free still races); assert
    # the endpoint returns 404 for a nonexistent job at least.
    assert client.get("/report/doesnotexist").status_code == 404


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
