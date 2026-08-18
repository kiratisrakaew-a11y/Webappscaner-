"""FastAPI service: submit scans, poll status, fetch reports.

Endpoints:
    GET  /                 -> submit form (web/index.html)
    GET  /healthz          -> liveness probe
    POST /scan             -> {target} : auth-gate, create job, trigger worker
    GET  /scan/{job_id}    -> job status JSON
    GET  /jobs             -> recent jobs
    GET  /report/{job_id}  -> report.html (once status == done)

The auth gate runs HERE, before a job is ever queued — no traffic is sent to a
target that isn't on the allowlist. The actual scanning happens in the worker
(cloud.jobs.trigger_scan), so requests return immediately with a job id.
"""

from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel

from scanner import auth_gate
from cloud import jobs
from cloud.store import get_store

app = FastAPI(title="AI Web Vulnerability Scanner", version="0.2.0")

_WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")


class ScanRequest(BaseModel):
    target: str


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    path = os.path.join(_WEB_DIR, "index.html")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    return "<h1>AI Web Vulnerability Scanner</h1><p>POST /scan {\"target\": \"...\"}</p>"


@app.post("/scan")
def create_scan(req: ScanRequest) -> JSONResponse:
    allowlist = auth_gate.load_allowlist()
    try:
        target = auth_gate.authorize(req.target, allowlist)
    except auth_gate.AuthorizationError as exc:
        # 403: refused by policy (not on allowlist / bad scheme).
        raise HTTPException(status_code=403, detail=str(exc))

    store = get_store()
    job_id = store.create_job(target)
    jobs.trigger_scan(job_id, target)
    return JSONResponse(
        status_code=202,
        content={"job_id": job_id, "status": "queued", "target": target},
    )


@app.get("/scan/{job_id}")
def get_scan(job_id: str) -> dict:
    job = get_store().get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return job


@app.get("/jobs")
def list_jobs(limit: int = 50) -> dict:
    return {"jobs": get_store().list_jobs(limit=limit)}


@app.get("/report/{job_id}", response_class=HTMLResponse)
def get_report(job_id: str) -> HTMLResponse:
    store = get_store()
    job = store.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    if job.get("status") != "done":
        # 425 Too Early: valid job, report not ready yet.
        raise HTTPException(status_code=425, detail=f"report not ready (status={job.get('status')})")
    artifact = store.get_artifact(job_id, "report.html")
    if artifact is None:
        raise HTTPException(status_code=404, detail="report artifact missing")
    return HTMLResponse(content=artifact[0])
