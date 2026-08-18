"""Trigger the scan worker for a queued job.

Two execution modes, chosen from the env (RUN_MODE, default "local"):

    local  — run the worker inline in a background thread. No queue, no extra
             services; ideal for dev and the docker-compose stack.
    cloud  — launch a Cloud Run Job execution, passing JOB_ID + TARGET as env
             overrides. The job runs the same worker entrypoint in its own
             container with no HTTP timeout (right fit for long ZAP scans).

The API only calls ``trigger_scan``; it never blocks on the scan itself.
"""

from __future__ import annotations

import os
import threading
from typing import Optional


def trigger_scan(job_id: str, target: str) -> None:
    mode = os.environ.get("RUN_MODE", "local").lower()
    if mode == "cloud":
        _trigger_cloud_run_job(job_id, target)
    else:
        _trigger_inline(job_id, target)


def _trigger_inline(job_id: str, target: str) -> None:
    # Import here to avoid a circular import (worker imports cloud.store).
    from worker.main import run_job

    thread = threading.Thread(
        target=run_job, args=(job_id, target), daemon=True,
        name=f"scan-{job_id}",
    )
    thread.start()


def _trigger_cloud_run_job(job_id: str, target: str) -> None:
    """Execute a pre-deployed Cloud Run Job with per-run env overrides.

    Requires env: GOOGLE_CLOUD_PROJECT, CLOUD_RUN_REGION, WORKER_JOB_NAME.
    The worker job's container must run ``python -m worker.main`` and read
    JOB_ID / TARGET from the environment.
    """
    from google.cloud import run_v2  # type: ignore

    project = os.environ["GOOGLE_CLOUD_PROJECT"]
    region = os.environ.get("CLOUD_RUN_REGION", "asia-southeast1")
    job_name = os.environ.get("WORKER_JOB_NAME", "webscan-worker")

    client = run_v2.JobsClient()
    name = f"projects/{project}/locations/{region}/jobs/{job_name}"

    overrides = run_v2.RunJobRequest.Overrides(
        container_overrides=[
            run_v2.RunJobRequest.Overrides.ContainerOverride(
                env=[
                    run_v2.EnvVar(name="JOB_ID", value=job_id),
                    run_v2.EnvVar(name="TARGET", value=target),
                ]
            )
        ]
    )
    client.run_job(run_v2.RunJobRequest(name=name, overrides=overrides))
