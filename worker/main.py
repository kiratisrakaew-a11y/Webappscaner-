"""Worker entrypoint: run the full scan pipeline for one job.

Reuses the Phase 0 pipeline modules (scanner.*) unchanged — this worker only
adds job lifecycle + artifact storage around them. It runs either:
    * inline in a thread (RUN_MODE=local, called by cloud.jobs), or
    * as a Cloud Run Job container: ``python -m worker.main`` reading
      JOB_ID / TARGET from the environment.

Flow: mark running -> ZAP scan -> normalize -> assess -> store artifacts +
summary -> mark done/failed. Any exception is captured onto the job record so
the API can show it instead of hanging in "running".
"""

from __future__ import annotations

import json
import os
import sys
import traceback

from scanner import zap_runner, normalize, ai_assessor, report
from cloud.store import get_store


def run_job(job_id: str, target: str) -> None:
    store = get_store()
    log_lines: list[str] = []

    def log(msg: str) -> None:
        print(f"[{job_id}] {msg}", flush=True)
        log_lines.append(msg)

    try:
        store.update_job(job_id, status="running")

        # 1) ZAP scan (auth was already enforced by the API before queueing).
        runner = zap_runner.ZapRunner(
            proxy=os.environ.get("ZAP_PROXY", "http://127.0.0.1:8090"),
            api_key=os.environ.get("ZAP_API_KEY"),
            timeout=int(os.environ.get("SCAN_TIMEOUT", "1800")),
            on_progress=log,
        )
        raw_alerts = runner.scan(target)

        # 2) Normalize -> findings.
        findings = normalize.normalize_zap(raw_alerts)
        store.put_artifact(
            job_id, "findings.json",
            json.dumps([f.to_dict() for f in findings], ensure_ascii=False, indent=2),
        )

        # 3) AI assessment (falls back to static mapping without a key).
        use_ai = os.environ.get("USE_AI", "1") != "0"
        assessed = ai_assessor.assess(findings, use_ai=use_ai, on_progress=log)
        store.put_artifact(
            job_id, "assessment.json",
            json.dumps([af.to_dict() for af in assessed], ensure_ascii=False, indent=2),
        )

        # 4) Report artifacts.
        store.put_artifact(job_id, "report.html",
                           report.build_html(target, assessed), "text/html")
        report_json = report.build_json(target, assessed)
        store.put_artifact(job_id, "report.json",
                           json.dumps(report_json, ensure_ascii=False, indent=2))

        store.update_job(job_id, status="done", summary=report_json["summary"])
        log("done")

    except Exception as exc:  # noqa: BLE001 - record any failure on the job
        err = f"{type(exc).__name__}: {exc}"
        log(f"FAILED: {err}")
        traceback.print_exc()
        try:
            store.update_job(job_id, status="failed", error=err)
        except Exception:  # pragma: no cover - best-effort
            pass


def main() -> int:
    job_id = os.environ.get("JOB_ID")
    target = os.environ.get("TARGET")
    if not job_id or not target:
        print("JOB_ID and TARGET env vars are required", file=sys.stderr)
        return 2
    run_job(job_id, target)
    return 0


if __name__ == "__main__":
    sys.exit(main())
