"""Job + artifact storage with two interchangeable backends.

A "job" tracks one scan request through its lifecycle:
    queued -> running -> done | failed
Artifacts are the outputs of a job (findings.json, assessment.json,
report.html, report.json).

Backends:
    * LocalStore  — filesystem under DATA_DIR. Zero dependencies, used for
                    local dev/testing and as the default.
    * GcpStore    — Firestore (job metadata) + Cloud Storage (artifacts).
                    Used in production on Cloud Run.

Selection (``get_store``): GcpStore when GOOGLE_CLOUD_PROJECT *and*
STORAGE_BUCKET are set, else LocalStore. This keeps the API/worker code
backend-agnostic — they only ever see the ``JobStore`` interface.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any, Optional


JOB_STATUSES = ("queued", "running", "done", "failed")


class JobStore:
    """Interface both backends implement."""

    def create_job(self, target: str, meta: Optional[dict] = None) -> str:
        raise NotImplementedError

    def get_job(self, job_id: str) -> Optional[dict[str, Any]]:
        raise NotImplementedError

    def update_job(self, job_id: str, **fields: Any) -> None:
        raise NotImplementedError

    def list_jobs(self, limit: int = 50) -> list[dict[str, Any]]:
        raise NotImplementedError

    def put_artifact(self, job_id: str, name: str, content: str,
                     content_type: str = "application/json") -> None:
        raise NotImplementedError

    def get_artifact(self, job_id: str, name: str) -> Optional[tuple[str, str]]:
        """Return (content, content_type) or None."""
        raise NotImplementedError


def _now() -> float:
    return time.time()


def _new_job_doc(job_id: str, target: str, meta: Optional[dict]) -> dict[str, Any]:
    return {
        "id": job_id,
        "target": target,
        "status": "queued",
        "created_at": _now(),
        "updated_at": _now(),
        "error": None,
        "summary": None,
        "meta": meta or {},
    }


# ---------------------------------------------------------------------------
# Local filesystem backend
# ---------------------------------------------------------------------------
class LocalStore(JobStore):
    def __init__(self, base_dir: Optional[str] = None) -> None:
        self.base = base_dir or os.environ.get("DATA_DIR", "./data")
        os.makedirs(self.base, exist_ok=True)

    def _job_dir(self, job_id: str) -> str:
        return os.path.join(self.base, "jobs", job_id)

    def _meta_path(self, job_id: str) -> str:
        return os.path.join(self._job_dir(job_id), "job.json")

    def create_job(self, target: str, meta: Optional[dict] = None) -> str:
        job_id = uuid.uuid4().hex[:12]
        os.makedirs(os.path.join(self._job_dir(job_id), "artifacts"), exist_ok=True)
        self._write_meta(job_id, _new_job_doc(job_id, target, meta))
        return job_id

    def _write_meta(self, job_id: str, doc: dict) -> None:
        with open(self._meta_path(job_id), "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=2)

    def get_job(self, job_id: str) -> Optional[dict[str, Any]]:
        path = self._meta_path(job_id)
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    def update_job(self, job_id: str, **fields: Any) -> None:
        doc = self.get_job(job_id)
        if doc is None:
            raise KeyError(job_id)
        doc.update(fields)
        doc["updated_at"] = _now()
        self._write_meta(job_id, doc)

    def list_jobs(self, limit: int = 50) -> list[dict[str, Any]]:
        jobs_dir = os.path.join(self.base, "jobs")
        if not os.path.isdir(jobs_dir):
            return []
        docs = []
        for jid in os.listdir(jobs_dir):
            doc = self.get_job(jid)
            if doc:
                docs.append(doc)
        docs.sort(key=lambda d: d.get("created_at", 0), reverse=True)
        return docs[:limit]

    def put_artifact(self, job_id: str, name: str, content: str,
                     content_type: str = "application/json") -> None:
        art_dir = os.path.join(self._job_dir(job_id), "artifacts")
        os.makedirs(art_dir, exist_ok=True)
        with open(os.path.join(art_dir, name), "w", encoding="utf-8") as fh:
            fh.write(content)

    def get_artifact(self, job_id: str, name: str) -> Optional[tuple[str, str]]:
        path = os.path.join(self._job_dir(job_id), "artifacts", name)
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8") as fh:
            content = fh.read()
        ct = "text/html" if name.endswith(".html") else "application/json"
        return content, ct


# ---------------------------------------------------------------------------
# Google Cloud backend (Firestore + Cloud Storage)
# ---------------------------------------------------------------------------
class GcpStore(JobStore):
    def __init__(self, project: str, bucket: str,
                 collection: str = "scan_jobs") -> None:
        # Imported lazily so local runs never need these packages installed.
        from google.cloud import firestore, storage  # type: ignore
        self._db = firestore.Client(project=project)
        self._col = self._db.collection(collection)
        self._bucket = storage.Client(project=project).bucket(bucket)

    def create_job(self, target: str, meta: Optional[dict] = None) -> str:
        job_id = uuid.uuid4().hex[:12]
        self._col.document(job_id).set(_new_job_doc(job_id, target, meta))
        return job_id

    def get_job(self, job_id: str) -> Optional[dict[str, Any]]:
        snap = self._col.document(job_id).get()
        return snap.to_dict() if snap.exists else None

    def update_job(self, job_id: str, **fields: Any) -> None:
        fields["updated_at"] = _now()
        self._col.document(job_id).update(fields)

    def list_jobs(self, limit: int = 50) -> list[dict[str, Any]]:
        from google.cloud import firestore  # type: ignore
        q = self._col.order_by("created_at", direction=firestore.Query.DESCENDING).limit(limit)
        return [d.to_dict() for d in q.stream()]

    def put_artifact(self, job_id: str, name: str, content: str,
                     content_type: str = "application/json") -> None:
        blob = self._bucket.blob(f"jobs/{job_id}/{name}")
        blob.upload_from_string(content, content_type=content_type)

    def get_artifact(self, job_id: str, name: str) -> Optional[tuple[str, str]]:
        blob = self._bucket.blob(f"jobs/{job_id}/{name}")
        if not blob.exists():
            return None
        content = blob.download_as_text()
        ct = "text/html" if name.endswith(".html") else "application/json"
        return content, ct


_store_singleton: Optional[JobStore] = None


def get_store() -> JobStore:
    """Return the process-wide store, picking the backend from the env."""
    global _store_singleton
    if _store_singleton is not None:
        return _store_singleton

    project = os.environ.get("GOOGLE_CLOUD_PROJECT")
    bucket = os.environ.get("STORAGE_BUCKET")
    if project and bucket:
        _store_singleton = GcpStore(project=project, bucket=bucket)
    else:
        _store_singleton = LocalStore()
    return _store_singleton
