"""Cloud integration layer: job storage + worker triggering.

Backends are chosen at runtime from the environment so the same code runs
locally (filesystem + inline worker) and on Google Cloud (Firestore + GCS +
Cloud Run Jobs). See ``store.get_store()`` and ``jobs.trigger_scan()``.
"""
