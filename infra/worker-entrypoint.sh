#!/usr/bin/env bash
# Start a local ZAP daemon, wait until its API answers, then run the worker
# for the single job identified by $JOB_ID / $TARGET. Used by Cloud Run Jobs.
set -euo pipefail

ZAP_PORT="${ZAP_PORT:-8090}"

echo "[entrypoint] starting ZAP daemon on :${ZAP_PORT}"
zap.sh -daemon -host 127.0.0.1 -port "${ZAP_PORT}" \
  -config api.disablekey=true \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true &
ZAP_PID=$!

# Wait for the ZAP API to become responsive (max ~90s).
echo "[entrypoint] waiting for ZAP to be ready..."
for i in $(seq 1 45); do
  if curl -s "http://127.0.0.1:${ZAP_PORT}/JSON/core/view/version/" >/dev/null 2>&1; then
    echo "[entrypoint] ZAP is up"
    break
  fi
  sleep 2
done

# Run the scan for this job, then shut ZAP down.
set +e
python3 -m worker.main
RC=$?
set -e

echo "[entrypoint] worker exited rc=${RC}, stopping ZAP"
kill "${ZAP_PID}" 2>/dev/null || true
exit "${RC}"
