#!/usr/bin/env bash
#
# One-command deploy of the scanner to Google Cloud.
#
# Prereqs on YOUR machine (not needed in the repo):
#   - gcloud CLI installed and authenticated:  gcloud auth login
#   - a billing-enabled GCP project
#   - (optional) an Anthropic API key for AI assessment
#
# Configure via env vars, then run:  bash infra/deploy.sh
#
#   PROJECT_ID=my-proj REGION=asia-southeast1 \
#   ALLOWLIST=example.com,localhost \
#   ANTHROPIC_API_KEY=sk-ant-... \
#   bash infra/deploy.sh
#
set -euo pipefail

PROJECT_ID="${PROJECT_ID:?set PROJECT_ID}"
REGION="${REGION:-asia-southeast1}"
REPO="${REPO:-webscan}"
BUCKET="${BUCKET:-${PROJECT_ID}-webscan}"
API_SERVICE="${API_SERVICE:-webscan-api}"
WORKER_JOB="${WORKER_JOB:-webscan-worker}"
ALLOWLIST="${ALLOWLIST:-localhost}"
USE_AI="${USE_AI:-1}"
ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}"

IMG_BASE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}"

echo "== project: ${PROJECT_ID}  region: ${REGION} =="
gcloud config set project "${PROJECT_ID}"

echo "== enabling APIs =="
gcloud services enable \
  run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com \
  firestore.googleapis.com storage.googleapis.com secretmanager.googleapis.com

echo "== artifact registry =="
gcloud artifacts repositories describe "${REPO}" --location="${REGION}" >/dev/null 2>&1 || \
  gcloud artifacts repositories create "${REPO}" \
    --repository-format=docker --location="${REGION}"

echo "== storage bucket =="
gcloud storage buckets describe "gs://${BUCKET}" >/dev/null 2>&1 || \
  gcloud storage buckets create "gs://${BUCKET}" --location="${REGION}"

echo "== firestore (native) =="
gcloud firestore databases describe --database="(default)" >/dev/null 2>&1 || \
  gcloud firestore databases create --location="${REGION}" --type=firestore-native

echo "== secret (Anthropic key) =="
if [ -n "${ANTHROPIC_API_KEY}" ]; then
  gcloud secrets describe anthropic-api-key >/dev/null 2>&1 || \
    gcloud secrets create anthropic-api-key --replication-policy=automatic
  printf '%s' "${ANTHROPIC_API_KEY}" | gcloud secrets versions add anthropic-api-key --data-file=-
fi

echo "== build + push images =="
gcloud builds submit --config infra/cloudbuild.yaml \
  --substitutions=_REGION="${REGION}",_REPO="${REPO}"

# Common env for worker + shared config.
WORKER_ENV="GOOGLE_CLOUD_PROJECT=${PROJECT_ID},STORAGE_BUCKET=${BUCKET},USE_AI=${USE_AI},SCAN_TIMEOUT=1800"

echo "== deploy worker (Cloud Run Job) =="
WORKER_SECRET_ARGS=()
if [ -n "${ANTHROPIC_API_KEY}" ]; then
  WORKER_SECRET_ARGS=(--set-secrets "ANTHROPIC_API_KEY=anthropic-api-key:latest")
fi
gcloud run jobs describe "${WORKER_JOB}" --region="${REGION}" >/dev/null 2>&1 && ACT=update || ACT=create
gcloud run jobs "${ACT}" "${WORKER_JOB}" \
  --image "${IMG_BASE}/webscan-worker:latest" \
  --region "${REGION}" \
  --task-timeout 3600 --memory 2Gi --cpu 2 --max-retries 0 \
  --set-env-vars "${WORKER_ENV}" \
  "${WORKER_SECRET_ARGS[@]}"

echo "== deploy api (Cloud Run service) =="
API_ENV="RUN_MODE=cloud,GOOGLE_CLOUD_PROJECT=${PROJECT_ID},STORAGE_BUCKET=${BUCKET},CLOUD_RUN_REGION=${REGION},WORKER_JOB_NAME=${WORKER_JOB},SCAN_ALLOWLIST=${ALLOWLIST}"
gcloud run deploy "${API_SERVICE}" \
  --image "${IMG_BASE}/webscan-api:latest" \
  --region "${REGION}" \
  --allow-unauthenticated \
  --memory 512Mi \
  --set-env-vars "${API_ENV}"

# Grant the API's runtime service account the roles it needs to run jobs and
# read/write Firestore + GCS.
SA="$(gcloud run services describe "${API_SERVICE}" --region="${REGION}" --format='value(spec.template.spec.serviceAccountName)')"
SA="${SA:-$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')-compute@developer.gserviceaccount.com}"
echo "== granting IAM to ${SA} =="
for role in roles/run.developer roles/datastore.user roles/storage.objectAdmin; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member "serviceAccount:${SA}" --role "${role}" --condition=None >/dev/null
done

URL="$(gcloud run services describe "${API_SERVICE}" --region="${REGION}" --format='value(status.url)')"
echo
echo "✅ Deployed. API URL: ${URL}"
echo "   เปิดหน้าเว็บที่ ${URL} แล้วส่ง target ที่อยู่ใน ALLOWLIST=${ALLOWLIST}"
