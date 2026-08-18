# Deploy to Google Cloud (Phase 1)

สถาปัตยกรรม MVP บน Google Cloud:

```
ผู้ใช้ ──HTTP──> Cloud Run service (API)  ──trigger──> Cloud Run Job (Worker)
                     │  auth-gate                        │  ZAP daemon (in-container)
                     │  create job (Firestore)           │  scan → AI assess → report
                     ▼                                    ▼
                 Firestore (job state)  <────────  Cloud Storage (artifacts)
                     ▲                                    │
                     └────────  API reads report ◄────────┘
```

- **API** (Cloud Run *service*): รับ URL, ตรวจ allowlist, สร้าง job ใน Firestore, สั่ง worker แล้วตอบ `job_id` ทันที (ไม่บล็อก)
- **Worker** (Cloud Run *Job*): image รวม ZAP ในตัว → สแกน → AI ประเมิน → เขียน report ลง Cloud Storage, อัปเดตสถานะใน Firestore
- ใช้ **Cloud Run Job** เพราะสแกนใช้เวลานาน (ไม่ติด HTTP timeout ของ service)

## ต้องเตรียม (บนเครื่องคุณ)
1. `gcloud` CLI + login: `gcloud auth login`
2. GCP project ที่เปิด billing
3. (ถ้าจะใช้ AI) Anthropic API key

## Deploy ครั้งเดียวจบ
```bash
PROJECT_ID=your-project \
REGION=asia-southeast1 \
ALLOWLIST=example.com,localhost \
ANTHROPIC_API_KEY=sk-ant-... \
bash infra/deploy.sh
```

`deploy.sh` จะทำให้อัตโนมัติ: เปิด API, สร้าง Artifact Registry + GCS bucket + Firestore, เก็บ API key ใน Secret Manager, build+push image ทั้งสอง, deploy API service + Worker job, และ grant IAM ให้ service account (`run.developer`, `datastore.user`, `storage.objectAdmin`)

เสร็จแล้วสคริปต์จะพิมพ์ **API URL** — เปิดในเบราว์เซอร์ กรอก target (ต้องอยู่ใน `ALLOWLIST`) แล้วกดสแกน

## ใช้งานผ่าน API ตรงๆ
```bash
BASE=https://webscan-api-xxxx.a.run.app
# สั่งสแกน
curl -X POST "$BASE/scan" -H 'Content-Type: application/json' \
     -d '{"target":"https://example.com"}'      # -> {"job_id":"abc123",...}
# เช็คสถานะ
curl "$BASE/scan/abc123"                          # -> {"status":"running"|"done"|...}
# เปิดรายงาน (เมื่อ done)
open "$BASE/report/abc123"
```

## หมายเหตุด้านความปลอดภัย
- `--allow-unauthenticated` เปิด public ไว้เพื่อความง่ายของ MVP — **ควรใส่ auth** (IAP / API key / Firebase Auth) ก่อนใช้จริง เพราะเป็นเครื่องมือสแกน
- `SCAN_ALLOWLIST` คือด่านกันสแกนมั่ว — ตั้งเฉพาะโดเมนที่คุณมีสิทธิ์เท่านั้น
- Phase 3 จะเพิ่ม ownership verification (DNS TXT/meta tag) แทน allowlist แบบ static

## ทดสอบ local ก่อน deploy (ไม่ต้องมี GCP)
```bash
pip install -r requirements.txt
docker compose up -d              # ZAP + Juice Shop
export SCAN_ALLOWLIST=localhost,juice-shop
uvicorn api.main:app --port 8080  # RUN_MODE ไม่ได้ตั้ง = local (worker รันใน thread), store = ./data
# เปิด http://localhost:8080
```
