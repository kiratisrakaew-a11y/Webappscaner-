# AI-Assisted Black-box Web Vulnerability Scanner

เครื่องมือสแกนช่องโหว่ **web application** ตาม **OWASP Top 10 (2021)** แบบ **black-box (DAST — ไม่ต้องมี source code)**
โดยใช้ **OWASP ZAP** เป็น scan engine และให้ **Claude (AI)** ช่วยประเมินผล จัดหมวด และเขียนรายงาน

```
URL → ZAP → JSON Findings → AI Assessment → OWASP Top 10 → WSTG → CWE → Risk / Confidence → Recommendation → Web Security Assessment Report
```

## ⚠️ คำเตือนด้านกฎหมาย

สแกนได้ **เฉพาะระบบที่คุณเป็นเจ้าของหรือมีหนังสืออนุญาตเป็นลายลักษณ์อักษร** การสแกนระบบผู้อื่นโดยไม่ได้รับอนุญาตเป็นความผิดตามกฎหมาย (เช่น พ.ร.บ.คอมพิวเตอร์) เครื่องมือนี้มี **authorization gate** ที่บังคับให้ target อยู่ใน allowlist ก่อนเริ่มสแกน

## ขอบเขตของ black-box (สำคัญ — ต้องเข้าใจก่อนใช้)

DAST มองเห็นแอปจากภายนอกเท่านั้น จึงครอบคลุม OWASP Top 10 ได้ไม่ครบทุกหมวด:

| OWASP 2021 | Black-box | หมายเหตุ |
|---|---|---|
| A01 Broken Access Control | ⚠️ บางส่วน | ต้องมี multi-user login context |
| A02 Cryptographic Failures | ✅ ดี | TLS/cipher, cookie flags |
| A03 Injection | ✅ จุดแข็ง | SQLi / XSS / command injection |
| A04 Insecure Design | ❌ | ต้อง threat modeling |
| A05 Security Misconfiguration | ✅ ดี | headers, dir listing, error leak |
| A06 Vulnerable Components | ⚠️ บางส่วน | fingerprint version → CVE |
| A07 Auth Failures | ⚠️ บางส่วน | session/brute-force |
| A08 Integrity Failures | ⚠️ จำกัด | SRI missing |
| A09 Logging/Monitoring | ❌ | มองจากภายนอกไม่เห็น |
| A10 SSRF | ⚠️ บางส่วน | ถ้า input trigger server request |

รายงานจะระบุชัดว่าหมวดใด "out of black-box scope" เพื่อไม่ให้เข้าใจผิดว่าปลอดภัย

## Pipeline / โครงสร้างโค้ด

```
scanner/
  auth_gate.py     # ยืนยันสิทธิ์ target ก่อนสแกน (allowlist)
  zap_runner.py    # คุม ZAP: spider → active scan → export alerts
  normalize.py     # รวม findings → schema กลาง (Finding)
  mappings.py      # ZAP pluginId / CWE → OWASP 2021 + WSTG (ground truth ให้ AI)
  ai_assessor.py   # เรียก Claude: risk, confidence, remediation, false-positive
  report.py        # ประกอบ Web Security Assessment Report (HTML + JSON)
  models.py        # dataclasses ที่ใช้ร่วมกัน
run_scan.py        # orchestrator CLI: URL → รายงาน
docker-compose.yml # ZAP daemon + OWASP Juice Shop (target ทดสอบ)
```

## วิธีรัน (Phase 0 — PoC บนเครื่อง)

### 1. ติดตั้ง dependency
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 2. ตั้งค่า
```bash
export ANTHROPIC_API_KEY=sk-ant-...        # คีย์ Claude
export SCAN_ALLOWLIST=localhost,juice-shop # target ที่อนุญาต (คั่นด้วย ,)
```

### 3. ยก ZAP + target ทดสอบ
```bash
docker compose up -d          # zap (port 8090) + juice-shop (port 3000)
```

### 4. สแกน
```bash
python run_scan.py --target http://localhost:3000 --out ./out
# ได้: out/findings.json, out/assessment.json, out/report.html
```

> ไม่มี `ANTHROPIC_API_KEY`? ใส่ `--no-ai` เพื่อรัน pipeline โดยข้ามขั้น AI (ใช้ mapping แบบ static แทน) เหมาะกับทดสอบ ZAP อย่างเดียว

## รันเป็น service (API + web UI)

นอกจาก CLI แล้ว มี API service (FastAPI) + หน้าเว็บ submit ให้ด้วย — รัน local ได้เลย:
```bash
docker compose up -d                 # ZAP + Juice Shop
export SCAN_ALLOWLIST=localhost,juice-shop
uvicorn api.main:app --port 8080     # เปิด http://localhost:8080
```
โหมด local: worker รันใน background thread, เก็บผลใน `./data` (ไม่ต้องมี GCP)

## Roadmap
- **Phase 0 ✅:** PoC local — pipeline ครบวงจร (CLI)
- **Phase 1 ✅:** API service + worker + Google Cloud deploy — ดู **[DEPLOY.md](DEPLOY.md)**
  (Cloud Run service + Cloud Run Job + Firestore + Cloud Storage, deploy ด้วย `infra/deploy.sh`)
- **Phase 2:** เสริม testssl/nuclei, authenticated scan, ลด false positive
- **Phase 3:** production hardening (ownership verification, audit log, PDF, multi-user)
