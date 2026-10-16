# 🛡️ Prowler IASM Microservice

A standalone, production-grade **Internal Attack Surface Management (IASM) & Cloud Security Scanner** microservice built around Prowler and AWS APIs.

This module is completely decoupled from heavy databases (PostgreSQL, Valkey/Redis, Neo4j) and designed for ultra-low memory usage, high reliability, and turnkey frontend integration.

---

## ⚡ Highlights

* **Ultra-Low Memory Footprint:** Consumes only **~60 MB RAM at idle**. When a scan triggers, worker RAM climbs to ~450 MB and is **100% reclaimed by the OS kernel immediately upon completion**.
* **Instant Connection Testing:** `< 500ms` AWS STS verification before starting long scans.
* **Concurrency Guard:** Hard-capped parallel scan execution (`MAX_CONCURRENT_SCANS=2` by default) to protect your host from OOM.
* **Frontend-Ready Outputs:** Automatically produces:
  * `summary.json`: Pre-calculated Security Score (0–100%), severity breakdowns, and top failing services.
  * `findings.json`: Filterable, paginated findings with remediation advice.
  * `assets.json`: Complete cloud inventory for Attack Surface visibility.
  * `report.html`: Interactive visual HTML dashboard.
  * `<scan_id>_bundle.zip`: 1-click comprehensive downloadable archive.
* **Customer CloudFormation Role:** Ready-to-deploy least-privilege IAM Role template in [`templates/aws-prowler-role.yml`](templates/aws-prowler-role.yml).

---

## 🏗️ Architecture

```
┌───────────────────────────────┐
│  Frontend (React / Next.js)   │
└───────────────┬───────────────┘
                │ HTTP REST API (port 8000)
                ▼
┌────────────────────────────────────────────────────────┐
│               Prowler IASM Microservice                │
│  - FastAPI Web Server (Idle: ~60 MB RAM)               │
│  - Async Semaphore (Concurrency Limiter)               │
│  - STS Pre-flight Connection Tester (< 500ms)          │
└───────────────────────┬────────────────────────────────┘
                        │ Spawns ephemeral child process
                        ▼
┌────────────────────────────────────────────────────────┐
│               run_scan.sh (Worker Task)                │
│  - Executes Prowler against AWS (STS / AssumeRole)     │
│  - Generates JSONs, HTML, CSV, and ZIP Bundle          │
│  - Terminates immediately → Releases 100% Scan RAM     │
└───────────────────────┬────────────────────────────────┘
                        │
                        ▼
┌────────────────────────────────────────────────────────┐
│              scan_results/<scan_id>/                   │
│   ├── summary.json          ├── findings.json          │
│   ├── assets.json           ├── report.html            │
│   ├── execution.log         └── <scan_id>_bundle.zip   │
└────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Option 1: Docker Compose (Recommended)

1. Clone or copy the `prowler_IASM` directory to your server:
   ```bash
   cd prowler_IASM
   ```

2. (Optional) Adjust settings in `.env`:
   ```bash
   cp .env.example .env
   ```

3. Build and run:
   ```bash
   docker compose up -d
   ```

* **Swagger API Documentation:** [http://localhost:8000/docs](http://localhost:8000/docs)
* **Interactive Test UI:** [http://localhost:8501](http://localhost:8501)

---

### Option 2: Native Python / Virtual Environment

```bash
cd prowler_IASM

# Create virtualenv & install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Start the REST API
uvicorn src.api.api:app --host 0.0.0.0 --port 8000 --reload
```

---

### Option 3: Direct Python Code Module (In-Process Library)

If you have an existing Python backend (Django, FastAPI, Celery, etc.) and want to invoke scans directly from Python without HTTP requests:

```python
from prowler_IASM.src import ProwlerScanner

scanner = ProwlerScanner()

# 1. Test AWS connection (< 500ms)
conn = scanner.test_connection(
    role_arn="arn:aws:iam::123456789012:role/ProwlerIASMScanRole",
    external_id="client-identifier-123"
)
print("Connection:", conn["status"], conn.get("account_id"))

# 2. Run scan
scan = scanner.run_scan(
    role_arn="arn:aws:iam::123456789012:role/ProwlerIASMScanRole",
    regions=["us-east-1"],
    services=["s3", "iam"]
)
print("Security Score:", scan["summary"]["security_score"])
print("Total Findings:", len(scan["findings"]))
print("Downloadable Bundle:", scan["files"]["zip_bundle"])
```

---

## 📡 REST API Reference

### 1. Test Connection (`< 500ms`)
Verifies AWS credentials or AssumeRole configuration using AWS STS without running any scan.

```bash
curl -X POST "http://localhost:8000/api/v1/scans/test-connection" \
  -H "Content-Type: application/json" \
  -d '{
    "role_arn": "arn:aws:iam::123456789012:role/ProwlerIASMScanRole",
    "external_id": "client-identifier-123",
    "region": "us-east-1"
  }'
```

**Response:**
```json
{
  "status": "success",
  "account": "123456789012",
  "arn": "arn:aws:sts::123456789012:assumed-role/ProwlerIASMScanRole/ProwlerScanSession",
  "mode": "assume_role",
  "duration_ms": 412.5
}
```

---

### 2. Trigger Scan
Enqueues an asynchronous scan. Returns immediately with a `scan_id`.

```bash
curl -X POST "http://localhost:8000/api/v1/scans/run" \
  -H "Content-Type: application/json" \
  -d '{
    "role_arn": "arn:aws:iam::123456789012:role/ProwlerIASMScanRole",
    "external_id": "client-identifier-123",
    "regions": ["us-east-1", "ap-south-1"],
    "services": ["s3", "iam", "ec2"]
  }'
```

**Response:**
```json
{
  "scan_id": "scan_4a8b9c1d2e3f",
  "status": "queued",
  "created_at": "2026-10-16T14:00:00Z",
  "message": "Scan successfully enqueued for execution."
}
```

---

### 3. Check Scan Status
Polls current execution status (`queued` -> `running` -> `completed` / `failed`).

```bash
curl "http://localhost:8000/api/v1/scans/scan_4a8b9c1d2e3f/status"
```

**Response:**
```json
{
  "scan_id": "scan_4a8b9c1d2e3f",
  "status": "completed",
  "created_at": "2026-10-16T14:00:00Z",
  "started_at": "2026-10-16T14:00:01Z",
  "completed_at": "2026-10-16T14:01:25Z",
  "duration_seconds": 84.2,
  "has_summary": true,
  "has_bundle": true
}
```

---

### 4. Get KPI Summary (Score & Severity Counts)
Fetches aggregated metrics for dashboard cards and charts.

```bash
curl "http://localhost:8000/api/v1/scans/scan_4a8b9c1d2e3f/summary"
```

**Response:**
```json
{
  "scan_id": "scan_4a8b9c1d2e3f",
  "account_id": "123456789012",
  "security_score": 78.5,
  "total_findings": 142,
  "passed": 111,
  "failed": 31,
  "muted": 0,
  "critical": 2,
  "high": 9,
  "medium": 14,
  "low": 6,
  "services_breakdown": {
    "iam": { "PASS": 24, "FAIL": 8 },
    "s3": { "PASS": 35, "FAIL": 12 },
    "ec2": { "PASS": 52, "FAIL": 11 }
  }
}
```

---

### 5. Get Filterable Findings Table
Fetches paginated findings for table components.

```bash
curl "http://localhost:8000/api/v1/scans/scan_4a8b9c1d2e3f/findings?severity=critical&status=FAIL&limit=10"
```

---

### 6. 1-Click Download ZIP Bundle
Direct download of the comprehensive scan bundle containing CSV, JSON, and HTML.

```bash
curl -O -J "http://localhost:8000/api/v1/scans/scan_4a8b9c1d2e3f/download-zip"
```

---

### 7. Cancel Active Scan
Terminates an actively running or queued scan process immediately.

```bash
curl -X POST "http://localhost:8000/api/v1/scans/scan_4a8b9c1d2e3f/cancel"
```


---

## 💻 Frontend Integration Guide (React / Next.js)

```typescript
// 1. Instant Connection Test (< 500ms)
async function testConnection(roleArn: string, externalId: string) {
  const res = await fetch('http://localhost:8000/api/v1/scans/test-connection', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role_arn: roleArn, external_id: externalId })
  });
  return await res.json();
}

// 2. Trigger Scan
async function triggerScan(roleArn: string) {
  const res = await fetch('http://localhost:8000/api/v1/scans/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role_arn: roleArn, regions: ['us-east-1'] })
  });
  const data = await res.json();
  return data.scan_id; // Poll status with this ID
}

// 3. Poll Scan Status
async function pollStatus(scanId: string) {
  const res = await fetch(`http://localhost:8000/api/v1/scans/${scanId}/status`);
  return await res.json();
}

// 4. Load Dashboard Summary
async function loadSummary(scanId: string) {
  const res = await fetch(`http://localhost:8000/api/v1/scans/${scanId}/summary`);
  return await res.json();
}
```

---

## 🛡️ Customer Onboarding (CloudFormation)

Share `templates/aws-prowler-role.yml` with your customer or AWS administrator.

They deploy the stack in their AWS account in under 2 minutes:
1. Open **AWS CloudFormation Console** -> **Create Stack**.
2. Upload `templates/aws-prowler-role.yml`.
3. Provide your Platform's AWS Account ID and an External ID.
4. Stack outputs the `ProwlerScanRoleArn` to paste into your frontend.

