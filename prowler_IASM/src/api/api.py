import asyncio
import json
import logging
import os
import re
import shutil
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

# Configuration & Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("prowler_iasm_api")

BASE_DIR = Path(__file__).resolve().parent.parent.parent
RUN_SCAN_SCRIPT = BASE_DIR / "run_scan.sh"
DEFAULT_OUTPUT_DIR = BASE_DIR / "scan_results"
OUTPUT_DIR = Path(os.getenv("SCAN_OUTPUT_DIR", str(DEFAULT_OUTPUT_DIR))).resolve()
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "2"))
SCAN_SEMAPHORE = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
SCAN_TIMEOUT_SECONDS = int(os.getenv("SCAN_TIMEOUT_SECONDS", "3600"))

# Active subprocess registry for abort/cancel capability
ACTIVE_PROCESSES: Dict[str, asyncio.subprocess.Process] = {}

# In-memory registry for live tracking; populated from disk on startup
SCAN_REGISTRY: Dict[str, Dict[str, Any]] = {}

# Security Helpers
def sanitize_scan_id(scan_id: str) -> str:
    """Prevents directory traversal and shell injection via custom scan IDs."""
    if not re.match(r"^[a-zA-Z0-9_\-]+$", scan_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid scan_id format. Must contain only alphanumeric characters, underscores, or hyphens."
        )
    return scan_id

def get_scan_dir(scan_id: str) -> Path:
    """Resolves and enforces that the scan path remains strictly inside OUTPUT_DIR."""
    clean_id = sanitize_scan_id(scan_id)
    target = (OUTPUT_DIR / clean_id).resolve()
    if not target.is_relative_to(OUTPUT_DIR):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Illegal directory traversal detected."
        )
    return target

# FastAPI App Initialization & Compliant CORS
app = FastAPI(
    title="Prowler IASM Microservice",
    description="Production-grade REST API for AWS Attack Surface Management & Security Compliance",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

cors_origins_env = os.getenv("CORS_ORIGINS", "*").strip()
if cors_origins_env == "*":
    allow_origins = ["*"]
    allow_credentials = False  # W3C specification compliance (no wildcard with credentials)
else:
    allow_origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()]
    allow_credentials = True

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Data Models (Pydantic)
class TestConnectionRequest(BaseModel):
    role_arn: Optional[str] = Field(None, description="AWS IAM Role ARN (AssumeRole mode)")
    external_id: Optional[str] = Field(None, description="External ID for AssumeRole")
    access_key: Optional[str] = Field(None, description="AWS Access Key ID")
    secret_key: Optional[str] = Field(None, description="AWS Secret Access Key")
    session_token: Optional[str] = Field(None, description="Optional AWS Session Token")
    region: Optional[str] = Field("us-east-1", description="Primary AWS region to verify against")

class TestConnectionResponse(BaseModel):
    status: str
    account: Optional[str] = None
    arn: Optional[str] = None
    mode: Optional[str] = None
    message: Optional[str] = None
    duration_ms: float

class ScanRequest(BaseModel):
    role_arn: Optional[str] = Field(None, description="IAM Role ARN to assume")
    external_id: Optional[str] = Field(None, description="External ID for AssumeRole")
    access_key: Optional[str] = Field(None, description="AWS Access Key ID")
    secret_key: Optional[str] = Field(None, description="AWS Secret Access Key")
    session_token: Optional[str] = Field(None, description="Optional AWS Session Token")
    regions: Optional[List[str]] = Field(["us-east-1", "ap-south-1"], description="Target AWS regions")
    services: Optional[List[str]] = Field(None, description="Specific AWS services (e.g. s3, iam, ec2)")
    checks: Optional[List[str]] = Field(None, description="Specific check IDs to execute")
    scan_id: Optional[str] = Field(None, description="Optional custom scan ID (UUID generated if omitted)")

class ScanLaunchResponse(BaseModel):
    scan_id: str
    status: str
    created_at: str
    message: str

class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None
    has_summary: bool = False
    has_bundle: bool = False

# State Persistence & Crash Recovery
def save_metadata(scan_id: str, data: Dict[str, Any]):
    scan_dir = get_scan_dir(scan_id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    meta_path = scan_dir / "metadata.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def load_metadata_from_disk():
    """Restores scan registry from disk and reconciles interrupted scans."""
    if not OUTPUT_DIR.exists():
        return
    for item in OUTPUT_DIR.iterdir():
        if item.is_dir():
            meta_path = item / "metadata.json"
            if meta_path.exists():
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        data = json.load(f)

                        # Reconcile orphaned/interrupted scans if the server rebooted mid-scan
                        if data.get("status") in ("running", "queued"):
                            data["status"] = "failed"
                            data["error_message"] = "Scan interrupted due to server reboot or container restart."
                            data["completed_at"] = datetime.now(timezone.utc).isoformat()
                            with open(meta_path, "w", encoding="utf-8") as fw:
                                json.dump(data, fw, indent=2)

                        SCAN_REGISTRY[item.name] = data
                except Exception as e:
                    logger.warning(f"Failed to load metadata for {item.name}: {e}")

@app.on_event("startup")
def startup_event():
    logger.info("Initializing Prowler IASM Microservice...")
    load_metadata_from_disk()
    logger.info(f"Loaded {len(SCAN_REGISTRY)} scans from disk. Max concurrent scans: {MAX_CONCURRENT_SCANS}")

# Background Scan Execution Task
async def execute_prowler_scan(scan_id: str, req: ScanRequest):
    async with SCAN_SEMAPHORE:
        scan_dir = get_scan_dir(scan_id)
        scan_dir.mkdir(parents=True, exist_ok=True)
        log_file = scan_dir / "execution.log"

        meta = SCAN_REGISTRY.get(scan_id, {})
        meta["status"] = "running"
        meta["started_at"] = datetime.now(timezone.utc).isoformat()
        save_metadata(scan_id, meta)
        logger.info(f"Scan [{scan_id}] started execution.")

        start_time = time.time()

        # Build command arguments for run_scan.sh
        cmd = [
            str(RUN_SCAN_SCRIPT),
            "--scan-id", scan_id,
            "--output-dir", str(OUTPUT_DIR),
            "--format", "all"
        ]

        if req.role_arn:
            cmd.extend(["--role-arn", req.role_arn])
        if req.external_id:
            cmd.extend(["--external-id", req.external_id])
        if req.access_key:
            cmd.extend(["--access-key", req.access_key])
        if req.secret_key:
            cmd.extend(["--secret-key", req.secret_key])
        if req.session_token:
            cmd.extend(["--session-token", req.session_token])
        if req.regions:
            cmd.extend(["--regions", ",".join(req.regions)])
        if req.services:
            cmd.extend(["--services", ",".join(req.services)])
        if req.checks:
            cmd.extend(["--checks", ",".join(req.checks)])

        try:
            with open(log_file, "w", encoding="utf-8") as lf:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=lf,
                    stderr=asyncio.subprocess.STDOUT
                )
                ACTIVE_PROCESSES[scan_id] = process

                # Enforce timeout guard to prevent hangs
                try:
                    return_code = await asyncio.wait_for(process.wait(), timeout=SCAN_TIMEOUT_SECONDS)
                except asyncio.TimeoutError:
                    logger.error(f"Scan [{scan_id}] exceeded timeout limit of {SCAN_TIMEOUT_SECONDS}s. Terminating.")
                    process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), timeout=5.0)
                    except asyncio.TimeoutError:
                        process.kill()
                    return_code = -9
                    meta["error_message"] = f"Scan timed out after {SCAN_TIMEOUT_SECONDS} seconds."

            ACTIVE_PROCESSES.pop(scan_id, None)

            duration = round(time.time() - start_time, 2)
            meta["duration_seconds"] = duration
            meta["completed_at"] = datetime.now(timezone.utc).isoformat()

            summary_file = scan_dir / "summary.json"
            zip_file = scan_dir / f"{scan_id}_bundle.zip"

            if return_code == 0 and summary_file.exists():
                meta["status"] = "completed"
                meta["has_summary"] = True
                meta["has_bundle"] = zip_file.exists()
                logger.info(f"Scan [{scan_id}] completed successfully in {duration}s.")
            elif meta.get("status") == "cancelled":
                logger.info(f"Scan [{scan_id}] marked as cancelled.")
            else:
                meta["status"] = "failed"
                if not meta.get("error_message"):
                    error_snippet = "Scan execution failed. Check execution.log for details."
                    if log_file.exists():
                        try:
                            with open(log_file, "r", encoding="utf-8") as lf:
                                lines = lf.readlines()
                                if lines:
                                    error_snippet = "".join(lines[-15:])
                        except Exception:
                            pass
                    meta["error_message"] = error_snippet
                logger.error(f"Scan [{scan_id}] failed with code {return_code}. Duration: {duration}s")

        except Exception as exc:
            ACTIVE_PROCESSES.pop(scan_id, None)
            duration = round(time.time() - start_time, 2)
            meta["status"] = "failed"
            meta["duration_seconds"] = duration
            meta["completed_at"] = datetime.now(timezone.utc).isoformat()
            meta["error_message"] = str(exc)
            logger.exception(f"Unhandled error during scan [{scan_id}]: {exc}")

        finally:
            save_metadata(scan_id, meta)

#### API Endpoints ####
# Healthcheck Endpoint
@app.get("/health", tags=["System"])
@app.get("/api/v1/health", tags=["System"])
def health():
    """Healthcheck endpoint for Kubernetes, ECS, or Docker Compose."""
    active_count = len(ACTIVE_PROCESSES)
    return {
        "status": "healthy",
        "service": "prowler-iasm",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "active_scans_running": active_count,
        "max_concurrent_scans": MAX_CONCURRENT_SCANS,
        "available_slots": max(0, MAX_CONCURRENT_SCANS - active_count)
    }

# Connection Check Endpoint
@app.post("/api/v1/scans/test-connection", response_model=TestConnectionResponse, tags=["Scans"])
async def test_connection(req: TestConnectionRequest):
    """
    Validates AWS credentials or Role Assume configuration via AWS STS.
    Executes in < 500ms without triggering any security scans.
    """
    start_time = time.time()
    cmd = [str(RUN_SCAN_SCRIPT), "--test-connection-only"]

    if req.role_arn:
        cmd.extend(["--role-arn", req.role_arn])
    if req.external_id:
        cmd.extend(["--external-id", req.external_id])
    if req.access_key:
        cmd.extend(["--access-key", req.access_key])
    if req.secret_key:
        cmd.extend(["--secret-key", req.secret_key])
    if req.session_token:
        cmd.extend(["--session-token", req.session_token])
    if req.region:
        cmd.extend(["--regions", req.region])

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=15.0)
    except asyncio.TimeoutError:
        process.kill()
        return TestConnectionResponse(
            status="error",
            message="Connection verification timed out after 15 seconds.",
            duration_ms=round((time.time() - start_time) * 1000, 2)
        )

    duration_ms = round((time.time() - start_time) * 1000, 2)
    output_str = stdout.decode("utf-8").strip()

    try:
        data = json.loads(output_str) if output_str else {}
    except Exception:
        data = {
            "status": "error",
            "message": stderr.decode("utf-8").strip() or output_str or "STS validation failed"
        }

    return TestConnectionResponse(
        status=data.get("status", "error"),
        account=data.get("account_id") or data.get("account"),
        arn=data.get("arn"),
        mode=data.get("mode"),
        message=data.get("message") or data.get("error"),
        duration_ms=duration_ms
    )

# Run Scan Endpoint 
@app.post("/api/v1/scans/run", response_model=ScanLaunchResponse, tags=["Scans"])
async def trigger_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """
    Triggers an asynchronous Prowler Attack Surface Management scan.
    Returns immediately with a unique scan_id.
    """
    scan_id = req.scan_id or f"scan_{uuid.uuid4().hex[:12]}"
    sanitize_scan_id(scan_id)

    if scan_id in SCAN_REGISTRY and SCAN_REGISTRY[scan_id].get("status") in ("queued", "running"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan '{scan_id}' is already actively executing."
        )

    now_iso = datetime.now(timezone.utc).isoformat()
    meta = {
        "scan_id": scan_id,
        "status": "queued",
        "created_at": now_iso,
        "started_at": None,
        "completed_at": None,
        "duration_seconds": None,
        "error_message": None,
        "has_summary": False,
        "has_bundle": False,
        "regions": req.regions,
        "services": req.services,
    }

    SCAN_REGISTRY[scan_id] = meta
    save_metadata(scan_id, meta)

    # Dispatch to background task worker
    background_tasks.add_task(execute_prowler_scan, scan_id, req)

    return ScanLaunchResponse(
        scan_id=scan_id,
        status="queued",
        created_at=now_iso,
        message="Scan successfully enqueued for execution."
    )

# Scan Cancellation Endpoint
@app.post("/api/v1/scans/{scan_id}/cancel", tags=["Scans"])
async def cancel_scan(scan_id: str):
    """Cancels an actively running or queued scan."""
    sanitize_scan_id(scan_id)
    proc = ACTIVE_PROCESSES.get(scan_id)
    if proc:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=3.0)
        except asyncio.TimeoutError:
            proc.kill()
        ACTIVE_PROCESSES.pop(scan_id, None)

    if scan_id in SCAN_REGISTRY:
        meta = SCAN_REGISTRY[scan_id]
        meta["status"] = "cancelled"
        meta["error_message"] = "Scan was cancelled by user request."
        meta["completed_at"] = datetime.now(timezone.utc).isoformat()
        save_metadata(scan_id, meta)
        return {"status": "success", "message": f"Scan '{scan_id}' cancelled successfully."}

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Active scan '{scan_id}' not found.")

# Scan Result Retrieval Endpoint (Status)
@app.get("/api/v1/scans/{scan_id}/status", response_model=ScanStatusResponse, tags=["Scans"])
def get_scan_status(scan_id: str):
    """Returns the live execution status and lifecycle timestamps of a scan."""
    sanitize_scan_id(scan_id)
    meta = SCAN_REGISTRY.get(scan_id)
    if not meta:
        meta_path = get_scan_dir(scan_id) / "metadata.json"
        if meta_path.exists():
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
                SCAN_REGISTRY[scan_id] = meta
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found.")

    return ScanStatusResponse(
        scan_id=scan_id,
        status=meta.get("status", "unknown"),
        created_at=meta.get("created_at", ""),
        started_at=meta.get("started_at"),
        completed_at=meta.get("completed_at"),
        duration_seconds=meta.get("duration_seconds"),
        error_message=meta.get("error_message"),
        has_summary=meta.get("has_summary", False),
        has_bundle=meta.get("has_bundle", False)
    )

# Scan Result Retrieval Endpoint (Artifacts)
@app.get("/api/v1/scans/{scan_id}/summary", tags=["Scans"])
def get_scan_summary(scan_id: str):
    """
    Returns high-level KPI cards data: Security Score, severity distribution,
    and service breakdown for dashboard charts.
    """
    summary_path = get_scan_dir(scan_id) / "summary.json"
    if not summary_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Summary for scan '{scan_id}' is not yet available or scan failed."
        )

    try:
        with open(summary_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Summary report is currently being written. Please retry."
        )

# Scan Result Retrieval Endpoint (Findings & Assets)
@app.get("/api/v1/scans/{scan_id}/findings", tags=["Findings & Assets"])
def get_scan_findings(
    scan_id: str,
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by PASS, FAIL, MUTED"),
    severity_filter: Optional[str] = Query(None, alias="severity", description="Filter by critical, high, medium, low"),
    service_filter: Optional[str] = Query(None, alias="service", description="Filter by AWS service (e.g. s3, iam)"),
    search: Optional[str] = Query(None, description="Free text search in check title or resource"),
    limit: int = Query(50, ge=1, le=500, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset")
):
    """Returns paginated, filterable security findings directly for UI tables."""
    findings_path = get_scan_dir(scan_id) / "findings.json"
    if not findings_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Findings for scan '{scan_id}' not available."
        )

    try:
        with open(findings_path, "r", encoding="utf-8") as f:
            findings: List[Dict[str, Any]] = json.load(f)
    except json.JSONDecodeError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Findings report is being written. Retry.")

    # In-memory filtering supporting both 'service' and 'service_name'
    filtered = findings
    if status_filter:
        status_upper = status_filter.upper()
        filtered = [f for f in filtered if f.get("status", "").upper() == status_upper]

    if severity_filter:
        sev_lower = severity_filter.lower()
        filtered = [f for f in filtered if f.get("severity", "").lower() == sev_lower]

    if service_filter:
        svc_lower = service_filter.lower()
        filtered = [
            f for f in filtered
            if (f.get("service_name") or f.get("service") or "").lower() == svc_lower
        ]

    if search:
        search_lower = search.lower()
        filtered = [
            f for f in filtered
            if search_lower in (f.get("check_title") or "").lower()
            or search_lower in (f.get("resource_id") or "").lower()
            or search_lower in (f.get("resource_name") or "").lower()
            or search_lower in (f.get("description") or "").lower()
        ]

    total_count = len(filtered)
    paginated = filtered[offset : offset + limit]

    return {
        "scan_id": scan_id,
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "findings": paginated
    }

# Scan Result Retrieval Endpoint (Assets)
@app.get("/api/v1/scans/{scan_id}/assets", tags=["Findings & Assets"])
def get_scan_assets(
    scan_id: str,
    service_filter: Optional[str] = Query(None, alias="service"),
    region_filter: Optional[str] = Query(None, alias="region"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0)
):
    """Returns discovered cloud asset inventory for IASM visibility."""
    assets_path = get_scan_dir(scan_id) / "assets.json"
    if not assets_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assets inventory for scan '{scan_id}' not available."
        )

    try:
        with open(assets_path, "r", encoding="utf-8") as f:
            assets: List[Dict[str, Any]] = json.load(f)
    except json.JSONDecodeError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Asset inventory is being written. Retry.")

    filtered = assets
    if service_filter:
        svc_lower = service_filter.lower()
        filtered = [
            a for a in filtered
            if (a.get("service_name") or a.get("service") or "").lower() == svc_lower
        ]

    if region_filter:
        reg_lower = region_filter.lower()
        filtered = [a for a in filtered if (a.get("region") or "").lower() == reg_lower]

    total_count = len(filtered)
    paginated = filtered[offset : offset + limit]

    return {
        "scan_id": scan_id,
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "assets": paginated
    }

# Scan Result Retrieval Endpoint (Download ZIP Bundle)
@app.get("/api/v1/scans/{scan_id}/download-zip", tags=["Export & Reports"])
def download_scan_bundle(scan_id: str):
    """1-Click download of the complete scan bundle (.zip with JSON, CSV, and HTML reports)."""
    zip_path = get_scan_dir(scan_id) / f"{scan_id}_bundle.zip"
    if not zip_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report bundle for scan '{scan_id}' not found."
        )

    return FileResponse(
        path=str(zip_path),
        filename=f"prowler_scan_{scan_id}.zip",
        media_type="application/zip"
    )

# Scan Result Retrieval Endpoint (View HTML Report)
@app.get("/api/v1/scans/{scan_id}/report-html", tags=["Export & Reports"])
def view_html_report(scan_id: str):
    """Serves the interactive Prowler HTML visual report."""
    html_path = get_scan_dir(scan_id) / "report.html"
    if not html_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"HTML report for scan '{scan_id}' not found."
        )

    return FileResponse(path=str(html_path), media_type="text/html")

# Scan Result Retrieval Endpoint (View CSV Report)
@app.get("/api/v1/scans/{scan_id}/report-csv", tags=["Export & Reports"])
def view_csv_report(scan_id: str):
    """Serves the CSV report for a specific scan."""
    csv_path = get_scan_dir(scan_id) / "report.csv"
    if not csv_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"CSV report for scan '{scan_id}' not found."
        )

    return FileResponse(path=str(csv_path), media_type="text/csv")

# Scan Result Retrieval Endpoint (List Scans)
@app.get("/api/v1/scans", tags=["Scans"])
def list_scans():
    """Lists all past and currently executing scans."""
    load_metadata_from_disk()
    sorted_scans = sorted(
        SCAN_REGISTRY.values(),
        key=lambda x: x.get("created_at", ""),
        reverse=True
    )
    return {"total": len(sorted_scans), "scans": sorted_scans}

# Scan Result Retrieval Endpoint (Delete Scan)
@app.delete("/api/v1/scans/{scan_id}", tags=["Scans"])
def delete_scan(scan_id: str):
    """Deletes a scan and frees all associated disk space."""
    scan_dir = get_scan_dir(scan_id)
    if scan_dir.exists():
        shutil.rmtree(scan_dir)

    if scan_id in SCAN_REGISTRY:
        del SCAN_REGISTRY[scan_id]

    return {"status": "success", "message": f"Scan '{scan_id}' deleted successfully."}
