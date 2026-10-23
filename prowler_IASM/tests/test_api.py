"""
Comprehensive API Unit and Integration Tests for Prowler IASM Microservice.
"""

import json
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

import pytest
from fastapi.testclient import TestClient

import src.api.api as api_module
from src.api.api import (
    app,
    sanitize_scan_id,
    prune_expired_scans,
    SCAN_REGISTRY,
    FINDINGS_CACHE,
    ASSETS_CACHE,
    SCAN_LOGS_BUFFER,
)


class TestHealthEndpoint:
    def test_health_check_returns_healthy(self, client: TestClient):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "prowler-iasm"
        assert "timestamp" in data
        assert "active_scans_running" in data
        assert "max_concurrent_scans" in data
        assert "available_slots" in data
        assert "auth_enabled" in data


class TestAuthentication:
    def test_auth_open_access_when_api_key_unset(self, client: TestClient, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(api_module, "API_KEY", "")
        response = client.get("/api/v1/scans")
        assert response.status_code == 200

    def test_auth_enforced_blocks_unauthorized(self, client: TestClient, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(api_module, "API_KEY", "prod-secret-key-xyz")
        response = client.get("/api/v1/scans")
        assert response.status_code == 401
        assert "Invalid or missing" in response.json()["detail"]

    def test_auth_enforced_rejects_invalid_key(self, client: TestClient, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(api_module, "API_KEY", "prod-secret-key-xyz")
        response = client.get("/api/v1/scans", headers={"X-API-Key": "wrong-key"})
        assert response.status_code == 401

    def test_auth_enforced_accepts_valid_header(self, client: TestClient, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(api_module, "API_KEY", "prod-secret-key-xyz")
        response = client.get("/api/v1/scans", headers={"X-API-Key": "prod-secret-key-xyz"})
        assert response.status_code == 200

    def test_auth_enforced_accepts_valid_query_param(self, client: TestClient, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(api_module, "API_KEY", "prod-secret-key-xyz")
        response = client.get("/api/v1/scans?api_key=prod-secret-key-xyz")
        assert response.status_code == 200


class TestSanitization:
    @pytest.mark.parametrize("valid_id", [
        "scan_12345",
        "audit-prod-2026",
        "client_corp.assessment",
        "SCAN-001_A"
    ])
    def test_valid_scan_ids_accepted(self, valid_id: str):
        assert sanitize_scan_id(valid_id) == valid_id

    @pytest.mark.parametrize("malicious_id", [
        "../etc/passwd",
        "..\\windows\\system32",
        "scan/subfolder",
        "scan\\backslash",
        "scan;rm -rf /",
        "scan && echo hacked",
        "scan|cat /etc/shadow",
        "scan$HOME",
        "scan`whoami`",
        "   "
    ])
    def test_path_traversal_and_injection_rejected(self, malicious_id: str):
        with pytest.raises(Exception) as exc_info:
            sanitize_scan_id(malicious_id)
        assert "Invalid scan_id" in str(exc_info.value.detail)


class TestScanLifecycleAndArtifacts:
    def test_list_scans(self, client: TestClient, mock_scan_artifacts: dict):
        response = client.get("/api/v1/scans")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1
        scan_ids = [s["scan_id"] for s in data["scans"]]
        assert mock_scan_artifacts["scan_id"] in scan_ids

    def test_get_scan_status(self, client: TestClient, mock_scan_artifacts: dict):
        scan_id = mock_scan_artifacts["scan_id"]
        response = client.get(f"/api/v1/scans/{scan_id}/status")
        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == scan_id
        assert data["status"] == "completed"
        assert data["has_summary"] is True
        assert data["has_bundle"] is True

    def test_get_scan_status_not_found(self, client: TestClient):
        response = client.get("/api/v1/scans/non_existent_scan_123/status")
        assert response.status_code == 404

    def test_get_scan_summary(self, client: TestClient, mock_scan_artifacts: dict):
        scan_id = mock_scan_artifacts["scan_id"]
        response = client.get(f"/api/v1/scans/{scan_id}/summary")
        assert response.status_code == 200
        data = response.json()
        assert data["security_score"] == 85.5
        assert data["total_findings"] == 3
        assert data["critical"] == 1
        assert "services_breakdown" in data
        assert "compliance_overview" in data
        assert "CIS-AWS-3.0" in data["compliance_overview"]
        assert data["compliance_overview"]["CIS-AWS-3.0"]["score"] == 66.7
        assert data["compliance_overview"]["CIS-AWS-3.0"]["requirements_count"] == 3

    def test_get_scan_findings_pagination_and_filters(self, client: TestClient, mock_scan_artifacts: dict):
        scan_id = mock_scan_artifacts["scan_id"]
        
        # Test unfiltered (pagination)
        res = client.get(f"/api/v1/scans/{scan_id}/findings?limit=2&offset=0")
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 3
        assert len(data["findings"]) == 2

        # Test enriched metadata fields exist
        first_f = data["findings"][0]
        assert "risk" in first_f
        assert "categories" in first_f
        assert "compliance" in first_f
        assert "remediation_cli" in first_f
        assert "uid" in first_f
        assert isinstance(first_f["categories"], list)
        assert isinstance(first_f["compliance"], dict)

        # Test filter by status=FAIL
        res_fail = client.get(f"/api/v1/scans/{scan_id}/findings?status=FAIL")
        assert res_fail.status_code == 200
        data_fail = res_fail.json()
        assert data_fail["total"] == 1
        assert data_fail["findings"][0]["status"] == "FAIL"
        assert data_fail["findings"][0]["service"] == "s3"

        # Test filter by severity=critical
        res_crit = client.get(f"/api/v1/scans/{scan_id}/findings?severity=critical")
        assert res_crit.status_code == 200
        assert res_crit.json()["total"] == 2

        # Test filter by service=iam
        res_iam = client.get(f"/api/v1/scans/{scan_id}/findings?service=iam")
        assert res_iam.status_code == 200
        assert res_iam.json()["total"] == 1
        assert res_iam.json()["findings"][0]["check_id"] == "iam_root_mfa_enabled"

        # Test free text search
        res_search = client.get(f"/api/v1/scans/{scan_id}/findings?search=Hardware MFA")
        assert res_search.status_code == 200
        assert res_search.json()["total"] == 1

    def test_get_scan_assets(self, client: TestClient, mock_scan_artifacts: dict):
        scan_id = mock_scan_artifacts["scan_id"]
        response = client.get(f"/api/v1/scans/{scan_id}/assets")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2

        # Verify child checks are present on asset
        vulnerable_asset = next(a for a in data["assets"] if a["resource_name"] == "my-public-bucket")
        assert len(vulnerable_asset["failed_checks"]) == 1
        assert vulnerable_asset["failed_checks"][0]["check_id"] == "s3_bucket_public_access"
        assert len(vulnerable_asset["passed_checks"]) == 1

        # Filter by service=s3
        res_s3 = client.get(f"/api/v1/scans/{scan_id}/assets?service=s3")
        assert res_s3.status_code == 200
        assert res_s3.json()["total"] == 1
        assert res_s3.json()["assets"][0]["resource_name"] == "my-public-bucket"

    def test_download_endpoints(self, client: TestClient, mock_scan_artifacts: dict):
        scan_id = mock_scan_artifacts["scan_id"]

        # Download ZIP
        zip_res = client.get(f"/api/v1/scans/{scan_id}/download-zip")
        assert zip_res.status_code == 200
        assert zip_res.headers["content-type"] == "application/zip"

        # View HTML
        html_res = client.get(f"/api/v1/scans/{scan_id}/report-html")
        assert html_res.status_code == 200
        assert "text/html" in html_res.headers["content-type"]
        assert "Prowler Report" in html_res.text

        # View CSV
        csv_res = client.get(f"/api/v1/scans/{scan_id}/report-csv")
        assert csv_res.status_code == 200
        assert "text/csv" in csv_res.headers["content-type"]
        assert "id,status,severity" in csv_res.text

        # Executive PDF Report (generates on-the-fly and caches)
        pdf_res = client.get(f"/api/v1/scans/{scan_id}/report-pdf")
        assert pdf_res.status_code == 200
        assert pdf_res.headers["content-type"] == "application/pdf"
        assert pdf_res.content.startswith(b"%PDF")

        # Framework-specific CSV export
        comp_csv_res = client.get(f"/api/v1/scans/{scan_id}/compliance/CIS-AWS-3.0/csv")
        assert comp_csv_res.status_code == 200
        assert "text/csv" in comp_csv_res.headers["content-type"]
        assert "Framework,Requirement,Status" in comp_csv_res.text
        assert "CIS-AWS-3.0" in comp_csv_res.text

        # Framework-specific PDF export
        comp_pdf_res = client.get(f"/api/v1/scans/{scan_id}/compliance/CIS-AWS-3.0/pdf")
        assert comp_pdf_res.status_code == 200
        assert comp_pdf_res.headers["content-type"] == "application/pdf"
        assert comp_pdf_res.content.startswith(b"%PDF")

    def test_cancel_scan(self, client: TestClient, mock_scan_artifacts: dict):
        scan_id = mock_scan_artifacts["scan_id"]
        res = client.post(f"/api/v1/scans/{scan_id}/cancel")
        assert res.status_code == 200
        assert res.json()["status"] == "success"
        assert SCAN_REGISTRY[scan_id]["status"] == "cancelled"

    def test_trigger_scan_returns_202_accepted(self, client: TestClient):
        payload = {
            "regions": ["us-east-1"],
            "role_arn": "arn:aws:iam::123456789012:role/SecurityAuditRole",
            "external_id": "test-ext-id",
            "account_id": "123456789012",
            "provider_alias": "Production AWS Core",
        }
        with patch("src.api.api.execute_prowler_scan") as mock_exec:
            res = client.post("/api/v1/scans/run", json=payload)
            assert res.status_code == 202
            data = res.json()
            assert "scan_id" in data
            assert data["status"] == "queued"
            assert data["scan_id"] in SCAN_REGISTRY
            assert SCAN_REGISTRY[data["scan_id"]]["account_id"] == "123456789012"
            assert SCAN_REGISTRY[data["scan_id"]]["provider_alias"] == "Production AWS Core"

    def test_test_connection_success(self, client: TestClient):
        payload = {
            "account_id": "123456789012",
            "role_arn": "arn:aws:iam::123456789012:role/AuditRole",
            "region": "us-east-1"
        }
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(
            json.dumps({"status": "connected", "account_id": "123456789012", "arn": "arn:aws:sts::123456789012:assumed-role/AuditRole/session"}).encode("utf-8"),
            b""
        ))
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            res = client.post("/api/v1/scans/test-connection", json=payload)
            assert res.status_code == 200
            data = res.json()
            assert data["status"] == "connected"
            assert data["account"] == "123456789012"
            assert "AuditRole" in data["arn"]

    def test_test_connection_failure_combines_error(self, client: TestClient):
        payload = {
            "account_id": "123456789012",
            "access_key": "AKIAINVALIDKEY123",
            "secret_key": "INVALIDSECRETKEY123456789",
            "region": "us-east-1"
        }
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(
            json.dumps({
                "status": "not_configured",
                "message": "AWS account not configured or credentials invalid",
                "error": "An error occurred (InvalidClientTokenId) when calling the GetCallerIdentity operation: The security token included in the request is invalid."
            }).encode("utf-8"),
            b""
        ))
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            res = client.post("/api/v1/scans/test-connection", json=payload)
            assert res.status_code == 200
            data = res.json()
            assert data["status"] == "not_configured"
            # Verify error message contains both the generic msg AND the specific STS error
            assert "AWS account not configured or credentials invalid" in data["message"]
            assert "InvalidClientTokenId" in data["message"]

    def test_test_connection_timeout(self, client: TestClient):
        payload = {
            "account_id": "123456789012",
            "role_arn": "arn:aws:iam::123456789012:role/AuditRole",
            "region": "us-east-1"
        }
        mock_proc = MagicMock()
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch("asyncio.wait_for", side_effect=__import__("asyncio").TimeoutError()):
                with patch("src.api.api.kill_process_tree"):
                    res = client.post("/api/v1/scans/test-connection", json=payload)
                    assert res.status_code == 200
                    data = res.json()
                    assert data["status"] == "error"
                    assert "timed out after 15 seconds" in data["message"]

    def test_findings_and_assets_caching(self, client: TestClient, mock_scan_artifacts: dict):
        scan_id = mock_scan_artifacts["scan_id"]
        FINDINGS_CACHE.clear()
        ASSETS_CACHE.clear()

        # First read populates cache
        res_f1 = client.get(f"/api/v1/scans/{scan_id}/findings")
        assert res_f1.status_code == 200
        assert scan_id in FINDINGS_CACHE

        res_a1 = client.get(f"/api/v1/scans/{scan_id}/assets")
        assert res_a1.status_code == 200
        assert scan_id in ASSETS_CACHE

        # Second read serves from cache
        res_f2 = client.get(f"/api/v1/scans/{scan_id}/findings")
        assert res_f2.status_code == 200
        assert res_f2.json()["total"] == res_f1.json()["total"]

    def test_delete_scan(self, client: TestClient, mock_scan_artifacts: dict):
        scan_id = mock_scan_artifacts["scan_id"]
        scan_dir = mock_scan_artifacts["dir"]
        assert scan_dir.exists()

        # Pre-seed cache to ensure delete purges memory cache
        FINDINGS_CACHE[scan_id] = (time.time(), [{"dummy": 1}])
        ASSETS_CACHE[scan_id] = (time.time(), [{"dummy": 2}])
        from collections import deque
        SCAN_LOGS_BUFFER[scan_id] = deque(["line 1\n", "line 2\n"])

        res = client.delete(f"/api/v1/scans/{scan_id}")
        assert res.status_code == 200
        assert not scan_dir.exists()
        assert scan_id not in SCAN_REGISTRY
        assert scan_id not in FINDINGS_CACHE
        assert scan_id not in ASSETS_CACHE
        assert scan_id not in SCAN_LOGS_BUFFER

    def test_get_scan_logs_ring_buffer_and_disk(self, client: TestClient, mock_scan_artifacts: dict):
        scan_id = mock_scan_artifacts["scan_id"]
        scan_dir = mock_scan_artifacts["dir"]
        log_file = scan_dir / "execution.log"

        # 1. Test disk read
        with open(log_file, "w", encoding="utf-8") as f:
            f.write("[INFO] Scanning service: s3\n[INFO] Executing check s3_bucket_default_encryption\n")

        SCAN_LOGS_BUFFER.pop(scan_id, None)
        res = client.get(f"/api/v1/scans/{scan_id}/logs?tail=10")
        assert res.status_code == 200
        data = res.json()
        assert data["scan_id"] == scan_id
        assert data["current_service"] == "S3"
        assert data["current_check"] == "s3_bucket_default_encryption"
        assert len(data["lines"]) == 2

        # 2. Test in-memory ring buffer (RAM priority with Prowler v5 format)
        from collections import deque
        SCAN_LOGS_BUFFER[scan_id] = deque([
            "Check ID: s3_bucket_default_encryption - s3 [HIGH]\n",
            "\tFAIL us-east-1: S3 Bucket test has no encryption.\n"
        ])
        res_mem = client.get(f"/api/v1/scans/{scan_id}/logs?tail=10")
        assert res_mem.status_code == 200
        data_mem = res_mem.json()
        assert data_mem["current_service"] == "S3"
        assert data_mem["current_check"] == "s3_bucket_default_encryption"


class TestRetentionPruner:
    def test_prune_expired_scans(self, temp_output_dir: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(api_module, "SCAN_RETENTION_DAYS", 15)

        # Create old scan (30 days ago)
        old_id = "scan_old_expired"
        old_dir = temp_output_dir / old_id
        old_dir.mkdir(parents=True, exist_ok=True)
        old_date = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        with open(old_dir / "metadata.json", "w", encoding="utf-8") as f:
            json.dump({"scan_id": old_id, "created_at": old_date, "status": "completed"}, f)
        SCAN_REGISTRY[old_id] = {"scan_id": old_id, "created_at": old_date, "status": "completed"}

        # Create recent scan (2 days ago)
        recent_id = "scan_recent_active"
        recent_dir = temp_output_dir / recent_id
        recent_dir.mkdir(parents=True, exist_ok=True)
        recent_date = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        with open(recent_dir / "metadata.json", "w", encoding="utf-8") as f:
            json.dump({"scan_id": recent_id, "created_at": recent_date, "status": "completed"}, f)
        SCAN_REGISTRY[recent_id] = {"scan_id": recent_id, "created_at": recent_date, "status": "completed"}

        # Run pruner
        prune_expired_scans()

        assert not old_dir.exists()
        assert old_id not in SCAN_REGISTRY
        assert recent_dir.exists()
        assert recent_id in SCAN_REGISTRY


class TestReportGenerators:
    def test_executive_pdf_generator_memory_and_disk(self, tmp_path: Path):
        from src.reports.pdf_generator import generate_executive_pdf_report
        summary = {
            "scan_id": "test_pdf_01",
            "account_id": "112233445566",
            "security_score": 92.0,
            "duration_seconds": 15.0,
            "total_findings": 2,
            "passed": 1,
            "critical": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
            "compliance_overview": {
                "CIS-AWS-3.0": {"passed": 1, "failed": 1, "total": 2, "score": 50.0}
            }
        }
        findings = [
            {
                "check_id": "s3_bucket_public",
                "check_title": "S3 Public Bucket",
                "service": "s3",
                "severity": "critical",
                "status": "FAIL",
                "resource_id": "arn:aws:s3:::test-bucket",
                "risk": "Public access risk",
                "remediation_cli": "aws s3api put-public-access-block"
            }
        ]
        assets = [{"resource_name": "test-bucket"}]

        # 1. In-memory buffer test
        buf = generate_executive_pdf_report(summary, findings, assets)
        assert buf.getvalue().startswith(b"%PDF")
        assert len(buf.getvalue()) > 1000

        # 2. Disk write test
        out_file = tmp_path / "test_report.pdf"
        res_path = generate_executive_pdf_report(summary, findings, assets, output_path=out_file)
        assert res_path.exists()
        assert out_file.read_bytes().startswith(b"%PDF")

    def test_compliance_pdf_and_csv_generators(self, tmp_path: Path):
        from src.reports.pdf_generator import generate_compliance_pdf_report
        from src.reports.csv_generator import generate_compliance_csv

        summary = {"scan_id": "comp_test", "compliance_overview": {}}
        findings = [
            {
                "check_id": "iam_mfa",
                "check_title": "Root MFA",
                "service": "iam",
                "severity": "critical",
                "status": "PASS",
                "resource_id": "root",
                "compliance": {"CIS-AWS-3.0": ["1.1", "1.2"]}
            }
        ]

        # In-memory compliance PDF
        pdf_buf = generate_compliance_pdf_report("CIS-AWS-3.0", summary, findings)
        assert pdf_buf.getvalue().startswith(b"%PDF")

        # In-memory compliance CSV
        csv_buf = generate_compliance_csv(findings, "CIS-AWS-3.0")
        csv_text = csv_buf.getvalue()
        assert "Framework,Requirement,Status" in csv_text
        assert "CIS-AWS-3.0" in csv_text
        assert "1.1, 1.2" in csv_text

        # Disk compliance CSV
        csv_path = tmp_path / "cis_export.csv"
        generate_compliance_csv(findings, "CIS-AWS-3.0", output_path=csv_path)
        assert csv_path.exists()
        assert "CIS-AWS-3.0" in csv_path.read_text(encoding="utf-8")

        # Substring matching test (e.g. "cis" matches "CIS-AWS-3.0")
        csv_sub = generate_compliance_csv(findings, "cis")
        assert "CIS-AWS-3.0" in csv_sub.getvalue()

    def test_report_generators_empty_data_resilience(self, tmp_path: Path):
        """Ensures report generators don't crash when scan has 0 findings or empty summaries."""
        from src.reports.pdf_generator import generate_compliance_pdf_report, generate_executive_pdf_report
        from src.reports.csv_generator import generate_compliance_csv

        empty_summary = {"security_score": 100.0, "passed": 0, "failed": 0, "critical": 0, "high": 0}
        
        # Empty Executive PDF
        exec_buf = generate_executive_pdf_report(empty_summary, [], [])
        assert exec_buf.getvalue().startswith(b"%PDF")

        # Empty Compliance PDF
        comp_buf = generate_compliance_pdf_report("CIS-AWS-3.0", empty_summary, [])
        assert comp_buf.getvalue().startswith(b"%PDF")

        # Empty Compliance CSV
        csv_buf = generate_compliance_csv([], "CIS-AWS-3.0")
        assert "Framework,Requirement,Status" in csv_buf.getvalue()

    def test_finding_and_asset_drawer_fields_fidelity(self, client: TestClient, mock_scan_artifacts: Path):
        """Verifies finding item schema contains all 6-drawer fields required by Prowler Web UI."""
        response = client.get("/api/v1/scans/test_scan_enterprise_001/findings")
        assert response.status_code == 200
        findings = response.json()["findings"]
        assert len(findings) > 0

        for f in findings:
            # Tab 1: Overview fields
            assert "check_id" in f and f["check_id"]
            assert "id" in f and f["id"]
            assert "uid" in f and f["uid"]
            assert "risk" in f
            assert "categories" in f and isinstance(f["categories"], list)
            assert "references" in f and isinstance(f["references"], list)

            # Tab 2: Remediation
            assert "remediation" in f
            assert "remediation_cli" in f

            # Tab 3: Evidence
            assert "resource_id" in f and f["resource_id"]
            assert "service" in f and f["service"]
            assert "region" in f and f["region"]

            # Tab 5 & 6: Scans & Events
            assert "scan_id" in f and f["scan_id"]
            assert "timestamp" in f

