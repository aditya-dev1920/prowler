"""
Comprehensive API Unit and Integration Tests for Prowler IASM Microservice.
"""

import json
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

import src.api.api as api_module
from src.api.api import app, sanitize_scan_id, prune_expired_scans, SCAN_REGISTRY


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

    def test_get_scan_findings_pagination_and_filters(self, client: TestClient, mock_scan_artifacts: dict):
        scan_id = mock_scan_artifacts["scan_id"]
        
        # Test unfiltered (pagination)
        res = client.get(f"/api/v1/scans/{scan_id}/findings?limit=2&offset=0")
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 3
        assert len(data["findings"]) == 2

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

    def test_cancel_scan(self, client: TestClient, mock_scan_artifacts: dict):
        scan_id = mock_scan_artifacts["scan_id"]
        res = client.post(f"/api/v1/scans/{scan_id}/cancel")
        assert res.status_code == 200
        assert res.json()["status"] == "success"
        assert SCAN_REGISTRY[scan_id]["status"] == "cancelled"

    def test_delete_scan(self, client: TestClient, mock_scan_artifacts: dict):
        scan_id = mock_scan_artifacts["scan_id"]
        scan_dir = mock_scan_artifacts["dir"]
        assert scan_dir.exists()

        res = client.delete(f"/api/v1/scans/{scan_id}")
        assert res.status_code == 200
        assert not scan_dir.exists()
        assert scan_id not in SCAN_REGISTRY


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

