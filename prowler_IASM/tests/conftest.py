"""
Pytest configuration and shared test fixtures for Prowler IASM.
"""

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Generator

import pytest
from fastapi.testclient import TestClient

# Ensure prowler_IASM is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import src.api.api as api_module
from src.api.api import app, SCAN_REGISTRY


@pytest.fixture(autouse=True)
def clean_registry():
    """Ensures SCAN_REGISTRY is clean for every test run."""
    SCAN_REGISTRY.clear()
    yield
    SCAN_REGISTRY.clear()


@pytest.fixture
def temp_output_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Provides an isolated temporary directory for scan results."""
    scan_dir = tmp_path / "scan_results"
    scan_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(api_module, "OUTPUT_DIR", scan_dir)
    return scan_dir


@pytest.fixture
def client(temp_output_dir: Path) -> Generator[TestClient, None, None]:
    """TestClient instance configured with temporary output directory."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def mock_scan_artifacts(temp_output_dir: Path):
    """
    Creates a realistic mock completed scan inside temp_output_dir
    with summary.json, findings.json, assets.json, report.html, report.csv, and ZIP bundle.
    """
    scan_id = "test_scan_enterprise_001"
    scan_dir = temp_output_dir / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "scan_id": scan_id,
        "account_id": "123456789012",
        "security_score": 85.5,
        "duration_seconds": 42.0,
        "total_findings": 3,
        "passed": 2,
        "failed": 1,
        "muted": 0,
        "critical": 1,
        "high": 0,
        "medium": 0,
        "low": 0,
        "services_breakdown": {
            "s3": {"PASS": 1, "FAIL": 1, "pass": 1, "fail": 1},
            "iam": {"PASS": 1, "FAIL": 0, "pass": 1, "fail": 0}
        },
        "compliance_overview": {
            "CIS-AWS-3.0": {
                "passed": 2,
                "failed": 1,
                "total": 3,
                "score": 66.7,
                "requirements_count": 3
            },
            "PCI-DSS-4.0": {
                "passed": 2,
                "failed": 0,
                "total": 2,
                "score": 100.0,
                "requirements_count": 2
            }
        },
        "total_assets_scanned": 2
    }
    with open(scan_dir / "summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f)

    findings = [
        {
            "id": "f-1",
            "uid": "prowler-aws-s3-public-access-001",
            "check_id": "s3_bucket_public_access",
            "check_title": "S3 Public Access Block Disabled",
            "service": "s3",
            "service_name": "s3",
            "severity": "critical",
            "status": "FAIL",
            "region": "us-east-1",
            "resource_id": "arn:aws:s3:::my-public-bucket",
            "resource_name": "my-public-bucket",
            "description": "Bucket public access block is disabled.",
            "status_extended": "Bucket my-public-bucket allows public access.",
            "risk": "Public S3 buckets allow unauthenticated access leading to critical data breaches.",
            "categories": ["storage", "data-protection"],
            "compliance": {"CIS-AWS-3.0": ["2.1.4"], "PCI-DSS-4.0": ["3.4.1"]},
            "remediation": "Enable S3 Block Public Access at the bucket level.",
            "remediation_cli": "aws s3api put-public-access-block --bucket my-public-bucket --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'",
            "remediation_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
            "references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"],
            "scan_id": scan_id,
            "timestamp": "2026-10-21T18:00:00Z"
        },
        {
            "id": "f-2",
            "uid": "prowler-aws-s3-encryption-002",
            "check_id": "s3_bucket_default_encryption",
            "check_title": "S3 Default Encryption Enabled",
            "service": "s3",
            "service_name": "s3",
            "severity": "high",
            "status": "PASS",
            "region": "us-east-1",
            "resource_id": "arn:aws:s3:::my-public-bucket",
            "resource_name": "my-public-bucket",
            "description": "Bucket has default SSE-S3 encryption enabled.",
            "status_extended": "Bucket encrypted.",
            "risk": "Unencrypted buckets expose resting data to unauthorized physical media extraction.",
            "categories": ["encryption", "storage"],
            "compliance": {"CIS-AWS-3.0": ["2.1.1"], "PCI-DSS-4.0": ["3.4.1"]},
            "remediation": "Enable default encryption.",
            "remediation_cli": "aws s3api put-bucket-encryption --bucket my-public-bucket",
            "remediation_url": "",
            "references": [],
            "scan_id": scan_id,
            "timestamp": "2026-10-21T18:00:00Z"
        },
        {
            "id": "f-3",
            "uid": "prowler-aws-iam-root-mfa-003",
            "check_id": "iam_root_mfa_enabled",
            "check_title": "Root Account MFA Enabled",
            "service": "iam",
            "service_name": "iam",
            "severity": "critical",
            "status": "PASS",
            "region": "global",
            "resource_id": "arn:aws:iam::123456789012:root",
            "resource_name": "root",
            "description": "Hardware MFA is configured for root.",
            "status_extended": "MFA active.",
            "risk": "Root account without MFA is susceptible to credential stuffing and takeover.",
            "categories": ["identity-and-access-management", "mfa"],
            "compliance": {"CIS-AWS-3.0": ["1.5"]},
            "remediation": "Configure MFA for root account.",
            "remediation_cli": "",
            "remediation_url": "",
            "references": [],
            "scan_id": scan_id,
            "timestamp": "2026-10-21T18:00:00Z"
        }
    ]
    with open(scan_dir / "findings.json", "w", encoding="utf-8") as f:
        json.dump(findings, f)

    assets = [
        {
            "resource_arn": "arn:aws:s3:::my-public-bucket",
            "resource_name": "my-public-bucket",
            "service": "s3",
            "region": "us-east-1",
            "status": "vulnerable",
            "critical_failures": 1,
            "high_failures": 0,
            "total_checks_evaluated": 2,
            "failed_checks": [
                {
                    "check_id": "s3_bucket_public_access",
                    "check_title": "S3 Public Access Block Disabled",
                    "severity": "critical",
                    "status": "FAIL"
                }
            ],
            "passed_checks": [
                {
                    "check_id": "s3_bucket_default_encryption",
                    "check_title": "S3 Default Encryption Enabled",
                    "severity": "high",
                    "status": "PASS"
                }
            ]
        },
        {
            "resource_arn": "arn:aws:iam::123456789012:root",
            "resource_name": "root",
            "service": "iam",
            "region": "global",
            "status": "secure",
            "critical_failures": 0,
            "high_failures": 0,
            "total_checks_evaluated": 1,
            "failed_checks": [],
            "passed_checks": [
                {
                    "check_id": "iam_root_mfa_enabled",
                    "check_title": "Root Account MFA Enabled",
                    "severity": "critical",
                    "status": "PASS"
                }
            ]
        }
    ]
    with open(scan_dir / "assets.json", "w", encoding="utf-8") as f:
        json.dump(assets, f)

    metadata = {
        "scan_id": scan_id,
        "status": "completed",
        "created_at": "2026-10-21T06:00:00+00:00",
        "started_at": "2026-10-21T06:00:01+00:00",
        "completed_at": "2026-10-21T06:00:43+00:00",
        "duration_seconds": 42.0,
        "error_message": None,
        "has_summary": True,
        "has_bundle": True,
        "regions": ["us-east-1"],
        "services": ["s3", "iam"]
    }
    with open(scan_dir / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f)

    # Empty mock report files
    (scan_dir / "report.html").write_text("<html><body>Prowler Report</body></html>", encoding="utf-8")
    (scan_dir / "report.csv").write_text("id,status,severity\nf-1,FAIL,critical\n", encoding="utf-8")
    (scan_dir / f"{scan_id}_bundle.zip").write_bytes(b"PK\x05\x06" + b"\x00" * 18)

    SCAN_REGISTRY[scan_id] = metadata

    return {
        "scan_id": scan_id,
        "dir": scan_dir,
        "summary": summary,
        "findings": findings,
        "assets": assets,
        "metadata": metadata
    }

