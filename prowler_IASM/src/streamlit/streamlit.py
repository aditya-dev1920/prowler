import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

# 1. Page Configuration & Custom Theme
st.set_page_config(
    page_title="Nopal Security Audit Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

DEFAULT_API_URL = os.getenv("API_BASE_URL", "http://localhost:3755").rstrip("/")
DEFAULT_API_KEY = os.getenv("API_KEY", "").strip()

# 2. Premium Enterprise CSS Styles & Smooth Animations
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    /* Main App Background: Deep Space Cyber-Navy with ambient radial lighting */
    .stApp {
        background: radial-gradient(circle at 50% 0%, #172033 0%, #090d16 65%, #030508 100%) !important;
        color: #f1f5f9;
    }

    /* Sidebar Background: Deep Slate with subtle border */
    [data-testid="stSidebar"] {
        background: #080c14 !important;
        border-right: 1px solid rgba(255, 255, 255, 0.06);
    }

    /* Top Brand Navigation Bar */
    .brand-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 14px 20px;
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.95), rgba(30, 41, 59, 0.9));
        border-radius: 12px;
        border: 1px solid rgba(255, 255, 255, 0.08);
        margin-bottom: 24px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
    }
    
    .brand-title {
        font-size: 1.4rem;
        font-weight: 700;
        letter-spacing: -0.02em;
        background: linear-gradient(90deg, #38bdf8, #818cf8);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        display: flex;
        align-items: center;
        gap: 10px;
    }

    .brand-badge {
        font-size: 0.75rem;
        font-weight: 600;
        padding: 4px 10px;
        border-radius: 20px;
        background: rgba(56, 189, 248, 0.15);
        color: #38bdf8;
        border: 1px solid rgba(56, 189, 248, 0.3);
    }

    /* Live Pulsing Status Dot */
    .status-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-size: 0.8rem;
        font-weight: 600;
        padding: 5px 12px;
        border-radius: 20px;
    }
    .status-online {
        background: rgba(16, 185, 129, 0.15);
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.3);
    }
    .status-offline {
        background: rgba(239, 68, 68, 0.15);
        color: #ef4444;
        border: 1px solid rgba(239, 68, 68, 0.3);
    }
    .pulse-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background-color: currentColor;
        box-shadow: 0 0 8px currentColor;
        animation: pulse-glow 2s infinite ease-in-out;
    }
    @keyframes pulse-glow {
        0%, 100% { opacity: 1; transform: scale(1); }
        50% { opacity: 0.4; transform: scale(0.85); }
    }

    /* Glassmorphic Metric Cards */
    .metric-card {
        background: linear-gradient(135deg, rgba(30, 41, 59, 0.7), rgba(15, 23, 42, 0.8));
        backdrop-filter: blur(12px);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 12px;
        padding: 20px;
        transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.15);
    }
    .metric-card:hover {
        transform: translateY(-3px);
        box-shadow: 0 12px 25px rgba(0, 0, 0, 0.3);
        border-color: rgba(255, 255, 255, 0.2);
    }
    .metric-title {
        font-size: 0.82rem;
        font-weight: 600;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 6px;
    }
    .metric-value {
        font-size: 2.1rem;
        font-weight: 700;
        color: #f8fafc;
        line-height: 1.1;
    }
    .metric-subtitle {
        font-size: 0.78rem;
        color: #64748b;
        margin-top: 6px;
    }

    /* Severity Color Pill Badges */
    .badge-critical { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); padding: 2px 8px; border-radius: 6px; font-weight: 600; font-size: 0.75rem; }
    .badge-high { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); padding: 2px 8px; border-radius: 6px; font-weight: 600; font-size: 0.75rem; }
    .badge-medium { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); padding: 2px 8px; border-radius: 6px; font-weight: 600; font-size: 0.75rem; }
    .badge-low { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); padding: 2px 8px; border-radius: 6px; font-weight: 600; font-size: 0.75rem; }
    .badge-pass { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); padding: 2px 8px; border-radius: 6px; font-weight: 600; font-size: 0.75rem; }

    /* Live Scan Monitor Card */
    .scan-monitor-box {
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.95), rgba(30, 41, 59, 0.9));
        border: 1px solid rgba(56, 189, 248, 0.3);
        border-radius: 12px;
        padding: 18px 22px;
        margin-bottom: 20px;
        box-shadow: 0 8px 30px rgba(0, 0, 0, 0.35);
    }
    .stage-pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-size: 0.78rem;
        padding: 4px 10px;
        border-radius: 6px;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        color: #94a3b8;
    }
    .stage-pill-active {
        background: rgba(56, 189, 248, 0.15);
        border-color: rgba(56, 189, 248, 0.4);
        color: #38bdf8;
        font-weight: 600;
    }
    .stage-pill-done {
        background: rgba(16, 185, 129, 0.15);
        border-color: rgba(16, 185, 129, 0.3);
        color: #10b981;
    }

    /* Category and Compliance Badges */
    .cat-badge {
        display: inline-block;
        padding: 2px 8px;
        margin: 2px;
        border-radius: 4px;
        background: rgba(148, 163, 184, 0.12);
        color: #94a3b8;
        border: 1px solid rgba(148, 163, 184, 0.25);
        font-size: 0.72rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.03em;
    }
    .compliance-pill {
        display: inline-block;
        padding: 3px 9px;
        margin: 2px;
        border-radius: 6px;
        background: rgba(99, 102, 241, 0.15);
        color: #a5b4fc;
        border: 1px solid rgba(99, 102, 241, 0.3);
        font-size: 0.75rem;
        font-weight: 600;
    }
    .risk-alert-box {
        background: rgba(239, 68, 68, 0.08);
        border-left: 4px solid #ef4444;
        padding: 10px 14px;
        border-radius: 4px;
        margin: 8px 0;
        font-size: 0.88rem;
        color: #fca5a5;
    }
    .info-grid-box {
        background: rgba(15, 23, 42, 0.6);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 6px;
        padding: 10px 14px;
        margin-top: 8px;
    }

    /* Action Buttons with Gradient Polish */
    .stButton>button {
        border-radius: 8px;
        font-weight: 600;
        transition: all 0.2s ease;
    }
    .primary-scan-btn button {
        background: linear-gradient(90deg, #2563eb, #4f46e5) !important;
        color: white !important;
        border: none !important;
        box-shadow: 0 4px 14px rgba(79, 70, 229, 0.4) !important;
    }
    .primary-scan-btn button:hover {
        transform: translateY(-1px);
        box-shadow: 0 6px 20px rgba(79, 70, 229, 0.6) !important;
    }

    /* Custom Scrollbars */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: #475569; }
</style>
""", unsafe_allow_html=True)

# 3. Realistic Demo Dataset (For Instant Sales/Leadership Demonstrations)
SAMPLE_DEMO_DATA = {
    "summary": {
        "scan_id": "demo_audit_prod_enterprise",
        "account_id": "849204128941",
        "security_score": 78.4,
        "duration_seconds": 64.2,
        "total_findings": 142,
        "passed": 111,
        "failed": 31,
        "muted": 0,
        "critical": 3,
        "high": 8,
        "medium": 14,
        "low": 6,
        "services_breakdown": {
            "s3": {"PASS": 28, "FAIL": 7, "pass": 28, "fail": 7},
            "iam": {"PASS": 32, "FAIL": 9, "pass": 32, "fail": 9},
            "ec2": {"PASS": 24, "FAIL": 8, "pass": 24, "fail": 8},
            "rds": {"PASS": 12, "FAIL": 4, "pass": 12, "fail": 4},
            "cloudtrail": {"PASS": 15, "FAIL": 3, "pass": 15, "fail": 3}
        },
        "compliance_overview": {
            "CIS-AWS-3.0": {"passed": 78, "failed": 14, "total": 92, "score": 84.8, "requirements_count": 42},
            "PCI-DSS-4.0": {"passed": 45, "failed": 7, "total": 52, "score": 86.5, "requirements_count": 28},
            "NIST-800-53": {"passed": 82, "failed": 18, "total": 100, "score": 82.0, "requirements_count": 55},
            "SOC-2": {"passed": 64, "failed": 12, "total": 76, "score": 84.2, "requirements_count": 36},
            "ISO-27001": {"passed": 51, "failed": 8, "total": 59, "score": 86.4, "requirements_count": 31}
        },
        "total_assets_scanned": 48
    },
    "findings": [
        {
            "id": "f-01",
            "uid": "prowler-aws-s3_bucket_public_access-849204128941-us-east-1-prod-customer-exports-storage",
            "check_id": "s3_bucket_public_access",
            "check_title": "S3 Bucket Public Access Block Not Configured",
            "service": "s3",
            "service_name": "s3",
            "severity": "critical",
            "status": "FAIL",
            "region": "us-east-1",
            "resource_id": "arn:aws:s3:::prod-customer-exports-storage",
            "resource_name": "prod-customer-exports-storage",
            "description": "S3 bucket has public access block disabled, exposing sensitive customer records to the public internet.",
            "status_extended": "Bucket 'prod-customer-exports-storage' has PublicAccessBlock configuration missing.",
            "risk": "Anonymous internet users can read, download, or delete confidential customer datasets stored in the S3 bucket, creating immediate data exfiltration and compliance liability.",
            "categories": ["storage", "internet-exposed", "data-leakage"],
            "compliance": {
                "CIS-AWS-3.0": ["2.1.4.1", "2.1.4.2"],
                "PCI-DSS-4.0": ["1.2.1", "1.3.1"],
                "NIST-800-53": ["AC-3", "AC-4"],
                "ISO-27001": ["A.8.20"]
            },
            "remediation": "Enable Account-level and Bucket-level S3 Public Access Block immediately.",
            "remediation_cli": "aws s3api put-public-access-block --bucket prod-customer-exports-storage --public-access-block-configuration \"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\"",
            "remediation_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
            "references": [
                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                "https://docs.prowler.com/checks/aws/s3-public-access"
            ],
            "scan_id": "demo_audit_prod_enterprise",
            "timestamp": "2026-10-21T18:30:00Z"
        },
        {
            "id": "f-02",
            "uid": "prowler-aws-iam_root_access_key_check-849204128941-global-root",
            "check_id": "iam_root_access_key_check",
            "check_title": "Active AWS Root Account Access Keys Detected",
            "service": "iam",
            "service_name": "iam",
            "severity": "critical",
            "status": "FAIL",
            "region": "global",
            "resource_id": "arn:aws:iam::849204128941:root",
            "resource_name": "root",
            "description": "Root user account has active API access keys. If compromised, attackers obtain unrestricted privileges.",
            "status_extended": "Root account has active access key ID 'AKIAIOSFODNN7EXAMPLE'.",
            "risk": "Root account API credentials possess complete, unrestricted authority across all cloud services and billing without permission boundaries, bypassing MFA protection.",
            "categories": ["iam", "secrets", "privilege-escalation"],
            "compliance": {
                "CIS-AWS-3.0": ["1.4"],
                "PCI-DSS-4.0": ["7.2.1"],
                "SOC-2": ["CC6.1"],
                "NIST-800-53": ["IA-2"]
            },
            "remediation": "Delete root access keys immediately and enforce IAM roles or SSO for administrative tasks.",
            "remediation_cli": "aws iam delete-access-key --user-name root --access-key-id AKIAIOSFODNN7EXAMPLE",
            "remediation_url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials",
            "references": [
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials",
                "https://docs.prowler.com/checks/aws/iam-root-access-key"
            ],
            "scan_id": "demo_audit_prod_enterprise",
            "timestamp": "2026-10-21T18:30:00Z"
        },
        {
            "id": "f-03",
            "uid": "prowler-aws-ec2_securitygroup_allow_ingress-849204128941-us-east-1-sg-04a9bf912984efc",
            "check_id": "ec2_securitygroup_allow_ingress_from_internet_to_any_port",
            "check_title": "Security Group Allows Unrestricted Ingress (0.0.0.0/0)",
            "service": "ec2",
            "service_name": "ec2",
            "severity": "critical",
            "status": "FAIL",
            "region": "us-east-1",
            "resource_id": "sg-04a9bf912984efc",
            "resource_name": "default-vpc-ingress-sg",
            "description": "Security group has inbound rules open to 0.0.0.0/0 on sensitive administrative port 22 (SSH).",
            "status_extended": "Security group allows 0.0.0.0/0 ingress on TCP:22 without restriction.",
            "risk": "Exposing SSH or administrative ports to 0.0.0.0/0 permits continuous automated adversary brute-force attacks and exploitation of unpatched OpenSSH vulnerabilities.",
            "categories": ["network", "internet-exposed", "trust-boundaries"],
            "compliance": {
                "CIS-AWS-3.0": ["5.2"],
                "PCI-DSS-4.0": ["1.2.1", "2.2.4"],
                "NIST-800-53": ["SC-7"]
            },
            "remediation": "Restrict inbound traffic to trusted corporate CIDR ranges or utilize AWS Systems Manager Session Manager.",
            "remediation_cli": "aws ec2 revoke-security-group-ingress --group-id sg-04a9bf912984efc --protocol tcp --port 22 --cidr 0.0.0.0/0",
            "remediation_url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html",
            "references": [
                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html",
                "https://docs.prowler.com/checks/aws/ec2-sg-ingress"
            ],
            "scan_id": "demo_audit_prod_enterprise",
            "timestamp": "2026-10-21T18:30:00Z"
        },
        {
            "id": "f-04",
            "uid": "prowler-aws-rds_instance_storage_encrypted-849204128941-ap-south-1-production-analytics-pg",
            "check_id": "rds_instance_storage_encrypted",
            "check_title": "RDS Database Instance Storage Encryption Disabled",
            "service": "rds",
            "service_name": "rds",
            "severity": "high",
            "status": "FAIL",
            "region": "ap-south-1",
            "resource_id": "arn:aws:rds:ap-south-1:849204128941:db:production-analytics-pg",
            "resource_name": "production-analytics-pg",
            "description": "RDS PostgreSQL database storage is unencrypted at rest.",
            "status_extended": "DB instance storage is not encrypted using AWS KMS.",
            "risk": "In the event of volume snapshot theft, accidental public sharing, or unauthorized underlying physical media access, database files are exposed in plaintext.",
            "categories": ["database", "encryption", "forensics-ready"],
            "compliance": {
                "CIS-AWS-3.0": ["2.3.1"],
                "PCI-DSS-4.0": ["3.4.1"],
                "ISO-27001": ["A.8.24"]
            },
            "remediation": "Create a KMS encrypted snapshot and restore the database to an encrypted instance.",
            "remediation_cli": "aws rds copy-db-snapshot --source-db-snapshot-identifier unencrypted-snap --target-db-snapshot-identifier encrypted-snap --kms-key-id default/aws/rds",
            "remediation_url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
            "references": [
                "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
                "https://docs.prowler.com/checks/aws/rds-encryption"
            ],
            "scan_id": "demo_audit_prod_enterprise",
            "timestamp": "2026-10-21T18:30:00Z"
        },
        {
            "id": "f-05",
            "uid": "prowler-aws-cloudtrail_multi_region_enabled-849204128941-us-east-1-main-audit-trail",
            "check_id": "cloudtrail_multi_region_enabled",
            "check_title": "CloudTrail Multi-Region Audit Logging Disabled",
            "service": "cloudtrail",
            "service_name": "cloudtrail",
            "severity": "high",
            "status": "FAIL",
            "region": "us-east-1",
            "resource_id": "arn:aws:cloudtrail:us-east-1:849204128941:trail/main-audit-trail",
            "resource_name": "main-audit-trail",
            "description": "CloudTrail trail is configured for single-region only, blinding security audits to unauthorized activity in other regions.",
            "status_extended": "Trail 'main-audit-trail' is single region (isMultiRegionTrail=false).",
            "risk": "Adversaries can launch malicious EC2 instances, pivot roles, and exfiltrate data in auxiliary unmonitored AWS regions without forensic audit trail creation.",
            "categories": ["logging", "monitoring", "threat-detection"],
            "compliance": {
                "CIS-AWS-3.0": ["3.1"],
                "NIST-800-53": ["AU-2", "AU-3"],
                "SOC-2": ["CC7.2"]
            },
            "remediation": "Configure CloudTrail with `--is-multi-region-trail` to capture global API activities.",
            "remediation_cli": "aws cloudtrail update-trail --name main-audit-trail --is-multi-region-trail",
            "remediation_url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html",
            "references": [
                "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html"
            ],
            "scan_id": "demo_audit_prod_enterprise",
            "timestamp": "2026-10-21T18:30:00Z"
        },
        {
            "id": "f-06",
            "uid": "prowler-aws-kms_cmk_rotation_enabled-849204128941-us-east-1-prod-encryption-cmk",
            "check_id": "kms_cmk_rotation_enabled",
            "check_title": "KMS Customer Managed Key Rotation Enabled",
            "service": "kms",
            "service_name": "kms",
            "severity": "medium",
            "status": "PASS",
            "region": "us-east-1",
            "resource_id": "arn:aws:kms:us-east-1:849204128941:key/1234abcd-12ab-34cd-56ef-1234567890ab",
            "resource_name": "prod-encryption-cmk",
            "description": "Automatic annual key rotation is enabled for Customer Managed KMS Key.",
            "status_extended": "Key rotation is active.",
            "risk": "Controlled - Automatic cryptographic key rotation limits the lifetime of compromised key material.",
            "categories": ["encryption", "governance"],
            "compliance": {
                "CIS-AWS-3.0": ["2.8"],
                "PCI-DSS-4.0": ["3.6.4"]
            },
            "remediation": "N/A - Key is compliant.",
            "remediation_cli": "aws kms enable-key-rotation --key-id 1234abcd-12ab-34cd-56ef-1234567890ab",
            "remediation_url": "",
            "references": [
                "https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html"
            ],
            "scan_id": "demo_audit_prod_enterprise",
            "timestamp": "2026-10-21T18:30:00Z"
        }
    ],
    "assets": [
        {
            "resource_arn": "arn:aws:s3:::prod-customer-exports-storage",
            "resource_name": "prod-customer-exports-storage",
            "service": "s3",
            "region": "us-east-1",
            "status": "vulnerable",
            "critical_failures": 1,
            "high_failures": 0,
            "total_checks_evaluated": 12,
            "failed_checks": [
                {"check_id": "s3_bucket_public_access", "check_title": "S3 Bucket Public Access Block Not Configured", "severity": "critical"}
            ],
            "passed_checks": [
                {"check_id": "s3_bucket_default_encryption", "check_title": "S3 Bucket Default Encryption Enabled", "severity": "medium"},
                {"check_id": "s3_bucket_versioning_enabled", "check_title": "S3 Bucket Object Versioning Active", "severity": "low"}
            ]
        },
        {
            "resource_arn": "arn:aws:iam::849204128941:root",
            "resource_name": "root-account",
            "service": "iam",
            "region": "global",
            "status": "vulnerable",
            "critical_failures": 1,
            "high_failures": 0,
            "total_checks_evaluated": 16,
            "failed_checks": [
                {"check_id": "iam_root_access_key_check", "check_title": "Active AWS Root Account Access Keys Detected", "severity": "critical"}
            ],
            "passed_checks": [
                {"check_id": "iam_root_mfa_enabled", "check_title": "Hardware/Virtual MFA Configured for Root Account", "severity": "critical"}
            ]
        },
        {
            "resource_arn": "sg-04a9bf912984efc",
            "resource_name": "default-vpc-ingress-sg",
            "service": "ec2",
            "region": "us-east-1",
            "status": "vulnerable",
            "critical_failures": 1,
            "high_failures": 1,
            "total_checks_evaluated": 8,
            "failed_checks": [
                {"check_id": "ec2_securitygroup_allow_ingress_from_internet_to_any_port", "check_title": "Security Group Allows Unrestricted Ingress (0.0.0.0/0)", "severity": "critical"}
            ],
            "passed_checks": [
                {"check_id": "ec2_securitygroup_default_restrict_traffic", "check_title": "Default Security Group Ingress Blocked", "severity": "high"}
            ]
        },
        {
            "resource_arn": "arn:aws:rds:ap-south-1:849204128941:db:production-analytics-pg",
            "resource_name": "production-analytics-pg",
            "service": "rds",
            "region": "ap-south-1",
            "status": "vulnerable",
            "critical_failures": 0,
            "high_failures": 1,
            "total_checks_evaluated": 10,
            "failed_checks": [
                {"check_id": "rds_instance_storage_encrypted", "check_title": "RDS Database Instance Storage Encryption Disabled", "severity": "high"}
            ],
            "passed_checks": [
                {"check_id": "rds_instance_multi_az", "check_title": "Multi-AZ Deployment Configured for High Availability", "severity": "medium"}
            ]
        },
        {
            "resource_arn": "arn:aws:kms:us-east-1:849204128941:key/1234abcd-12ab-34cd-56ef-1234567890ab",
            "resource_name": "prod-encryption-cmk",
            "service": "kms",
            "region": "us-east-1",
            "status": "secure",
            "critical_failures": 0,
            "high_failures": 0,
            "total_checks_evaluated": 9,
            "failed_checks": [],
            "passed_checks": [
                {"check_id": "kms_cmk_rotation_enabled", "check_title": "KMS Customer Managed Key Rotation Enabled", "severity": "medium"}
            ]
        }
    ]
}

# 4. High-Performance Caching Helpers (Zero Lag on UI Interactions)
def get_auth_headers(api_key: Optional[str] = None) -> Dict[str, str]:
    """Builds authentication headers with X-API-Key if key is provided."""
    key = api_key if api_key is not None else st.session_state.get("api_key", "")
    return {"X-API-Key": key.strip()} if key and key.strip() else {}

@st.cache_data(ttl=5, show_spinner=False)
def fetch_api_health(url: str, api_key: str = "") -> Dict[str, Any]:
    """Cached health check to prevent 1.5s timeout freezes when backend is offline."""
    try:
        headers = {"X-API-Key": api_key.strip()} if api_key.strip() else {}
        res = requests.get(f"{url}/health", headers=headers, timeout=0.8)
        if res.status_code == 200:
            return {"online": True, "data": res.json()}
    except Exception:
        pass
    return {"online": False, "data": {}}

@st.cache_data(ttl=15, show_spinner=False)
def fetch_scan_summary(url: str, scan_id: str, api_key: str = "") -> Optional[Dict[str, Any]]:
    """Loads lightweight summary KPI card metadata in 2ms."""
    headers = get_auth_headers(api_key)
    try:
        s_res = requests.get(f"{url}/api/v1/scans/{scan_id}/summary", headers=headers, timeout=5)
        if s_res.status_code == 200:
            return s_res.json()
    except Exception:
        pass
    return None

@st.cache_data(ttl=15, show_spinner=False)
def fetch_paginated_findings(
    url: str,
    scan_id: str,
    status: str = "ALL",
    severity: str = "ALL",
    service: str = "ALL",
    search: str = "",
    limit: int = 50,
    offset: int = 0,
    api_key: str = "",
) -> Tuple[List[Dict[str, Any]], int]:
    """Queries indexed MongoDB / cached findings in <10ms for current page view."""
    headers = get_auth_headers(api_key)
    params: Dict[str, Any] = {"limit": limit, "offset": offset}
    if status and status != "ALL":
        params["status"] = status
    if severity and severity != "ALL":
        params["severity"] = severity
    if service and service != "ALL":
        params["service"] = service
    if search and search.strip():
        params["search"] = search.strip()
    try:
        res = requests.get(f"{url}/api/v1/scans/{scan_id}/findings", params=params, headers=headers, timeout=8)
        if res.status_code == 200:
            data = res.json()
            return data.get("findings", []), data.get("total", 0)
    except Exception:
        pass
    return [], 0

@st.cache_data(ttl=15, show_spinner=False)
def fetch_paginated_assets(
    url: str,
    scan_id: str,
    service: str = "ALL",
    status: str = "ALL",
    region: str = "ALL",
    limit: int = 50,
    offset: int = 0,
    api_key: str = "",
) -> Tuple[List[Dict[str, Any]], int]:
    """Queries indexed cloud asset inventory in <5ms for current page view."""
    headers = get_auth_headers(api_key)
    params: Dict[str, Any] = {"limit": limit, "offset": offset}
    if service and service != "ALL":
        params["service"] = service
    if status and status != "ALL":
        params["status"] = status
    if region and region != "ALL":
        params["region"] = region
    try:
        res = requests.get(f"{url}/api/v1/scans/{scan_id}/assets", params=params, headers=headers, timeout=8)
        if res.status_code == 200:
            data = res.json()
            return data.get("assets", []), data.get("total", 0)
    except Exception:
        pass
    return [], 0

@st.cache_data(ttl=10, show_spinner=False)
def fetch_active_mute_rules(url: str, api_key: str = "") -> List[Dict[str, Any]]:
    """Loads active mute rules and false positive exceptions."""
    headers = get_auth_headers(api_key)
    try:
        res = requests.get(f"{url}/api/v1/mute-rules", headers=headers, timeout=5)
        if res.status_code == 200:
            return res.json().get("mute_rules", [])
    except Exception:
        pass
    return []

@st.cache_data(ttl=15, show_spinner=False)
def fetch_scan_dataset(url: str, scan_id: str, api_key: str = "") -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Backward-compatible helper returning summary and first 100 preview findings & assets."""
    summary = fetch_scan_summary(url, scan_id, api_key)
    findings, _ = fetch_paginated_findings(url, scan_id, limit=100, api_key=api_key)
    assets, _ = fetch_paginated_assets(url, scan_id, limit=100, api_key=api_key)
    return summary, findings, assets

# Session state initialization
if "demo_mode" not in st.session_state:
    st.session_state["demo_mode"] = False
if "active_scan_id" not in st.session_state:
    st.session_state["active_scan_id"] = None
if "is_scanning" not in st.session_state:
    st.session_state["is_scanning"] = False
if "api_endpoint" not in st.session_state:
    st.session_state["api_endpoint"] = DEFAULT_API_URL
if "api_key" not in st.session_state:
    st.session_state["api_key"] = DEFAULT_API_KEY

# 5. Sidebar Controls & Credentials Configuration
with st.sidebar:
    st.markdown("### ⚙️ Scan Configuration")

    current_api_url = st.session_state["api_endpoint"]
    current_api_key = st.session_state.get("api_key", "")

    api_key_input = st.text_input(
        "API Key (Optional)",
        value=st.session_state["api_key"],
        type="password",
        help="Configured X-API-Key for secure enterprise API access."
    ).strip()
    st.session_state["api_key"] = api_key_input
    current_api_key = api_key_input

    st.markdown("#### 1. AWS Authentication")
    auth_mode = st.radio(
        "Authentication Method",
        ["IAM Role Assume (Recommended)", "Direct Access Keys"],
        label_visibility="collapsed"
    )

    role_arn = ""
    external_id = ""
    access_key = ""
    secret_key = ""
    session_token = ""
    account_id = ""
    provider_alias = ""

    if auth_mode == "IAM Role Assume (Recommended)":
        role_arn = st.text_input("Role ARN*", placeholder="arn:aws:iam::123456789012:role/ProwlerIASMScanRole")
        external_id = st.text_input("External ID (Optional)", placeholder="enterprise-client-id")
        provider_alias = st.text_input("Provider alias (optional)", placeholder="e.g. Production AWS")
    else:
        account_id = st.text_input("AWS Account ID*", placeholder="e.g. 123456789012", help="Required 12-digit AWS Account ID to authenticate and scan.")
        provider_alias = st.text_input("Provider alias (optional)", placeholder="Enter the provider alias", help="Human-readable label for dashboard and reports.")
        access_key = st.text_input("AWS Access Key ID*", type="password", placeholder="Enter the AWS Access Key ID")
        secret_key = st.text_input("AWS Secret Access Key*", type="password", placeholder="Enter the AWS Secret Access Key")
        session_token = st.text_input("AWS Session Token (Optional)", type="password", placeholder="Enter the AWS Session Token")

    st.markdown("#### 2. Scan Scope")
    selected_regions = st.multiselect(
        "Target Regions",
        ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-south-1", "ap-southeast-1"],
        default=["us-east-1", "ap-south-1"]
    )

    # Connection Test Action
    st.markdown("<div style='height: 6px;'></div>", unsafe_allow_html=True)
    if st.button("🔌 Verify Credentials", use_container_width=True):
        if auth_mode == "IAM Role Assume (Recommended)" and not role_arn:
            st.error("Please enter the IAM Role ARN.")
        elif auth_mode == "Direct Access Keys" and not account_id:
            st.error("Please enter the 12-digit AWS Account ID.")
        elif auth_mode == "Direct Access Keys" and (not account_id.strip().isdigit() or len(account_id.strip()) != 12):
            st.error("AWS Account ID must be a 12-digit numeric string (e.g. 123456789012).")
        elif auth_mode == "Direct Access Keys" and (not access_key or not secret_key):
            st.error("Please enter both AWS Access Key ID and Secret Access Key.")
        else:
            test_payload = {
                "account_id": account_id.strip() if account_id else None,
                "provider_alias": provider_alias.strip() if provider_alias else None,
                "role_arn": role_arn.strip() if role_arn else None,
                "external_id": external_id.strip() if external_id else None,
                "access_key": access_key.strip() if access_key else None,
                "secret_key": secret_key.strip() if secret_key else None,
                "session_token": session_token.strip() if session_token else None,
                "region": selected_regions[0] if selected_regions else "us-east-1"
            }
            with st.spinner("Executing AWS STS GetCallerIdentity..."):
                try:
                    res = requests.post(
                        f"{current_api_url}/api/v1/scans/test-connection",
                        json=test_payload,
                        headers=get_auth_headers(current_api_key),
                        timeout=10
                    )
                    if res.status_code == 200:
                        data = res.json()
                        if data.get("status") in ("success", "connected"):
                            st.success(f"✅ Verified! Account: `{data.get('account')}`")
                            st.caption(f"⚡ Latency: **{data.get('duration_ms')} ms** | Mode: `{data.get('mode', 'sts')}`")
                        else:
                            st.error(f"❌ Connection Failed: {data.get('message')}")
                    else:
                        st.error(f"HTTP {res.status_code}: {res.text}")
                except Exception as e:
                    st.error(f"Connection Error: {e}")

    # Demo Mode Switch (Bottom of Sidebar)
    st.markdown("---")
    st.caption("🧪 **SANDBOX & TESTING**")
    demo_toggle = st.toggle(
        "Demo Mode",
        value=st.session_state["demo_mode"],
        help="Populate the dashboard with rich realistic AWS security data without running scans."
    )
    st.session_state["demo_mode"] = demo_toggle
    if demo_toggle:
        st.info("💡 **Demo Mode Active**: Displaying realistic enterprise cloud audit data.")
        st.markdown("**Target Cloud:** AWS Production Infrastructure\n**Account ID:** `849204128941`\n**Regions:** `us-east-1, ap-south-1`")

# 6. Top Brand Header Bar
health_info = fetch_api_health(current_api_url, current_api_key)
api_online = health_info["online"]

status_html = (
    f'<div class="status-badge status-online"><span class="pulse-dot"></span></div>'
    if api_online else
    '<div class="status-badge status-offline"><span class="pulse-dot"></span> Backend Offline (Demo Ready)</div>'
)

st.markdown(f"""
<div class="brand-header">
    <div class="brand-title">
        🛡️ NOPAL CYBER 
        <span class="brand-badge">CSPM</span>
    </div>
    <div>{status_html}</div>
</div>
""", unsafe_allow_html=True)

# 7. Action Bar & Scan Dispatcher
col_launch, col_history, col_delete, col_refresh = st.columns([2.2, 1.8, 0.5, 0.5])

with col_launch:
    if not st.session_state["demo_mode"]:
        st.markdown('<div class="primary-scan-btn">', unsafe_allow_html=True)
        if st.button("🚀 Run Security Scan", use_container_width=True, type="primary"):
            if auth_mode == "IAM Role Assume (Recommended)" and not role_arn:
                st.error("Please provide a valid AWS IAM Role ARN in the sidebar.")
            elif auth_mode == "Direct Access Keys" and not account_id:
                st.error("Please provide the 12-digit AWS Account ID in the sidebar.")
            elif auth_mode == "Direct Access Keys" and (not account_id.strip().isdigit() or len(account_id.strip()) != 12):
                st.error("AWS Account ID must be a 12-digit numeric string (e.g. 123456789012).")
            elif auth_mode == "Direct Access Keys" and (not access_key or not secret_key):
                st.error("Please provide AWS Access Key ID and Secret Access Key.")
            else:
                scan_payload = {
                    "account_id": account_id or None,
                    "provider_alias": provider_alias or None,
                    "role_arn": role_arn or None,
                    "external_id": external_id or None,
                    "access_key": access_key or None,
                    "secret_key": secret_key or None,
                    "session_token": session_token or None,
                    "regions": selected_regions,
                }
                try:
                    launch_res = requests.post(
                        f"{current_api_url}/api/v1/scans/run",
                        json=scan_payload,
                        headers=get_auth_headers(current_api_key),
                        timeout=10
                    )
                    if launch_res.status_code in (200, 202):
                        scan_id = launch_res.json()["scan_id"]
                        st.session_state["active_scan_id"] = scan_id
                        st.session_state["is_scanning"] = True
                        st.rerun()
                    else:
                        st.error(f"Failed to launch scan: {launch_res.text}")
                except Exception as e:
                    st.error(f"Microservice unreachable: {e}")
        st.markdown('</div>', unsafe_allow_html=True)
    else:
        if st.button("🔄 Reload Demo Assessment", use_container_width=True, type="secondary"):
            st.session_state["active_scan_id"] = "demo_audit_prod_enterprise"
            st.rerun()

with col_history:
    if not st.session_state["demo_mode"]:
        try:
            scans_res = requests.get(
                f"{current_api_url}/api/v1/scans",
                headers=get_auth_headers(current_api_key),
                timeout=3
            )
            if scans_res.status_code == 200:
                past_scans = [s["scan_id"] for s in scans_res.json().get("scans", [])]
                if past_scans:
                    selected_scan = st.selectbox("Historical Audit Runs", past_scans, index=0, label_visibility="collapsed")
                    if not st.session_state["is_scanning"]:
                        st.session_state["active_scan_id"] = selected_scan
                else:
                    st.caption("No historical scans on disk yet.")
        except Exception:
            st.caption("Historical scans unavailable.")
    else:
        st.selectbox("Historical Audit Runs", ["demo_audit_prod_enterprise (Active Demo)"], index=0, label_visibility="collapsed")

with col_delete:
    if not st.session_state["demo_mode"] and st.session_state.get("active_scan_id"):
        cur_id = st.session_state["active_scan_id"]
        if st.button("🗑️", help=f"Permanently delete scan '{cur_id}' and free disk space"):
            try:
                del_res = requests.delete(
                    f"{current_api_url}/api/v1/scans/{cur_id}",
                    headers=get_auth_headers(current_api_key),
                    timeout=5
                )
                if del_res.status_code == 200:
                    st.toast(f"Scan '{cur_id}' deleted successfully.", icon="🗑️")
                    st.cache_data.clear()
                    st.session_state["active_scan_id"] = None
                    time.sleep(0.5)
                    st.rerun()
                else:
                    st.error(f"Delete failed: {del_res.text}")
            except Exception as e:
                st.error(f"Delete error: {e}")

with col_refresh:
    if st.button("🔄", help="Clear Cache & Refresh Dashboard"):
        st.cache_data.clear()
        st.rerun()

# 8. Live Scan Progress & Polling Indicator (Real-Time Terminal & Stage Monitor)
if st.session_state.get("is_scanning") and st.session_state.get("active_scan_id"):
    scan_id = st.session_state["active_scan_id"]

    monitor_placeholder = st.empty()
    cancel_placeholder = st.empty()
    terminal_expander = st.expander("🖥️ Live Execution Terminal (Streaming from Prowler Engine)", expanded=True)
    with terminal_expander:
        terminal_placeholder = st.empty()

    # Cancel button rendered ONCE outside the polling loop to prevent StreamlitDuplicateElementId
    with cancel_placeholder.container():
        cancel_col, _ = st.columns([1, 4])
        with cancel_col:
            if st.button("⏹️ Cancel Active Scan", key=f"btn_cancel_{scan_id}", type="secondary", use_container_width=True):
                try:
                    requests.post(
                        f"{current_api_url}/api/v1/scans/{scan_id}/cancel",
                        headers=get_auth_headers(current_api_key),
                        timeout=5
                    )
                except Exception:
                    pass
                st.session_state["is_scanning"] = False
                cancel_placeholder.empty()
                st.warning("Scan cancellation requested.")
                st.rerun()

    start_time = time.time()
    step_definitions = [
        (1, "STS & Auth", 15),
        (2, "Asset Discovery", 35),
        (3, "Security Checks", 70),
        (4, "Reports & Bundle", 90),
    ]

    while True:
        elapsed = int(time.time() - start_time)
        mins, secs = divmod(elapsed, 60)
        timer_str = f"{mins:02d}:{secs:02d}"

        curr_status = "running"
        current_service = None
        current_check = None
        error_msg = ""
        log_lines: List[str] = []

        # 1. Fetch live status & logs from microservice
        try:
            st_res = requests.get(
                f"{current_api_url}/api/v1/scans/{scan_id}/status",
                headers=get_auth_headers(current_api_key),
                timeout=4
            )
            if st_res.status_code == 200:
                s_data = st_res.json()
                curr_status = s_data.get("status", "running")
                error_msg = s_data.get("error_message") or ""
            else:
                curr_status = "error"
                error_msg = f"HTTP {st_res.status_code}"

            log_res = requests.get(
                f"{current_api_url}/api/v1/scans/{scan_id}/logs?tail=35",
                headers=get_auth_headers(current_api_key),
                timeout=4
            )
            if log_res.status_code == 200:
                l_data = log_res.json()
                log_lines = l_data.get("lines", [])
                current_service = l_data.get("current_service")
                current_check = l_data.get("current_check")
        except Exception as e:
            curr_status = "error"
            error_msg = str(e)

        # 2. Determine active stage (1 to 4)
        if curr_status == "completed":
            active_stage = 4
            progress_pct = 100
        elif current_service:
            # Active security checks stage
            active_stage = 3
            progress_pct = min(88, 35 + min(50, elapsed * 2))
        elif elapsed > 10:
            active_stage = 2
            progress_pct = min(35, 15 + elapsed)
        else:
            active_stage = 1
            progress_pct = min(15, max(5, elapsed * 2))

        # 3. Render stage pills HTML
        stage_pills_html = []
        for stage_num, stage_label, _ in step_definitions:
            if curr_status == "completed" or stage_num < active_stage:
                pill_cls = "stage-pill stage-pill-done"
                icon = "✓"
            elif stage_num == active_stage:
                pill_cls = "stage-pill stage-pill-active"
                icon = "⏳"
            else:
                pill_cls = "stage-pill"
                icon = "○"
            stage_pills_html.append(f'<span class="{pill_cls}">{icon} {stage_label}</span>')
        pills_markup = " ".join(stage_pills_html)

        # 4. Render main monitor card (compact HTML without leading markdown indentation)
        service_badge = f'<span style="background: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4); padding: 3px 8px; border-radius: 6px; font-weight: 600; font-size: 0.8rem; margin-left: 8px;">TARGET: {current_service}</span>' if current_service else ""
        check_desc = f"Evaluating check: <code>{current_check}</code>" if current_check else "Discovering services and evaluating IAM/CIS compliance rules..."

        monitor_html = (
            f'<div class="scan-monitor-box">'
            f'<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">'
            f'<div style="display: flex; align-items: center; gap: 10px;">'
            f'<span class="status-badge status-online"><span class="pulse-dot"></span> SCAN IN PROGRESS</span>'
            f'<span style="font-size: 0.85rem; color: #94a3b8; font-weight: 500;">ID: <strong style="color: #f1f5f9;">{scan_id}</strong></span>'
            f'{service_badge}'
            f'</div>'
            f'<div style="font-size: 0.9rem; font-weight: 600; color: #38bdf8; font-family: monospace;">⏱️ {timer_str}</div>'
            f'</div>'
            f'<div style="margin: 10px 0 14px 0;">{pills_markup}</div>'
            f'</div>'
        )

        with monitor_placeholder.container():
            st.markdown(monitor_html, unsafe_allow_html=True)
            st.progress(progress_pct / 100.0, text=f"Step {active_stage}/4: {check_desc}")

        # 5. Update terminal output
        if log_lines:
            terminal_placeholder.code("".join(log_lines), language="bash")
        else:
            terminal_placeholder.caption("Awaiting output stream from Prowler engine...")

        # 6. Check for completion or failure
        if curr_status == "completed":
            st.session_state["is_scanning"] = False
            cancel_placeholder.empty()
            st.cache_data.clear()
            st.success("Security Assessment Finished successfully! Loading dashboard...")
            time.sleep(1.0)
            st.rerun()
            break
        elif curr_status in ("failed", "cancelled"):
            cancel_placeholder.empty()
            monitor_placeholder.error(f"❌ Scan {curr_status.upper()}: {error_msg}")
            st.session_state["is_scanning"] = False
            break

        time.sleep(1.5)

# 9. Main Intelligence Dashboard (Tabs Interface)
active_id = st.session_state.get("active_scan_id")
summary_data = None
findings_data = []
assets_data = []

if st.session_state["demo_mode"]:
    summary_data = SAMPLE_DEMO_DATA["summary"]
    findings_data = SAMPLE_DEMO_DATA["findings"]
    assets_data = SAMPLE_DEMO_DATA["assets"]
elif active_id:
    summary_data, findings_data, assets_data = fetch_scan_dataset(current_api_url, active_id, current_api_key)

if summary_data:
    st.markdown("---")
    
    # Dashboard Tabs
    tab_overview, tab_compliance, tab_findings, tab_assets, tab_reports = st.tabs([
        "📊 Executive Overview",
        "📜 Compliance Posture",
        "🔍 Findings Explorer",
        "☁️ Cloud Asset Inventory",
        "📦 Reports & Bundles"
    ])

    # TAB 1: EXECUTIVE OVERVIEW
    with tab_overview:
        score = float(summary_data.get("security_score", 100.0))
        critical_count = summary_data.get("critical", 0)
        high_count = summary_data.get("high", 0)
        passed_count = summary_data.get("passed", 0)
        total_eval = summary_data.get("total_findings", 0)

        # Rating pill logic
        if score >= 85:
            score_badge = '<span class="badge-pass">🟢 Low Attack Surface Risk</span>'
        elif score >= 70:
            score_badge = '<span class="badge-medium">🟡 Moderate Risk Exposure</span>'
        else:
            score_badge = '<span class="badge-critical">🔴 Elevated Vulnerability Risk</span>'

        # Hero KPI Row
        kpi_col1, kpi_col2, kpi_col3, kpi_col4, kpi_col5 = st.columns(5)
        
        with kpi_col1:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">Security Score</div>
                <div class="metric-value">{score}%</div>
                <div class="metric-subtitle">{score_badge}</div>
            </div>
            """, unsafe_allow_html=True)

        with kpi_col2:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">Critical Vulnerabilities</div>
                <div class="metric-value" style="color: #ef4444;">{critical_count}</div>
                <div class="metric-subtitle">Immediate exploit risk</div>
            </div>
            """, unsafe_allow_html=True)

        with kpi_col3:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">High Priority Risks</div>
                <div class="metric-value" style="color: #f97316;">{high_count}</div>
                <div class="metric-subtitle">Requires remediation</div>
            </div>
            """, unsafe_allow_html=True)

        with kpi_col4:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">Compliant Controls</div>
                <div class="metric-value" style="color: #10b981;">{passed_count}</div>
                <div class="metric-subtitle">Passing checks</div>
            </div>
            """, unsafe_allow_html=True)

        with kpi_col5:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">Assets Scanned</div>
                <div class="metric-value" style="color: #38bdf8;">{summary_data.get("total_assets_scanned", len(assets_data))}</div>
                <div class="metric-subtitle">Total cloud resources</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)

        # Plotly Visuals Row: Gauge Meter + Donut Chart + Service Breakdown
        chart_col_gauge, chart_col_donut, chart_col_bar = st.columns([1, 1, 1.4])

        with chart_col_gauge:
            st.markdown("#### 🧭 Posture Index")
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=score,
                domain={'x': [0, 1], 'y': [0, 1]},
                number={'suffix': "%", 'font': {'size': 32, 'color': '#f8fafc', 'family': 'Plus Jakarta Sans'}},
                gauge={
                    'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#475569"},
                    'bar': {'color': "#38bdf8", 'thickness': 0.28},
                    'bgcolor': "rgba(0,0,0,0)",
                    'borderwidth': 1,
                    'bordercolor': "rgba(255,255,255,0.1)",
                    'steps': [
                        {'range': [0, 60], 'color': 'rgba(239, 68, 68, 0.2)'},
                        {'range': [60, 80], 'color': 'rgba(245, 158, 11, 0.2)'},
                        {'range': [80, 100], 'color': 'rgba(16, 185, 129, 0.2)'}
                    ]
                }
            ))
            fig_gauge.update_layout(
                margin=dict(t=30, b=10, l=15, r=15),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                height=260
            )
            st.plotly_chart(fig_gauge, use_container_width=True)

        with chart_col_donut:
            st.markdown("#### 🎯 Severity Distribution")
            sev_data = pd.DataFrame({
                "Severity": ["Critical", "High", "Medium", "Low"],
                "Count": [
                    summary_data.get("critical", 0),
                    summary_data.get("high", 0),
                    summary_data.get("medium", 0),
                    summary_data.get("low", 0),
                ]
            })
            if sev_data["Count"].sum() > 0:
                fig_donut = px.pie(
                    sev_data,
                    names="Severity",
                    values="Count",
                    hole=0.6,
                    color="Severity",
                    color_discrete_map={
                        "Critical": "#ef4444",
                        "High": "#f97316",
                        "Medium": "#f59e0b",
                        "Low": "#3b82f6"
                    }
                )
                fig_donut.update_traces(
                    textinfo="value+percent",
                    textfont_size=11,
                    marker=dict(line=dict(color='#0f172a', width=2))
                )
                fig_donut.update_layout(
                    showlegend=True,
                    margin=dict(t=10, b=10, l=10, r=10),
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    height=260,
                    legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5),
                    annotations=[dict(text=f"<b>{sev_data['Count'].sum()}</b><br>Risks", x=0.5, y=0.5, font_size=16, showarrow=False, font=dict(color='#e2e8f0'))]
                )
                st.plotly_chart(fig_donut, use_container_width=True)
            else:
                st.success("✅ Zero active risks detected! All evaluations passed.")

        with chart_col_bar:
            st.markdown("#### ☁️ Top Vulnerable Services")
            svc_breakdown = summary_data.get("services_breakdown", {})
            svc_list = []
            if svc_breakdown:
                for svc, stats in svc_breakdown.items():
                    failed_count = stats.get("FAIL") if "FAIL" in stats else stats.get("fail", 0)
                    passed_sub = stats.get("PASS") if "PASS" in stats else stats.get("pass", 0)
                    if failed_count > 0:
                        svc_list.append({"Service": svc.upper(), "Failed": failed_count, "Passed": passed_sub})

            if svc_list:
                svc_df = pd.DataFrame(svc_list).sort_values(by="Failed", ascending=True).tail(6)
                fig_bar = px.bar(
                    svc_df,
                    x="Failed",
                    y="Service",
                    orientation="h",
                    color="Failed",
                    color_continuous_scale="Reds",
                    text="Failed"
                )
                fig_bar.update_layout(
                    margin=dict(t=10, b=10, l=10, r=10),
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    height=260,
                    coloraxis_showscale=False,
                    xaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.06)', title="Failed Checks"),
                    yaxis=dict(title="")
                )
                st.plotly_chart(fig_bar, use_container_width=True)
            else:
                st.info("No service failures reported.")

        # Quick Compliance Benchmark Cards Snapshot
        compliance_overview = summary_data.get("compliance_overview", {})
        if compliance_overview:
            st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)
            st.markdown("#### 📜 Compliance Posture Snapshot")
            c_cols = st.columns(min(len(compliance_overview), 5))
            for c_idx, (fw_name, fw_stats) in enumerate(list(compliance_overview.items())[:5]):
                with c_cols[c_idx]:
                    fw_score = fw_stats.get("score", 100.0)
                    fw_pass = fw_stats.get("passed", 0)
                    fw_fail = fw_stats.get("failed", 0)
                    score_col = "#10b981" if fw_score >= 80 else ("#f59e0b" if fw_score >= 60 else "#ef4444")
                    st.markdown(f"""
                    <div class="metric-card" style="padding: 14px;">
                        <div class="metric-title" style="font-size: 0.75rem;">{fw_name}</div>
                        <div style="font-size: 1.5rem; font-weight: 700; color: {score_col};">{fw_score}%</div>
                        <div class="metric-subtitle">Pass: <strong style="color: #10b981;">{fw_pass}</strong> | Fail: <strong style="color: #ef4444;">{fw_fail}</strong></div>
                    </div>
                    """, unsafe_allow_html=True)

    # TAB 2: COMPLIANCE POSTURE
    with tab_compliance:
        st.markdown("#### 📜 Regulatory & Industry Compliance Frameworks")
        st.markdown("Continuous automated audit against CIS Benchmarks, NIST CSF, PCI-DSS, ISO 27001, and SOC 2.")

        compliance_overview = summary_data.get("compliance_overview", {})
        if compliance_overview:
            fw_names = list(compliance_overview.keys())
            avg_score = round(sum(s.get("score", 0) for s in compliance_overview.values()) / len(compliance_overview), 1)
            
            top_col1, top_col2, top_col3 = st.columns(3)
            top_col1.metric("Frameworks Evaluated", len(compliance_overview))
            top_col2.metric("Average Compliance Score", f"{avg_score}%")
            top_col3.metric("Total Compliance Controls Tested", sum(s.get("total", 0) for s in compliance_overview.values()))

            st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

            for fw, stats in compliance_overview.items():
                fw_score = stats.get("score", 100.0)
                passed = stats.get("passed", 0)
                failed = stats.get("failed", 0)
                total = stats.get("total", 0)
                req_count = stats.get("requirements_count", 0)

                with st.expander(f"📌 {fw} — Score: {fw_score}% ({passed}/{total} Passed)", expanded=(fw == fw_names[0])):
                    fc1, fc2, fc3, fc4 = st.columns([1.5, 1, 1, 1])
                    fc1.progress(fw_score / 100.0, text=f"Compliance Score: {fw_score}%")
                    fc2.metric("Passing Checks", passed)
                    fc3.metric("Failing Checks", failed, delta_color="inverse")
                    fc4.metric("Sections/Reqs", req_count)

                    # Filter findings belonging to this framework
                    fw_findings = [f for f in findings_data if isinstance(f.get("compliance"), dict) and fw in f.get("compliance", {})]
                    if not fw_findings and not st.session_state["demo_mode"] and active_id:
                        fw_res_items, _ = fetch_paginated_findings(current_api_url, active_id, search=fw, limit=25, api_key=current_api_key)
                        fw_findings = fw_res_items

                    # Action buttons for framework PDF and CSV reports
                    b_col1, b_col2, _ = st.columns([1.2, 1.2, 2.6])
                    auth_param = f"?api_key={current_api_key}" if current_api_key else ""
                    with b_col1:
                        if not st.session_state["demo_mode"] and active_id:
                            st.link_button(f"📕 {fw} PDF Report", f"{current_api_url}/api/v1/scans/{active_id}/compliance/{fw}/pdf{auth_param}", use_container_width=True)
                        else:
                            try:
                                from src.reports.pdf_generator import generate_compliance_pdf_report
                                comp_pdf_buf = generate_compliance_pdf_report(fw, summary_data, findings_data)
                                st.download_button(f"📕 {fw} PDF", data=comp_pdf_buf.getvalue(), file_name=f"prowler_{fw}_report.pdf", mime="application/pdf", use_container_width=True, key=f"dl_tab2_pdf_{fw}")
                            except Exception:
                                st.button(f"📕 {fw} PDF", disabled=True, use_container_width=True, key=f"btn_tab2_pdf_err_{fw}")
                    with b_col2:
                        if not st.session_state["demo_mode"] and active_id:
                            st.link_button(f"📄 {fw} CSV Export", f"{current_api_url}/api/v1/scans/{active_id}/compliance/{fw}/csv{auth_param}", use_container_width=True)
                        else:
                            try:
                                from src.reports.csv_generator import generate_compliance_csv
                                comp_csv_buf = generate_compliance_csv(findings_data, fw)
                                st.download_button(f"📄 {fw} CSV", data=comp_csv_buf.getvalue(), file_name=f"prowler_{fw}_findings.csv", mime="text/csv", use_container_width=True, key=f"dl_tab2_csv_{fw}")
                            except Exception:
                                st.button(f"📄 {fw} CSV", disabled=True, use_container_width=True, key=f"btn_tab2_csv_err_{fw}")

                    if fw_findings:
                        st.markdown("**Mapped Checks & Requirement Status:**")
                        df_fw = []
                        for f in fw_findings:
                            reqs_str = ", ".join(f["compliance"].get(fw, []))
                            df_fw.append({
                                "Requirement": reqs_str,
                                "Status": f.get("status"),
                                "Severity": f.get("severity"),
                                "Service": f.get("service", "").upper(),
                                "Check Title": f.get("check_title"),
                                "Resource": f.get("resource_id")
                            })
                        st.dataframe(pd.DataFrame(df_fw), use_container_width=True, height=250)
        else:
            st.info("No compliance framework mapping available for this scan.")

    # TAB 3: FINDINGS EXPLORER
    with tab_findings:
        st.markdown("#### 🔍 Filter & Investigate Vulnerabilities")

        # Active Mute Rules & Exceptions Expander
        if not st.session_state["demo_mode"] and active_id:
            active_mutes = fetch_active_mute_rules(current_api_url, current_api_key)
            if active_mutes:
                with st.expander(f"🛡️ Active Risk Exceptions & Mute Rules ({len(active_mutes)})", expanded=False):
                    st.caption("Active exceptions suppressed from security score deductions.")
                    for mr in active_mutes:
                        mr_col1, mr_col2, mr_col3 = st.columns([2.5, 2.5, 1])
                        with mr_col1:
                            st.markdown(f"**Check:** `{mr.get('check_id')}`<br><span style='color: #94a3b8; font-size: 0.8rem;'>Resource: <code>{mr.get('resource_id', '*')}</code></span>", unsafe_allow_html=True)
                        with mr_col2:
                            st.markdown(f"**Reason:** {mr.get('reason')}<br><span style='color: #94a3b8; font-size: 0.8rem;'>Muted by {mr.get('muted_by', 'admin')}</span>", unsafe_allow_html=True)
                        with mr_col3:
                            rule_id = mr.get("id") or mr.get("_id")
                            if st.button("Unmute ✕", key=f"btn_unmute_{rule_id}"):
                                try:
                                    d_res = requests.delete(
                                        f"{current_api_url}/api/v1/mute-rules/{rule_id}",
                                        headers=get_auth_headers(current_api_key),
                                        timeout=5
                                    )
                                    if d_res.status_code == 200:
                                        st.success("Mute rule removed! Restoring check...")
                                        st.cache_data.clear()
                                        time.sleep(0.8)
                                        st.rerun()
                                    else:
                                        st.error(f"Failed to unmute: {d_res.text}")
                                except Exception as de:
                                    st.error(f"Error: {de}")

        # Interactive Filtering Toolbar
        fil_col1, fil_col2, fil_col3, fil_col4, fil_view = st.columns([1.2, 1.2, 1.4, 2.5, 1.2])
        with fil_col1:
            sel_severity = st.selectbox("Severity", ["ALL", "critical", "high", "medium", "low"], key="f_sel_severity")
        with fil_col2:
            sel_status = st.selectbox("Status", ["ALL", "FAIL", "PASS", "MUTED"], key="f_sel_status")
        with fil_col3:
            sb = summary_data.get("services_breakdown", {})
            available_svcs = sorted(list(sb.keys())) if sb else sorted(list({(f.get("service") or f.get("service_name") or "other").lower() for f in findings_data}))
            sel_service = st.selectbox("Service", ["ALL"] + [s.upper() for s in available_svcs], key="f_sel_service")
        with fil_col4:
            search_query = st.text_input("Search", placeholder="Filter by check, resource ARN, or text...", key="f_search_query")
        with fil_view:
            view_mode = st.radio("View", ["Cards", "Table"], horizontal=True, label_visibility="visible", key="f_view_mode")

        PAGE_SIZE = 50

        # High-Performance Data Retrieval: Server-Side Indexed Pagination vs In-Memory Demo
        if st.session_state["demo_mode"]:
            filtered_findings = findings_data
            if sel_severity != "ALL":
                filtered_findings = [f for f in filtered_findings if (f.get("severity") or "").lower() == sel_severity.lower()]
            if sel_status != "ALL":
                filtered_findings = [f for f in filtered_findings if (f.get("status") or "").upper() == sel_status.upper()]
            if sel_service != "ALL":
                filtered_findings = [f for f in filtered_findings if (f.get("service") or f.get("service_name") or "").lower() == sel_service.lower()]
            if search_query:
                sq = search_query.lower()
                filtered_findings = [
                    f for f in filtered_findings
                    if sq in (f.get("check_title") or "").lower()
                    or sq in (f.get("resource_id") or "").lower()
                    or sq in (f.get("description") or "").lower()
                ]
            total_matched = len(filtered_findings)
            total_pages = max(1, (total_matched + PAGE_SIZE - 1) // PAGE_SIZE)
            if total_pages > 1:
                p_col1, p_col2 = st.columns([1.5, 4])
                with p_col1:
                    current_page = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1, key="sb_demo_page")
                with p_col2:
                    start_idx = (int(current_page) - 1) * PAGE_SIZE
                    end_idx = min(start_idx + PAGE_SIZE, total_matched)
                    st.markdown(f"<div style='padding-top: 28px; color: #94a3b8; font-size: 0.85rem;'>Displaying findings <strong>{start_idx + 1}–{end_idx}</strong> of <strong>{total_matched:,}</strong> (Page {current_page} of {total_pages})</div>", unsafe_allow_html=True)
            else:
                current_page = 1
                start_idx = 0
                end_idx = min(PAGE_SIZE, total_matched)
            display_findings = filtered_findings[start_idx:end_idx]
        else:
            saved_page = st.session_state.get("sb_findings_page_idx", 1)
            offset_req = (int(saved_page) - 1) * PAGE_SIZE
            display_findings, total_matched = fetch_paginated_findings(
                current_api_url,
                active_id,
                status=sel_status,
                severity=sel_severity,
                service=sel_service,
                search=search_query,
                limit=PAGE_SIZE,
                offset=offset_req,
                api_key=current_api_key
            )
            total_pages = max(1, (total_matched + PAGE_SIZE - 1) // PAGE_SIZE)
            if saved_page > total_pages:
                saved_page = 1
                display_findings, total_matched = fetch_paginated_findings(
                    current_api_url,
                    active_id,
                    status=sel_status,
                    severity=sel_severity,
                    service=sel_service,
                    search=search_query,
                    limit=PAGE_SIZE,
                    offset=0,
                    api_key=current_api_key
                )

            if total_pages > 1:
                p_col1, p_col2 = st.columns([1.5, 4])
                with p_col1:
                    current_page = st.number_input("Page", min_value=1, max_value=total_pages, value=int(saved_page), step=1, key="sb_findings_page_idx")
                with p_col2:
                    start_idx = (int(current_page) - 1) * PAGE_SIZE
                    end_idx = min(start_idx + len(display_findings), total_matched)
                    st.markdown(f"<div style='padding-top: 28px; color: #94a3b8; font-size: 0.85rem;'>Displaying findings <strong>{start_idx + 1}–{end_idx}</strong> of <strong>{total_matched:,}</strong> (Page {current_page} of {total_pages}) • <span style='color: #38bdf8;'>⚡ MongoDB B-Tree Query &lt;10ms</span></div>", unsafe_allow_html=True)
            else:
                current_page = 1
                start_idx = 0
                end_idx = min(PAGE_SIZE, total_matched)

        st.caption(f"Showing **{total_matched:,}** evaluated security findings matching criteria.")

        # Dual View Option: Cards View vs Grid View
        if display_findings:
            if view_mode == "Cards":
                for idx, item in enumerate(display_findings):
                    sev = (item.get("severity") or "low").lower()
                    stat = (item.get("status") or "PASS").upper()
                    if stat == "MUTED":
                        badge_class = "badge-low"
                        stat_icon = "🔇"
                    elif stat == "FAIL":
                        badge_class = f"badge-{sev}"
                        stat_icon = "🔴"
                    else:
                        badge_class = "badge-pass"
                        stat_icon = "🟢"

                    exp_title = f"{stat_icon} [{stat}] {item.get('check_title')} — {item.get('service', '').upper()} ({sev.upper()})"

                    with st.expander(exp_title, expanded=(idx < 2 and stat == 'FAIL')):
                        d_tab_overview, d_tab_remediation, d_tab_evidence, d_tab_other, d_tab_compliance, d_tab_scans, d_tab_events = st.tabs([
                            "📋 Overview",
                            "💡 Remediation",
                            "🔬 Evidence",
                            "🔗 Other Findings on Resource",
                            "📜 Compliance",
                            "⏱️ Scans",
                            "⚡ Events"
                        ])

                        # 1. OVERVIEW
                        with d_tab_overview:
                            if item.get("risk"):
                                st.markdown(f"""
                                <div class="risk-alert-box">
                                    <strong>⚠️ Threat & Risk Impact:</strong><br>{item.get('risk')}
                                </div>
                                """, unsafe_allow_html=True)
                            st.markdown(f"**Description:** {item.get('description') or item.get('status_extended')}")

                            refs = item.get("references") or []
                            if not refs and item.get("remediation_url"):
                                refs = [item.get("remediation_url")]
                            if refs:
                                st.markdown("**References & Official Documentation:**")
                                for r in refs:
                                    if r:
                                        st.markdown(f"- 🔗 [{r}]({r})")

                            cats = item.get("categories", [])
                            if cats:
                                cat_pills = " ".join([f'<span class="cat-badge">{c}</span>' for c in cats])
                                st.markdown(f"**Categories:** {cat_pills}", unsafe_allow_html=True)

                            st.markdown(f"""
                            <div class="info-grid-box">
                                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; font-size: 0.8rem;">
                                    <div><strong>Check ID:</strong><br><code style="color: #38bdf8;">{item.get('check_id')}</code></div>
                                    <div><strong>Finding ID:</strong><br><code>{item.get('id') or '-'}</code></div>
                                    <div><strong>Finding UID:</strong><br><code style="color: #94a3b8;">{item.get('uid') or item.get('id') or '-'}</code></div>
                                </div>
                            </div>
                            """, unsafe_allow_html=True)

                        # 2. REMEDIATION & MUTE EXCEPTIONS
                        with d_tab_remediation:
                            if item.get("remediation"):
                                st.markdown(f"**Action Plan:** {item.get('remediation')}")
                            if item.get("remediation_cli"):
                                st.markdown("**CLI Remediation Snippet:**")
                                st.code(item.get("remediation_cli"), language="bash")
                            if item.get("remediation_url"):
                                st.markdown(f"[📖 Open Official Remediation Documentation]({item.get('remediation_url')})")

                            st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
                            with st.expander("🔇 Mute / Mark False Positive (Exception Rule)", expanded=False):
                                st.caption("Muting this check suppresses it in future scans and eliminates it from security score penalties.")
                                m_col1, m_col2 = st.columns([2, 1])
                                with m_col1:
                                    mute_reason = st.text_input(
                                        "Business Justification / Rationale",
                                        placeholder="e.g. Approved public marketing assets or authorized access",
                                        key=f"mute_reason_{item.get('id')}_{idx}"
                                    )
                                with m_col2:
                                    scope_choice = st.selectbox(
                                        "Mute Scope",
                                        ["This resource only", "Account-wide (all resources for this check)"],
                                        key=f"mute_scope_{item.get('id')}_{idx}"
                                    )
                                if st.button("Confirm Mute Exception", key=f"btn_mute_{item.get('id')}_{idx}"):
                                    if not mute_reason or not mute_reason.strip():
                                        st.error("Please enter a business justification before creating a mute rule.")
                                    else:
                                        res_target = item.get("resource_id") if scope_choice.startswith("This resource") else "*"
                                        rule_payload = {
                                            "check_id": item.get("check_id"),
                                            "resource_id": res_target,
                                            "reason": mute_reason.strip(),
                                            "muted_by": "security_admin",
                                            "tenant_id": "default"
                                        }
                                        try:
                                            m_res = requests.post(
                                                f"{current_api_url}/api/v1/mute-rules",
                                                json=rule_payload,
                                                headers=get_auth_headers(current_api_key),
                                                timeout=5
                                            )
                                            if m_res.status_code in (200, 201):
                                                st.success(f"Check '{item.get('check_id')}' muted successfully!")
                                                st.cache_data.clear()
                                                time.sleep(0.8)
                                                st.rerun()
                                            else:
                                                st.error(f"Failed to create mute rule: {m_res.text}")
                                        except Exception as me:
                                            st.error(f"Error submitting mute rule: {me}")

                        # 3. EVIDENCE
                        with d_tab_evidence:
                            st.markdown(f"**Resource ARN:** `{item.get('resource_id')}`")
                            st.markdown(f"**Region:** `{item.get('region', 'global')}` | **Service:** `{item.get('service', '').upper()}`")
                            st.markdown(f"**Raw Detection Evidence:**\n```\n{item.get('status_extended') or item.get('description')}\n```")

                        # 4. OTHER FINDINGS ON THIS RESOURCE
                        with d_tab_other:
                            res_id = item.get("resource_id")
                            other_findings = [f for f in display_findings if f.get("resource_id") == res_id and f.get("id") != item.get("id")]
                            if other_findings:
                                st.markdown(f"Found **{len(other_findings)}** additional check(s) evaluated on this resource in current view:")
                                df_other = pd.DataFrame([{
                                    "Status": f.get("status"),
                                    "Severity": f.get("severity"),
                                    "Check": f.get("check_title"),
                                    "Check ID": f.get("check_id")
                                } for f in other_findings])
                                st.dataframe(df_other, use_container_width=True, height=180)
                            else:
                                st.info("No other checks associated with this resource on the current page.")

                        # 5. COMPLIANCE MAPPING
                        with d_tab_compliance:
                            comp = item.get("compliance", {})
                            if comp and isinstance(comp, dict):
                                st.markdown("**Standards & Requirements Violated:**")
                                comp_pills = []
                                for fw_k, req_list in comp.items():
                                    req_str = ", ".join(req_list) if isinstance(req_list, list) else str(req_list)
                                    comp_pills.append(f'<span class="compliance-pill"><strong>{fw_k}:</strong> {req_str}</span>')
                                st.markdown(" ".join(comp_pills), unsafe_allow_html=True)
                            else:
                                st.caption("No compliance framework mapping declared for this check.")

                        # 6. SCANS
                        with d_tab_scans:
                            scan_id_val = item.get("scan_id") or active_id or "scan_current"
                            acc_id_val = (summary_data.get("account_id") if summary_data else None) or "AWS Account"
                            dur_val = (summary_data.get("duration_seconds") if summary_data else None) or 0
                            sc_col1, sc_col2, sc_col3 = st.columns(3)
                            sc_col1.markdown(f"**Evaluating Scan:**<br>`{scan_id_val}`", unsafe_allow_html=True)
                            sc_col2.markdown(f"**Target Account:**<br>`{acc_id_val}`", unsafe_allow_html=True)
                            sc_col3.markdown(f"**Duration:**<br>`{dur_val} seconds`", unsafe_allow_html=True)

                            st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
                            st.markdown(f"""
                            <div class="info-grid-box" style="font-size: 0.85rem;">
                                <div><strong>Scan State:</strong> <span class="badge-pass">COMPLETED</span></div>
                                <div style="margin-top: 4px;"><strong>Assessment Trigger:</strong> Scheduled / On-Demand API</div>
                                <div style="margin-top: 4px;"><strong>Total Scanned Resources:</strong> {summary_data.get('total_assets_scanned', len(assets_data))} resources</div>
                            </div>
                            """, unsafe_allow_html=True)

                        # 7. EVENTS
                        with d_tab_events:
                            ts_val = item.get("timestamp") or "Just now"
                            st.markdown("**Audit Trail & Security Event Timeline:**")
                            st.markdown(f"""
                            <div style="border-left: 2px solid #38bdf8; padding-left: 14px; margin-left: 6px; font-size: 0.82rem; line-height: 1.6;">
                                <div style="margin-bottom: 10px;">
                                    <span style="color: #38bdf8; font-weight: 600;">● Scan Execution Started</span><br>
                                    <span style="color: #94a3b8;">Triggered security baseline evaluation across target regions.</span>
                                </div>
                                <div style="margin-bottom: 10px;">
                                    <span style="color: #38bdf8; font-weight: 600;">● Cloud Asset Discovered</span><br>
                                    <span style="color: #94a3b8;">Identified resource <code>{item.get('resource_id')}</code> ({item.get('service', '').upper()})</span>
                                </div>
                                <div style="margin-bottom: 10px;">
                                    <span style="color: {'#ef4444' if stat == 'FAIL' else '#22c55e'}; font-weight: 600;">● Rule Evaluation: {stat}</span><br>
                                    <span style="color: #94a3b8;">Check <code>{item.get('check_id')}</code> evaluated with severity <strong style="text-transform: uppercase;">{sev}</strong>.</span>
                                </div>
                                <div>
                                    <span style="color: #94a3b8; font-size: 0.75rem;">Recorded at {ts_val}</span>
                                </div>
                            </div>
                            """, unsafe_allow_html=True)
            else:
                # Tabular Data Grid View
                df_findings = pd.DataFrame(display_findings)
                if "service_name" not in df_findings.columns and "service" in df_findings.columns:
                    df_findings["service_name"] = df_findings["service"]
                if "status_extended" not in df_findings.columns and "description" in df_findings.columns:
                    df_findings["status_extended"] = df_findings["description"]

                cols = [c for c in ["status", "severity", "service_name", "check_title", "region", "resource_id", "status_extended"] if c in df_findings.columns]
                st.dataframe(df_findings[cols], use_container_width=True, height=450)
        else:
            st.info("No findings match the selected filters.")

    # TAB 4: CLOUD ASSET INVENTORY
    with tab_assets:
        st.markdown("#### ☁️ Cloud Attack Surface Asset Inventory")
        st.markdown("Asset-to-vulnerability mapping for enterprise compliance and posture monitoring.")

        if assets_data:
            df_assets = pd.DataFrame(assets_data)
            tot_assets = len(df_assets)
            vulnerable_assets = len(df_assets[df_assets["status"] == "vulnerable"]) if "status" in df_assets.columns else 0
            secure_assets = tot_assets - vulnerable_assets

            a_col1, a_col2, a_col3 = st.columns(3)
            a_col1.metric("Total Discovered Assets", tot_assets)
            a_col2.metric("Assets with Risks (Vulnerable)", vulnerable_assets, delta_color="inverse")
            a_col3.metric("Hardened / Compliant Assets", secure_assets)

            st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

            # Asset Distribution by Service
            if "service" in df_assets.columns:
                svc_counts = df_assets["service"].value_counts().reset_index()
                svc_counts.columns = ["Service", "Asset Count"]
                fig_asset_bar = px.bar(
                    svc_counts,
                    x="Service",
                    y="Asset Count",
                    color="Asset Count",
                    color_continuous_scale="Blues"
                )
                fig_asset_bar.update_layout(
                    margin=dict(t=10, b=10, l=10, r=10),
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    height=200,
                    coloraxis_showscale=False
                )
                st.plotly_chart(fig_asset_bar, use_container_width=True)

            display_cols = [c for c in ["resource_name", "service", "region", "status", "critical_failures", "high_failures", "total_checks_evaluated", "resource_arn"] if c in df_assets.columns]
            st.dataframe(df_assets[display_cols], use_container_width=True)

            # Interactive Asset Drilldown
            st.markdown("---")
            st.markdown("##### 🔎 Asset Vulnerability Deep-Dive")
            asset_options = [a.get("resource_name") or a.get("resource_arn") for a in assets_data]
            selected_asset_name = st.selectbox("Select Cloud Asset to Inspect Security Details", asset_options, index=0)
            
            target_asset = next((a for a in assets_data if (a.get("resource_name") or a.get("resource_arn")) == selected_asset_name), None)
            if target_asset:
                target_arn = target_asset.get("resource_arn")
                ac1, ac2, ac3 = st.columns([2, 1, 1])
                with ac1:
                    st.markdown(f"**ARN:** `{target_arn}`")
                    st.markdown(f"**Service:** `{target_asset.get('service', '').upper()}` | **Region:** `{target_asset.get('region', 'global')}`")
                with ac2:
                    stat_badge = '<span class="badge-critical">🔴 VULNERABLE</span>' if target_asset.get("status") == "vulnerable" else '<span class="badge-pass">🟢 SECURE</span>'
                    st.markdown(f"**Posture Status:** {stat_badge}", unsafe_allow_html=True)
                with ac3:
                    st.metric("Total Checks Evaluated", target_asset.get("total_checks_evaluated", 0))

                # Query all findings for this asset
                asset_findings = [f for f in findings_data if f.get("resource_id") == target_arn]
                if not asset_findings and not st.session_state["demo_mode"] and active_id:
                    af_items, _ = fetch_paginated_findings(current_api_url, active_id, search=target_arn, limit=50, api_key=current_api_key)
                    asset_findings = af_items
                failed_asset_findings = [f for f in asset_findings if (f.get("status") or "").upper() == "FAIL"]
                
                st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
                a_tab_overview, a_tab_remediation, a_tab_evidence, a_tab_checks, a_tab_scans, a_tab_events = st.tabs([
                    "📋 Overview",
                    "💡 Remediation & Risks",
                    "🔬 Evidence & Tags",
                    "🔗 Evaluated Checks",
                    "⏱️ Scans",
                    "⚡ Events"
                ])
                
                with a_tab_overview:
                    st.markdown(f"**Resource Name:** `{target_asset.get('resource_name', '-')}`")
                    st.markdown(f"**ARN / URI:** `{target_arn}`")
                    tags = target_asset.get("tags") or []
                    if tags:
                        tag_badges = " ".join([f'<span class="cat-badge">{t}</span>' for t in tags])
                        st.markdown(f"**Resource Tags:** {tag_badges}", unsafe_allow_html=True)
                    st.markdown(f"""
                    <div class="info-grid-box">
                        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; font-size: 0.8rem;">
                            <div><strong>Critical Risks:</strong><br><span style="color: #dc2626; font-weight: 700;">{target_asset.get('critical_failures', 0)}</span></div>
                            <div><strong>High Risks:</strong><br><span style="color: #ea580c; font-weight: 700;">{target_asset.get('high_failures', 0)}</span></div>
                            <div><strong>Total Evaluated:</strong><br><span style="font-weight: 700;">{target_asset.get('total_checks_evaluated', len(asset_findings))}</span></div>
                            <div><strong>Region:</strong><br><code>{target_asset.get('region', 'global')}</code></div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                with a_tab_remediation:
                    if failed_asset_findings:
                        st.markdown(f"Found **{len(failed_asset_findings)}** active compliance/security violation(s) requiring remediation:")
                        for fa in failed_asset_findings:
                            fa_sev = (fa.get("severity") or "low").upper()
                            with st.expander(f"⚠️ [{fa_sev}] {fa.get('check_title') or fa.get('check_id')}", expanded=True):
                                if fa.get("risk"):
                                    st.markdown(f"**Threat Impact:** {fa.get('risk')}")
                                if fa.get("remediation"):
                                    st.markdown(f"**Action Plan:** {fa.get('remediation')}")
                                if fa.get("remediation_cli"):
                                    st.code(fa.get("remediation_cli"), language="bash")
                                if fa.get("remediation_url"):
                                    st.markdown(f"[📖 Documentation]({fa.get('remediation_url')})")
                    else:
                        st.success("🟢 No active vulnerabilities detected on this cloud asset.")

                with a_tab_evidence:
                    st.markdown("**Asset Metadata & Discovery Attributes:**")
                    st.json({
                        "resource_arn": target_arn,
                        "resource_name": target_asset.get("resource_name"),
                        "service": target_asset.get("service"),
                        "region": target_asset.get("region"),
                        "status": target_asset.get("status"),
                        "tags": target_asset.get("tags", []),
                        "critical_failures": target_asset.get("critical_failures", 0),
                        "high_failures": target_asset.get("high_failures", 0),
                        "total_checks": target_asset.get("total_checks_evaluated", len(asset_findings))
                    })

                with a_tab_checks:
                    if asset_findings:
                        df_af = pd.DataFrame([{
                            "Status": f.get("status"),
                            "Severity": (f.get("severity") or "").upper(),
                            "Check Title": f.get("check_title"),
                            "Check ID": f.get("check_id"),
                            "Description": f.get("description") or f.get("status_extended")
                        } for f in asset_findings])
                        st.dataframe(df_af, use_container_width=True, height=220)
                    else:
                        st.info("No specific findings mapped to this asset ARN.")

                with a_tab_scans:
                    scan_id_val = active_id or "scan_current"
                    acc_id_val = (summary_data.get("account_id") if summary_data else None) or "AWS Account"
                    dur_val = (summary_data.get("duration_seconds") if summary_data else None) or 0
                    sc_col1, sc_col2, sc_col3 = st.columns(3)
                    sc_col1.markdown(f"**Evaluating Scan:**<br>`{scan_id_val}`", unsafe_allow_html=True)
                    sc_col2.markdown(f"**Target Account:**<br>`{acc_id_val}`", unsafe_allow_html=True)
                    sc_col3.markdown(f"**Duration:**<br>`{dur_val} seconds`", unsafe_allow_html=True)
                    st.markdown(f"""
                    <div class="info-grid-box" style="font-size: 0.85rem; margin-top: 10px;">
                        <div><strong>Scan Posture:</strong> <span class="badge-pass">COMPLETED</span></div>
                        <div style="margin-top: 4px;"><strong>Assessment Engine:</strong> Prowler v5 Cloud Security Engine</div>
                    </div>
                    """, unsafe_allow_html=True)

                with a_tab_events:
                    st.markdown("**Asset Audit Trail & Discovery Events:**")
                    st.markdown(f"""
                    <div style="border-left: 2px solid #38bdf8; padding-left: 14px; margin-left: 6px; font-size: 0.82rem; line-height: 1.6;">
                        <div style="margin-bottom: 10px;">
                            <span style="color: #38bdf8; font-weight: 600;">● Cloud Asset Discovery</span><br>
                            <span style="color: #94a3b8;">Resource identified in region <code>{target_asset.get('region', 'global')}</code></span>
                        </div>
                        <div style="margin-bottom: 10px;">
                            <span style="color: #38bdf8; font-weight: 600;">● Security Baseline Assessment</span><br>
                            <span style="color: #94a3b8;">Evaluated {target_asset.get('total_checks_evaluated', len(asset_findings))} rules against CIS & Best Practice benchmarks</span>
                        </div>
                        <div>
                            <span style="color: {'#ef4444' if target_asset.get('status') == 'vulnerable' else '#22c55e'}; font-weight: 600;">● Posture Established: {target_asset.get('status', 'secure').upper()}</span><br>
                            <span style="color: #94a3b8;">Posture state updated in asset catalog</span>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
        else:
            st.info("No assets discovered or asset data not available.")

    # TAB 5: REPORTS & EXPORT BUNDLES
    with tab_reports:
        st.markdown("#### 📥 Enterprise Deliverables & Compliance Bundles")
        st.markdown("Download full assessment reports in standard industry formats (Executive PDF, OCSF JSON, CSV, and interactive HTML).")

        rep_col_pdf, rep_col_zip, rep_col_html, rep_col_csv = st.columns(4)
        auth_param = f"?api_key={current_api_key}" if current_api_key else ""

        with rep_col_pdf:
            st.markdown("""
            <div class="metric-card">
                <div class="metric-title">Executive PDF Deliverable</div>
                <div style="font-size: 1.15rem; font-weight: 700; margin: 8px 0; color: #38bdf8;">📕 Executive Report (.pdf)</div>
                <div class="metric-subtitle">Publication-grade audit report for C-suite, board, and auditors.</div>
            </div>
            """, unsafe_allow_html=True)
            if not st.session_state["demo_mode"] and active_id:
                st.link_button("📕 Open Executive PDF", f"{current_api_url}/api/v1/scans/{active_id}/report-pdf{auth_param}", use_container_width=True)
            else:
                try:
                    from src.reports.pdf_generator import generate_executive_pdf_report
                    demo_pdf_buf = generate_executive_pdf_report(SAMPLE_DEMO_DATA["summary"], SAMPLE_DEMO_DATA["findings"], SAMPLE_DEMO_DATA["assets"])
                    st.download_button("📕 Download Demo PDF", data=demo_pdf_buf.getvalue(), file_name="prowler_executive_report_demo.pdf", mime="application/pdf", use_container_width=True, key="dl_tab5_exec_pdf")
                except Exception as e:
                    st.button("📕 Executive PDF (Online Only)", disabled=True, use_container_width=True, key="btn_tab5_exec_err")

        with rep_col_zip:
            st.markdown("""
            <div class="metric-card">
                <div class="metric-title">Complete Scan Archive</div>
                <div style="font-size: 1.15rem; font-weight: 700; margin: 8px 0;">📦 Full Bundle (.zip)</div>
                <div class="metric-subtitle">Includes PDF, findings.json, assets.json, summary.json, CSV & HTML.</div>
            </div>
            """, unsafe_allow_html=True)
            if not st.session_state["demo_mode"] and active_id:
                st.link_button("⬇️ Download .ZIP Bundle", f"{current_api_url}/api/v1/scans/{active_id}/download-zip{auth_param}", use_container_width=True)
            else:
                demo_zip_bytes = json.dumps(SAMPLE_DEMO_DATA, indent=2).encode('utf-8')
                st.download_button("⬇️ Download Demo Archive (JSON)", data=demo_zip_bytes, file_name="prowler_demo_bundle.json", mime="application/json", use_container_width=True, key="dl_tab5_zip_demo")

        with rep_col_html:
            st.markdown("""
            <div class="metric-card">
                <div class="metric-title">Interactive HTML Report</div>
                <div style="font-size: 1.15rem; font-weight: 700; margin: 8px 0;">🌐 Standalone HTML</div>
                <div class="metric-subtitle">Visual, interactive HTML report with embedded search and charts.</div>
            </div>
            """, unsafe_allow_html=True)
            if not st.session_state["demo_mode"] and active_id:
                st.link_button("🌐 Open HTML Report", f"{current_api_url}/api/v1/scans/{active_id}/report-html{auth_param}", use_container_width=True)
            else:
                st.button("🌐 Open HTML Report (Online Scans Only)", disabled=True, use_container_width=True, key="btn_tab5_html_err")

        with rep_col_csv:
            st.markdown("""
            <div class="metric-card">
                <div class="metric-title">Tabular Findings</div>
                <div style="font-size: 1.15rem; font-weight: 700; margin: 8px 0;">📄 Spreadsheet (.csv)</div>
                <div class="metric-subtitle">Raw security findings ready for Excel, Jira, or SIEM ingestion.</div>
            </div>
            """, unsafe_allow_html=True)
            if not st.session_state["demo_mode"] and active_id:
                st.link_button("⬇️ Direct CSV Download", f"{current_api_url}/api/v1/scans/{active_id}/report-csv{auth_param}", use_container_width=True)
            elif findings_data:
                csv_bytes = pd.DataFrame(findings_data).to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="⬇️ Download Findings CSV",
                    data=csv_bytes,
                    file_name=f"prowler_findings_{active_id or 'demo'}.csv",
                    mime="text/csv",
                    use_container_width=True,
                    key="dl_tab5_findings_csv"
                )

        # Compliance Framework Exports Matrix
        comp_overview = summary_data.get("compliance_overview", {})
        if comp_overview:
            st.markdown("---")
            st.markdown("##### 📜 Framework-Specific Compliance Reports (PDF & CSV)")
            st.caption("Generate tailored compliance evidence for regulatory audits:")
            
            cf_col_sel, cf_col_pdf, cf_col_csv = st.columns([2, 1, 1])
            with cf_col_sel:
                selected_fw = st.selectbox("Select Target Compliance Standard", list(comp_overview.keys()), index=0, key="sb_tab5_compliance_fw")
            with cf_col_pdf:
                if not st.session_state["demo_mode"] and active_id:
                    st.link_button(f"📕 {selected_fw} PDF", f"{current_api_url}/api/v1/scans/{active_id}/compliance/{selected_fw}/pdf{auth_param}", use_container_width=True)
                else:
                    try:
                        from src.reports.pdf_generator import generate_compliance_pdf_report
                        cf_pdf_buf = generate_compliance_pdf_report(selected_fw, summary_data, findings_data)
                        st.download_button(f"📕 Download {selected_fw} PDF", data=cf_pdf_buf.getvalue(), file_name=f"prowler_{selected_fw}_report.pdf", mime="application/pdf", use_container_width=True, key=f"dl_tab5_pdf_{selected_fw}")
                    except Exception:
                        st.button(f"📕 {selected_fw} PDF", disabled=True, use_container_width=True, key=f"btn_tab5_pdf_err_{selected_fw}")
            with cf_col_csv:
                if not st.session_state["demo_mode"] and active_id:
                    st.link_button(f"📄 {selected_fw} CSV", f"{current_api_url}/api/v1/scans/{active_id}/compliance/{selected_fw}/csv{auth_param}", use_container_width=True)
                else:
                    try:
                        from src.reports.csv_generator import generate_compliance_csv
                        cf_csv_buf = generate_compliance_csv(findings_data, selected_fw)
                        st.download_button(f"📄 Download {selected_fw} CSV", data=cf_csv_buf.getvalue(), file_name=f"prowler_{selected_fw}_findings.csv", mime="text/csv", use_container_width=True, key=f"dl_tab5_csv_{selected_fw}")
                    except Exception:
                        st.button(f"📄 {selected_fw} CSV", disabled=True, use_container_width=True, key=f"btn_tab5_csv_err_{selected_fw}")

        # JSON Summary Inspector
        with st.expander("🔍 View Raw Audit Metadata (`summary.json`)"):
            st.json(summary_data)
else:
    st.info("👈 **Get Started:** Select your AWS Role ARN or Access Keys in the sidebar, or toggle **'Demo Mode'** to explore the dashboard immediately.")
