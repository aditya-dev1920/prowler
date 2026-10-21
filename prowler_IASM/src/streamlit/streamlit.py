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

# ------------------------------------------------------------------------------
# 1. Page Configuration & Custom Theme
# ------------------------------------------------------------------------------
st.set_page_config(
    page_title="Nopal IASM - Cloud Security Posture Management",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

DEFAULT_API_URL = os.getenv("API_BASE_URL", "http://localhost:8000").rstrip("/")
DEFAULT_API_KEY = os.getenv("API_KEY", "").strip()

# ------------------------------------------------------------------------------
# 2. Premium Enterprise CSS Styles & Smooth Animations
# ------------------------------------------------------------------------------
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

# ------------------------------------------------------------------------------
# 3. Realistic Demo Dataset (For Instant Sales/Leadership Demonstrations)
# ------------------------------------------------------------------------------
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
        "total_assets_scanned": 48
    },
    "findings": [
        {
            "id": "f-01",
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
            "remediation": "Enable Account-level and Bucket-level S3 Public Access Block immediately.",
            "remediation_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
        },
        {
            "id": "f-02",
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
            "status_extended": "Root account has active access key ID 'AKIA...EXAMPLE'.",
            "remediation": "Delete root access keys immediately and enforce IAM roles or SSO for administrative tasks.",
            "remediation_url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials"
        },
        {
            "id": "f-03",
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
            "remediation": "Restrict inbound traffic to trusted corporate CIDR ranges or utilize AWS Systems Manager Session Manager.",
            "remediation_url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html"
        },
        {
            "id": "f-04",
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
            "remediation": "Create a KMS encrypted snapshot and restore the database to an encrypted instance.",
            "remediation_url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"
        },
        {
            "id": "f-05",
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
            "remediation": "Configure CloudTrail with `--is-multi-region-trail` to capture global API activities.",
            "remediation_url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html"
        },
        {
            "id": "f-06",
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
            "remediation": "N/A - Key is compliant.",
            "remediation_url": ""
        }
    ],
    "assets": [
        {"resource_arn": "arn:aws:s3:::prod-customer-exports-storage", "resource_name": "prod-customer-exports-storage", "service": "s3", "region": "us-east-1", "status": "vulnerable", "critical_failures": 1, "high_failures": 0, "total_checks_evaluated": 12},
        {"resource_arn": "arn:aws:iam::849204128941:root", "resource_name": "root-account", "service": "iam", "region": "global", "status": "vulnerable", "critical_failures": 1, "high_failures": 0, "total_checks_evaluated": 16},
        {"resource_arn": "sg-04a9bf912984efc", "resource_name": "default-vpc-ingress-sg", "service": "ec2", "region": "us-east-1", "status": "vulnerable", "critical_failures": 1, "high_failures": 1, "total_checks_evaluated": 8},
        {"resource_arn": "arn:aws:rds:ap-south-1:849204128941:db:production-analytics-pg", "resource_name": "production-analytics-pg", "service": "rds", "region": "ap-south-1", "status": "vulnerable", "critical_failures": 0, "high_failures": 1, "total_checks_evaluated": 10},
        {"resource_arn": "arn:aws:kms:us-east-1:849204128941:key/1234abcd", "resource_name": "prod-encryption-cmk", "service": "kms", "region": "us-east-1", "status": "secure", "critical_failures": 0, "high_failures": 0, "total_checks_evaluated": 9}
    ]
}

# ------------------------------------------------------------------------------
# 4. High-Performance Caching Helpers (Zero Lag on UI Interactions)
# ------------------------------------------------------------------------------
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
def fetch_scan_dataset(url: str, scan_id: str, api_key: str = "") -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Caches scan results in memory so tab navigation and filtering are instant (0ms)."""
    summary = None
    findings = []
    assets = []
    headers = {"X-API-Key": api_key.strip()} if api_key.strip() else {}
    try:
        s_res = requests.get(f"{url}/api/v1/scans/{scan_id}/summary", headers=headers, timeout=5)
        if s_res.status_code == 200:
            summary = s_res.json()
        f_res = requests.get(f"{url}/api/v1/scans/{scan_id}/findings?limit=500", headers=headers, timeout=8)
        if f_res.status_code == 200:
            findings = f_res.json().get("findings", [])
        a_res = requests.get(f"{url}/api/v1/scans/{scan_id}/assets?limit=500", headers=headers, timeout=8)
        if a_res.status_code == 200:
            assets = a_res.json().get("assets", [])
    except Exception:
        pass
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

# ------------------------------------------------------------------------------
# 5. Sidebar Controls & Credentials Configuration
# ------------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### ⚙️ Scan Configuration")
    
    # Demo Mode Switch
    demo_toggle = st.toggle(
        "✨ Instant Demo Mode",
        value=st.session_state["demo_mode"],
        help="Populate the dashboard with rich realistic AWS security data without running scans."
    )
    st.session_state["demo_mode"] = demo_toggle

    if not st.session_state["demo_mode"]:
        st.markdown("---")
        endpoint_input = st.text_input("Microservice Endpoint", value=st.session_state["api_endpoint"]).rstrip("/")
        st.session_state["api_endpoint"] = endpoint_input
        current_api_url = endpoint_input

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

        if auth_mode == "IAM Role Assume (Recommended)":
            role_arn = st.text_input("Role ARN", placeholder="arn:aws:iam::123456789012:role/ProwlerIASMScanRole")
            external_id = st.text_input("External ID (Optional)", placeholder="enterprise-client-id")
        else:
            access_key = st.text_input("AWS Access Key ID", type="password")
            secret_key = st.text_input("AWS Secret Access Key", type="password")
            session_token = st.text_input("AWS Session Token (Optional)", type="password")

        st.markdown("#### 2. Scan Scope")
        selected_regions = st.multiselect(
            "Target Regions",
            ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-south-1", "ap-southeast-1"],
            default=["us-east-1", "ap-south-1"]
        )

        all_services = ["s3", "iam", "ec2", "rds", "vpc", "cloudtrail", "kms", "cloudwatch", "guardduty"]
        selected_services = st.multiselect(
            "Target Services (Default: All)",
            all_services,
            default=[]
        )

        # Connection Test Action
        st.markdown("---")
        if st.button("🔌 Verify STS Connection (< 500ms)", use_container_width=True):
            test_payload = {
                "role_arn": role_arn or None,
                "external_id": external_id or None,
                "access_key": access_key or None,
                "secret_key": secret_key or None,
                "session_token": session_token or None,
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
    else:
        current_api_url = st.session_state["api_endpoint"]
        current_api_key = st.session_state.get("api_key", "")
        st.info("💡 **Demo Mode Active**: Displaying realistic enterprise cloud audit data.")
        st.markdown("**Target Cloud:** AWS Production Infrastructure\n**Account ID:** `849204128941`\n**Regions:** `us-east-1, ap-south-1`")

# ------------------------------------------------------------------------------
# 6. Top Brand Header Bar
# ------------------------------------------------------------------------------
health_info = fetch_api_health(current_api_url, current_api_key)
api_online = health_info["online"]

status_html = (
    f'<div class="status-badge status-online"><span class="pulse-dot"></span> API Engine Online ({current_api_url})</div>'
    if api_online else
    '<div class="status-badge status-offline"><span class="pulse-dot"></span> Backend Offline (Demo Ready)</div>'
)

st.markdown(f"""
<div class="brand-header">
    <div class="brand-title">
        🛡️ NOPAL IASM 
        <span class="brand-badge">v1.0 Production</span>
    </div>
    <div>{status_html}</div>
</div>
""", unsafe_allow_html=True)

# ------------------------------------------------------------------------------
# 7. Action Bar & Scan Dispatcher
# ------------------------------------------------------------------------------
col_launch, col_history, col_refresh = st.columns([2.5, 2, 0.5])

with col_launch:
    if not st.session_state["demo_mode"]:
        st.markdown('<div class="primary-scan-btn">', unsafe_allow_html=True)
        if st.button("🚀 Trigger Security Posture Assessment", use_container_width=True, type="primary"):
            if auth_mode == "IAM Role Assume (Recommended)" and not role_arn:
                st.error("Please provide a valid AWS IAM Role ARN in the sidebar.")
            elif auth_mode == "Direct Access Keys" and (not access_key or not secret_key):
                st.error("Please provide AWS Access Key ID and Secret Access Key.")
            else:
                scan_payload = {
                    "role_arn": role_arn or None,
                    "external_id": external_id or None,
                    "access_key": access_key or None,
                    "secret_key": secret_key or None,
                    "session_token": session_token or None,
                    "regions": selected_regions,
                    "services": selected_services if selected_services else None,
                }
                try:
                    launch_res = requests.post(
                        f"{current_api_url}/api/v1/scans/run",
                        json=scan_payload,
                        headers=get_auth_headers(current_api_key),
                        timeout=10
                    )
                    if launch_res.status_code == 200:
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

with col_refresh:
    if st.button("🔄", help="Clear Cache & Refresh Dashboard"):
        st.cache_data.clear()
        st.rerun()

# ------------------------------------------------------------------------------
# 8. Live Scan Progress & Polling Indicator
# ------------------------------------------------------------------------------
if st.session_state.get("is_scanning") and st.session_state.get("active_scan_id"):
    scan_id = st.session_state["active_scan_id"]
    progress_bar = st.progress(0, text="Initializing Prowler security engine...")
    status_text = st.empty()
    cancel_btn_col, _ = st.columns([1, 4])
    
    with cancel_btn_col:
        if st.button("⏹️ Cancel Active Scan", type="secondary", use_container_width=True):
            try:
                requests.post(
                    f"{current_api_url}/api/v1/scans/{scan_id}/cancel",
                    headers=get_auth_headers(current_api_key),
                    timeout=5
                )
            except Exception:
                pass
            st.session_state["is_scanning"] = False
            st.warning("Scan cancellation requested.")
            st.rerun()

    start_time = time.time()
    steps = [
        (15, "Step 1/4: Authenticating STS credentials & verifying role assumption..."),
        (40, "Step 2/4: Discovering Cloud Asset topology across selected AWS regions..."),
        (75, "Step 3/4: Evaluating CIS benchmarks, IAM permissions & CIS/Attack-paths..."),
        (90, "Step 4/4: Compiling OCSF reports, asset inventories & ZIP bundles...")
    ]

    step_idx = 0
    while True:
        time.sleep(2.5)
        elapsed = int(time.time() - start_time)
        try:
            st_res = requests.get(
                f"{current_api_url}/api/v1/scans/{scan_id}/status",
                headers=get_auth_headers(current_api_key),
                timeout=5
            )
            if st_res.status_code == 200:
                s_data = st_res.json()
                curr_status = s_data.get("status")

                if step_idx < len(steps):
                    progress_bar.progress(steps[step_idx][0], text=steps[step_idx][1])
                    if elapsed > (step_idx + 1) * 8:
                        step_idx += 1

                status_text.caption(f"⏱️ Elapsed: **{elapsed}s** | Worker Status: **{curr_status.upper()}**")

                if curr_status == "completed":
                    progress_bar.progress(100, text="🎉 Security Assessment Finished!")
                    st.session_state["is_scanning"] = False
                    st.cache_data.clear()
                    time.sleep(1)
                    st.rerun()
                elif curr_status in ("failed", "cancelled"):
                    progress_bar.empty()
                    status_text.error(f"❌ Scan {curr_status}: {s_data.get('error_message')}")
                    st.session_state["is_scanning"] = False
                    break
        except Exception as e:
            status_text.error(f"Polling error: {e}")
            break

# ------------------------------------------------------------------------------
# 9. Main Intelligence Dashboard (Tabs Interface)
# ------------------------------------------------------------------------------
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
    tab_overview, tab_findings, tab_assets, tab_reports = st.tabs([
        "📊 Executive Overview",
        "🔍 Findings Explorer",
        "☁️ Cloud Asset Inventory",
        "📦 Reports & Bundles"
    ])

    # --------------------------------------------------------------------------
    # TAB 1: EXECUTIVE OVERVIEW
    # --------------------------------------------------------------------------
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

    # --------------------------------------------------------------------------
    # TAB 2: FINDINGS EXPLORER
    # --------------------------------------------------------------------------
    with tab_findings:
        st.markdown("#### 🔍 Filter & Investigate Vulnerabilities")
        
        # Interactive Filtering Toolbar
        fil_col1, fil_col2, fil_col3, fil_col4, fil_view = st.columns([1.2, 1.2, 1.4, 2.5, 1.2])
        with fil_col1:
            sel_severity = st.selectbox("Severity", ["ALL", "critical", "high", "medium", "low"])
        with fil_col2:
            sel_status = st.selectbox("Status", ["ALL", "FAIL", "PASS"])
        with fil_col3:
            available_svcs = sorted(list({(f.get("service") or f.get("service_name") or "other").lower() for f in findings_data}))
            sel_service = st.selectbox("Service", ["ALL"] + [s.upper() for s in available_svcs])
        with fil_col4:
            search_query = st.text_input("Search", placeholder="Filter by check, resource ARN, or text...")
        with fil_view:
            view_mode = st.radio("View", ["Cards", "Table"], horizontal=True, label_visibility="visible")

        # Apply In-Memory Filters (Instant 0ms latency)
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

        st.caption(f"Showing **{len(filtered_findings)}** of **{len(findings_data)}** evaluated security findings.")

        # Dual View Option: Cards View vs Grid View
        if filtered_findings:
            if view_mode == "Cards":
                for idx, item in enumerate(filtered_findings[:60]):
                    sev = (item.get("severity") or "low").lower()
                    stat = (item.get("status") or "PASS").upper()
                    badge_class = f"badge-{sev}" if stat == "FAIL" else "badge-pass"
                    
                    exp_title = f"{'🔴' if stat == 'FAIL' else '🟢'} [{stat}] {item.get('check_title')} — {item.get('service', '').upper()} ({sev.upper()})"
                    
                    with st.expander(exp_title, expanded=(idx < 2 and stat == 'FAIL')):
                        det_col1, det_col2 = st.columns([2.2, 1])
                        with det_col1:
                            st.markdown(f"**Resource:** `{item.get('resource_id')}`")
                            st.markdown(f"**Region:** `{item.get('region', 'global')}` | **Check ID:** `{item.get('check_id')}`")
                            st.markdown(f"**Details:** {item.get('description') or item.get('status_extended')}")
                        with det_col2:
                            st.markdown(f"**Severity:** <span class='{badge_class}'>{sev.upper()}</span>", unsafe_allow_html=True)
                            if item.get("remediation"):
                                st.info(f"💡 **Remediation:**\n{item.get('remediation')}")
                            if item.get("remediation_url"):
                                st.markdown(f"[📖 Official AWS Remediation Guide]({item.get('remediation_url')})")
            else:
                # Tabular Data Grid View
                df_findings = pd.DataFrame(filtered_findings)
                if "service_name" not in df_findings.columns and "service" in df_findings.columns:
                    df_findings["service_name"] = df_findings["service"]
                if "status_extended" not in df_findings.columns and "description" in df_findings.columns:
                    df_findings["status_extended"] = df_findings["description"]

                cols = [c for c in ["status", "severity", "service_name", "check_title", "region", "resource_id", "status_extended"] if c in df_findings.columns]
                st.dataframe(df_findings[cols], use_container_width=True, height=450)
        else:
            st.info("No findings match the selected filters.")

    # --------------------------------------------------------------------------
    # TAB 3: CLOUD ASSET INVENTORY
    # --------------------------------------------------------------------------
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
        else:
            st.info("No assets discovered or asset data not available.")

    # --------------------------------------------------------------------------
    # TAB 4: REPORTS & EXPORT BUNDLES
    # --------------------------------------------------------------------------
    with tab_reports:
        st.markdown("#### 📥 Enterprise Deliverables & Compliance Bundles")
        st.markdown("Download full assessment reports in standard industry formats (OCSF JSON, CSV, and interactive HTML).")

        rep_col1, rep_col2, rep_col3 = st.columns(3)
        
        with rep_col1:
            st.markdown("""
            <div class="metric-card">
                <div class="metric-title">Complete Scan Archive</div>
                <div style="font-size: 1.2rem; font-weight: 700; margin: 8px 0;">📦 Full Bundle (.zip)</div>
                <div class="metric-subtitle">Includes findings.json, assets.json, summary.json, CSV & HTML report.</div>
            </div>
            """, unsafe_allow_html=True)
            if not st.session_state["demo_mode"] and active_id:
                auth_param = f"?api_key={current_api_key}" if current_api_key else ""
                st.link_button("⬇️ Download .ZIP Bundle", f"{current_api_url}/api/v1/scans/{active_id}/download-zip{auth_param}", use_container_width=True)
            else:
                demo_zip_bytes = json.dumps(SAMPLE_DEMO_DATA, indent=2).encode('utf-8')
                st.download_button("⬇️ Download Demo Archive (JSON)", data=demo_zip_bytes, file_name="prowler_demo_bundle.json", mime="application/json", use_container_width=True)

        with rep_col2:
            st.markdown("""
            <div class="metric-card">
                <div class="metric-title">Executive HTML Report</div>
                <div style="font-size: 1.2rem; font-weight: 700; margin: 8px 0;">🌐 Interactive Dashboard</div>
                <div class="metric-subtitle">Visual, standalone HTML report for C-suite and auditors.</div>
            </div>
            """, unsafe_allow_html=True)
            if not st.session_state["demo_mode"] and active_id:
                auth_param = f"?api_key={current_api_key}" if current_api_key else ""
                st.link_button("🌐 Open HTML Report", f"{current_api_url}/api/v1/scans/{active_id}/report-html{auth_param}", use_container_width=True)
            else:
                st.button("🌐 Open HTML Report (Online Scans Only)", disabled=True, use_container_width=True)

        with rep_col3:
            st.markdown("""
            <div class="metric-card">
                <div class="metric-title">Tabular Findings</div>
                <div style="font-size: 1.2rem; font-weight: 700; margin: 8px 0;">📄 Spreadsheet (.csv)</div>
                <div class="metric-subtitle">Raw security findings ready for Excel, Jira, or SIEM ingestion.</div>
            </div>
            """, unsafe_allow_html=True)
            if findings_data:
                csv_bytes = pd.DataFrame(findings_data).to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="⬇️ Download Findings CSV",
                    data=csv_bytes,
                    file_name=f"prowler_findings_{active_id or 'demo'}.csv",
                    mime="text/csv",
                    use_container_width=True
                )

        # JSON Summary Inspector
        with st.expander("🔍 View Raw Audit Metadata (`summary.json`)"):
            st.json(summary_data)
else:
    st.info("👈 **Get Started:** Select your AWS Role ARN or Access Keys in the sidebar, or toggle **'✨ Instant Demo Mode'** to explore the dashboard immediately.")
