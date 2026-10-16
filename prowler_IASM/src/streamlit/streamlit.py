import json
import os
import time
from pathlib import Path
import pandas as pd
import plotly.express as px
import requests
import streamlit as st


# App Configuration
st.set_page_config(
    page_title="Prowler IASM Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")

# Custom Styles
st.markdown("""
<style>
    .metric-card {
        background-color: #1e293b;
        border-radius: 8px;
        padding: 16px;
        color: white;
        border: 1px solid #334155;
    }
    .stButton>button {
        width: 100%;
        border-radius: 6px;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar - AWS Configuration & Scope
st.sidebar.title("🛡️ Prowler IASM")
st.sidebar.caption("Internal Attack Surface Management & Cloud Security")

st.sidebar.subheader("1. Microservice Endpoint")
api_url = st.sidebar.text_input("API URL", value=API_BASE_URL).rstrip("/")

st.sidebar.subheader("2. Authentication Mode")
auth_mode = st.sidebar.radio(
    "Choose AWS Credential Method",
    ["IAM Role Assume (Recommended)", "Direct Access Keys"]
)

role_arn = ""
external_id = ""
access_key = ""
secret_key = ""
session_token = ""

if auth_mode == "IAM Role Assume (Recommended)":
    role_arn = st.sidebar.text_input("Role ARN", placeholder="arn:aws:iam::123456789012:role/ProwlerIASMScanRole")
    external_id = st.sidebar.text_input("External ID (Optional)", placeholder="prowler-iasm-client-id")
else:
    access_key = st.sidebar.text_input("AWS Access Key ID", type="password")
    secret_key = st.sidebar.text_input("AWS Secret Access Key", type="password")
    session_token = st.sidebar.text_input("AWS Session Token (Optional)", type="password")

st.sidebar.subheader("3. Scan Scope")
selected_regions = st.sidebar.multiselect(
    "AWS Regions",
    ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-south-1", "ap-southeast-1"],
    default=["us-east-1", "ap-south-1"]
)

all_services = ["s3", "iam", "ec2", "rds", "vpc", "cloudtrail", "kms", "cloudwatch", "guardduty"]
selected_services = st.sidebar.multiselect(
    "Target Services (Leave blank for all)",
    all_services,
    default=[]
)

# Test Connection Action
st.sidebar.markdown("---")
if st.sidebar.button("🔌 Test Connection (< 500ms)", type="secondary"):
    payload = {
        "role_arn": role_arn or None,
        "external_id": external_id or None,
        "access_key": access_key or None,
        "secret_key": secret_key or None,
        "session_token": session_token or None,
        "region": selected_regions[0] if selected_regions else "us-east-1"
    }
    with st.spinner("Verifying AWS STS connection..."):
        try:
            res = requests.post(f"{api_url}/api/v1/scans/test-connection", json=payload, timeout=10)
            if res.status_code == 200:
                data = res.json()
                if data.get("status") == "success":
                    st.sidebar.success(f" Connected! Account: {data.get('account')}")
                    st.sidebar.info(f"Latency: {data.get('duration_ms')} ms")
                else:
                    st.sidebar.error(f"❌ Failed: {data.get('message')}")
            else:
                st.sidebar.error(f"HTTP {res.status_code}: {res.text}")
        except Exception as e:
            st.sidebar.error(f"Could not connect to API: {e}")

# Main Dashboard View
st.title("AWS Attack Surface & Security Posture")
st.markdown("Run automated, production-grade security assessments and download full compliance bundles.")

col_run, col_history = st.columns([2, 1])

with col_run:
    if st.button("🚀 Run Security Assessment Scan", type="primary"):
        if auth_mode == "IAM Role Assume (Recommended)" and not role_arn:
            st.error("Please provide a valid Role ARN in the sidebar.")
        elif auth_mode == "Direct Access Keys" and (not access_key or not secret_key):
            st.error("Please provide AWS Access Key and Secret Key in the sidebar.")
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
                launch_res = requests.post(f"{api_url}/api/v1/scans/run", json=scan_payload, timeout=10)
                if launch_res.status_code == 200:
                    scan_info = launch_res.json()
                    scan_id = scan_info["scan_id"]
                    st.session_state["active_scan_id"] = scan_id

                    progress_placeholder = st.empty()
                    status_placeholder = st.empty()

                    # Polling loop
                    start_time = time.time()
                    while True:
                        time.sleep(2)
                        st_res = requests.get(f"{api_url}/api/v1/scans/{scan_id}/status", timeout=5)
                        if st_res.status_code == 200:
                            s_data = st_res.json()
                            current_status = s_data["status"]
                            elapsed = int(time.time() - start_time)

                            status_placeholder.info(f"Status: **{current_status.upper()}** (Elapsed: {elapsed}s)")

                            if current_status == "completed":
                                progress_placeholder.success("🎉 Scan Completed Successfully!")
                                break
                            elif current_status == "failed":
                                progress_placeholder.error(f"❌ Scan Failed: {s_data.get('error_message')}")
                                break
                else:
                    st.error(f"Failed to launch scan: {launch_res.text}")
            except Exception as e:
                st.error(f"API Error: {e}")

with col_history:
    st.subheader("Recent Scans")
    try:
        scans_res = requests.get(f"{api_url}/api/v1/scans", timeout=5)
        if scans_res.status_code == 200:
            scans_list = scans_res.json().get("scans", [])
            scan_options = [s["scan_id"] for s in scans_list]
            if scan_options:
                selected_scan = st.selectbox("Select Past Scan", scan_options, index=0)
                st.session_state["active_scan_id"] = selected_scan
    except Exception:
        pass

# Display Scan Results
active_scan_id = st.session_state.get("active_scan_id")

if active_scan_id:
    st.markdown("---")
    st.subheader(f"Results for Scan: `{active_scan_id}`")

    # Fetch summary
    try:
        summary_res = requests.get(f"{api_url}/api/v1/scans/{active_scan_id}/summary", timeout=5)
        if summary_res.status_code == 200:
            summary = summary_res.json()

            # KPI Cards
            kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
            kpi1.metric("Security Score", f"{summary.get('security_score', 0)}%")
            kpi2.metric("Critical Risks", summary.get("critical", 0), delta_color="inverse")
            kpi3.metric("High Risks", summary.get("high", 0), delta_color="inverse")
            kpi4.metric("Passed Checks", summary.get("passed", 0))
            kpi5.metric("Total Findings", summary.get("total_findings", 0))

            # Charts
            chart_col1, chart_col2 = st.columns(2)

            with chart_col1:
                st.markdown("### Severity Distribution")
                sev_counts = [
                    summary.get("critical", 0),
                    summary.get("high", 0),
                    summary.get("medium", 0),
                    summary.get("low", 0),
                ]
                if sum(sev_counts) > 0:
                    sev_data = pd.DataFrame({
                        "Severity": ["Critical", "High", "Medium", "Low"],
                        "Count": sev_counts
                    })
                    fig_donut = px.pie(
                        sev_data,
                        names="Severity",
                        values="Count",
                        hole=0.45,
                        color="Severity",
                        color_discrete_map={
                            "Critical": "#dc2626",
                            "High": "#f97316",
                            "Medium": "#eab308",
                            "Low": "#3b82f6"
                        }
                    )
                    st.plotly_chart(fig_donut, use_container_width=True)
                else:
                    st.success("✅ Zero active risks detected! All security evaluations passed.")

            with chart_col2:
                st.markdown("### Top Failing AWS Services")
                svc_breakdown = summary.get("services_breakdown", {})
                svc_list = []
                if svc_breakdown:
                    for svc, stats in svc_breakdown.items():
                        failed_count = stats.get("FAIL") if "FAIL" in stats else stats.get("fail", 0)
                        passed_count = stats.get("PASS") if "PASS" in stats else stats.get("pass", 0)
                        if failed_count > 0:
                            svc_list.append({
                                "Service": svc.upper(),
                                "Failed": failed_count,
                                "Passed": passed_count
                            })
                if svc_list:
                    svc_df = pd.DataFrame(svc_list).sort_values(by="Failed", ascending=False).head(8)
                    fig_bar = px.bar(
                        svc_df,
                        x="Service",
                        y="Failed",
                        color="Failed",
                        color_continuous_scale="Reds",
                        text="Failed"
                    )
                    st.plotly_chart(fig_bar, use_container_width=True)
                else:
                    st.info("No service-level failures reported.")

            # Download Buttons
            st.markdown("### 📥 Reports & Bundles")
            btn_col1, btn_col2 = st.columns([1, 1])
            with btn_col1:
                st.markdown(
                    f'<a href="{api_url}/api/v1/scans/{active_scan_id}/download-zip" target="_blank">'
                    f'<button style="background-color:#0284c7;color:white;padding:10px 20px;border-radius:6px;border:none;cursor:pointer;font-weight:600;width:100%">'
                    f'📦 Download Full Bundle (.zip)'
                    f'</button></a>',
                    unsafe_allow_html=True
                )
            with btn_col2:
                st.markdown(
                    f'<a href="{api_url}/api/v1/scans/{active_scan_id}/report-html" target="_blank">'
                    f'<button style="background-color:#334155;color:white;padding:10px 20px;border-radius:6px;border:none;cursor:pointer;font-weight:600;width:100%">'
                    f'🌐 View Interactive HTML Report'
                    f'</button></a>',
                    unsafe_allow_html=True
                )

            # Detailed Findings Table
            st.markdown("---")
            st.subheader("🔍 Findings Explorer")
            findings_res = requests.get(f"{api_url}/api/v1/scans/{active_scan_id}/findings?limit=200", timeout=10)
            if findings_res.status_code == 200:
                findings_data = findings_res.json().get("findings", [])
                if findings_data:
                    df = pd.DataFrame(findings_data)
                    if "service_name" not in df.columns and "service" in df.columns:
                        df["service_name"] = df["service"]
                    if "status_extended" not in df.columns and "description" in df.columns:
                        df["status_extended"] = df["description"]

                    display_cols = [
                        col for col in [
                            "status", "severity", "service_name", "check_title",
                            "resource_id", "region", "status_extended"
                        ] if col in df.columns
                    ]
                    st.dataframe(df[display_cols], use_container_width=True)
                else:
                    st.info("No findings found for this scan.")

    except Exception as e:
        st.warning(f"Could not load scan data: {e}")

