#!/usr/bin/env bash
# ==============================================================================
# run_scan.sh - Standalone Prowler Automation Script
# Runs 100% natively without Docker.
# Produces: findings.json, assets.json, summary.json, and a downloadable .zip
# ==============================================================================

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Defaults
ROLE_ARN=""
EXTERNAL_ID=""
ACCESS_KEY=""
SECRET_KEY=""
SESSION_TOKEN=""
REGIONS="us-east-1,ap-south-1"
OUTPUT_DIR="./scan_results"
FORMAT="all"  # options: zip, json, all

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --role-arn <ARN>            IAM Role ARN to assume (AssumeRole mode)
  --external-id <ID>          Optional External ID for AssumeRole
  --access-key <KEY>          AWS Access Key ID (Direct Credentials mode)
  --secret-key <SECRET>       AWS Secret Access Key
  --session-token <TOKEN>     Optional AWS Session Token
  --regions <reg1,reg2>       Comma-separated AWS regions (default: us-east-1,ap-south-1)
  --output-dir <DIR>          Output directory (default: ./scan_results)
  --format <zip|json|all>     Output format to generate (default: all)
  -h, --help                  Show this help message
EOF
    exit 0
}

# Parse CLI arguments
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --role-arn) ROLE_ARN="$2"; shift 2 ;;
        --external-id) EXTERNAL_ID="$2"; shift 2 ;;
        --access-key) ACCESS_KEY="$2"; shift 2 ;;
        --secret-key) SECRET_KEY="$2"; shift 2 ;;
        --session-token) SESSION_TOKEN="$2"; shift 2 ;;
        --regions) REGIONS="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --format) FORMAT="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Split comma-separated regions into array for prowler CLI
IFS=',' read -r -a REGION_ARRAY <<< "$REGIONS"

# ------------------------------------------------------------------------------
# STEP 1: PRE-FLIGHT AUTHENTICATION VERIFICATION
# ------------------------------------------------------------------------------
PREFLIGHT_JSON=$(uv run python -c "
import sys, json, boto3
from botocore.exceptions import ClientError, NoCredentialsError

role_arn = '''$ROLE_ARN'''.strip()
external_id = '''$EXTERNAL_ID'''.strip()
access_key = '''$ACCESS_KEY'''.strip()
secret_key = '''$SECRET_KEY'''.strip()
session_token = '''$SESSION_TOKEN'''.strip()
region = '${REGION_ARRAY[0]}'

try:
    if role_arn:
        sts = boto3.client('sts', region_name=region)
        kwargs = {'RoleArn': role_arn, 'RoleSessionName': 'ProwlerPreflightCheck', 'DurationSeconds': 900}
        if external_id:
            kwargs['ExternalId'] = external_id
        assumed = sts.assume_role(**kwargs)['Credentials']
        test_client = boto3.client(
            'sts',
            aws_access_key_id=assumed['AccessKeyId'],
            aws_secret_access_key=assumed['SecretAccessKey'],
            aws_session_token=assumed['SessionToken'],
            region_name=region
        )
    elif access_key and secret_key:
        test_client = boto3.client(
            'sts',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token if session_token else None,
            region_name=region
        )
    else:
        test_client = boto3.client('sts', region_name=region)

    identity = test_client.get_caller_identity()
    print(json.dumps({'connected': True, 'account_id': identity.get('Account'), 'arn': identity.get('Arn')}))
except Exception as e:
    print(json.dumps({'connected': False, 'error': str(e)}))
")

CONNECTED=$(echo "$PREFLIGHT_JSON" | jq -r '.connected')
if [[ "$CONNECTED" != "true" ]]; then
    ERROR_MSG=$(echo "$PREFLIGHT_JSON" | jq -r '.error')
    echo "{\"status\": \"not_configured\", \"message\": \"AWS account not configured or credentials invalid\", \"error\": \"$ERROR_MSG\"}"
    exit 1
fi

ACCOUNT_ID=$(echo "$PREFLIGHT_JSON" | jq -r '.account_id')
TIMESTAMP=$(date -u +"%Y%m%d_%H%M%S")
SCAN_ID="scan_${ACCOUNT_ID}_${TIMESTAMP}"
TARGET_DIR="${OUTPUT_DIR}/${SCAN_ID}"
mkdir -p "$TARGET_DIR"

# ------------------------------------------------------------------------------
# STEP 2: BUILD PROWLER CLI COMMAND
# ------------------------------------------------------------------------------
CMD=(uv run prowler aws)
CMD+=(--output-directory "$TARGET_DIR")
CMD+=(--output-filename "report")
CMD+=(--output-modes "json-ocsf" "csv" "html")
CMD+=(--excluded-service "inspector2")
CMD+=(--ignore-exit-code-3)
CMD+=(--no-banner)

for r in "${REGION_ARRAY[@]}"; do
    CMD+=(--region "$r")
done

if [[ -n "$ROLE_ARN" ]]; then
    CMD+=(--role "$ROLE_ARN")
    if [[ -n "$EXTERNAL_ID" ]]; then
        CMD+=(--external-id "$EXTERNAL_ID")
    fi
elif [[ -n "$ACCESS_KEY" && -n "$SECRET_KEY" ]]; then
    export AWS_ACCESS_KEY_ID="$ACCESS_KEY"
    export AWS_SECRET_ACCESS_KEY="$SECRET_KEY"
    if [[ -n "$SESSION_TOKEN" ]]; then
        export AWS_SESSION_TOKEN="$SESSION_TOKEN"
    fi
fi

# ------------------------------------------------------------------------------
# STEP 3: EXECUTE SCAN
# ------------------------------------------------------------------------------
START_TIME=$(date +%s)
# Run scanner, logging to scan.log inside the target directory
"${CMD[@]}" > "${TARGET_DIR}/scan_execution.log" 2>&1 || true
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# ------------------------------------------------------------------------------
# STEP 4: EXTRACT FINDINGS & ASSETS INVENTORY (JSON)
# ------------------------------------------------------------------------------
OCSF_FILE="${TARGET_DIR}/report.ocsf.json"
uv run python -c "
import json
from pathlib import Path

ocsf_path = Path('''$OCSF_FILE''')
target_dir = Path('''$TARGET_DIR''')

findings = []
assets_map = {}
status_counts = {'FAIL': 0, 'PASS': 0, 'MANUAL': 0, 'MUTED': 0}
severity_counts = {
    'critical': {'fail': 0, 'pass': 0},
    'high': {'fail': 0, 'pass': 0},
    'medium': {'fail': 0, 'pass': 0},
    'low': {'fail': 0, 'pass': 0}
}

if ocsf_path.exists():
    with open(ocsf_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except Exception:
                continue

            status = record.get('status', 'PASS').upper()
            severity = record.get('severity', 'low').lower()
            status_counts[status] = status_counts.get(status, 0) + 1
            if severity in severity_counts and status in ('FAIL', 'PASS'):
                severity_counts[severity][status.lower()] += 1

            resources = record.get('resources', [])
            res = resources[0] if resources else {}
            res_arn = res.get('uid') or res.get('name') or 'unknown_resource'
            res_type = res.get('type', '')
            res_service = res_type.split('::')[-1].lower() if '::' in res_type else 'aws'
            res_region = res.get('region', 'global')

            # 1. Finding Item
            finding = {
                'id': record.get('id'),
                'check_id': record.get('metadata', {}).get('product', {}).get('name', record.get('activity_name')),
                'check_title': record.get('message'),
                'service': res_service,
                'severity': severity,
                'status': status,
                'region': res_region,
                'resource_id': res_arn,
                'resource_name': res.get('name', res_arn),
                'description': record.get('status_detail', record.get('message')),
                'remediation': record.get('remediation', {}).get('desc', ''),
                'remediation_url': (record.get('remediation', {}).get('references') or [''])[0]
            }
            findings.append(finding)

            # 2. Asset / Resource Item (Deduplicated)
            if res_arn not in assets_map:
                assets_map[res_arn] = {
                    'resource_arn': res_arn,
                    'resource_name': res.get('name', res_arn),
                    'service': res_service,
                    'region': res_region,
                    'status': 'secure',
                    'critical_failures': 0,
                    'high_failures': 0,
                    'medium_failures': 0,
                    'low_failures': 0,
                    'total_checks_evaluated': 0
                }
            assets_map[res_arn]['total_checks_evaluated'] += 1
            if status == 'FAIL':
                assets_map[res_arn]['status'] = 'vulnerable'
                if severity in severity_counts:
                    assets_map[res_arn][f'{severity}_failures'] += 1

assets_list = list(assets_map.values())

summary = {
    'scan_id': '''$SCAN_ID''',
    'account_id': '''$ACCOUNT_ID''',
    'duration_seconds': $DURATION,
    'total_findings': len(findings),
    'status_counts': status_counts,
    'severity_breakdown': severity_counts,
    'total_assets_scanned': len(assets_list)
}

with open(target_dir / 'findings.json', 'w', encoding='utf-8') as f:
    json.dump(findings, f, indent=2)

with open(target_dir / 'assets.json', 'w', encoding='utf-8') as f:
    json.dump(assets_list, f, indent=2)

with open(target_dir / 'summary.json', 'w', encoding='utf-8') as f:
    json.dump(summary, f, indent=2)
"

# ------------------------------------------------------------------------------
# STEP 5: CREATE ZIP ARCHIVE IF REQUESTED
# ------------------------------------------------------------------------------
ZIP_FILE=""
if [[ "$FORMAT" == "zip" || "$FORMAT" == "all" ]]; then
    ZIP_FILE="${TARGET_DIR}/${SCAN_ID}_bundle.zip"
    (
        cd "$TARGET_DIR"
        zip -q -r "$(basename "$ZIP_FILE")" findings.json assets.json summary.json report.csv report.html 2>/dev/null || \
        zip -q -r "$(basename "$ZIP_FILE")" *.json *.csv *.html 2>/dev/null
    )
fi

# ------------------------------------------------------------------------------
# STEP 6: OUTPUT STRUCTURED JSON ON STDOUT
# ------------------------------------------------------------------------------
SUMMARY_CONTENT=$(cat "${TARGET_DIR}/summary.json")
ZIP_ABS_PATH=""
if [[ -f "$ZIP_FILE" ]]; then
    ZIP_ABS_PATH="$(cd "$(dirname "$ZIP_FILE")" && pwd)/$(basename "$ZIP_FILE")"
fi

cat <<EOF
{
  "status": "success",
  "scan_id": "$SCAN_ID",
  "account_id": "$ACCOUNT_ID",
  "duration_seconds": $DURATION,
  "summary": $SUMMARY_CONTENT,
  "files": {
    "zip_bundle": "$ZIP_ABS_PATH",
    "findings_json": "$(cd "$TARGET_DIR" && pwd)/findings.json",
    "assets_json": "$(cd "$TARGET_DIR" && pwd)/assets.json",
    "summary_json": "$(cd "$TARGET_DIR" && pwd)/summary.json",
    "csv_report": "$(cd "$TARGET_DIR" && pwd)/report.csv",
    "html_report": "$(cd "$TARGET_DIR" && pwd)/report.html"
  }
}
EOF
