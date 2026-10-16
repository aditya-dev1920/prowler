#!/usr/bin/env bash
# run_scan.sh - Standalone Prowler Automation Script
# Runs 100% natively without Docker.
# Produces: findings.json, assets.json, summary.json, and a downloadable .zip

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Detect prowler and python binaries dynamically (works with pip install, venvs, or uv)
if command -v prowler &> /dev/null; then
    PROWLER_BIN=(prowler)
    PYTHON_BIN=(python3)
elif command -v uv &> /dev/null; then
    PROWLER_BIN=(uv run prowler)
    PYTHON_BIN=(uv run python)
elif command -v python &> /dev/null && python -c "import prowler" &> /dev/null; then
    PROWLER_BIN=(python -m prowler)
    PYTHON_BIN=(python)
else
    echo "{\"status\": \"error\", \"message\": \"Prowler is not installed. Install via: pip install prowler boto3\"}" >&2
    exit 1
fi

# Defaults
ROLE_ARN=""
EXTERNAL_ID=""
ACCESS_KEY=""
SECRET_KEY=""
SESSION_TOKEN=""
REGIONS="us-east-1,ap-south-1"
SERVICES=""
CHECKS=""
SCAN_ID=""
OUTPUT_DIR="./scan_results"
FORMAT="all"  # options: zip, json, all
TEST_CONNECTION_ONLY="false"

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
  --services <svc1,svc2>      Comma-separated AWS services to scan (e.g., s3,iam,ec2)
  --checks <check1,check2>    Comma-separated specific check names to run
  --scan-id <ID>              Custom scan ID / UUID (default: auto-generated)
  --output-dir <DIR>          Output directory (default: ./scan_results)
  --format <zip|json|all>     Output format to generate (default: all)
  --test-connection-only      Only verify AWS credentials/role and exit (no scan)
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
        --services) SERVICES="$2"; shift 2 ;;
        --checks) CHECKS="$2"; shift 2 ;;
        --scan-id) SCAN_ID="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --format) FORMAT="$2"; shift 2 ;;
        --test-connection-only) TEST_CONNECTION_ONLY="true"; shift 1 ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Split comma-separated regions into array for prowler CLI
IFS=',' read -r -a REGION_ARRAY <<< "$REGIONS"
PRIMARY_REGION="${REGION_ARRAY[0]:-us-east-1}"

# STEP 1: PRE-FLIGHT AUTHENTICATION VERIFICATION
# (Uses environment variables to prevent parameter injection & quote escaping)
PREFLIGHT_JSON=$(ROLE_ARN="$ROLE_ARN" \
  EXTERNAL_ID="$EXTERNAL_ID" \
  ACCESS_KEY="$ACCESS_KEY" \
  SECRET_KEY="$SECRET_KEY" \
  SESSION_TOKEN="$SESSION_TOKEN" \
  AWS_REGION="$PRIMARY_REGION" \
  "${PYTHON_BIN[@]}" -c "
import os, sys, json, boto3
from botocore.exceptions import ClientError, NoCredentialsError

role_arn = os.environ.get('ROLE_ARN', '').strip()
external_id = os.environ.get('EXTERNAL_ID', '').strip()
access_key = os.environ.get('ACCESS_KEY', '').strip()
secret_key = os.environ.get('SECRET_KEY', '').strip()
session_token = os.environ.get('SESSION_TOKEN', '').strip()
region = os.environ.get('AWS_REGION', 'us-east-1').strip()

# Security Guard: Never fall back to host machine's IAM credentials in multi-tenant setup
if not role_arn and not (access_key and secret_key):
    print(json.dumps({'connected': False, 'error': 'No AWS authentication credentials or Role ARN provided.'}))
    sys.exit(0)

try:
    sts_kwargs = {'region_name': region}
    if access_key and secret_key:
        sts_kwargs['aws_access_key_id'] = access_key
        sts_kwargs['aws_secret_access_key'] = secret_key
        if session_token:
            sts_kwargs['aws_session_token'] = session_token

    if role_arn:
        sts = boto3.client('sts', **sts_kwargs)
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
        test_client = boto3.client('sts', **sts_kwargs)

    identity = test_client.get_caller_identity()
    print(json.dumps({'connected': True, 'account_id': identity.get('Account'), 'arn': identity.get('Arn')}))
except Exception as e:
    print(json.dumps({'connected': False, 'error': str(e)}))
")

parse_preflight() {
    local key="$1"
    if command -v jq &> /dev/null; then
        echo "$PREFLIGHT_JSON" | jq -r ".$key // empty"
    else
        echo "$PREFLIGHT_JSON" | "${PYTHON_BIN[@]}" -c "import sys, json; print(json.load(sys.stdin).get('$key', ''))" 2>/dev/null || echo ""
    fi
}

CONNECTED=$(parse_preflight "connected")
if [[ "$CONNECTED" != "true" ]]; then
    ERROR_MSG=$(parse_preflight "error")
    echo "{\"status\": \"not_configured\", \"message\": \"AWS account not configured or credentials invalid\", \"error\": \"$ERROR_MSG\"}"
    exit 1
fi

ACCOUNT_ID=$(parse_preflight "account_id")
CALLER_ARN=$(parse_preflight "arn")

# If caller only wanted to verify the connection (e.g. from 'Test Connection' button), return success and exit cleanly
if [[ "$TEST_CONNECTION_ONLY" == "true" ]]; then
    echo "{\"status\": \"connected\", \"message\": \"AWS connection verified successfully\", \"account_id\": \"$ACCOUNT_ID\", \"arn\": \"$CALLER_ARN\"}"
    exit 0
fi

TIMESTAMP=$(date -u +"%Y%m%d_%H%M%S")
if [[ -z "$SCAN_ID" ]]; then
    SCAN_ID="scan_${ACCOUNT_ID}_${TIMESTAMP}"
fi
TARGET_DIR="${OUTPUT_DIR}/${SCAN_ID}"
mkdir -p "$TARGET_DIR"


# STEP 2: BUILD PROWLER CLI COMMAND
CMD=("${PROWLER_BIN[@]}" aws)
CMD+=(--output-directory "$TARGET_DIR")
CMD+=(--output-filename "report")
CMD+=(--output-modes "json-ocsf" "csv" "html")
CMD+=(--excluded-service "inspector2")
CMD+=(--ignore-exit-code-3)
CMD+=(--no-banner)

CMD+=(--region "${REGION_ARRAY[@]}")

if [[ -n "$SERVICES" ]]; then
    IFS=',' read -r -a SERVICES_ARRAY <<< "$SERVICES"
    CMD+=(--services "${SERVICES_ARRAY[@]}")
fi

if [[ -n "$CHECKS" ]]; then
    IFS=',' read -r -a CHECKS_ARRAY <<< "$CHECKS"
    CMD+=(--checks "${CHECKS_ARRAY[@]}")
fi

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

# STEP 3: EXECUTE SCAN
START_TIME=$(date +%s)
OCSF_FILE="${TARGET_DIR}/report.ocsf.json"

# Run scanner and capture exit code (ignore code 3 since fail checks exit 3)
set +e
"${CMD[@]}" > "${TARGET_DIR}/scan_execution.log" 2>&1
PROWLER_EXIT_CODE=$?
set -e
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Cleanup temporary AWS credential exports
if [[ -n "$ACCESS_KEY" ]]; then
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
fi

# Locate OCSF findings report with fallback
if [[ ! -f "$OCSF_FILE" ]]; then
    FOUND_OCSF=$(find "$TARGET_DIR" -name "*.ocsf.json" -type f | head -n 1 || true)
    if [[ -n "$FOUND_OCSF" ]]; then
        OCSF_FILE="$FOUND_OCSF"
    fi
fi

# Handle execution failure gracefully if report was not created
if [[ ! -f "$OCSF_FILE" && $PROWLER_EXIT_CODE -ne 0 ]]; then
    ERROR_SNIPPET=$(tail -n 20 "${TARGET_DIR}/scan_execution.log" | tr '\n' ' ' | sed 's/"/\\"/g')
    echo "{\"status\": \"error\", \"message\": \"Prowler scan failed to execute\", \"exit_code\": $PROWLER_EXIT_CODE, \"log_tail\": \"$ERROR_SNIPPET\"}"
    exit $PROWLER_EXIT_CODE
fi

# STEP 4: EXTRACT FINDINGS & ASSETS INVENTORY (JSON)
# (Uses environment variables for safety against quoting/injection)
OCSF_FILE="$OCSF_FILE" \
TARGET_DIR="$TARGET_DIR" \
SCAN_ID="$SCAN_ID" \
ACCOUNT_ID="$ACCOUNT_ID" \
DURATION="$DURATION" \
"${PYTHON_BIN[@]}" -c "
import os, json
from pathlib import Path

ocsf_path = Path(os.environ.get('OCSF_FILE', ''))
target_dir = Path(os.environ.get('TARGET_DIR', ''))
scan_id = os.environ.get('SCAN_ID', '')
account_id = os.environ.get('ACCOUNT_ID', '')
duration = int(os.environ.get('DURATION', 0))

findings = []
assets_map = {}
status_counts = {'FAIL': 0, 'PASS': 0, 'MANUAL': 0, 'MUTED': 0}
severity_counts = {
    'critical': {'fail': 0, 'pass': 0},
    'high': {'fail': 0, 'pass': 0},
    'medium': {'fail': 0, 'pass': 0},
    'low': {'fail': 0, 'pass': 0}
}
services_breakdown = {}

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
            status_ext = record.get('status_detail', record.get('message', ''))

            # 1. Finding Item (includes both service and service_name + status_extended for UI compatibility)
            finding = {
                'id': record.get('id'),
                'check_id': record.get('metadata', {}).get('product', {}).get('name', record.get('activity_name')),
                'check_title': record.get('message'),
                'service': res_service,
                'service_name': res_service,
                'severity': severity,
                'status': status,
                'region': res_region,
                'resource_id': res_arn,
                'resource_name': res.get('name', res_arn),
                'description': status_ext,
                'status_extended': status_ext,
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
                    'service_name': res_service,
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

            # 3. Services breakdown (for frontend service comparison charts)
            if res_service not in services_breakdown:
                services_breakdown[res_service] = {'pass': 0, 'fail': 0, 'total': 0, 'PASS': 0, 'FAIL': 0}
            services_breakdown[res_service]['total'] += 1
            if status in ('PASS', 'FAIL'):
                services_breakdown[res_service][status.lower()] += 1
                services_breakdown[res_service][status.upper()] += 1

assets_list = list(assets_map.values())

total_evaluated = status_counts.get('PASS', 0) + status_counts.get('FAIL', 0)
security_score = round((status_counts.get('PASS', 0) / total_evaluated * 100), 1) if total_evaluated > 0 else 100.0

# Summary object with flattened convenience keys for frontend KPI cards
summary = {
    'scan_id': scan_id,
    'account_id': account_id,
    'security_score': security_score,
    'duration_seconds': duration,
    'total_findings': len(findings),
    'passed': status_counts.get('PASS', 0),
    'failed': status_counts.get('FAIL', 0),
    'muted': status_counts.get('MUTED', 0),
    'manual': status_counts.get('MANUAL', 0),
    'critical': severity_counts['critical']['fail'],
    'high': severity_counts['high']['fail'],
    'medium': severity_counts['medium']['fail'],
    'low': severity_counts['low']['fail'],
    'status_counts': status_counts,
    'severity_breakdown': severity_counts,
    'services_breakdown': services_breakdown,
    'total_assets_scanned': len(assets_list)
}

with open(target_dir / 'findings.json', 'w', encoding='utf-8') as f:
    json.dump(findings, f, indent=2)

with open(target_dir / 'assets.json', 'w', encoding='utf-8') as f:
    json.dump(assets_list, f, indent=2)

with open(target_dir / 'summary.json', 'w', encoding='utf-8') as f:
    json.dump(summary, f, indent=2)
"

# STEP 5: CREATE ZIP ARCHIVE IF REQUESTED
ZIP_FILE=""
if [[ "$FORMAT" == "zip" || "$FORMAT" == "all" ]]; then
    ZIP_FILE="${TARGET_DIR}/${SCAN_ID}_bundle.zip"
    if command -v zip &> /dev/null; then
        (
            cd "$TARGET_DIR"
            zip -q -r "$(basename "$ZIP_FILE")" findings.json assets.json summary.json report.csv report.html 2>/dev/null || \
            zip -q -r "$(basename "$ZIP_FILE")" *.json *.csv *.html 2>/dev/null || true
        )
    else
        TARGET_DIR="$TARGET_DIR" ZIP_FILE="$ZIP_FILE" "${PYTHON_BIN[@]}" -c "
import os, zipfile
from pathlib import Path
target = Path(os.environ['TARGET_DIR'])
zip_path = Path(os.environ['ZIP_FILE'])
files_to_pack = ['findings.json', 'assets.json', 'summary.json', 'report.csv', 'report.html']
with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
    for f in files_to_pack:
        fp = target / f
        if fp.exists():
            zf.write(fp, arcname=f)
    for p in target.glob('*'):
        if p.suffix in ('.json', '.csv', '.html') and p.name not in files_to_pack and p.name != zip_path.name:
            zf.write(p, arcname=p.name)
" 2>/dev/null || true
    fi
fi


# STEP 6: OUTPUT STRUCTURED JSON ON STDOUT
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
