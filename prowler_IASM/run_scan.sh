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

# Defaults (Credentials read securely from environment by default)
ROLE_ARN="${ROLE_ARN:-}"
EXTERNAL_ID="${EXTERNAL_ID:-}"
ACCESS_KEY="${AWS_ACCESS_KEY_ID:-}"
SECRET_KEY="${AWS_SECRET_ACCESS_KEY:-}"
SESSION_TOKEN="${AWS_SESSION_TOKEN:-}"
EXPECTED_ACCOUNT_ID="${EXPECTED_ACCOUNT_ID:-}"
PROVIDER_ALIAS="${PROVIDER_ALIAS:-}"
REGIONS="${DEFAULT_REGIONS:-us-east-1,ap-south-1}"
SERVICES=""
CHECKS=""
SCAN_ID=""
OUTPUT_DIR="${SCAN_OUTPUT_DIR:-./scan_results}"
FORMAT="all"  # options: zip, json, all
TEST_CONNECTION_ONLY="false"

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --role-arn <ARN>            IAM Role ARN to assume (AssumeRole mode)
  --external-id <ID>          Optional External ID for AssumeRole
  --access-key <KEY>          AWS Access Key ID (Legacy CLI mode; prefer AWS_ACCESS_KEY_ID env var)
  --secret-key <SECRET>       AWS Secret Access Key (Legacy CLI mode; prefer AWS_SECRET_ACCESS_KEY env var)
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
        --account-id) EXPECTED_ACCOUNT_ID="$2"; shift 2 ;;
        --provider-alias) PROVIDER_ALIAS="$2"; shift 2 ;;
        --role-arn) ROLE_ARN="$2"; shift 2 ;;
        --external-id) EXTERNAL_ID="$2"; shift 2 ;;
        --access-key)
            echo "[SECURITY WARNING] Passing credentials via CLI arguments exposes them in the system process table. Use AWS_ACCESS_KEY_ID environment variable instead." >&2
            ACCESS_KEY="$2"; shift 2 ;;
        --secret-key)
            echo "[SECURITY WARNING] Passing credentials via CLI arguments exposes them in the system process table. Use AWS_SECRET_ACCESS_KEY environment variable instead." >&2
            SECRET_KEY="$2"; shift 2 ;;
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
  EXPECTED_ACCOUNT_ID="$EXPECTED_ACCOUNT_ID" \
  PROVIDER_ALIAS="$PROVIDER_ALIAS" \
  AWS_REGION="$PRIMARY_REGION" \
  "${PYTHON_BIN[@]}" -c "
import os, sys, json, boto3
from botocore.exceptions import ClientError, NoCredentialsError

role_arn = os.environ.get('ROLE_ARN', '').strip()
external_id = os.environ.get('EXTERNAL_ID', '').strip()
access_key = os.environ.get('ACCESS_KEY', '').strip()
secret_key = os.environ.get('SECRET_KEY', '').strip()
session_token = os.environ.get('SESSION_TOKEN', '').strip()
expected_account = os.environ.get('EXPECTED_ACCOUNT_ID', '').strip()
provider_alias = os.environ.get('PROVIDER_ALIAS', '').strip()
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
    actual_account = identity.get('Account')

    # Cross-verification: If user specified an expected Account ID, verify match
    if expected_account and expected_account != actual_account:
        print(json.dumps({
            'connected': False,
            'error': f'Account ID verification failed: Expected {expected_account}, but credentials authenticate to {actual_account}'
        }))
        sys.exit(0)

    print(json.dumps({
        'connected': True,
        'account_id': actual_account,
        'arn': identity.get('Arn'),
        'provider_alias': provider_alias
    }))
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
CMD+=(--verbose)
CMD+=(--only-logs)
CMD+=(--log-level "ERROR")

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
if command -v tee &> /dev/null; then
    "${CMD[@]}" 2>&1 | tee "${TARGET_DIR}/scan_execution.log"
    PROWLER_EXIT_CODE=${PIPESTATUS[0]}
else
    "${CMD[@]}" > "${TARGET_DIR}/scan_execution.log" 2>&1
    PROWLER_EXIT_CODE=$?
fi
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

# STEP 4: EXTRACT FINDINGS, ASSETS, SUMMARY & GENERATE PDF/ZIP
PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH" "${PYTHON_BIN[@]}" -m src.reports.post_processor \
    --target-dir "$TARGET_DIR" \
    --scan-id "$SCAN_ID" \
    --account-id "$ACCOUNT_ID" \
    --provider-alias "$PROVIDER_ALIAS" \
    --duration "$DURATION" \
    --ocsf-file "$OCSF_FILE"

ZIP_FILE="${TARGET_DIR}/${SCAN_ID}_bundle.zip"


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
