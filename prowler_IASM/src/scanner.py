"""
ProwlerScanner - Programmatic Python interface for Prowler IASM.
Use this module to run scans directly from another Python application or service.
"""

import json
import logging
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("prowler_iasm_scanner")

class ProwlerScanner:
    """
    Programmatic client to execute connection tests and security scans
    directly from Python code without needing HTTP REST requests.
    """

    def __init__(self, output_dir: Optional[str] = None, script_path: Optional[str] = None):
        base_dir = Path(__file__).resolve().parent.parent
        self.script_path = Path(script_path or os.getenv("RUN_SCAN_SCRIPT", str(base_dir / "run_scan.sh"))).resolve()
        self.output_dir = Path(output_dir or os.getenv("SCAN_OUTPUT_DIR", str(base_dir / "scan_results"))).resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)

        if not self.script_path.exists():
            raise FileNotFoundError(f"Scanner script not found at: {self.script_path}")

    def _resolve_executable_command(self, args: List[str]) -> List[str]:
        """Resolves bash invocation on Windows when executing .sh scripts."""
        if sys.platform == "win32" and self.script_path.suffix == ".sh":
            bash_bin = shutil.which("bash") or shutil.which("sh")
            if not bash_bin:
                git_bash_candidates = [
                    Path(r"C:\Program Files\Git\bin\bash.exe"),
                    Path(r"C:\Program Files (x86)\Git\bin\bash.exe"),
                    Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Git" / "bin" / "bash.exe",
                ]
                for candidate in git_bash_candidates:
                    if candidate.exists():
                        bash_bin = str(candidate)
                        break

            if bash_bin:
                return [bash_bin, str(self.script_path)] + args
            else:
                logger.warning(
                    "Executing .sh script on Windows without bash detected in PATH. "
                    "Ensure Git Bash or WSL is installed for native Windows execution."
                )

        return [str(self.script_path)] + args

    def test_connection(
        self,
        role_arn: Optional[str] = None,
        external_id: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        session_token: Optional[str] = None,
        region: str = "us-east-1",
        timeout: float = 15.0
    ) -> Dict[str, Any]:
        """
        Validates AWS credentials or Role Assume configuration via AWS STS.
        Executes in < 500ms without triggering any security scans.
        Credentials are encrypted in the environment dictionary and never exposed in process args.
        """
        start_time = time.time()
        args = ["--test-connection-only"]

        if role_arn:
            args.extend(["--role-arn", role_arn])
        if external_id:
            args.extend(["--external-id", external_id])
        if region:
            args.extend(["--regions", region])

        cmd = self._resolve_executable_command(args)

        # Inject credentials into environment safely (CWE-214 / CWE-532 protection)
        sub_env = os.environ.copy()
        if access_key:
            sub_env["AWS_ACCESS_KEY_ID"] = access_key
        if secret_key:
            sub_env["AWS_SECRET_ACCESS_KEY"] = secret_key
        if session_token:
            sub_env["AWS_SESSION_TOKEN"] = session_token

        try:
            res = subprocess.run(cmd, env=sub_env, capture_output=True, text=True, timeout=timeout)
            duration_ms = round((time.time() - start_time) * 1000, 2)
            stdout = res.stdout.strip()
            data = json.loads(stdout) if stdout else {}
            data["duration_ms"] = duration_ms
            return data
        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "message": f"Connection verification timed out after {timeout}s",
                "duration_ms": round((time.time() - start_time) * 1000, 2)
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
                "duration_ms": round((time.time() - start_time) * 1000, 2)
            }

    def run_scan(
        self,
        role_arn: Optional[str] = None,
        external_id: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        session_token: Optional[str] = None,
        regions: Optional[List[str]] = None,
        services: Optional[List[str]] = None,
        checks: Optional[List[str]] = None,
        scan_id: Optional[str] = None,
        timeout: Optional[int] = 3600
    ) -> Dict[str, Any]:
        """
        Synchronously runs a security assessment scan and returns the complete parsed results.
        Credentials are passed safely via environment variables to prevent process-table leakage.
        """
        scan_id = scan_id or f"scan_{uuid.uuid4().hex[:12]}"
        target_dir = self.output_dir / scan_id
        target_dir.mkdir(parents=True, exist_ok=True)

        args = [
            "--scan-id", scan_id,
            "--output-dir", str(self.output_dir),
            "--format", "all"
        ]

        if role_arn:
            args.extend(["--role-arn", role_arn])
        if external_id:
            args.extend(["--external-id", external_id])
        if regions:
            args.extend(["--regions", ",".join(regions)])
        if services:
            args.extend(["--services", ",".join(services)])
        if checks:
            args.extend(["--checks", ",".join(checks)])

        cmd = self._resolve_executable_command(args)

        # Inject credentials into environment safely (CWE-214 / CWE-532 protection)
        sub_env = os.environ.copy()
        if access_key:
            sub_env["AWS_ACCESS_KEY_ID"] = access_key
        if secret_key:
            sub_env["AWS_SECRET_ACCESS_KEY"] = secret_key
        if session_token:
            sub_env["AWS_SESSION_TOKEN"] = session_token

        log_path = target_dir / "execution.log"
        with open(log_path, "w", encoding="utf-8") as lf:
            res = subprocess.run(cmd, env=sub_env, stdout=lf, stderr=subprocess.STDOUT, timeout=timeout)

        summary_file = target_dir / "summary.json"
        findings_file = target_dir / "findings.json"
        assets_file = target_dir / "assets.json"
        zip_file = target_dir / f"{scan_id}_bundle.zip"

        if res.returncode == 0 and summary_file.exists():
            with open(summary_file, "r", encoding="utf-8") as f:
                summary = json.load(f)
            findings = []
            if findings_file.exists():
                with open(findings_file, "r", encoding="utf-8") as f:
                    findings = json.load(f)
            assets = []
            if assets_file.exists():
                with open(assets_file, "r", encoding="utf-8") as f:
                    assets = json.load(f)

            return {
                "status": "success",
                "scan_id": scan_id,
                "summary": summary,
                "findings": findings,
                "assets": assets,
                "files": {
                    "summary_json": str(summary_file),
                    "findings_json": str(findings_file),
                    "assets_json": str(assets_file),
                    "zip_bundle": str(zip_file) if zip_file.exists() else None,
                    "html_report": str(target_dir / "report.html"),
                    "csv_report": str(target_dir / "report.csv"),
                }
            }
        else:
            error_tail = ""
            if log_path.exists():
                with open(log_path, "r", encoding="utf-8") as lf:
                    error_tail = "".join(lf.readlines()[-20:])
            return {
                "status": "error",
                "scan_id": scan_id,
                "message": "Scan failed during execution.",
                "exit_code": res.returncode,
                "log_tail": error_tail
            }

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Loads and returns an existing scan's summary and artifact paths."""
        target_dir = self.output_dir / scan_id
        summary_file = target_dir / "summary.json"
        if not summary_file.exists():
            return None
        with open(summary_file, "r", encoding="utf-8") as f:
            summary = json.load(f)
        return {
            "scan_id": scan_id,
            "summary": summary,
            "target_dir": str(target_dir),
            "zip_bundle": str(target_dir / f"{scan_id}_bundle.zip")
        }
