"""
Unit Tests for ProwlerScanner Programmatic Python Client.
"""

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.scanner import ProwlerScanner


class TestProwlerScanner:
    def test_scanner_init_success(self, tmp_path: Path):
        dummy_script = tmp_path / "run_scan.sh"
        dummy_script.write_text("#!/bin/bash\necho ok\n", encoding="utf-8")
        out_dir = tmp_path / "output"

        scanner = ProwlerScanner(output_dir=str(out_dir), script_path=str(dummy_script))
        assert scanner.script_path == dummy_script.resolve()
        assert scanner.output_dir == out_dir.resolve()
        assert out_dir.exists()

    def test_scanner_init_missing_script_raises(self, tmp_path: Path):
        non_existent = tmp_path / "non_existent.sh"
        with pytest.raises(FileNotFoundError):
            ProwlerScanner(script_path=str(non_existent))

    def test_resolve_executable_command_windows(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        dummy_script = tmp_path / "run_scan.sh"
        dummy_script.write_text("#!/bin/bash\n", encoding="utf-8")
        scanner = ProwlerScanner(script_path=str(dummy_script))

        # Test when bash is detected
        monkeypatch.setattr(sys, "platform", "win32")
        with patch("shutil.which", return_value="C:\\Program Files\\Git\\bin\\bash.exe"):
            cmd = scanner._resolve_executable_command(["--flag", "val"])
            assert cmd[0] == "C:\\Program Files\\Git\\bin\\bash.exe"
            assert cmd[1] == str(dummy_script.resolve())
            assert cmd[2:] == ["--flag", "val"]

    def test_test_connection_environment_injection(self, tmp_path: Path):
        dummy_script = tmp_path / "run_scan.sh"
        dummy_script.write_text("#!/bin/bash\n", encoding="utf-8")
        scanner = ProwlerScanner(script_path=str(dummy_script))

        mock_result = MagicMock()
        mock_result.stdout = json.dumps({"status": "success", "account": "123456789012", "mode": "keys"})
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            res = scanner.test_connection(
                access_key="AKIAEXAMPLETESTKEY",
                secret_key="SECRETEXAMPLETESTKEY",
                session_token="SESSIONTOKEN123",
                region="us-east-1"
            )

            assert res["status"] == "success"
            assert res["account"] == "123456789012"
            assert "duration_ms" in res

            # Verify subprocess call security:
            # 1. Credentials must NOT be passed in command arguments
            call_args = mock_run.call_args[0][0]
            assert "AKIAEXAMPLETESTKEY" not in " ".join(call_args)
            assert "SECRETEXAMPLETESTKEY" not in " ".join(call_args)

            # 2. Credentials MUST be in the injected sub_env
            call_env = mock_run.call_args[1]["env"]
            assert call_env["AWS_ACCESS_KEY_ID"] == "AKIAEXAMPLETESTKEY"
            assert call_env["AWS_SECRET_ACCESS_KEY"] == "SECRETEXAMPLETESTKEY"
            assert call_env["AWS_SESSION_TOKEN"] == "SESSIONTOKEN123"

    def test_run_scan_environment_injection_and_arguments(self, tmp_path: Path):
        dummy_script = tmp_path / "run_scan.sh"
        dummy_script.write_text("#!/bin/bash\n", encoding="utf-8")
        out_dir = tmp_path / "output"
        scanner = ProwlerScanner(output_dir=str(out_dir), script_path=str(dummy_script))

        scan_id = "test_scan_run_01"
        target_dir = out_dir / scan_id
        target_dir.mkdir(parents=True, exist_ok=True)
        
        # Prepopulate summary so run_scan sees successful scan
        summary_data = {"scan_id": scan_id, "security_score": 90.0}
        with open(target_dir / "summary.json", "w", encoding="utf-8") as f:
            json.dump(summary_data, f)

        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            res = scanner.run_scan(
                role_arn="arn:aws:iam::123456789012:role/AuditRole",
                external_id="ext-123",
                access_key="AKIAKEY123",
                secret_key="SECRETKEY123",
                regions=["us-east-1", "eu-west-1"],
                services=["s3", "iam"],
                scan_id=scan_id
            )

            assert res["status"] == "success"
            assert res["scan_id"] == scan_id
            assert res["summary"] == summary_data

            call_args = mock_run.call_args[0][0]
            # Ensure args have role, external_id, regions, services
            assert "--role-arn" in call_args
            assert "--external-id" in call_args
            assert "--regions" in call_args
            assert "us-east-1,eu-west-1" in call_args
            assert "--services" in call_args
            assert "s3,iam" in call_args
            # Ensure secrets are NOT in args
            assert "AKIAKEY123" not in " ".join(call_args)
            assert "SECRETKEY123" not in " ".join(call_args)

            # Ensure secrets ARE in environment
            call_env = mock_run.call_args[1]["env"]
            assert call_env["AWS_ACCESS_KEY_ID"] == "AKIAKEY123"
            assert call_env["AWS_SECRET_ACCESS_KEY"] == "SECRETKEY123"

