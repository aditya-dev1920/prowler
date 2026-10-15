import os
import time
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any, Iterable


SCAN_LOGS_DIR = os.getenv(
    "PROWLER_SCAN_LOGS_DIR", "/home/prowler/backend/scan_logs"
)


class ScanExecutionLogger:
    """
    Dedicated per-scan execution logger.
    Creates a dedicated log file per scan (e.g. scan_<scan_id>_<timestamp>.log)
    to record input parameters, real-time discovered resources/findings, and
    an inventory of all discovered cloud assets (S3 buckets, VPCs, EC2 instances, etc.).
    """

    def __init__(
        self,
        scan_id: str,
        tenant_id: str,
        provider_id: str,
        provider_type: str,
        provider_uid: str,
        checks_to_execute: list[str] | None = None,
    ):
        self.scan_id = str(scan_id)
        self.tenant_id = str(tenant_id)
        self.provider_id = str(provider_id)
        self.provider_type = str(provider_type).upper()
        self.provider_uid = str(provider_uid)
        self.checks_to_execute = checks_to_execute
        self.audited_regions: list[str] = []

        self.start_time = time.time()
        self.start_datetime = datetime.now(tz=UTC)

        # Output metrics
        self.total_findings = 0
        self.status_counts = {"PASS": 0, "FAIL": 0, "MUTED": 0}
        self.severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
        }

        # Track unique discovered assets by service: {service: {resource_name: region}}
        self.discovered_assets = defaultdict(dict)

        self.log_file_path = None
        self._file = None

        self._init_log_file()

    def _init_log_file(self):
        try:
            os.makedirs(SCAN_LOGS_DIR, exist_ok=True)
            ts = self.start_datetime.strftime("%Y%m%d_%H%M%S")
            filename = f"scan_{self.scan_id[:8]}_{ts}.log"
            self.log_file_path = os.path.join(SCAN_LOGS_DIR, filename)
            self._file = open(self.log_file_path, "a", encoding="utf-8")

            checks_repr = (
                f"{len(self.checks_to_execute)} checks selected"
                if self.checks_to_execute
                else "ALL default checks"
            )

            header = (
                f"{'='*80}\n"
                f"PROWLER SCAN EXECUTION MONITORING & ASSET DISCOVERY LOG\n"
                f"{'='*80}\n"
                f"Scan ID:          {self.scan_id}\n"
                f"Tenant ID:        {self.tenant_id}\n"
                f"Provider:         {self.provider_type} (UID: {self.provider_uid})\n"
                f"Provider ID:      {self.provider_id}\n"
                f"Started At:       {self.start_datetime.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                f"Checks Scoped:    {checks_repr}\n"
                f"Log File:         {self.log_file_path}\n"
                f"{'='*80}\n\n"
                f"{'='*80}\n"
                f"LIVE FINDINGS & DISCOVERED RESOURCES STREAM\n"
                f"{'='*80}\n"
            )
            self._write(header)
            self.log_event("Scan status transitioned to EXECUTING")
        except Exception:
            self._file = None

    def _write(self, text: str):
        if self._file:
            try:
                self._file.write(text)
                self._file.flush()
            except Exception:
                pass

    def log_event(self, message: str):
        """Log a timestamped event entry."""
        now_str = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        self._write(f"[{now_str}] {message}\n")

    def set_audited_regions(self, regions: Iterable[str] | None):
        """Record the actual resolved target regions."""
        if regions:
            self.audited_regions = sorted(list(regions))
            self.log_event(f"Audited Regions Confirmed: {', '.join(self.audited_regions)}")

    def _extract_finding(self, finding: Any) -> dict:
        """Safely extract resource name, service, status, and details from any finding object."""
        # 1. Metadata extraction
        metadata = getattr(finding, "metadata", None)
        if metadata:
            service = getattr(metadata, "ServiceName", "") or getattr(metadata, "service_name", "")
            check_id = getattr(metadata, "CheckID", "") or getattr(metadata, "check_id", "")
            raw_sev = getattr(metadata, "Severity", None)
            severity = getattr(raw_sev, "value", str(raw_sev)) if raw_sev else "informational"
        elif isinstance(finding, dict):
            m = finding.get("metadata", {})
            service = m.get("ServiceName", m.get("service_name", ""))
            check_id = m.get("CheckID", m.get("check_id", ""))
            severity = str(m.get("Severity", "informational"))
        else:
            service, check_id, severity = "", "", "informational"

        # 2. Status
        raw_status = getattr(finding, "status", None) if not isinstance(finding, dict) else finding.get("status")
        if hasattr(raw_status, "value"):
            status_str = str(raw_status.value).upper()
        else:
            status_str = str(raw_status).upper() if raw_status else "UNKNOWN"

        # 3. Resource identification (S3 bucket name, VPC ID, EC2 ID, etc.)
        res_name = getattr(finding, "resource_name", None) if not isinstance(finding, dict) else finding.get("resource_name")
        res_uid = getattr(finding, "resource_uid", None) if not isinstance(finding, dict) else finding.get("resource_uid")
        name = res_name or res_uid or "UnknownResource"

        region = getattr(finding, "region", None) if not isinstance(finding, dict) else finding.get("region")
        details = getattr(finding, "status_extended", "") if not isinstance(finding, dict) else finding.get("status_extended", "")

        return {
            "service": str(service).lower() if service else "aws",
            "check_id": str(check_id) if check_id else "check",
            "severity": str(severity).lower() if severity else "informational",
            "status": status_str,
            "region": str(region) if region else "global",
            "resource_name": str(name),
            "details": str(details).strip(),
        }

    def record_findings_batch(self, findings: Iterable[Any]):
        """Record finding metrics, stream detailed finding rows, and catalog discovered assets."""
        now_str = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

        for raw_finding in findings:
            self.total_findings += 1
            f = self._extract_finding(raw_finding)

            # Update counters
            status = f["status"]
            if status in self.status_counts:
                self.status_counts[status] += 1
            else:
                self.status_counts["FAIL"] += 1

            sev = f["severity"]
            if sev in self.severity_counts:
                self.severity_counts[sev] += 1
            else:
                self.severity_counts["informational"] += 1

            # Catalog discovered resource
            service_key = f["service"].upper()
            self.discovered_assets[service_key][f["resource_name"]] = f["region"]

            # Format live log line
            status_label = f"FAIL:{f['severity'].upper()}" if status == "FAIL" else status
            log_line = (
                f"[{now_str}] [{status_label:<14}] [{f['region']:<12}] [{f['service']:<10}] "
                f"Resource: {f['resource_name']} | Check: {f['check_id']}"
            )
            if f["details"]:
                log_line += f" | {f['details']}"
            self._write(log_line + "\n")

    def log_progress(self, progress: float):
        """Log periodic progress milestones."""
        self.log_event(
            f"==> Progress: {progress:.1f}% completed (Discovered Findings: {self.total_findings}) <=="
        )

    def finish(
        self,
        state: str,
        duration: float | None = None,
        unique_resources_count: int = 0,
        exception: Exception | None = None,
    ):
        """Write asset inventory, summary outputs, and close log file."""
        end_datetime = datetime.now(tz=UTC)
        total_duration = duration if duration is not None else (time.time() - self.start_time)
        mins, secs = divmod(int(total_duration), 60)

        # 1. Discovered Cloud Assets Inventory Section
        self._write("\n" + "="*80 + "\n")
        self._write("DISCOVERED CLOUD ASSETS INVENTORY (BY SERVICE)\n")
        self._write("="*80 + "\n")

        if self.discovered_assets:
            for service in sorted(self.discovered_assets.keys()):
                resources = self.discovered_assets[service]
                self._write(f"\n[{service}] ({len(resources)} unique resource(s) discovered):\n")
                for res_name, reg in sorted(resources.items()):
                    self._write(f"  • {res_name} (Region: {reg})\n")
        else:
            self._write("No cloud resources recorded during this execution.\n")

        # 2. Final Summary & Metrics
        self._write("\n" + "="*80 + "\n")
        self._write("SCAN EXECUTION SUMMARY & OUTPUTS\n")
        self._write("="*80 + "\n")
        self._write(f"Final State:         {state}\n")
        self._write(f"Completed At:        {end_datetime.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        self._write(f"Total Duration:      {mins}m {secs}s ({total_duration:.2f} seconds)\n")
        self._write(f"Unique Resources:    {unique_resources_count or sum(len(r) for r in self.discovered_assets.values())}\n")
        self._write(f"Total Findings:      {self.total_findings}\n")
        self._write(
            f"  - Passed:          {self.status_counts.get('PASS', 0)}\n"
            f"  - Failed:          {self.status_counts.get('FAIL', 0)}\n"
            f"  - Muted:           {self.status_counts.get('MUTED', 0)}\n"
        )
        self._write("Severity Breakdown:\n")
        for sev, count in self.severity_counts.items():
            self._write(f"  - {sev.upper():<14} {count}\n")

        if exception:
            self._write(f"\nExecution Exception: {exception.__class__.__name__}: {exception}\n")

        self._write("="*80 + "\n")

        if self._file:
            try:
                self._file.flush()
                self._file.close()
            except Exception:
                pass
            finally:
                self._file = None
