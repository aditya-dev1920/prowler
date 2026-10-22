"""
CSV Report Generator for Prowler IASM.
Supports generating universal compliance framework CSV extracts and custom findings CSVs.
"""

import csv
import io
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


def generate_compliance_csv(
    findings_data: List[Dict[str, Any]],
    framework_name: str,
    output_path: Optional[Union[str, Path]] = None,
) -> Union[Path, io.StringIO]:
    """
    Filters findings matching the specified compliance framework and exports
    a clean, standardized audit spreadsheet (.csv).
    """
    output_buffer = io.StringIO() if output_path is None else open(output_path, "w", newline="", encoding="utf-8")

    fieldnames = [
        "Framework",
        "Requirement",
        "Status",
        "Severity",
        "Service",
        "Check ID",
        "Check Title",
        "Resource ID",
        "Region",
        "Description",
        "Risk",
        "Remediation",
        "Remediation CLI"
    ]

    writer = csv.DictWriter(output_buffer, fieldnames=fieldnames)
    writer.writeheader()

    for item in findings_data:
        comp = item.get("compliance") or {}
        if not isinstance(comp, dict):
            continue

        # Match exact framework name or case-insensitive variant/substring
        matched_reqs = None
        for fw_key, req_list in comp.items():
            if fw_key.lower() == framework_name.lower() or framework_name.lower() in fw_key.lower():
                matched_reqs = req_list
                break

        if matched_reqs is not None:
            req_str = ", ".join(matched_reqs) if isinstance(matched_reqs, list) else str(matched_reqs)
            writer.writerow({
                "Framework": fw_key,
                "Requirement": req_str,
                "Status": (item.get("status") or "PASS").upper(),
                "Severity": (item.get("severity") or "low").upper(),
                "Service": (item.get("service") or item.get("service_name") or "").upper(),
                "Check ID": item.get("check_id") or "",
                "Check Title": item.get("check_title") or "",
                "Resource ID": item.get("resource_id") or "",
                "Region": item.get("region") or "global",
                "Description": item.get("description") or item.get("status_extended") or "",
                "Risk": item.get("risk") or "",
                "Remediation": item.get("remediation") or "",
                "Remediation CLI": item.get("remediation_cli") or ""
            })

    if output_path is not None:
        output_buffer.close()
        return Path(output_path)
    else:
        output_buffer.seek(0)
        return output_buffer

