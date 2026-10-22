"""
Prowler IASM Reporting Package.
Modular ReportLab generators matching Prowler's official reporting architecture.
"""

import io
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .base import BaseReportGenerator, ComplianceData, RequirementData, create_pdf_styles
from .charts import (
    create_progress_bar_drawing,
    create_severity_distribution_bar,
    get_chart_color_for_percentage,
)
from .cis import CISReportGenerator
from .components import (
    NumberedCanvas,
    create_data_table,
    create_info_table,
    create_status_badge,
    escape_html,
    truncate_text,
)
from .config import (
    COLOR_BLUE,
    COLOR_CRITICAL_RISK,
    COLOR_DARK_BLUE,
    COLOR_HIGH_RISK,
    COLOR_NAVY,
    COLOR_PASS,
    COLOR_WHITE,
)
from .csv_generator import generate_compliance_csv
from .executive import ExecutiveReportGenerator


def generate_executive_pdf_report(
    summary_data: Dict[str, Any],
    findings_data: List[Dict[str, Any]],
    assets_data: List[Dict[str, Any]],
    output_path: Optional[Union[str, Path]] = None,
) -> Union[Path, io.BytesIO]:
    """Generates the publication-grade Executive Cloud Security Assessment PDF report."""
    generator = ExecutiveReportGenerator()
    return generator.generate(summary_data, findings_data, assets_data, output_path=output_path)


def generate_compliance_pdf_report(
    framework_name: str,
    summary_data: Dict[str, Any],
    findings_data: List[Dict[str, Any]],
    output_path: Optional[Union[str, Path]] = None,
) -> Union[Path, io.BytesIO]:
    """Generates a compliance framework audit PDF report."""
    generator = CISReportGenerator()
    return generator.generate(framework_name, summary_data, findings_data, output_path=output_path)


__all__ = [
    "BaseReportGenerator",
    "CISReportGenerator",
    "ComplianceData",
    "ExecutiveReportGenerator",
    "NumberedCanvas",
    "RequirementData",
    "create_data_table",
    "create_info_table",
    "create_pdf_styles",
    "create_progress_bar_drawing",
    "create_severity_distribution_bar",
    "create_status_badge",
    "escape_html",
    "generate_compliance_csv",
    "generate_compliance_pdf_report",
    "generate_executive_pdf_report",
    "get_chart_color_for_percentage",
    "truncate_text",
]

