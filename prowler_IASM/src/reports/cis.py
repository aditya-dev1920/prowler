"""
CIS Benchmark Report Generator for Prowler IASM.
Mirrors Prowler's CISReportGenerator architecture.
"""

import io
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from reportlab.lib import colors
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .base import BaseReportGenerator
from .charts import create_progress_bar_drawing
from .components import NumberedCanvas, create_data_table, create_info_table, create_status_badge, escape_html
from .config import COLOR_BORDER, COLOR_CRITICAL_RISK, COLOR_MEDIUM_RISK, COLOR_PASS, COLOR_WHITE


class CISReportGenerator(BaseReportGenerator):
    """
    Report generator for CIS (Center for Internet Security) Benchmarks.
    Produces formal audit evidence documentation with section and requirement mappings.
    """

    def generate(
        self,
        compliance_id: str,
        summary_data: Dict[str, Any],
        findings_data: List[Dict[str, Any]],
        output_path: Optional[Union[str, Path]] = None,
    ) -> Union[Path, io.BytesIO]:
        target = str(output_path) if output_path is not None else io.BytesIO()
        doc = self.setup_document(target)
        story = []

        # 1. HEADER
        header = self.create_header_banner(
            title=f"{compliance_id.upper()} COMPLIANCE AUDIT",
            subtitle="CIS Benchmark Technical Verification & Regulatory Evidence Report"
        )
        story.append(header)
        story.append(Spacer(1, 12))

        # Filter findings that map to this framework
        fw_findings = []
        for f in findings_data:
            comp = f.get("compliance") or {}
            if isinstance(comp, dict):
                for fw_k, reqs in comp.items():
                    if fw_k.lower() == compliance_id.lower() or compliance_id.lower() in fw_k.lower():
                        fw_findings.append((reqs, f))
                        break

        passed_count = sum(1 for _, f in fw_findings if (f.get("status") or "").upper() == "PASS")
        failed_count = sum(1 for _, f in fw_findings if (f.get("status") or "").upper() == "FAIL")
        total_count = len(fw_findings)
        score = round((passed_count / total_count * 100), 1) if total_count > 0 else 100.0

        # 2. METADATA
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        meta_dict = {
            "Framework Standard": escape_html(compliance_id),
            "Target Account ID": escape_html(summary_data.get("account_id", "N/A")),
            "Audit Timestamp": now_str,
            "Total Evaluated Controls": f"{total_count} security checks",
            "Passing Controls": f"{passed_count} compliant",
            "Failing Controls": f"{failed_count} violations",
        }
        story.append(create_info_table(meta_dict))
        story.append(Spacer(1, 14))

        # 3. KPI SCORECARD
        score_color = COLOR_PASS if score >= 85 else (COLOR_MEDIUM_RISK if score >= 70 else COLOR_CRITICAL_RISK)
        kpi_data = [
            [
                Paragraph(f"<font color='{score_color.hexval()}'>{score}%</font>", self.styles["KpiValue"]),
                Paragraph(f"<font color='#16a34a'>{passed_count}</font>", self.styles["KpiValue"]),
                Paragraph(f"<font color='#dc2626'>{failed_count}</font>", self.styles["KpiValue"]),
                Paragraph(f"{total_count}", self.styles["KpiValue"]),
            ],
            [
                Paragraph("COMPLIANCE SCORE", self.styles["KpiLabel"]),
                Paragraph("PASSED CHECKS", self.styles["KpiLabel"]),
                Paragraph("FAILED CHECKS", self.styles["KpiLabel"]),
                Paragraph("TOTAL CONTROLS", self.styles["KpiLabel"]),
            ],
        ]
        kpi_table = Table(kpi_data, colWidths=[133, 133, 133, 133])
        kpi_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), COLOR_WHITE),
            ("BOX", (0, 0), (-1, -1), 1, COLOR_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 2),
        ]))
        story.append(kpi_table)
        story.append(Spacer(1, 10))

        # Visual progress bar
        story.append(create_progress_bar_drawing(score, width=532, height=12))
        story.append(Spacer(1, 16))

        # 4. CONTROLS AUDIT TABLE
        story.append(Paragraph("Evaluated CIS Benchmark Requirements & Status", self.styles["SectionHeader"]))
        table_headers = [
            Paragraph("Requirement", self.styles["TableHeader"]),
            Paragraph("Status", self.styles["TableHeader"]),
            Paragraph("Severity", self.styles["TableHeader"]),
            Paragraph("Service", self.styles["TableHeader"]),
            Paragraph("Check Title / Rule", self.styles["TableHeader"]),
        ]
        t_rows = []
        for reqs, item in fw_findings[:60]:
            req_str = ", ".join(reqs) if isinstance(reqs, list) else str(reqs)
            stat = (item.get("status") or "PASS").upper()
            sev = (item.get("severity") or "low").upper()
            status_badge = create_status_badge(stat, width=50, height=14)
            c_title = escape_html(item.get("check_title") or item.get("check_id") or "")
            c_svc = escape_html((item.get("service") or item.get("service_name") or "").upper())
            t_rows.append([
                Paragraph(f"<b>{escape_html(req_str)}</b>", self.styles["TableCellBold"]),
                status_badge,
                Paragraph(sev, self.styles["TableCell"]),
                Paragraph(c_svc, self.styles["TableCell"]),
                Paragraph(c_title, self.styles["TableCell"]),
            ])

        story.append(create_data_table(table_headers, t_rows, [90, 60, 55, 60, 267]))

        doc.build(story, canvasmaker=NumberedCanvas)

        if output_path is not None:
            return Path(output_path)
        else:
            target.seek(0)
            return target

