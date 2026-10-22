"""
Executive Report Generator for Prowler IASM.
Builds comprehensive, publication-quality executive cloud posture assessments.
"""

import io
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from reportlab.lib import colors
from reportlab.platypus import KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .base import BaseReportGenerator
from .charts import create_progress_bar_drawing, create_severity_distribution_bar
from .components import NumberedCanvas, create_data_table, create_info_table, escape_html
from .config import (
    COLOR_BORDER,
    COLOR_CODE_BG,
    COLOR_CRITICAL_RISK,
    COLOR_DARK_BLUE,
    COLOR_HIGH_RISK,
    COLOR_LIGHT_BG,
    COLOR_MEDIUM_RISK,
    COLOR_PASS,
    COLOR_WHITE,
)


class ExecutiveReportGenerator(BaseReportGenerator):
    """
    Generator for Executive Cloud Security Posture Assessment PDF Reports.
    Designed for presentation to CISOs, security directors, and compliance auditors.
    """

    def generate(
        self,
        summary_data: Dict[str, Any],
        findings_data: List[Dict[str, Any]],
        assets_data: List[Dict[str, Any]],
        output_path: Optional[Union[str, Path]] = None,
    ) -> Union[Path, io.BytesIO]:
        target = str(output_path) if output_path is not None else io.BytesIO()
        doc = self.setup_document(target)
        story = []

        # 1. HEADER BANNER
        header = self.create_header_banner(
            title="CLOUD SECURITY POSTURE REPORT",
            subtitle="Enterprise Cloud Infrastructure Audit & Attack Surface Management Assessment"
        )
        story.append(header)
        story.append(Spacer(1, 12))

        # 2. ASSESSMENT METADATA TABLE
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        acc_id = escape_html(summary_data.get('account_id', 'N/A'))
        s_id = escape_html(summary_data.get('scan_id', 'audit-run'))
        meta_dict = {
            "Target Account ID": f"<code>{acc_id}</code>",
            "Assessment Date": now_str,
            "Scan Identifier": f"<code>{s_id}</code>",
            "Execution Duration": f"{summary_data.get('duration_seconds', 0)} seconds",
            "Discovered Assets": f"{summary_data.get('total_assets_scanned', len(assets_data))} cloud resources",
            "Audit Standards": "CIS Benchmark, NIST, PCI-DSS, SOC 2, ISO 27001",
        }
        story.append(create_info_table(meta_dict))
        story.append(Spacer(1, 14))

        # 3. EXECUTIVE KPI METRICS
        score = float(summary_data.get("security_score", 100.0))
        crit_count = summary_data.get("critical", 0)
        high_count = summary_data.get("high", 0)
        pass_count = summary_data.get("passed", 0)

        score_color = COLOR_PASS if score >= 85 else (COLOR_MEDIUM_RISK if score >= 70 else COLOR_CRITICAL_RISK)
        kpi_data = [
            [
                Paragraph(f"<font color='{score_color.hexval()}'>{score}%</font>", self.styles["KpiValue"]),
                Paragraph(f"<font color='#dc2626'>{crit_count}</font>", self.styles["KpiValue"]),
                Paragraph(f"<font color='#ea580c'>{high_count}</font>", self.styles["KpiValue"]),
                Paragraph(f"<font color='#16a34a'>{pass_count}</font>", self.styles["KpiValue"]),
            ],
            [
                Paragraph("SECURITY POSTURE SCORE", self.styles["KpiLabel"]),
                Paragraph("CRITICAL RISKS", self.styles["KpiLabel"]),
                Paragraph("HIGH PRIORITY RISKS", self.styles["KpiLabel"]),
                Paragraph("PASSING CONTROLS", self.styles["KpiLabel"]),
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
        story.append(Spacer(1, 16))

        # 4. SEVERITY BREAKDOWN & SLA TABLE
        story.append(Paragraph("1. Attack Surface Severity & SLA Breakdown", self.styles["SectionHeader"]))
        
        # Add visual stacked severity distribution bar
        med_count = summary_data.get("medium", 0)
        low_count = summary_data.get("low", 0)
        story.append(create_severity_distribution_bar(crit_count, high_count, med_count, low_count, width=532))
        story.append(Spacer(1, 8))

        sev_headers = [
            Paragraph("Severity Level", self.styles["TableHeader"]),
            Paragraph("Failed Checks", self.styles["TableHeader"]),
            Paragraph("Passed Checks", self.styles["TableHeader"]),
            Paragraph("Risk Exposure Level", self.styles["TableHeader"]),
            Paragraph("Remediation Target SLA", self.styles["TableHeader"]),
        ]
        sev_rows = [
            [
                Paragraph("<font color='#dc2626'><b>CRITICAL</b></font>", self.styles["TableCellBold"]),
                Paragraph(str(crit_count), self.styles["TableCellBold"]),
                Paragraph("-", self.styles["TableCell"]),
                Paragraph("Immediate Remote Exploit Risk", self.styles["TableCell"]),
                Paragraph("<b>24 Hours</b>", self.styles["TableCellBold"]),
            ],
            [
                Paragraph("<font color='#ea580c'><b>HIGH</b></font>", self.styles["TableCellBold"]),
                Paragraph(str(high_count), self.styles["TableCellBold"]),
                Paragraph("-", self.styles["TableCell"]),
                Paragraph("Privilege Escalation / Breach Risk", self.styles["TableCell"]),
                Paragraph("<b>7 Days</b>", self.styles["TableCellBold"]),
            ],
            [
                Paragraph("<font color='#d97706'><b>MEDIUM</b></font>", self.styles["TableCellBold"]),
                Paragraph(str(med_count), self.styles["TableCellBold"]),
                Paragraph("-", self.styles["TableCell"]),
                Paragraph("Configuration Weakness", self.styles["TableCell"]),
                Paragraph("30 Days", self.styles["TableCell"]),
            ],
            [
                Paragraph("<font color='#2563eb'><b>LOW</b></font>", self.styles["TableCellBold"]),
                Paragraph(str(low_count), self.styles["TableCellBold"]),
                Paragraph("-", self.styles["TableCell"]),
                Paragraph("Best Practice Alignment", self.styles["TableCell"]),
                Paragraph("90 Days", self.styles["TableCell"]),
            ],
            [
                Paragraph("<font color='#16a34a'><b>PASS / COMPLIANT</b></font>", self.styles["TableCellBold"]),
                Paragraph("-", self.styles["TableCell"]),
                Paragraph(str(pass_count), self.styles["TableCellBold"]),
                Paragraph("Hardened Control Enforced", self.styles["TableCell"]),
                Paragraph("Continuous Monitoring", self.styles["TableCell"]),
            ],
        ]
        story.append(create_data_table(sev_headers, sev_rows, [100, 75, 75, 172, 110]))
        story.append(Spacer(1, 16))

        # 5. REGULATORY & INDUSTRY COMPLIANCE BENCHMARKS
        compliance_overview = summary_data.get("compliance_overview", {})
        if compliance_overview:
            story.append(Paragraph("2. Regulatory & Industry Benchmark Compliance", self.styles["SectionHeader"]))
            comp_headers = [
                Paragraph("Benchmark Framework", self.styles["TableHeader"]),
                Paragraph("Passing", self.styles["TableHeader"]),
                Paragraph("Failing", self.styles["TableHeader"]),
                Paragraph("Total Tested", self.styles["TableHeader"]),
                Paragraph("Compliance Score", self.styles["TableHeader"]),
                Paragraph("Audit Status", self.styles["TableHeader"]),
            ]
            comp_rows = []
            for fw_name, fw_stats in compliance_overview.items():
                f_score = fw_stats.get("score", 100.0)
                f_pass = fw_stats.get("passed", 0)
                f_fail = fw_stats.get("failed", 0)
                f_total = fw_stats.get("total", 0)
                status_text = "<font color='#16a34a'><b>COMPLIANT</b></font>" if f_score >= 85 else (
                    "<font color='#d97706'><b>NEEDS ATTENTION</b></font>" if f_score >= 70 else "<font color='#dc2626'><b>NON-COMPLIANT</b></font>"
                )
                comp_rows.append([
                    Paragraph(f"<b>{escape_html(fw_name)}</b>", self.styles["TableCellBold"]),
                    Paragraph(str(f_pass), self.styles["TableCell"]),
                    Paragraph(str(f_fail), self.styles["TableCell"]),
                    Paragraph(str(f_total), self.styles["TableCell"]),
                    Paragraph(f"<b>{f_score}%</b>", self.styles["TableCellBold"]),
                    Paragraph(status_text, self.styles["TableCell"]),
                ])
            story.append(create_data_table(comp_headers, comp_rows, [130, 80, 80, 72, 90, 80]))
            story.append(Spacer(1, 16))

        # 6. TOP VULNERABLE SERVICES BREAKDOWN
        services_breakdown = summary_data.get("services_breakdown", {})
        if services_breakdown:
            story.append(Paragraph("3. Cloud Services Vulnerability Exposure", self.styles["SectionHeader"]))
            svc_headers = [
                Paragraph("Cloud Service", self.styles["TableHeader"]),
                Paragraph("Failed Evaluations", self.styles["TableHeader"]),
                Paragraph("Passed Controls", self.styles["TableHeader"]),
                Paragraph("Failure Ratio", self.styles["TableHeader"]),
            ]
            svc_rows = []
            for svc, stats in list(services_breakdown.items())[:8]:
                failed = stats.get("FAIL") if "FAIL" in stats else stats.get("fail", 0)
                passed = stats.get("PASS") if "PASS" in stats else stats.get("pass", 0)
                total = failed + passed
                ratio = f"{round((failed / total * 100), 1)}%" if total > 0 else "0%"
                svc_rows.append([
                    Paragraph(f"<b>AWS {escape_html(svc.upper())}</b>", self.styles["TableCellBold"]),
                    Paragraph(f"<font color='#dc2626'><b>{failed}</b></font>", self.styles["TableCell"]),
                    Paragraph(f"<font color='#16a34a'>{passed}</font>", self.styles["TableCell"]),
                    Paragraph(ratio, self.styles["TableCell"]),
                ])
            story.append(create_data_table(svc_headers, svc_rows, [150, 127, 127, 128]))
            story.append(Spacer(1, 16))

        # Page Break for Detailed Action Plan
        story.append(PageBreak())

        # 7. PRIORITY ACTION PLAN (CRITICAL & HIGH FINDINGS)
        story.append(Paragraph("4. Priority Vulnerabilities & Actionable Remediation Plan", self.styles["SectionHeader"]))
        story.append(Paragraph(
            "Targeted technical countermeasures and copyable CLI remediation commands for detected risks:",
            self.styles["Body"]
        ))
        story.append(Spacer(1, 10))

        failing_findings = [f for f in findings_data if (f.get("status") or "").upper() == "FAIL"]
        priority_findings = [f for f in failing_findings if (f.get("severity") or "").lower() in ("critical", "high")]
        if not priority_findings:
            priority_findings = failing_findings[:10]

        for item in priority_findings[:15]:
            sev = (item.get("severity") or "low").upper()
            sev_color = "#dc2626" if sev == "CRITICAL" else "#ea580c"
            finding_elements = []

            # Finding Header
            f_title = escape_html(item.get("check_title") or item.get("check_id") or "Security Finding")
            finding_elements.append(Paragraph(f"<font color='{sev_color}'><b>[{sev}]</b></font> <b>{f_title}</b>", self.styles["SubHeader"]))
            finding_elements.append(Spacer(1, 3))

            # Metadata Row
            res_id = escape_html(item.get("resource_id") or item.get("resource_name") or "N/A")
            svc = escape_html((item.get("service") or item.get("service_name") or "").upper())
            reg = escape_html(item.get("region") or "global")
            finding_elements.append(Paragraph(f"<b>Service:</b> {svc} | <b>Region:</b> {reg} | <b>Resource:</b> <code>{res_id}</code>", self.styles["Muted"]))
            finding_elements.append(Spacer(1, 4))

            # Risk Callout Box
            risk_text = escape_html(item.get("risk") or item.get("description") or item.get("status_extended") or "")
            if risk_text:
                risk_box = Table([[Paragraph(f"<b>⚠️ Threat Impact:</b> {risk_text}", self.styles["RiskBox"])]], colWidths=[520])
                risk_box.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fef2f2")),
                    ("BOX", (0, 0), (-1, -1), 0.5, COLOR_CRITICAL_RISK),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ]))
                finding_elements.append(risk_box)
                finding_elements.append(Spacer(1, 4))

            # Remediation Code Block
            cli_code = item.get("remediation_cli")
            if cli_code:
                code_box = Table([
                    [Paragraph("<b>Remediation CLI Command:</b>", self.styles["TableCellBold"])],
                    [Paragraph(f"<code>$ {escape_html(cli_code)}</code>", self.styles["Code"])],
                ], colWidths=[520])
                code_box.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), COLOR_LIGHT_BG),
                    ("BACKGROUND", (0, 1), (-1, 1), COLOR_CODE_BG),
                    ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ]))
                finding_elements.append(code_box)
                finding_elements.append(Spacer(1, 8))
            else:
                rem_text = item.get("remediation")
                if rem_text:
                    finding_elements.append(Paragraph(f"<b>Remediation Action:</b> {escape_html(rem_text)}", self.styles["TableCell"]))
                    finding_elements.append(Spacer(1, 6))

            story.append(KeepTogether(finding_elements))

        # Build document
        doc.build(story, canvasmaker=NumberedCanvas)

        if output_path is not None:
            return Path(output_path)
        else:
            target.seek(0)
            return target

