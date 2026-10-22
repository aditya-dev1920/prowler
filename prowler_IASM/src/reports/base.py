"""
Base Report Generator and Data Models for Prowler IASM.
Mirrors Prowler's BaseComplianceReportGenerator architecture.
"""

import io
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .components import NumberedCanvas
from .config import (
    COLOR_BORDER,
    COLOR_CRITICAL_RISK,
    COLOR_DARK_BLUE,
    COLOR_HIGH_RISK,
    COLOR_NAVY,
    COLOR_PASS,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_WHITE,
)


@dataclass
class RequirementData:
    """Data model for an evaluated compliance requirement."""
    id: str
    description: str
    status: str
    passed_findings: int = 0
    failed_findings: int = 0
    total_findings: int = 0
    checks: List[str] = field(default_factory=list)
    attributes: Any = None


@dataclass
class ComplianceData:
    """Aggregated compliance framework data for audit reporting."""
    scan_id: str
    compliance_id: str
    framework: str
    version: str = ""
    description: str = ""
    score: float = 100.0
    requirements: List[RequirementData] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)


def create_pdf_styles() -> Dict[str, ParagraphStyle]:
    """Generates standardized typography styles matching Prowler's palette."""
    base = getSampleStyleSheet()

    return {
        "Title": ParagraphStyle(
            "CustomTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=COLOR_WHITE,
        ),
        "Subtitle": ParagraphStyle(
            "CustomSubtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=13,
            textColor=COLOR_BORDER,
        ),
        "SectionHeader": ParagraphStyle(
            "CustomSectionHeader",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=16,
            textColor=COLOR_NAVY,
            spaceAfter=6,
        ),
        "SubHeader": ParagraphStyle(
            "CustomSubHeader",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            textColor=COLOR_DARK_BLUE,
        ),
        "Body": ParagraphStyle(
            "CustomBody",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=COLOR_TEXT_PRIMARY,
        ),
        "Muted": ParagraphStyle(
            "CustomMuted",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=COLOR_TEXT_MUTED,
        ),
        "KpiValue": ParagraphStyle(
            "CustomKpiValue",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            alignment=1,  # Center
        ),
        "KpiLabel": ParagraphStyle(
            "CustomKpiLabel",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=9,
            textColor=COLOR_TEXT_MUTED,
            alignment=1,  # Center
        ),
        "TableHeader": ParagraphStyle(
            "CustomTableHeader",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=COLOR_WHITE,
        ),
        "TableCell": ParagraphStyle(
            "CustomTableCell",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=10,
            textColor=COLOR_TEXT_PRIMARY,
        ),
        "TableCellBold": ParagraphStyle(
            "CustomTableCellBold",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=COLOR_TEXT_PRIMARY,
        ),
        "RiskBox": ParagraphStyle(
            "CustomRiskBox",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=COLOR_CRITICAL_RISK,
        ),
        "Code": ParagraphStyle(
            "CustomCode",
            parent=base["Normal"],
            fontName="Courier",
            fontSize=7.5,
            leading=9.5,
            textColor=colors.HexColor("#38bdf8"),
        ),
    }


class BaseReportGenerator(ABC):
    """
    Abstract Base Class for PDF report generators.
    Encapsulates document creation, canvas pagination, header banners, and storytelling flow.
    """

    def __init__(self, page_size=letter):
        self.page_size = page_size
        self.styles = create_pdf_styles()

    def setup_document(self, output_target: Union[str, Path, io.BytesIO]) -> SimpleDocTemplate:
        """Initializes ReportLab SimpleDocTemplate with standard margins."""
        target = str(output_target) if isinstance(output_target, (str, Path)) else output_target
        return SimpleDocTemplate(
            target,
            pagesize=self.page_size,
            leftMargin=40,
            rightMargin=40,
            topMargin=48,
            bottomMargin=48,
        )

    def create_header_banner(self, title: str, subtitle: str) -> Table:
        """Renders the standard top branded banner."""
        data = [
            [Paragraph(f"🛡️ <b>NOPAL CYBER</b> — {title.upper()}", self.styles["Title"])],
            [Paragraph(subtitle, self.styles["Subtitle"])],
        ]
        t = Table(data, colWidths=[532])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), COLOR_NAVY),
            ("PADDING", (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 1), (-1, 1), 14),
        ]))
        return t

    @abstractmethod
    def generate(self, *args, **kwargs) -> Union[Path, io.BytesIO]:
        """Subclasses must implement the document compilation logic."""
        pass
