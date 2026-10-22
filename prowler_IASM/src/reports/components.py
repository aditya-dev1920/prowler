"""
ReportLab Reusable UI Components for Prowler IASM.
Mirrors Prowler's components module with tables, badges, cards, and canvas decorations.
"""

from typing import Any, Dict, List, Optional
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, Table, TableStyle

from .config import (
    COLOR_BORDER,
    COLOR_BORDER_GRAY,
    COLOR_CRITICAL_RISK,
    COLOR_DARK_BLUE,
    COLOR_DARK_GRAY,
    COLOR_GRAY,
    COLOR_GRID_GRAY,
    COLOR_HEADER_DARK,
    COLOR_HIGH_RISK,
    COLOR_LIGHT_BG,
    COLOR_LIGHT_GRAY,
    COLOR_LOW_RISK,
    COLOR_MEDIUM_RISK,
    COLOR_NAVY,
    COLOR_PASS,
    COLOR_SAFE,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_WHITE,
    PADDING_MEDIUM,
    PADDING_SMALL,
)


def truncate_text(text: str, max_len: int) -> str:
    """Truncates text to max_len characters with an ellipsis."""
    if not text:
        return ""
    text = str(text)
    if len(text) <= max_len:
        return text
    if max_len < 4:
        return text[:max_len]
    return text[: max_len - 3] + "..."


def escape_html(text: str) -> str:
    """Escapes HTML special characters for ReportLab Paragraph rendering."""
    return (
        str(text or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def get_color_for_risk_level(risk_level: str) -> colors.Color:
    """Maps finding severity to ReportLab Color."""
    risk_lower = str(risk_level).lower()
    if risk_lower == "critical":
        return COLOR_CRITICAL_RISK
    if risk_lower == "high":
        return COLOR_HIGH_RISK
    if risk_lower == "medium":
        return COLOR_MEDIUM_RISK
    if risk_lower == "low":
        return COLOR_LOW_RISK
    return COLOR_SAFE


def get_color_for_status(status: str) -> colors.Color:
    """Maps check status (PASS/FAIL) to ReportLab Color."""
    stat_upper = str(status).upper()
    if stat_upper == "PASS":
        return COLOR_PASS
    if stat_upper == "FAIL":
        return COLOR_CRITICAL_RISK
    return COLOR_DARK_GRAY


def create_status_badge(status: str, width: float = 55, height: float = 16) -> Table:
    """Renders a colored pill status badge (PASS / FAIL)."""
    stat_upper = str(status).upper()
    bg_color = colors.HexColor("#f0fdf4") if stat_upper == "PASS" else colors.HexColor("#fef2f2")
    border_color = COLOR_PASS if stat_upper == "PASS" else COLOR_CRITICAL_RISK
    text_color = "#16a34a" if stat_upper == "PASS" else "#dc2626"

    badge_style = ParagraphStyle(
        "BadgeText",
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=9,
        textColor=colors.HexColor(text_color),
        alignment=1,  # Center
    )
    t = Table([[Paragraph(stat_upper, badge_style)]], colWidths=[width], rowHeights=[height])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg_color),
        ("BOX", (0, 0), (-1, -1), 0.5, border_color),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING", (0, 0), (-1, -1), 0),
    ]))
    return t


def create_data_table(
    headers: List[Paragraph],
    rows: List[List[Any]],
    col_widths: List[float],
    header_bg: colors.Color = COLOR_DARK_BLUE,
    alternate_rows: bool = True,
) -> Table:
    """Creates a standard styled data table with alternating rows."""
    table_data = [headers] + rows
    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), header_bg),
        ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_WHITE),
        ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING", (0, 0), (-1, -1), PADDING_SMALL),
    ]
    if alternate_rows and len(rows) > 1:
        for idx in range(1, len(table_data)):
            bg = COLOR_WHITE if idx % 2 != 0 else COLOR_LIGHT_BG
            style_cmds.append(("BACKGROUND", (0, idx), (-1, idx), bg))

    t.setStyle(TableStyle(style_cmds))
    return t


def create_info_table(
    data_dict: Dict[str, Any],
    col_widths: Optional[List[float]] = None,
) -> Table:
    """Creates a 2-column or 4-column key-value metadata display table."""
    widths = col_widths or [105, 161, 105, 161]
    items = list(data_dict.items())
    rows = []
    
    k_style = ParagraphStyle("IK", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=COLOR_DARK_BLUE)
    v_style = ParagraphStyle("IV", fontName="Helvetica", fontSize=8, leading=10, textColor=COLOR_TEXT_PRIMARY)

    for i in range(0, len(items), 2):
        row = []
        # First pair
        k1, v1 = items[i]
        row.extend([Paragraph(f"<b>{k1}:</b>", k_style), Paragraph(str(v1), v_style)])
        # Second pair
        if i + 1 < len(items):
            k2, v2 = items[i + 1]
            row.extend([Paragraph(f"<b>{k2}:</b>", k_style), Paragraph(str(v2), v_style)])
        else:
            row.extend([Paragraph("", k_style), Paragraph("", v_style)])
        rows.append(row)

    t = Table(rows, colWidths=widths)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLOR_LIGHT_BG),
        ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    return t


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas that computes and draws the total page count
    alongside running headers and confidential security audit footers.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(COLOR_TEXT_MUTED)

        # Running Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(40, 755, "NOPAL CYBER CSPM — Executive Security Posture Assessment Report")
            self.setStrokeColor(COLOR_BORDER)
            self.setLineWidth(0.5)
            self.line(40, 747, 572, 747)

        # Running Footer (all pages)
        self.setStrokeColor(COLOR_BORDER)
        self.setLineWidth(0.5)
        self.line(40, 42, 572, 42)
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(572, 30, page_str)
        self.drawString(40, 30, "Confidential — For Internal & Authorized Security Audit Use Only | Powered by Prowler")
        self.restoreState()

