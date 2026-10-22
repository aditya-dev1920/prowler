"""
ReportLab Native Chart Drawings for Prowler IASM.
Generates pure vector-based charts and progress indicators without external dependencies like matplotlib.
"""

from reportlab.graphics.shapes import Drawing, Group, Rect, String
from reportlab.lib import colors

from .config import (
    CHART_COLOR_BLUE,
    CHART_COLOR_GREEN,
    CHART_COLOR_ORANGE,
    CHART_COLOR_RED,
    CHART_COLOR_YELLOW,
    COLOR_BORDER,
    COLOR_LIGHT_BG,
    COLOR_TEXT_PRIMARY,
)


def get_chart_color_for_percentage(percentage: float) -> str:
    """Returns standard hex color string based on compliance / posture score."""
    if percentage >= 85:
        return CHART_COLOR_GREEN
    if percentage >= 70:
        return CHART_COLOR_YELLOW
    if percentage >= 50:
        return CHART_COLOR_ORANGE
    return CHART_COLOR_RED


def create_progress_bar_drawing(
    percentage: float,
    width: float = 120,
    height: float = 10,
) -> Drawing:
    """Renders a sleek vector progress bar for compliance tables."""
    pct = max(0.0, min(100.0, float(percentage)))
    fill_width = (pct / 100.0) * width
    bar_color = colors.HexColor(get_chart_color_for_percentage(pct))

    d = Drawing(width, height)
    # Background track
    d.add(Rect(0, 0, width, height, rx=3, ry=3, fillColor=COLOR_BORDER, strokeColor=None))
    # Active fill
    if fill_width > 0:
        d.add(Rect(0, 0, fill_width, height, rx=3, ry=3, fillColor=bar_color, strokeColor=None))
    return d


def create_severity_distribution_bar(
    critical: int,
    high: int,
    medium: int,
    low: int,
    width: float = 520,
    height: float = 20,
) -> Drawing:
    """Renders a stacked severity distribution bar showing proportion of risk levels."""
    total = critical + high + medium + low
    d = Drawing(width, height)
    
    if total == 0:
        d.add(Rect(0, 0, width, height, rx=4, ry=4, fillColor=colors.HexColor(CHART_COLOR_GREEN), strokeColor=None))
        d.add(String(width / 2, 5, "100% COMPLIANT / ZERO ACTIVE RISKS", textAnchor="middle", fontSize=8, fontName="Helvetica-Bold", fillColor=colors.white))
        return d

    counts = [
        (critical, colors.HexColor(CHART_COLOR_RED)),
        (high, colors.HexColor(CHART_COLOR_ORANGE)),
        (medium, colors.HexColor(CHART_COLOR_YELLOW)),
        (low, colors.HexColor(CHART_COLOR_BLUE)),
    ]

    curr_x = 0.0
    for count, color in counts:
        if count <= 0:
            continue
        seg_w = (count / total) * width
        d.add(Rect(curr_x, 0, seg_w, height, fillColor=color, strokeColor=None))
        if seg_w > 25:
            d.add(String(curr_x + (seg_w / 2), 6, str(count), textAnchor="middle", fontSize=8, fontName="Helvetica-Bold", fillColor=colors.white))
        curr_x += seg_w

    return d

