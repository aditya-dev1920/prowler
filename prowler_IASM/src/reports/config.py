"""
Report Configuration and Theme Settings for Prowler IASM.
Mirrors Prowler's official styling constants, colors, margins, and performance thresholds.
"""

from dataclasses import dataclass
from reportlab.lib import colors
from reportlab.lib.units import inch

# =============================================================================
# Performance & Memory Optimization Settings
# =============================================================================
LONG_TABLE_THRESHOLD = 50
FINDINGS_TABLE_CHUNK_SIZE = 300
MAX_FINDINGS_PER_CHECK = 100

# =============================================================================
# Base Colors (Prowler Official Palette)
# =============================================================================
COLOR_PROWLER_DARK_GREEN = colors.Color(0.1, 0.5, 0.2)
COLOR_BLUE = colors.Color(0.2, 0.4, 0.6)
COLOR_LIGHT_BLUE = colors.Color(0.3, 0.5, 0.7)
COLOR_LIGHTER_BLUE = colors.Color(0.4, 0.6, 0.8)
COLOR_BG_BLUE = colors.Color(0.95, 0.97, 1.0)
COLOR_BG_LIGHT_BLUE = colors.Color(0.98, 0.99, 1.0)
COLOR_GRAY = colors.Color(0.2, 0.2, 0.2)
COLOR_LIGHT_GRAY = colors.Color(0.9, 0.9, 0.9)
COLOR_BORDER_GRAY = colors.Color(0.7, 0.8, 0.9)
COLOR_GRID_GRAY = colors.Color(0.7, 0.7, 0.7)
COLOR_DARK_GRAY = colors.Color(0.4, 0.4, 0.4)
COLOR_HEADER_DARK = colors.Color(0.1, 0.3, 0.5)
COLOR_HEADER_MEDIUM = colors.Color(0.15, 0.35, 0.55)
COLOR_WHITE = colors.white

# Cyber Executive Palette
COLOR_NAVY = colors.HexColor("#0f172a")
COLOR_CYBER_BLUE = colors.HexColor("#0284c7")
COLOR_DARK_BLUE = colors.HexColor("#1e293b")
COLOR_LIGHT_BG = colors.HexColor("#f8fafc")
COLOR_BORDER = colors.HexColor("#e2e8f0")
COLOR_TEXT_PRIMARY = colors.HexColor("#0f172a")
COLOR_TEXT_MUTED = colors.HexColor("#64748b")
COLOR_CODE_BG = colors.HexColor("#1e293b")

# Risk and Status Colors
COLOR_HIGH_RISK = colors.Color(0.8, 0.2, 0.2)      # #cc3333
COLOR_CRITICAL_RISK = colors.HexColor("#dc2626")   # #dc2626
COLOR_MEDIUM_RISK = colors.Color(0.9, 0.6, 0.2)    # #e69933
COLOR_LOW_RISK = colors.Color(0.9, 0.9, 0.2)       # #e6e633
COLOR_SAFE = colors.Color(0.2, 0.8, 0.2)           # #33cc33
COLOR_PASS = colors.HexColor("#16a34a")

# Chart and Badge Colors
CHART_COLOR_GREEN = "#16a34a"
CHART_COLOR_RED = "#dc2626"
CHART_COLOR_ORANGE = "#ea580c"
CHART_COLOR_YELLOW = "#d97706"
CHART_COLOR_BLUE = "#2563eb"

# Spacing & Paddings
PADDING_SMALL = 4
PADDING_MEDIUM = 8
PADDING_LARGE = 12
PADDING_XLARGE = 16


@dataclass
class ColumnConfig:
    """Configuration for a table column."""
    name: str
    width: float
    alignment: str = "left"

