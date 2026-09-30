"""
Central theme for the "hacking" look — Matrix-green on black, monospace
everywhere. Every GUI page imports colors/fonts from here so the whole
app stays visually consistent and easy to re-tune from one place.
"""

# ---------------------------------------------------------------------------
# Palette
# ---------------------------------------------------------------------------
BLACK = "#020602"            # root background
PANEL = "#0A120A"            # cards / frames
PANEL_ALT = "#0E1A0E"        # slightly lighter panel (rows, inputs)
BORDER = "#164A1E"           # dim green border for panels/inputs
BORDER_BRIGHT = "#00FF41"    # bright green border for focus/active

GREEN = "#00FF41"            # primary "matrix" green — headings, key numbers
GREEN_SOFT = "#39FF6A"       # buttons / hover
GREEN_DIM = "#5FA972"        # secondary/muted text
TEXT_MUTED = "#4D774E"

CYAN = "#00E5FF"             # secondary accent (Pro badges, links)
AMBER = "#FFB000"            # warnings
RED = "#FF3B3B"              # danger / missing / failed
LIME = "#B6FF3B"             # grade B

# ---------------------------------------------------------------------------
# Fonts (Consolas — monospace, ships with Windows; degrades gracefully
# to the platform default monospace elsewhere)
# ---------------------------------------------------------------------------
FONT = "Consolas"

F_LOGO = (FONT, 36, "bold")
F_TITLE = (FONT, 30, "bold")
F_HEADER = (FONT, 22, "bold")
F_SUBHEADER = (FONT, 18, "bold")
F_BODY = (FONT, 17)
F_BODY_BOLD = (FONT, 17, "bold")
F_SMALL = (FONT, 14)
F_IMPACT = (FONT, 16)
F_STAT = (FONT, 36, "bold")
F_MONO = (FONT, 17)
F_MONO_SMALL = (FONT, 14)
F_BADGE = (FONT, 14, "bold")
F_PORT = (FONT, 24, "bold")
F_GRADE = (FONT, 46, "bold")

# ---------------------------------------------------------------------------
# Presentation helpers (display-only — never used to alter scan results,
# only to color/label them for readability)
# ---------------------------------------------------------------------------
NOTABLE_PORTS = {
    21: "FTP — often unencrypted",
    23: "Telnet — unencrypted, avoid exposing",
    25: "SMTP — check for open relay",
    139: "NetBIOS — rarely needed externally",
    445: "SMB — frequent ransomware target",
    1433: "MSSQL — should not face the internet",
    3306: "MySQL — should not face the internet",
    3389: "RDP — high-value brute-force target",
    5432: "PostgreSQL — should not face the internet",
    5900: "VNC — often weakly authenticated",
    6379: "Redis — frequently misconfigured with no auth",
}


def port_flag(port: int):
    """Returns (label, color) for a port badge."""
    if port in NOTABLE_PORTS:
        return "⚠ REVIEW", AMBER
    return "OPEN", GREEN


def grade_color(grade: str) -> str:
    return {
        "A": GREEN,
        "B": LIME,
        "C": AMBER,
        "D": "#FF7A3B",
        "F": RED,
    }.get(grade, GREEN_DIM)


def status_icon_color(is_good: bool):
    return ("✓", GREEN) if is_good else ("✗", RED)
