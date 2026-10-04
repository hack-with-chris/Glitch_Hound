"""
Central configuration for the Glitch Hound desktop application.
Loads secrets from a local .env file (never commit .env to version control).
"""
import os
import sys
from dotenv import load_dotenv


def _app_dir() -> str:
    """
    Folder to look for .env in.
    - Normal `python main.py`: the project root (this file's folder).
    - Packaged .exe (PyInstaller): the folder the .exe itself lives in —
      NOT the temp folder PyInstaller extracts to (sys._MEIPASS), since
      that's wiped and recreated on every launch. This lets each installed
      copy ship its own .env right next to GlitchHound.exe.
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


load_dotenv(os.path.join(_app_dir(), ".env"))

# ---------------------------------------------------------------------------
# MongoDB Atlas
# ---------------------------------------------------------------------------
MONGODB_URI = os.getenv(
    "MONGODB_URI",
    "mongodb+srv://<username>:<password>@<cluster-url>/?retryWrites=true&w=majority",
)
# NOTE: only the *default* changed to glitch_hound_db. If your .env already
# sets DB_NAME explicitly (e.g. to the old cyberscan_db), nothing here
# touches your existing data — this default only applies when DB_NAME is
# unset. See my message after this edit for how to fully migrate if you want to.
DB_NAME = os.getenv("DB_NAME", "glitch_hound_db")

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
APP_NAME = "Glitch Hound"
APP_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Payment gateway
# ---------------------------------------------------------------------------
# "mock"      -> built-in simulated gateway, no signup needed, safe for a
#                college/portfolio project and for demoing offline.
# "razorpay"  -> real third-party API (https://razorpay.com). Test-mode API
#                keys are available immediately after signup.
PAYMENT_GATEWAY_MODE = os.getenv("PAYMENT_GATEWAY_MODE", "mock")  # "mock" | "razorpay"

RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "")

# ---------------------------------------------------------------------------
# Admin account (single, predefined — see database/db.py _ensure_admin_seeded)
# ---------------------------------------------------------------------------
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@glitchhound.local")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

# ---------------------------------------------------------------------------
# Email OTP (registration verification + forgot password)
# ---------------------------------------------------------------------------
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "")

OTP_LENGTH = 6
OTP_EXPIRY_MINUTES = int(os.getenv("OTP_EXPIRY_MINUTES", "10"))
OTP_MAX_ATTEMPTS = int(os.getenv("OTP_MAX_ATTEMPTS", "5"))
OTP_PEPPER = os.getenv("OTP_PEPPER", "change-this-otp-pepper-in-.env")

# Password hashing
PBKDF2_ITERATIONS = 260_000

# ---------------------------------------------------------------------------
# Subscription plans — feature tier is separate from billing cycle: "pro" is
# always the same features, BILLING_CYCLES below just controls price/duration
# for how long a Pro upgrade lasts.
# ---------------------------------------------------------------------------
PLAN_LIMITS = {
    "free": {
        "label": "Free",
        "scans_per_month": 5,
        "max_port": 1024,
        "port_scan_threads": 20,
        "vuln_checks": ["headers", "ssl", "email_trust"],
        "history_visible": 5,
        "can_download_reports": False,
        "report_formats": [],
        "host_discovery": True,
    },
    "pro": {
        "label": "Pro",
        "scans_per_month": None,    # unlimited
        "max_port": 65535,
        "port_scan_threads": 200,
        "vuln_checks": ["headers", "ssl", "email_trust", "exposed_paths", "cookies", "banner", "directory_listing"],
        "history_visible": None,    # unlimited
        "can_download_reports": True,
        "report_formats": ["pdf", "csv", "json"],
        "host_discovery": True,
    },
}

# Billing cycle options when upgrading to Pro. Yearly is priced at roughly
# 2 months free vs. paying monthly — tune freely.
BILLING_CYCLES = {
    "monthly": {"label": "Monthly", "price_inr": 999, "duration_days": 30},
    "yearly": {"label": "Yearly", "price_inr": 9999, "duration_days": 365},
}

COMMON_PORTS_TOP_100 = [
    7, 20, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119,
    135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515,
    543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027,
    1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
    2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101,
    5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6379, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 27017, 32768,
    49152, 49153, 49154, 49155, 49156, 49157,
]
