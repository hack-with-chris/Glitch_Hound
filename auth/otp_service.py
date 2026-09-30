"""
One-time-code generation & verification, shared by:
  - registration email verification (purpose="verify_email")
  - forgot-password (purpose="reset_password")

Codes are 6-digit, single-use, expire after config.OTP_EXPIRY_MINUTES, and
lock out after config.OTP_MAX_ATTEMPTS wrong guesses. They're stored as a
keyed hash (not plaintext) in the `otp_codes` collection.
"""
import hashlib
import random
from datetime import datetime, timedelta, timezone

import config


class OtpError(Exception):
    pass


def _hash_otp(otp_code: str, email: str) -> str:
    payload = f"{email.lower()}:{otp_code}:{config.OTP_PEPPER}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _ensure_aware(dt: datetime) -> datetime:
    """
    Defensive: the primary fix is tz_aware=True on the MongoClient
    (database/db.py), which makes every datetime read back from Mongo
    tz-aware. This is a second layer of protection in case a datetime
    ever reaches here naive some other way — without it, comparing a naive
    and an aware datetime raises TypeError instead of just working.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def generate_otp() -> str:
    return f"{random.randint(0, 10 ** config.OTP_LENGTH - 1):0{config.OTP_LENGTH}d}"


def create_and_store_otp(db, email: str, purpose: str) -> str:
    """Generates a new code, stores its hash, and returns the plaintext code to send."""
    email = email.strip().lower()
    otp_code = generate_otp()
    now = datetime.now(timezone.utc)
    db.create_otp(
        email=email,
        otp_hash=_hash_otp(otp_code, email),
        purpose=purpose,
        created_at=now,
        expires_at=now + timedelta(minutes=config.OTP_EXPIRY_MINUTES),
    )
    return otp_code


def verify_otp(db, email: str, code: str, purpose: str) -> None:
    """Raises OtpError with a user-facing message on any failure; returns None on success."""
    email = email.strip().lower()
    record = db.get_latest_otp(email, purpose)

    if not record:
        raise OtpError("No active code found for this email. Request a new one.")
    if record.get("used"):
        raise OtpError("This code has already been used. Request a new one.")
    if _ensure_aware(record["expires_at"]) < datetime.now(timezone.utc):
        raise OtpError("This code has expired. Request a new one.")
    if record.get("attempts", 0) >= config.OTP_MAX_ATTEMPTS:
        raise OtpError("Too many incorrect attempts. Request a new one.")

    if _hash_otp(code.strip(), email) != record["otp_hash"]:
        db.increment_otp_attempts(record["_id"])
        remaining = config.OTP_MAX_ATTEMPTS - (record.get("attempts", 0) + 1)
        raise OtpError(f"Incorrect code. {max(remaining, 0)} attempt(s) left.")

    db.mark_otp_used(record["_id"])
