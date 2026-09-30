"""
Handles registration, login, and password hashing.
Uses PBKDF2-HMAC-SHA256 (stdlib `hashlib`) so the project has zero extra
native-build dependencies.
"""
import hashlib
import os
import re
import binascii

import config


class AuthError(Exception):
    pass


class EmailNotVerifiedError(AuthError):
    """Raised on login when the account exists but hasn't completed OTP verification yet."""

    def __init__(self, email):
        super().__init__("Please verify your email before logging in.")
        self.email = email


def hash_password(plain_password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", plain_password.encode("utf-8"), salt, config.PBKDF2_ITERATIONS
    )
    return f"{config.PBKDF2_ITERATIONS}${binascii.hexlify(salt).decode()}${binascii.hexlify(dk).decode()}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    try:
        iterations_str, salt_hex, hash_hex = stored_hash.split("$")
        iterations = int(iterations_str)
        salt = binascii.unhexlify(salt_hex)
        expected = binascii.unhexlify(hash_hex)
    except (ValueError, binascii.Error):
        return False

    dk = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, iterations)
    return hashlib.compare_digest(dk, expected) if hasattr(hashlib, "compare_digest") else dk == expected


def _validate_email(email: str) -> bool:
    return re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email) is not None


class AuthManager:
    """Wraps the Database layer with registration/login business rules."""

    def __init__(self, db):
        self.db = db
        self.current_user = None
        self.current_admin = None

    def register(self, username, email, password, confirm_password, full_name=""):
        username = username.strip()
        email = email.strip().lower()

        if not username or len(username) < 3:
            raise AuthError("Username must be at least 3 characters.")
        if not _validate_email(email):
            raise AuthError("Enter a valid email address.")
        if len(password) < 8:
            raise AuthError("Password must be at least 8 characters.")
        if password != confirm_password:
            raise AuthError("Passwords do not match.")
        if self.db.get_user_by_username(username):
            raise AuthError("That username is already taken.")
        if self.db.get_user_by_email(email):
            raise AuthError("That email is already registered.")

        password_hash = hash_password(password)
        user_id = self.db.create_user(username, email, password_hash, full_name)
        return user_id

    def login(self, username, password):
        """
        Tries the single predefined admin account first (same login form as
        regular users), then falls back to a normal user login. Returns
        {"role": "admin"|"user", "doc": <document>}.
        """
        username = username.strip()

        admin = self.db.get_admin_by_username(username)
        if admin and verify_password(password, admin["password_hash"]):
            self.current_admin = admin
            self.current_user = None
            return {"role": "admin", "doc": admin}

        user = self.db.get_user_by_username(username)
        if not user or not verify_password(password, user["password_hash"]):
            raise AuthError("Invalid username or password.")
        if not user.get("email_verified", False):
            raise EmailNotVerifiedError(user["email"])

        self.current_user = user
        self.current_admin = None
        return {"role": "user", "doc": user}

    def logout(self):
        self.current_user = None
        self.current_admin = None

    def refresh_current_user(self):
        if self.current_user:
            self.current_user = self.db.get_user_by_id(str(self.current_user["_id"]))
        return self.current_user
