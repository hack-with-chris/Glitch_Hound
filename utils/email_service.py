"""
Sends OTP emails via SMTP (stdlib smtplib — no extra dependency).

If SMTP isn't configured in .env, calls fall back to printing the email to
the console instead of failing — so the verification/reset flows are fully
testable before you've set up a real mailbox.
"""
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import config


class EmailError(Exception):
    pass


def _smtp_configured() -> bool:
    return bool(config.SMTP_HOST and config.SMTP_USER and config.SMTP_PASSWORD)


def send_email(to_email: str, subject: str, body: str) -> None:
    if not _smtp_configured():
        print("=" * 60)
        print(f"[DEV MODE — SMTP not configured] Email to: {to_email}")
        print(f"Subject: {subject}")
        print(body)
        print("=" * 60)
        return

    msg = MIMEMultipart()
    msg["From"] = config.SMTP_FROM_EMAIL or config.SMTP_USER
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=10) as server:
            server.starttls(context=context)
            server.login(config.SMTP_USER, config.SMTP_PASSWORD)
            server.sendmail(msg["From"], [to_email], msg.as_string())
    except Exception as exc:
        raise EmailError(f"Could not send email: {exc}")


def send_otp_email(to_email: str, otp_code: str, purpose: str) -> None:
    if purpose == "verify_email":
        subject = f"Verify your {config.APP_NAME} account"
        intro = "Your email verification code is:"
    else:
        subject = f"{config.APP_NAME} password reset code"
        intro = "Your password reset code is:"

    body = (
        f"{intro} {otp_code}\n\n"
        f"This code expires in {config.OTP_EXPIRY_MINUTES} minutes and can only be used once.\n"
        "If you didn't request this, you can safely ignore this email."
    )
    send_email(to_email, subject, body)
