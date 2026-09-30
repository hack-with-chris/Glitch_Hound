"""
Dummy payment gateway.

Simulates a card-payment flow with basic client-side validation (Luhn
check, expiry format, CVV length) so the UI/UX feels real, but NO real
payment processor is contacted and NO real card data should ever be
entered here.
"""
import time
from datetime import datetime, timedelta, timezone


class PaymentError(Exception):
    pass


def _luhn_check(card_number: str) -> bool:
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 12:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def validate_card(card_number: str, expiry: str, cvv: str, name_on_card: str):
    card_number = card_number.replace(" ", "")
    if not name_on_card.strip():
        raise PaymentError("Name on card is required.")
    if not card_number.isdigit() or not _luhn_check(card_number):
        raise PaymentError("Card number is invalid.")
    if not (3 <= len(cvv) <= 4 and cvv.isdigit()):
        raise PaymentError("CVV is invalid.")
    try:
        month, year = expiry.split("/")
        exp_date = datetime(2000 + int(year), int(month), 1, tzinfo=timezone.utc)
        if exp_date < datetime.now(timezone.utc).replace(day=1, tzinfo=timezone.utc):
            raise PaymentError("Card has expired.")
    except (ValueError, IndexError):
        raise PaymentError("Expiry must be in MM/YY format.")
    return card_number[-4:]


def charge(card_number: str, expiry: str, cvv: str, name_on_card: str, amount: float):
    """
    Simulates contacting a payment processor. Always 'succeeds' unless the
    card fails Luhn validation or the (fake) card number ends in 0000,
    which is reserved as a deliberate 'declined' test case.
    """
    last4 = validate_card(card_number, expiry, cvv, name_on_card)
    time.sleep(1.2)

    if card_number.replace(" ", "").endswith("0000"):
        return {"status": "failed", "reason": "Card declined by issuer.", "last4": last4}

    return {
        "status": "success",
        "last4": last4,
        "amount": amount,
        "currency": "INR",
        "authorized_at": datetime.now(timezone.utc),
    }


def next_billing_date(days=30):
    return datetime.now(timezone.utc) + timedelta(days=days)
