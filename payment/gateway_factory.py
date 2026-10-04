"""
Returns whichever gateway backend is configured, so the rest of the app
(subscription_page.py) never imports MockGateway or RazorpayGateway directly.
"""
import config
from payment.mock_gateway import MockGateway


def get_gateway():
    mode = config.PAYMENT_GATEWAY_MODE.lower()
    if mode == "razorpay":
        from payment.razorpay_gateway import RazorpayGateway
        return RazorpayGateway()
    if mode == "mock":
        return MockGateway()
    raise ValueError(f"Unsupported payment gateway mode: {mode!r}")
