"""
Returns whichever gateway backend is configured, so the rest of the app
(subscription_page.py) never imports MockGateway/EasebuzzGateway/
RazorpayGateway directly.
"""
import config
from payment.mock_gateway import MockGateway


def get_gateway():
    mode = config.PAYMENT_GATEWAY_MODE.lower()
    if mode == "easebuzz":
        from payment.easebuzz_gateway import EasebuzzGateway  # imported lazily so
        return EasebuzzGateway()                              # 'mock' mode never needs the SDK installed
    if mode == "razorpay":
        from payment.razorpay_gateway import RazorpayGateway
        return RazorpayGateway()
    return MockGateway()
