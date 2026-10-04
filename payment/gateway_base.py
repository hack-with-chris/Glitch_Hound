"""
Abstract interface every payment gateway backend must implement.

Keeping this contract small means the GUI (subscription_page.py) never
needs to know whether it's talking to the mock simulator or Razorpay —
it just calls start_payment() / finalize_payment().
"""
from abc import ABC, abstractmethod


class GatewayResult:
    def __init__(self, status: str, transaction_id: str, amount: float,
                 currency: str = "INR", detail: str = "", raw: dict = None):
        self.status = status              # "success" | "failed" | "pending"
        self.transaction_id = transaction_id
        self.amount = amount
        self.currency = currency
        self.detail = detail              # human-readable message for the UI
        self.raw = raw or {}

    def __repr__(self):
        return f"<GatewayResult {self.status} {self.transaction_id} {self.amount}{self.currency}>"


class PaymentGateway(ABC):
    """
    Two-step flow that fits BOTH styles of gateway:
      - Direct/card gateways (mock simulator): start_payment() does
        everything and immediately returns a final result.
      - Redirect/hosted-checkout gateways (Razorpay):
        start_payment() opens the checkout in a browser and returns a
        "pending" result; finalize_payment() is called after the user
        confirms they've completed the payment, to verify it really went
        through.
    """

    name = "base"

    @abstractmethod
    def start_payment(self, user, plan: str, amount: float, **kwargs) -> GatewayResult:
        ...

    @abstractmethod
    def finalize_payment(self, pending_result: GatewayResult, **kwargs) -> GatewayResult:
        ...
