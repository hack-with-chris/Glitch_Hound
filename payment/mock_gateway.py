"""
Mock payment gateway — implements the same PaymentGateway interface as the
real Easebuzz/Razorpay backends, but never leaves your machine. Good
default for development, demos, and any environment without live credentials.
"""
import uuid

from payment.gateway_base import PaymentGateway, GatewayResult
from payment import dummy_payment


class MockGateway(PaymentGateway):
    name = "mock"

    def start_payment(self, user, plan, amount, card_number="", expiry="", cvv="", name_on_card="", **kwargs):
        try:
            result = dummy_payment.charge(card_number, expiry, cvv, name_on_card, amount)
        except dummy_payment.PaymentError as e:
            return GatewayResult(status="failed", transaction_id=f"mock_{uuid.uuid4().hex[:12]}",
                                  amount=amount, currency="INR", detail=str(e))

        if result["status"] == "success":
            return GatewayResult(
                status="success",
                transaction_id=f"mock_{uuid.uuid4().hex[:12]}",
                amount=amount, currency="INR",
                detail=f"Payment simulated successfully (card ending {result['last4']}).",
                raw=result,
            )
        return GatewayResult(
            status="failed",
            transaction_id=f"mock_{uuid.uuid4().hex[:12]}",
            amount=amount, currency="INR",
            detail=result.get("reason", "Payment declined."),
            raw=result,
        )

    def finalize_payment(self, pending_result: GatewayResult, **kwargs) -> GatewayResult:
        return pending_result  # nothing more to do — mock charges finish in one step
