"""
Real Razorpay integration (third-party API — https://razorpay.com).

SETUP — do this before switching PAYMENT_GATEWAY_MODE to "razorpay":
  1. pip install razorpay
  2. Sign up at https://razorpay.com and verify your email. Dashboard ->
     Settings -> API Keys -> Generate Test Key. Razorpay's TEST-mode keys
     work immediately after signup — no KYC/merchant
     approval needed just to try it out (KYC is only required to go live
     with real money).
  3. Put the keys in your .env file:
       RAZORPAY_KEY_ID=rzp_test_xxxxxxxxxxxxxx
       RAZORPAY_KEY_SECRET=your_test_key_secret
  4. Set PAYMENT_GATEWAY_MODE=razorpay in .env as well.

HOW THE FLOW WORKS (Razorpay's Payment Links API — a hosted checkout page,
not a JS-embedded widget, which is what makes it usable from a plain
desktop app with no web server of its own):
  1. start_payment() calls the Payment Links API to create a link for the
     exact amount, and opens its `short_url` in the user's browser.
  2. Because a desktop app has no public URL for Razorpay to POST a
     webhook to, finalize_payment() re-fetches that same Payment Link
     after the user says they've paid, and checks its `status` field is
     "paid" before granting Pro access — never trust the browser alone.

Test card for the Razorpay test-mode checkout: 4111 1111 1111 1111, any
future expiry, any CVV — see razorpay.com/docs/payments/payments/test-card-upi-details/
for the full list (UPI/netbanking test credentials too).
"""
import uuid
import webbrowser

import config
from payment.gateway_base import PaymentGateway, GatewayResult

try:
    import razorpay
except ImportError:
    razorpay = None


class RazorpayGateway(PaymentGateway):
    name = "razorpay"

    def __init__(self):
        if razorpay is None:
            raise RuntimeError("Run 'pip install razorpay' to use the Razorpay gateway.")
        if not config.RAZORPAY_KEY_ID or not config.RAZORPAY_KEY_SECRET:
            raise RuntimeError("Set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET in your .env file first.")
        self.client = razorpay.Client(auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET))

    def start_payment(self, user, plan, amount, **kwargs):
        reference_id = f"glitchhound_{uuid.uuid4().hex[:16]}"
        cycle_label = kwargs.get("cycle_label", "")

        try:
            link = self.client.payment_link.create({
                "amount": int(round(amount * 100)),  # Razorpay wants the amount in paise, not rupees
                "currency": "INR",
                "reference_id": reference_id,
                "description": f"{config.APP_NAME} {plan.upper()} subscription{(' — ' + cycle_label) if cycle_label else ''}",
                "customer": {
                    "name": user.get("full_name") or user.get("username", "Customer"),
                    "email": user.get("email", ""),
                },
                "notify": {"sms": False, "email": False},
            })
        except Exception as exc:
            return GatewayResult(status="failed", transaction_id=reference_id, amount=amount,
                                  currency="INR", detail=f"Could not reach Razorpay: {exc}")

        webbrowser.open(link["short_url"])

        return GatewayResult(
            status="pending",
            transaction_id=link["id"],  # the payment_link id (e.g. "plink_...") — needed to re-fetch status later
            amount=amount,
            currency="INR",
            detail="Checkout opened in your browser. Complete the payment, then confirm in the app.",
            raw={"payment_link_id": link["id"], "short_url": link["short_url"], "reference_id": reference_id},
        )

    def finalize_payment(self, pending_result: GatewayResult, **kwargs) -> GatewayResult:
        try:
            link = self.client.payment_link.fetch(pending_result.transaction_id)
        except Exception as exc:
            return GatewayResult(status="failed", transaction_id=pending_result.transaction_id,
                                  amount=pending_result.amount, currency="INR",
                                  detail=f"Status check failed: {exc}")

        status = link.get("status")
        if status == "paid":
            return GatewayResult(status="success", transaction_id=pending_result.transaction_id,
                                  amount=pending_result.amount, currency="INR",
                                  detail="Payment verified with Razorpay.", raw=link)
        return GatewayResult(status="failed", transaction_id=pending_result.transaction_id,
                              amount=pending_result.amount, currency="INR",
                              detail=f"Payment not confirmed (status: {status or 'unknown'}).", raw=link)
