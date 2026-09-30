"""
Real Easebuzz integration (third-party API — https://easebuzz.in).

SETUP — do this before switching PAYMENT_GATEWAY_MODE to "easebuzz":
  1. pip install Easebuzz
  2. Sign up at https://easebuzz.in (business/individual details + KYC docs).
     Sandbox/UAT test credentials are emailed to you after signup — they
     are NOT instantly generated the way Stripe/PayPal test keys are.
  3. Put the credentials in your .env file:
       EASEBUZZ_KEY=your_test_merchant_key
       EASEBUZZ_SALT=your_test_salt
       EASEBUZZ_ENV=test          # switch to "prod" only after go-live
  4. Set PAYMENT_GATEWAY_MODE=easebuzz in .env as well.

HOW THE FLOW WORKS (this is a *hosted-checkout* gateway, not a direct
card-charge API like Stripe, so it's a two-step flow):
  1. start_payment() calls Easebuzz's Initiate Payment API, which returns
     an `access_key`. We build the hosted-checkout URL from it and open
     it in the user's default browser with `webbrowser.open()`.
       Sandbox:    https://testpay.easebuzz.in/pay/<access_key>
       Production: https://pay.easebuzz.in/pay/<access_key>
     The user completes (or cancels) the payment in the browser.
  2. Because a desktop app has no public URL for Easebuzz to redirect/
     webhook back to, finalize_payment() asks the user to confirm they
     completed payment, then calls Easebuzz's Transaction Status API to
     verify server-side that the txnid really settled as a success before
     granting Pro access. NEVER trust the browser redirect alone for that.

IMPORTANT: the official `Easebuzz` PyPI package's public page only
documents `initiate_payment_api()` explicitly. If the transaction-status
method name below (`transaction_status_api`) doesn't exist in the version
you install, run this once to discover the real method name and adjust:
    from Easebuzz import EasebuzzAPIs
    api = EasebuzzAPIs("key", "salt", "test")
    print([m for m in dir(api) if not m.startswith("_")])
"""
import uuid
import webbrowser

import config
from payment.gateway_base import PaymentGateway, GatewayResult

try:
    from Easebuzz import EasebuzzAPIs
except ImportError:
    EasebuzzAPIs = None


class EasebuzzGateway(PaymentGateway):
    name = "easebuzz"

    def __init__(self):
        if EasebuzzAPIs is None:
            raise RuntimeError("Run 'pip install Easebuzz' to use the real Easebuzz gateway.")
        if not config.EASEBUZZ_KEY or not config.EASEBUZZ_SALT:
            raise RuntimeError("Set EASEBUZZ_KEY and EASEBUZZ_SALT in your .env file first.")
        self.api = EasebuzzAPIs(config.EASEBUZZ_KEY, config.EASEBUZZ_SALT, config.EASEBUZZ_ENV)

    def start_payment(self, user, plan, amount, **kwargs):
        txnid = f"glitchhound_{uuid.uuid4().hex[:16]}"
        payment_params = {
            "amount": str(amount),
            "firstname": user.get("full_name") or user.get("username", "Customer"),
            "email": user.get("email", ""),
            "phone": kwargs.get("phone", "9999999999"),
            "productinfo": f"{config.APP_NAME} {plan.upper()} subscription",
            "surl": "https://example.com/payment-success",
            "furl": "https://example.com/payment-failure",
        }

        try:
            response = self.api.initiate_payment_api(payment_params)
        except Exception as exc:
            return GatewayResult(status="failed", transaction_id=txnid, amount=amount,
                                  currency="INR", detail=f"Could not reach Easebuzz: {exc}")

        access_key = response.get("data") if isinstance(response, dict) else None
        if not access_key or response.get("status") != 1:
            return GatewayResult(status="failed", transaction_id=txnid, amount=amount,
                                  currency="INR", detail=f"Easebuzz rejected the request: {response}")

        base_url = "https://testpay.easebuzz.in/pay/" if config.EASEBUZZ_ENV == "test" else "https://pay.easebuzz.in/pay/"
        checkout_url = base_url + access_key
        webbrowser.open(checkout_url)

        return GatewayResult(
            status="pending",
            transaction_id=txnid,
            amount=amount,
            currency="INR",
            detail="Checkout opened in your browser. Complete the payment, then confirm in the app.",
            raw={"access_key": access_key, "checkout_url": checkout_url},
        )

    def finalize_payment(self, pending_result: GatewayResult, **kwargs) -> GatewayResult:
        txnid = pending_result.transaction_id
        try:
            status_response = self.api.transaction_status_api({"txnid": txnid})
        except AttributeError:
            return GatewayResult(
                status="failed", transaction_id=txnid, amount=pending_result.amount, currency="INR",
                detail=("This installed version of the Easebuzz SDK doesn't expose "
                        "transaction_status_api(). Check the package's real method name "
                        "(see this file's module docstring) and update finalize_payment()."),
            )
        except Exception as exc:
            return GatewayResult(status="failed", transaction_id=txnid, amount=pending_result.amount,
                                  currency="INR", detail=f"Status check failed: {exc}")

        txn_status = str(status_response.get("status", "")).lower() if isinstance(status_response, dict) else ""
        if txn_status == "success":
            return GatewayResult(status="success", transaction_id=txnid, amount=pending_result.amount,
                                  currency="INR", detail="Payment verified with Easebuzz.", raw=status_response)
        return GatewayResult(status="failed", transaction_id=txnid, amount=pending_result.amount,
                              currency="INR", detail=f"Payment not confirmed (status: {txn_status or 'unknown'}).",
                              raw=status_response)
