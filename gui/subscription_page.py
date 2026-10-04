import threading
from datetime import datetime, timedelta, timezone
from tkinter import messagebox

import customtkinter as ctk

import config
from payment.gateway_factory import get_gateway
from payment.gateway_base import GatewayResult
from gui import theme


class SubscriptionPage(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=theme.BLACK)
        self.app = app
        self.pending_result = None
        self.gateway = None
        self.selected_cycle = None   # "monthly" | "yearly"
        self.upgrade_btn = None

        ctk.CTkLabel(self, text="MANAGE SUBSCRIPTION", font=theme.F_TITLE, text_color=theme.GREEN).pack(
            anchor="w", padx=32, pady=(28, 6))
        self.plan_banner = ctk.CTkLabel(self, text="", font=theme.F_BODY)
        self.plan_banner.pack(anchor="w", padx=32, pady=(0, 16))

        compare = ctk.CTkFrame(self, fg_color="transparent")
        compare.pack(fill="x", padx=32)
        compare.grid_columnconfigure(0, weight=1)
        compare.grid_columnconfigure(1, weight=1)

        self._plan_card(compare, "free").grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self._plan_card(compare, "pro").grid(row=0, column=1, sticky="nsew", padx=(10, 0))

        # Cycle selector — shown when "Upgrade to Pro" is clicked, before the payment form
        self.cycle_frame = ctk.CTkFrame(self, fg_color=theme.PANEL, corner_radius=4,
                                         border_width=1, border_color=theme.BORDER_BRIGHT)

        # Payment form / hosted-checkout panel — shown after a cycle is chosen
        self.payment_frame = ctk.CTkFrame(self, fg_color=theme.PANEL, corner_radius=4,
                                           border_width=1, border_color=theme.BORDER_BRIGHT)

        # ctk.CTkLabel(self, text="BILLING HISTORY", font=theme.F_SUBHEADER, text_color=theme.GREEN).pack(
        #     anchor="w", padx=32, pady=(20, 6))
        self.history_label = ctk.CTkLabel(self, text="BILLING HISTORY", font=theme.F_SUBHEADER, text_color=theme.GREEN)
        self.history_label.pack(anchor="w", padx=39, pady=(20, 6))

        self.history_frame = ctk.CTkScrollableFrame(self, fg_color="transparent", height=160)
        self.history_frame.pack(fill="both", expand=True, padx=32, pady=(0, 24))

    def _plan_card(self, parent, plan_key):
        limits = config.PLAN_LIMITS[plan_key]
        is_pro = plan_key == "pro"
        card = ctk.CTkFrame(parent, fg_color=theme.PANEL, corner_radius=4, border_width=1,
                             border_color=theme.BORDER_BRIGHT if is_pro else theme.BORDER)

        ctk.CTkLabel(card, text=limits["label"].upper(), font=theme.F_HEADER,
                     text_color=theme.CYAN if is_pro else theme.GREEN_DIM).pack(anchor="w", padx=20, pady=(20, 0))

        if is_pro:
            monthly = config.BILLING_CYCLES["monthly"]
            yearly = config.BILLING_CYCLES["yearly"]
            ctk.CTkLabel(card, text=f"₹{monthly['price_inr']}/mo  or  ₹{yearly['price_inr']}/yr",
                         font=theme.F_STAT, text_color=theme.GREEN).pack(anchor="w", padx=20, pady=(0, 2))
            savings = monthly["price_inr"] * 12 - yearly["price_inr"]
            ctk.CTkLabel(card, text=f"Yearly saves ₹{savings} vs. paying monthly",
                         font=theme.F_SMALL, text_color=theme.AMBER).pack(anchor="w", padx=20, pady=(0, 14))
        else:
            ctk.CTkLabel(card, text="FREE", font=theme.F_STAT, text_color=theme.GREEN_DIM).pack(
                anchor="w", padx=20, pady=(0, 14))

        scans_text = "Unlimited" if limits["scans_per_month"] is None else str(limits["scans_per_month"])
        history_text = "Full" if limits["history_visible"] is None else f"Last {limits['history_visible']}"
        downloads_text = ("Yes (" + "/".join(limits["report_formats"]) + ")") if limits["can_download_reports"] else "No"

        features = [
            f"{scans_text} scans / month",
            f"Port scanning up to port {limits['max_port']}",
            f"Audit depth: {len(limits['vuln_checks'])} check categories",
            f"Scan history: {history_text}",
            f"Report downloads: {downloads_text}",
        ]
        for feat in features:
            icon_color = theme.GREEN if is_pro else theme.GREEN_DIM
            ctk.CTkLabel(card, text=f"✓  {feat}", font=theme.F_BODY, anchor="w",
                         text_color=icon_color).pack(anchor="w", padx=20, pady=3)

        if is_pro:
            self.upgrade_btn = ctk.CTkButton(card, text="UPGRADE TO PRO", height=46, font=theme.F_BODY_BOLD,
                                              fg_color=theme.GREEN, text_color=theme.BLACK,
                                              text_color_disabled=theme.BLACK,
                                              hover_color=theme.GREEN_SOFT, command=self._begin_upgrade)
            self.upgrade_btn.pack(anchor="w", padx=20, pady=(16, 20))
        else:
            ctk.CTkLabel(card, text=" ").pack(pady=(16, 20))

        return card

    def on_show(self):
        self.refresh()

    def refresh(self):
        user = self.app.auth.current_user
        plan = user.get("plan", "free")
        limits = config.PLAN_LIMITS[plan]

        if plan == "pro":
            expires = user.get("plan_expires_at")
            expiry_text = f" — renews/expires {expires.strftime('%b %d, %Y')}" if expires else ""
            self.plan_banner.configure(text=f"● You're on the {limits['label']} plan.{expiry_text}",
                                        text_color=theme.GREEN)
            self.upgrade_btn.configure(state="disabled", text="CURRENT PLAN")
        else:
            self.plan_banner.configure(text=f"● You're on the {limits['label']} plan. Upgrade for full access.",
                                        text_color=theme.GREEN_DIM)
            self.upgrade_btn.configure(state="normal", text="UPGRADE TO PRO")

        self.cycle_frame.pack_forget()
        self.payment_frame.pack_forget()
        for w in self.cycle_frame.winfo_children():
            w.destroy()
        for w in self.payment_frame.winfo_children():
            w.destroy()

        for w in self.history_frame.winfo_children():
            w.destroy()
        payments = self.app.db.get_payment_history(str(user["_id"]))
        if not payments:
            ctk.CTkLabel(self.history_frame, text="No payments yet.", font=theme.F_BODY,
                         text_color=theme.GREEN_DIM).pack(pady=10)
        for p in payments:
            row = ctk.CTkFrame(self.history_frame, fg_color=theme.PANEL, corner_radius=4,
                                border_width=1, border_color=theme.BORDER)
            row.pack(fill="x", pady=3)
            status_color = theme.GREEN if p["status"] == "success" else theme.RED
            cycle_label = f" ({p['billing_cycle']})" if p.get("billing_cycle") else ""
            ctk.CTkLabel(row, text=f"{p['plan_purchased'].upper()}{cycle_label} — {p['amount']} {p['currency']} "
                                    f"via {p.get('gateway', 'mock')}", font=theme.F_BODY,
                         text_color=theme.GREEN_DIM, anchor="w").pack(side="left", padx=12, pady=10)
            ctk.CTkLabel(row, text=p["status"].upper(), font=theme.F_BODY_BOLD,
                         text_color=status_color).pack(side="right", padx=12)
            ctk.CTkLabel(row, text=p["created_at"].strftime("%b %d, %Y"), font=theme.F_SMALL,
                         text_color=theme.GREEN_DIM).pack(side="right", padx=12)

    # ------------------------------------------------------------ #
    # Step 1: choose a billing cycle
    # ------------------------------------------------------------ #
    def _begin_upgrade(self):
        self.payment_frame.pack_forget()
        for w in self.payment_frame.winfo_children():
            w.destroy()

        # self.cycle_frame.pack(fill="x", padx=32, pady=(0, 20))
        self.cycle_frame.pack(fill="x", padx=32, pady=(0, 20), before=self.history_label)

        for w in self.cycle_frame.winfo_children():
            w.destroy()

        ctk.CTkLabel(self.cycle_frame, text="CHOOSE A BILLING CYCLE", font=theme.F_SUBHEADER,
                     text_color=theme.GREEN).pack(anchor="w", padx=20, pady=(16, 10))

        row = ctk.CTkFrame(self.cycle_frame, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(0, 20))
        row.grid_columnconfigure(0, weight=1)
        row.grid_columnconfigure(1, weight=1)

        for i, (cycle_key, cycle) in enumerate(config.BILLING_CYCLES.items()):
            cell = ctk.CTkFrame(row, fg_color=theme.PANEL_ALT, corner_radius=4,
                                 border_width=1, border_color=theme.BORDER)
            cell.grid(row=0, column=i, sticky="nsew", padx=6)
            ctk.CTkLabel(cell, text=cycle["label"].upper(), font=theme.F_BODY_BOLD, text_color=theme.GREEN).pack(
                anchor="w", padx=16, pady=(14, 2))
            ctk.CTkLabel(cell, text=f"₹{cycle['price_inr']}", font=theme.F_HEADER, text_color=theme.CYAN).pack(
                anchor="w", padx=16)
            per_month = round(cycle["price_inr"] / (cycle["duration_days"] / 30), 2)
            ctk.CTkLabel(cell, text=f"(~₹{per_month}/mo)", font=theme.F_SMALL, text_color=theme.GREEN_DIM).pack(
                anchor="w", padx=16, pady=(0, 10))
            ctk.CTkButton(cell, text="SELECT", height=36, font=theme.F_BODY_BOLD, fg_color=theme.GREEN,
                          text_color=theme.BLACK, hover_color=theme.GREEN_SOFT,
                          command=lambda k=cycle_key: self._choose_cycle(k)).pack(
                anchor="w", padx=16, pady=(0, 16), fill="x")

    def _choose_cycle(self, cycle_key):
        self.selected_cycle = cycle_key
        try:
            self.gateway = get_gateway()
        except RuntimeError as e:
            messagebox.showerror("Payment gateway not ready", str(e))
            return

        self.cycle_frame.pack_forget()
        # self.payment_frame.pack(fill="x", padx=32, pady=(0, 20))
        self.payment_frame.pack(fill="x", padx=32, pady=(0, 20), before=self.history_label)
        for w in self.payment_frame.winfo_children():
            w.destroy()

        if config.PAYMENT_GATEWAY_MODE == "razorpay":
            self._build_hosted_checkout_panel()
        else:
            self._build_mock_card_form()

    def _current_cycle_amount(self):
        return config.BILLING_CYCLES[self.selected_cycle]["price_inr"]

    def _current_cycle_label(self):
        return config.BILLING_CYCLES[self.selected_cycle]["label"]

    # ------------------------------------------------------------ #
    # Step 2a: mock card form
    # ------------------------------------------------------------ #
    def _build_mock_card_form(self):
        f = self.payment_frame
        amount = self._current_cycle_amount()
        entry_kwargs = dict(width=320, height=38, font=theme.F_BODY, fg_color=theme.PANEL_ALT,
                             border_color=theme.BORDER, border_width=1, text_color=theme.GREEN,
                             placeholder_text_color=theme.TEXT_MUTED)

        ctk.CTkLabel(f, text=f"PAYMENT DETAILS — {self._current_cycle_label()} plan (simulated — no real card is charged)",
                     font=theme.F_SUBHEADER, text_color=theme.GREEN, wraplength=650, justify="left").pack(
            anchor="w", padx=20, pady=(16, 10))

        self.card_name_entry = ctk.CTkEntry(f, placeholder_text="name on card", **entry_kwargs)
        self.card_name_entry.pack(anchor="w", padx=20, pady=4)
        self.card_number_entry = ctk.CTkEntry(f, placeholder_text="card number (try 4242 4242 4242 4242)",
                                               **entry_kwargs)
        self.card_number_entry.pack(anchor="w", padx=20, pady=4)

        row = ctk.CTkFrame(f, fg_color="transparent")
        row.pack(anchor="w", padx=20, pady=4)
        self.card_expiry_entry = ctk.CTkEntry(row, placeholder_text="MM/YY", width=150, height=38,
                                               font=theme.F_BODY, fg_color=theme.PANEL_ALT,
                                               border_color=theme.BORDER, text_color=theme.GREEN,
                                               placeholder_text_color=theme.TEXT_MUTED)
        self.card_expiry_entry.pack(side="left", padx=(0, 8))
        self.card_cvv_entry = ctk.CTkEntry(row, placeholder_text="CVV", show="•", width=150, height=38,
                                            font=theme.F_BODY, fg_color=theme.PANEL_ALT,
                                            border_color=theme.BORDER, text_color=theme.GREEN,
                                            placeholder_text_color=theme.TEXT_MUTED)
        self.card_cvv_entry.pack(side="left")

        ctk.CTkLabel(f, text="tip: a card number ending in 0000 simulates a declined payment.",
                     text_color=theme.TEXT_MUTED, font=theme.F_SMALL).pack(anchor="w", padx=20, pady=(6, 0))

        self.pay_status = ctk.CTkLabel(f, text="", font=theme.F_SMALL, text_color=theme.RED)
        self.pay_status.pack(anchor="w", padx=20, pady=(6, 0))

        self.pay_btn = ctk.CTkButton(f, text=f"PAY ₹{amount}", height=42,
                                      font=theme.F_BODY_BOLD, fg_color=theme.GREEN, text_color=theme.BLACK,
                                      text_color_disabled=theme.BLACK,
                                      hover_color=theme.GREEN_SOFT, command=self._submit_mock_payment)
        self.pay_btn.pack(anchor="w", padx=20, pady=16)

    def _submit_mock_payment(self):
        self.pay_btn.configure(state="disabled", text="PROCESSING...")
        self.pay_status.configure(text="")

        def worker():
            result = self.gateway.start_payment(
                user=self.app.auth.current_user, plan="pro",
                amount=self._current_cycle_amount(),
                card_number=self.card_number_entry.get(),
                expiry=self.card_expiry_entry.get(),
                cvv=self.card_cvv_entry.get(),
                name_on_card=self.card_name_entry.get(),
            )
            self.after(0, lambda: self._handle_payment_result(result))

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------ #
    # Step 2b: hosted checkout (Razorpay)
    # ------------------------------------------------------------ #
    def _build_hosted_checkout_panel(self):
        f = self.payment_frame
        gateway_label = "Razorpay"
        amount = self._current_cycle_amount()

        ctk.CTkLabel(f, text=f"PAY SECURELY VIA {gateway_label.upper()} — {self._current_cycle_label()} plan (₹{amount})",
                     font=theme.F_SUBHEADER, text_color=theme.GREEN, wraplength=650, justify="left").pack(
            anchor="w", padx=20, pady=(16, 6))
        ctk.CTkLabel(f, text="Clicking below opens a hosted checkout page in your browser. "
                             "Complete the payment there, then come back and confirm.",
                     font=theme.F_BODY, text_color=theme.GREEN_DIM, wraplength=650, justify="left").pack(
            anchor="w", padx=20)

        self.pay_status = ctk.CTkLabel(f, text="", font=theme.F_SMALL, text_color=theme.RED,
                                        wraplength=650, justify="left")
        self.pay_status.pack(anchor="w", padx=20, pady=(10, 0))

        self.pay_btn = ctk.CTkButton(f, text="OPEN CHECKOUT", height=42, font=theme.F_BODY_BOLD,
                                      fg_color=theme.GREEN, text_color=theme.BLACK,
                                      text_color_disabled=theme.BLACK,
                                      hover_color=theme.GREEN_SOFT, command=self._start_hosted_payment)
        self.pay_btn.pack(anchor="w", padx=20, pady=16)

    def _start_hosted_payment(self):
        self.pay_btn.configure(state="disabled", text="OPENING CHECKOUT...")

        def worker():
            result = self.gateway.start_payment(
                user=self.app.auth.current_user, plan="pro",
                amount=self._current_cycle_amount(), cycle_label=self._current_cycle_label(),
            )
            self.after(0, lambda: self._handle_hosted_pending(result))

        threading.Thread(target=worker, daemon=True).start()

    def _handle_hosted_pending(self, result: GatewayResult):
        if result.status == "failed":
            self.pay_btn.configure(state="normal", text="OPEN CHECKOUT")
            self.pay_status.configure(text=result.detail)
            return

        self.pending_result = result
        self.pay_btn.pack_forget()
        self.pay_status.configure(text_color=theme.GREEN_DIM, text=result.detail)

        confirm_btn = ctk.CTkButton(self.payment_frame, text="I'VE COMPLETED THE PAYMENT — VERIFY", height=42,
                                     font=theme.F_BODY_BOLD, fg_color=theme.GREEN, text_color=theme.BLACK,
                                     text_color_disabled=theme.BLACK,
                                     hover_color=theme.GREEN_SOFT, command=self._confirm_hosted_payment)
        confirm_btn.pack(anchor="w", padx=20, pady=16)

    def _confirm_hosted_payment(self):
        def worker():
            result = self.gateway.finalize_payment(self.pending_result)
            self.after(0, lambda: self._handle_payment_result(result))
        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------ #
    # Shared: apply the result of any gateway (mock/Razorpay)
    # ------------------------------------------------------------ #
    def _handle_payment_result(self, result: GatewayResult):
        user_id = str(self.app.auth.current_user["_id"])
        cycle = config.BILLING_CYCLES[self.selected_cycle]

        payment_id = self.app.db.save_payment(
            user_id=user_id, amount=result.amount, currency=result.currency,
            status=result.status, plan_purchased="pro", gateway=self.gateway.name,
            transaction_id=result.transaction_id,
            card_last4=result.raw.get("last4") if isinstance(result.raw, dict) else None,
            billing_cycle=self.selected_cycle,
        )

        if result.status != "success":
            if hasattr(self, "pay_btn"):
                self.pay_btn.configure(state="normal", text="TRY AGAIN")
            self.pay_status.configure(text_color=theme.RED, text=result.detail or "Payment failed.")
            return

        start = datetime.now(timezone.utc)
        end = start + timedelta(days=cycle["duration_days"])
        self.app.db.set_user_plan(user_id, "pro", expires_at=end)
        self.app.db.create_subscription_record(user_id, "pro", payment_id=payment_id, start_date=start,
                                                 end_date=end, billing_cycle=self.selected_cycle)
        self.app.refresh_plan_everywhere()
        messagebox.showinfo("Upgrade successful",
                             f"You're now on the Pro plan ({cycle['label']})! 🎉")
        self.refresh()
