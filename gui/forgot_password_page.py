import customtkinter as ctk

from auth import otp_service
from utils import email_service
from gui import theme
from gui.widgets import MatrixRain, labeled_entry


class ForgotPasswordPage(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=theme.BLACK)
        self.app = app

        self.rain = MatrixRain(self, font_size=15, speed_ms=55)
        self.rain.place(relx=0, rely=0, relwidth=1, relheight=1)

        card = ctk.CTkFrame(self, width=400, corner_radius=4, fg_color=theme.PANEL,
                             border_width=1, border_color=theme.BORDER_BRIGHT)
        card.place(relx=0.5, rely=0.5, anchor="center")
        self.card = card

        ctk.CTkLabel(card, text="> RESET PASSWORD", font=theme.F_HEADER, text_color=theme.GREEN).pack(pady=(30, 4))
        ctk.CTkLabel(card, text="Enter your account email — we'll send a reset code.", font=theme.F_SMALL,
                     text_color=theme.GREEN_DIM, wraplength=340, justify="left").pack(pady=(0, 20), padx=30)

        email_wrap, self.email_entry = labeled_entry(
            card, "Email", width=320, height=42, font=theme.F_BODY,
            fg_color=theme.PANEL_ALT, border_color=theme.BORDER, border_width=1,
            text_color=theme.GREEN, placeholder_text_color=theme.TEXT_MUTED,
        )
        email_wrap.pack(pady=8, padx=30)
        self.email_entry.bind("<Return>", lambda e: self._submit())

        self.status_label = ctk.CTkLabel(card, text="", font=theme.F_SMALL, text_color=theme.RED,
                                          wraplength=340, justify="left")
        self.status_label.pack(pady=(6, 0))

        self.submit_btn = ctk.CTkButton(
            card, text="[ SEND CODE ]", width=320, height=42, font=theme.F_BODY_BOLD,
            fg_color=theme.GREEN, text_color=theme.BLACK, hover_color=theme.GREEN_SOFT,
            command=self._submit,
        )
        self.submit_btn.pack(pady=(16, 8), padx=30)

        ctk.CTkButton(
            card, text="back to login", width=320, height=32, font=theme.F_SMALL,
            fg_color="transparent", text_color=theme.GREEN_DIM, hover_color=theme.PANEL_ALT,
            command=lambda: app.show_page("login"),
        ).pack(pady=(0, 30), padx=30)

    def set_context(self):
        pass  # no external context needed — kept for a consistent calling convention

    def on_show(self):
        self.email_entry.delete(0, "end")
        self.status_label.configure(text="")
        self.submit_btn.configure(state="normal", text="[ SEND CODE ]")
        self.rain.start()

    def on_hide(self):
        self.rain.stop()

    def _submit(self):
        email = self.email_entry.get().strip().lower()
        if not email or "@" not in email:
            self.status_label.configure(text_color=theme.RED, text="Enter a valid email.")
            return

        self.submit_btn.configure(state="disabled", text="checking...")

        # Explicitly confirms whether the email is registered, per request —
        # note this is a deliberate trade-off vs. the more privacy-preserving
        # "same message either way" pattern: it's more convenient for users
        # who mistype their email, but it does let someone probe which
        # emails have an account here. Fine for a project like this; a
        # production consumer app more often hides this.
        user = self.app.db.get_user_by_email(email)
        if not user:
            self.status_label.configure(text_color=theme.RED, text="✗ This email is not registered.")
            self.submit_btn.configure(state="normal", text="[ SEND CODE ]")
            return

        try:
            code = otp_service.create_and_store_otp(self.app.db, email, "reset_password")
            email_service.send_otp_email(email, code, "reset_password")
        except Exception as e:
            self.status_label.configure(text_color=theme.RED, text=f"✗ Could not send code: {e}")
            self.submit_btn.configure(state="normal", text="[ SEND CODE ]")
            return

        self.status_label.configure(text_color=theme.GREEN, text="✓ Reset code sent — check your email.")
        self.after(1200, lambda: self._go_to_otp(email))

    def _go_to_otp(self, email):
        self.app.pages["otp_verify"].set_context(
            email=email, purpose="reset_password", next_page="login", success_message="",
        )
        self.app.show_page("otp_verify")
