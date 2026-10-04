import customtkinter as ctk

from auth import otp_service
from utils import email_service
from gui import theme
from gui.widgets import MatrixRain


class OtpVerifyPage(ctk.CTkFrame):
    """
    Generic 'enter the code' screen. The page that navigates here first
    calls set_context(...) to say which email/purpose this verification is
    for and where to go on success — RegisterPage and LoginPage use this
    for email verification, ForgotPasswordPage uses it for password reset.
    """

    def __init__(self, parent, app):
        super().__init__(parent, fg_color=theme.BLACK)
        self.app = app
        self.email = None
        self.purpose = None
        self.next_page = "login"
        self.success_message = "✓ Verified!"

        self.rain = MatrixRain(self, font_size=15, speed_ms=55)
        self.rain.place(relx=0, rely=0, relwidth=1, relheight=1)

        card = ctk.CTkFrame(self, width=400, corner_radius=4, fg_color=theme.PANEL,
                             border_width=1, border_color=theme.BORDER_BRIGHT)
        card.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(card, text="> VERIFY CODE", font=theme.F_HEADER, text_color=theme.GREEN).pack(pady=(30, 4))
        self.subtitle_label = ctk.CTkLabel(card, text="", font=theme.F_SMALL, text_color=theme.GREEN_DIM,
                                            wraplength=340, justify="left")
        self.subtitle_label.pack(pady=(0, 20), padx=30)

        self.otp_entry = ctk.CTkEntry(
            card, placeholder_text="6-digit code", width=320, height=48, font=(theme.FONT, 22, "bold"),
            fg_color=theme.PANEL_ALT, border_color=theme.BORDER, border_width=1,
            text_color=theme.GREEN, placeholder_text_color=theme.TEXT_MUTED, justify="center",
        )
        self.otp_entry.pack(pady=8, padx=30)
        self.otp_entry.bind("<Return>", lambda e: self._verify())

        self.status_label = ctk.CTkLabel(card, text="", font=theme.F_SMALL, text_color=theme.RED,
                                          wraplength=340, justify="left")
        self.status_label.pack(pady=(6, 0))

        ctk.CTkButton(
            card, text="[ VERIFY ]", width=320, height=42, font=theme.F_BODY_BOLD,
            fg_color=theme.GREEN, text_color=theme.BLACK, hover_color=theme.GREEN_SOFT,
            command=self._verify,
        ).pack(pady=(16, 8), padx=30)

        self.resend_btn = ctk.CTkButton(
            card, text="resend code", width=320, height=36, font=theme.F_SMALL,
            fg_color="transparent", text_color=theme.CYAN, hover_color=theme.PANEL_ALT,
            border_width=1, border_color=theme.BORDER, command=self._resend,
        )
        self.resend_btn.pack(pady=(0, 8), padx=30)

        ctk.CTkButton(
            card, text="back to login", width=320, height=32, font=theme.F_SMALL,
            fg_color="transparent", text_color=theme.GREEN_DIM, hover_color=theme.PANEL_ALT,
            command=lambda: app.show_page("login"),
        ).pack(pady=(0, 30), padx=30)

    def set_context(self, email, purpose, next_page="login", success_message="✓ Verified!"):
        self.email = email
        self.purpose = purpose  # "verify_email" | "reset_password"
        self.next_page = next_page
        self.success_message = success_message

    def on_show(self):
        self.otp_entry.delete(0, "end")
        self.status_label.configure(text="")
        masked = self._mask_email(self.email or "")
        purpose_label = "verify your email" if self.purpose == "verify_email" else "reset your password"
        self.subtitle_label.configure(text=f"Enter the code sent to {masked} to {purpose_label}.")
        self.resend_btn.configure(state="normal", text="resend code")
        self.rain.start()

    def on_hide(self):
        self.rain.stop()

    @staticmethod
    def _mask_email(email):
        if "@" not in email:
            return email
        name, domain = email.split("@", 1)
        visible = name[:2] if len(name) > 2 else name[:1]
        return f"{visible}{'*' * max(len(name) - len(visible), 2)}@{domain}"

    def _verify(self):
        code = self.otp_entry.get().strip()
        if not code:
            self.status_label.configure(text_color=theme.RED, text="Enter the code.")
            return
        try:
            otp_service.verify_otp(self.app.db, self.email, code, self.purpose)
        except otp_service.OtpError as e:
            self.status_label.configure(text_color=theme.RED, text=f"✗ {e}")
            return

        if self.purpose == "verify_email":
            self.app.db.set_user_email_verified(self.email)
            self.status_label.configure(text_color=theme.GREEN, text=self.success_message)
            self.after(1200, lambda: self.app.show_page(self.next_page))
        else:  # reset_password — code proved ownership of the inbox, now let them set a new password
            self.app.pages["reset_password"].set_context(email=self.email)
            self.app.show_page("reset_password")

    def _resend(self):
        if not self.email or not self.purpose:
            return
        self.resend_btn.configure(state="disabled", text="sending...")
        try:
            code = otp_service.create_and_store_otp(self.app.db, self.email, self.purpose)
            email_service.send_otp_email(self.email, code, self.purpose)
            self.status_label.configure(text_color=theme.GREEN, text="✓ New code sent.")
        except Exception as e:
            self.status_label.configure(text_color=theme.RED, text=f"✗ Could not send code: {e}")
        finally:
            self._start_resend_cooldown(30)

    def _start_resend_cooldown(self, seconds_left):
        if seconds_left <= 0:
            self.resend_btn.configure(state="normal", text="resend code")
            return
        self.resend_btn.configure(text=f"resend in {seconds_left}s")
        self.after(1000, lambda: self._start_resend_cooldown(seconds_left - 1))
