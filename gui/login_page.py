import customtkinter as ctk

from auth.auth_manager import AuthError, EmailNotVerifiedError
from auth import otp_service
from utils import email_service
from gui import theme
from gui.widgets import MatrixRain, labeled_entry, labeled_password_entry


class LoginPage(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=theme.BLACK)
        self.app = app

        self.rain = MatrixRain(self, font_size=15, speed_ms=55)
        self.rain.place(relx=0, rely=0, relwidth=1, relheight=1)

        self.card = ctk.CTkFrame(self, width=420, corner_radius=4, fg_color=theme.PANEL,
                                  border_width=1, border_color=theme.BORDER_BRIGHT)
        self.card.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(self.card, text="🛡", font=(theme.FONT, 42)).pack(pady=(34, 0))
        ctk.CTkLabel(self.card, text="GLITCH HOUND", font=theme.F_LOGO, text_color=theme.GREEN).pack(pady=(4, 0))
        ctk.CTkLabel(self.card, text="root@glitchhound:~$ authenticate", font=theme.F_MONO_SMALL,
                     text_color=theme.GREEN_DIM).pack(pady=(2, 24))

        username_wrap, self.username_entry = labeled_entry(
            self.card, "Username", width=320, height=42, font=theme.F_BODY,
            fg_color=theme.PANEL_ALT, border_color=theme.BORDER, border_width=1,
            text_color=theme.GREEN, placeholder_text_color=theme.TEXT_MUTED,
        )
        username_wrap.pack(pady=8, padx=30)

        password_wrap, self.password_entry = labeled_password_entry(
            self.card, "Password", width=320, height=42, font=theme.F_BODY,
            fg_color=theme.PANEL_ALT, border_color=theme.BORDER, border_width=1,
            text_color=theme.GREEN, placeholder_text_color=theme.TEXT_MUTED,
        )
        password_wrap.pack(pady=8, padx=30)
        self.password_entry.bind("<Return>", lambda e: self.handle_login())

        forgot_row = ctk.CTkFrame(self.card, fg_color="transparent")
        forgot_row.pack(fill="x", padx=30, pady=(2, 0))
        ctk.CTkButton(
            forgot_row, text="forgot password?", font=theme.F_SMALL, fg_color="transparent",
            text_color=theme.CYAN, hover_color=theme.PANEL_ALT, height=24, width=140,
            command=self._go_forgot_password,
        ).pack(side="right")

        self.error_label = ctk.CTkLabel(self.card, text="", text_color=theme.RED, font=theme.F_SMALL,
                                         wraplength=340, justify="left")
        self.error_label.pack(pady=(6, 0))

        self.resend_btn = ctk.CTkButton(
            self.card, text="resend verification code", font=theme.F_SMALL, fg_color="transparent",
            text_color=theme.CYAN, hover_color=theme.PANEL_ALT, height=28, width=320,
            border_width=1, border_color=theme.BORDER, command=self._resend_verification,
        )

        ctk.CTkButton(
            self.card, text="[ LOG IN ]", width=320, height=42, font=theme.F_BODY_BOLD,
            fg_color=theme.GREEN, text_color=theme.BLACK, hover_color=theme.GREEN_SOFT,
            command=self.handle_login,
        ).pack(pady=(16, 10), padx=30)

        ctk.CTkButton(
            self.card, text="create an account", width=320, height=36, font=theme.F_SMALL,
            fg_color="transparent", text_color=theme.GREEN_DIM, hover_color=theme.PANEL_ALT,
            border_width=1, border_color=theme.BORDER,
            command=lambda: app.show_page("register"),
        ).pack(pady=(0, 34), padx=30)

        self._pending_unverified_email = None

    # ------------------------------------------------------------ #
    def on_show(self):
        self.username_entry.delete(0, "end")
        self.password_entry.delete(0, "end")
        self.error_label.configure(text="")
        self.resend_btn.pack_forget()
        self._pending_unverified_email = None
        self.rain.start()

    def on_hide(self):
        self.rain.stop()

    def _go_forgot_password(self):
        self.app.pages["forgot_password"].set_context()
        self.app.show_page("forgot_password")

    def handle_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        self.resend_btn.pack_forget()
        try:
            result = self.app.auth.login(username, password)
            self.username_entry.delete(0, "end")
            self.password_entry.delete(0, "end")
            self.error_label.configure(text="")
            self.app.on_login_success(is_admin=(result["role"] == "admin"))
        except EmailNotVerifiedError as e:
            self.password_entry.delete(0, "end")
            self.error_label.configure(text=f"✗ {e}")
            self._pending_unverified_email = e.email
            self.resend_btn.pack(pady=(8, 0), padx=30)
        except AuthError as e:
            self.password_entry.delete(0, "end")
            self.error_label.configure(text=f"✗ {e}")

    def _resend_verification(self):
        email = self._pending_unverified_email
        if not email:
            return
        try:
            code = otp_service.create_and_store_otp(self.app.db, email, "verify_email")
            email_service.send_otp_email(email, code, "verify_email")
        except Exception as e:
            self.error_label.configure(text=f"✗ Could not send code: {e}")
            return
        self.app.pages["otp_verify"].set_context(
            email=email, purpose="verify_email", next_page="login",
            success_message="✓ Email verified! You can log in now.",
        )
        self.app.show_page("otp_verify")
