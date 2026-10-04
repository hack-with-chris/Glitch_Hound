import customtkinter as ctk

from auth.auth_manager import AuthError
from auth import otp_service
from utils import email_service
from gui import theme
from gui.widgets import MatrixRain, labeled_entry, labeled_password_entry


class RegisterPage(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=theme.BLACK)
        self.app = app

        self.rain = MatrixRain(self, font_size=15, speed_ms=55)
        self.rain.place(relx=0, rely=0, relwidth=1, relheight=1)

        card = ctk.CTkFrame(self, width=440, corner_radius=4, fg_color=theme.PANEL,
                             border_width=1, border_color=theme.BORDER_BRIGHT)
        card.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(card, text="> NEW_USER_REGISTRATION", font=theme.F_HEADER,
                     text_color=theme.GREEN).pack(pady=(30, 4))
        ctk.CTkLabel(card, text="root@glitchhound:~$ create_account --new", font=theme.F_MONO_SMALL,
                     text_color=theme.GREEN_DIM).pack(pady=(0, 20))

        entry_kwargs = dict(width=340, height=40, font=theme.F_BODY, fg_color=theme.PANEL_ALT,
                             border_color=theme.BORDER, border_width=1, text_color=theme.GREEN,
                             placeholder_text_color=theme.TEXT_MUTED)

        full_name_wrap, self.full_name_entry = labeled_entry(card, "Full Name", **entry_kwargs)
        full_name_wrap.pack(pady=5, padx=30)

        username_wrap, self.username_entry = labeled_entry(card, "Username", **entry_kwargs)
        username_wrap.pack(pady=5, padx=30)

        email_wrap, self.email_entry = labeled_entry(card, "Email", **entry_kwargs)
        email_wrap.pack(pady=5, padx=30)

        password_wrap, self.password_entry = labeled_password_entry(
            card, "Password (min 8 characters)", **entry_kwargs)
        password_wrap.pack(pady=5, padx=30)

        confirm_wrap, self.confirm_entry = labeled_password_entry(card, "Confirm Password", **entry_kwargs)
        confirm_wrap.pack(pady=5, padx=30)

        self.error_label = ctk.CTkLabel(card, text="", text_color=theme.RED, font=theme.F_SMALL, wraplength=340)
        self.error_label.pack(pady=(8, 0))

        ctk.CTkButton(
            card, text="[ SIGN UP ]", width=340, height=42, font=theme.F_BODY_BOLD,
            fg_color=theme.GREEN, text_color=theme.BLACK, hover_color=theme.GREEN_SOFT,
            command=self.handle_register,
        ).pack(pady=(16, 10), padx=30)

        ctk.CTkButton(
            card, text="back to login", width=340, height=34, font=theme.F_SMALL,
            fg_color="transparent", text_color=theme.GREEN_DIM, hover_color=theme.PANEL_ALT,
            border_width=1, border_color=theme.BORDER,
            command=lambda: app.show_page("login"),
        ).pack(pady=(0, 30), padx=30)

    # ------------------------------------------------------------ #
    def on_show(self):
        for entry in (self.full_name_entry, self.username_entry, self.email_entry,
                      self.password_entry, self.confirm_entry):
            entry.delete(0, "end")
        self.error_label.configure(text="")
        self.rain.start()

    def on_hide(self):
        self.rain.stop()

    def handle_register(self):
        email = self.email_entry.get().strip().lower()
        try:
            self.app.auth.register(
                username=self.username_entry.get(),
                email=email,
                password=self.password_entry.get(),
                confirm_password=self.confirm_entry.get(),
                full_name=self.full_name_entry.get(),
            )
        except AuthError as e:
            self.error_label.configure(text_color=theme.RED, text=f"✗ {e}")
            return

        self.error_label.configure(text_color=theme.GREEN, text="✓ Account created! Sending verification code...")
        try:
            code = otp_service.create_and_store_otp(self.app.db, email, "verify_email")
            email_service.send_otp_email(email, code, "verify_email")
        except Exception as e:
            self.error_label.configure(
                text_color=theme.AMBER,
                text=f"Account created, but the verification email failed to send ({e}). "
                     "You can resend it from the login page.",
            )
            self.after(2500, lambda: self.app.show_page("login"))
            return

        self.app.pages["otp_verify"].set_context(
            email=email, purpose="verify_email", next_page="login",
            success_message="✓ Email verified! You can log in now.",
        )
        self.app.show_page("otp_verify")
