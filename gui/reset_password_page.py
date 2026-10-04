import customtkinter as ctk

from auth.auth_manager import hash_password
from gui import theme
from gui.widgets import MatrixRain, labeled_password_entry


class ResetPasswordPage(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=theme.BLACK)
        self.app = app
        self.email = None

        self.rain = MatrixRain(self, font_size=15, speed_ms=55)
        self.rain.place(relx=0, rely=0, relwidth=1, relheight=1)

        card = ctk.CTkFrame(self, width=400, corner_radius=4, fg_color=theme.PANEL,
                             border_width=1, border_color=theme.BORDER_BRIGHT)
        card.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(card, text="> SET NEW PASSWORD", font=theme.F_HEADER, text_color=theme.GREEN).pack(pady=(30, 4))
        ctk.CTkLabel(card, text="Code verified. Choose a new password.", font=theme.F_SMALL,
                     text_color=theme.GREEN_DIM).pack(pady=(0, 20), padx=30)

        entry_kwargs = dict(width=320, height=42, font=theme.F_BODY, fg_color=theme.PANEL_ALT,
                             border_color=theme.BORDER, border_width=1, text_color=theme.GREEN,
                             placeholder_text_color=theme.TEXT_MUTED)

        password_wrap, self.password_entry = labeled_password_entry(
            card, "New Password (min 8 characters)", **entry_kwargs)
        password_wrap.pack(pady=6, padx=30)

        confirm_wrap, self.confirm_entry = labeled_password_entry(card, "Confirm New Password", **entry_kwargs)
        confirm_wrap.pack(pady=6, padx=30)
        self.confirm_entry.bind("<Return>", lambda e: self._submit())

        self.status_label = ctk.CTkLabel(card, text="", font=theme.F_SMALL, text_color=theme.RED,
                                          wraplength=340, justify="left")
        self.status_label.pack(pady=(6, 0))

        ctk.CTkButton(
            card, text="[ RESET PASSWORD ]", width=320, height=42, font=theme.F_BODY_BOLD,
            fg_color=theme.GREEN, text_color=theme.BLACK, hover_color=theme.GREEN_SOFT,
            command=self._submit,
        ).pack(pady=(16, 30), padx=30)

    def set_context(self, email):
        self.email = email

    def on_show(self):
        self.password_entry.delete(0, "end")
        self.confirm_entry.delete(0, "end")
        self.status_label.configure(text="")
        self.rain.start()

    def on_hide(self):
        self.rain.stop()

    def _submit(self):
        password = self.password_entry.get()
        confirm = self.confirm_entry.get()
        if len(password) < 8:
            self.status_label.configure(text_color=theme.RED, text="Password must be at least 8 characters.")
            return
        if password != confirm:
            self.status_label.configure(text_color=theme.RED, text="Passwords do not match.")
            return
        if not self.email:
            self.status_label.configure(text_color=theme.RED, text="Session expired — start over from 'forgot password'.")
            return

        self.app.db.update_user_password_by_email(self.email, hash_password(password))
        self.status_label.configure(text_color=theme.GREEN, text="✓ Password updated! Redirecting to login...")
        self.after(1200, lambda: self.app.show_page("login"))
