import customtkinter as ctk

from auth.auth_manager import hash_password, verify_password
from gui import theme
from gui.widgets import labeled_entry, labeled_password_entry


class ProfilePage(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=theme.BLACK)
        self.app = app

        ctk.CTkLabel(self, text="PROFILE", font=theme.F_TITLE, text_color=theme.GREEN).pack(
            anchor="w", padx=32, pady=(28, 20))

        entry_kwargs = dict(width=380, height=40, font=theme.F_BODY, fg_color=theme.PANEL_ALT,
                             border_color=theme.BORDER, border_width=1, text_color=theme.GREEN,
                             placeholder_text_color=theme.TEXT_MUTED)

        card = ctk.CTkFrame(self, fg_color=theme.PANEL, corner_radius=4, border_width=1, border_color=theme.BORDER)
        card.pack(fill="x", padx=32)

        self.username_label = ctk.CTkLabel(card, text="", font=theme.F_BODY, text_color=theme.CYAN)
        self.username_label.pack(anchor="w", padx=24, pady=(20, 0))

        full_name_wrap, self.full_name_entry = labeled_entry(card, "Full Name", **entry_kwargs)
        full_name_wrap.pack(anchor="w", padx=24, pady=(14, 6))

        email_wrap, self.email_entry = labeled_entry(card, "Email", **entry_kwargs)
        email_wrap.pack(anchor="w", padx=24, pady=6)

        self.save_status = ctk.CTkLabel(card, text="", font=theme.F_SMALL, text_color=theme.GREEN)
        self.save_status.pack(anchor="w", padx=24)

        ctk.CTkButton(card, text="SAVE CHANGES", width=200, height=40, font=theme.F_BODY_BOLD,
                      fg_color=theme.GREEN, text_color=theme.BLACK, hover_color=theme.GREEN_SOFT,
                      command=self._save_profile).pack(anchor="w", padx=24, pady=(10, 22))

        pw_card = ctk.CTkFrame(self, fg_color=theme.PANEL, corner_radius=4, border_width=1, border_color=theme.BORDER)
        pw_card.pack(fill="x", padx=32, pady=20)
        ctk.CTkLabel(pw_card, text="CHANGE PASSWORD", font=theme.F_SUBHEADER, text_color=theme.GREEN).pack(
            anchor="w", padx=24, pady=(20, 12))

        current_pw_wrap, self.current_pw_entry = labeled_password_entry(pw_card, "Current Password", **entry_kwargs)
        current_pw_wrap.pack(anchor="w", padx=24, pady=6)
        new_pw_wrap, self.new_pw_entry = labeled_password_entry(
            pw_card, "New Password (min 8 characters)", **entry_kwargs)
        new_pw_wrap.pack(anchor="w", padx=24, pady=6)

        self.pw_status = ctk.CTkLabel(pw_card, text="", font=theme.F_SMALL, text_color=theme.RED)
        self.pw_status.pack(anchor="w", padx=24)

        ctk.CTkButton(pw_card, text="UPDATE PASSWORD", width=220, height=40, font=theme.F_BODY_BOLD,
                      fg_color="transparent", text_color=theme.GREEN, border_width=1, border_color=theme.BORDER_BRIGHT,
                      hover_color=theme.PANEL_ALT,
                      command=self._change_password).pack(anchor="w", padx=24, pady=(10, 22))

    def on_show(self):
        user = self.app.auth.current_user
        self.username_label.configure(
            text=f"@{user['username']}   •   member since {user['created_at'].strftime('%b %Y')}"
        )
        self.full_name_entry.delete(0, "end")
        self.full_name_entry.insert(0, user.get("full_name", ""))
        self.email_entry.delete(0, "end")
        self.email_entry.insert(0, user.get("email", ""))
        self.save_status.configure(text="")
        self.pw_status.configure(text="")
        self.current_pw_entry.delete(0, "end")
        self.new_pw_entry.delete(0, "end")

    def _save_profile(self):
        user_id = str(self.app.auth.current_user["_id"])
        self.app.db.update_user_profile(user_id, {
            "full_name": self.full_name_entry.get().strip(),
            "email": self.email_entry.get().strip().lower(),
        })
        self.app.auth.refresh_current_user()
        self.save_status.configure(text_color=theme.GREEN, text="✓ Saved!")

    def _change_password(self):
        user = self.app.auth.current_user
        current = self.current_pw_entry.get()
        new = self.new_pw_entry.get()

        if not verify_password(current, user["password_hash"]):
            self.pw_status.configure(text_color=theme.RED, text="✗ Current password is incorrect.")
            return
        if len(new) < 8:
            self.pw_status.configure(text_color=theme.RED, text="✗ New password must be at least 8 characters.")
            return

        self.app.db.update_user_profile(str(user["_id"]), {"password_hash": hash_password(new)})
        self.app.auth.refresh_current_user()
        self.current_pw_entry.delete(0, "end")
        self.new_pw_entry.delete(0, "end")
        self.pw_status.configure(text_color=theme.GREEN, text="✓ Password updated.")
