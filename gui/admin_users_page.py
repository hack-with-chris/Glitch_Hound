from datetime import datetime, timezone, timedelta
from tkinter import messagebox

import customtkinter as ctk

from gui import theme


class UserDetailModal(ctk.CTkToplevel):
    """Opened from a user row — shows profile, lets the admin set the plan or delete the account, and lists all of that user's scans."""

    def __init__(self, parent, app, user_doc, on_change=None):
        super().__init__(parent)
        self.app = app
        self.user_doc = user_doc
        self.on_change = on_change  # called after a plan change or delete, so the parent list can refresh
        self.title(f"User: {user_doc['username']}")
        self.geometry("760x680")
        self.configure(fg_color=theme.BLACK)
        self.grab_set()

        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=18, pady=18)

        ctk.CTkLabel(scroll, text=f"@{user_doc['username']}", font=theme.F_HEADER, text_color=theme.GREEN).pack(
            anchor="w")
        ctk.CTkLabel(scroll, text=user_doc.get("full_name") or "(no name set)", font=theme.F_BODY,
                     text_color=theme.GREEN_DIM).pack(anchor="w")
        ctk.CTkLabel(scroll, text=user_doc.get("email", ""), font=theme.F_BODY,
                     text_color=theme.GREEN_DIM).pack(anchor="w", pady=(0, 4))

        verified = "✓ Email verified" if user_doc.get("email_verified") else "✗ Email not verified"
        ctk.CTkLabel(scroll, text=verified, font=theme.F_SMALL,
                     text_color=theme.GREEN if user_doc.get("email_verified") else theme.RED).pack(anchor="w")
        ctk.CTkLabel(scroll, text=f"Joined {user_doc['created_at'].strftime('%b %d, %Y')}", font=theme.F_SMALL,
                     text_color=theme.TEXT_MUTED).pack(anchor="w", pady=(0, 16))

        # --- subscription / plan management -----------------------------
        plan_box = ctk.CTkFrame(scroll, fg_color=theme.PANEL, corner_radius=4,
                                 border_width=1, border_color=theme.BORDER)
        plan_box.pack(fill="x", pady=(0, 16))
        ctk.CTkLabel(plan_box, text="SUBSCRIPTION", font=theme.F_SUBHEADER, text_color=theme.GREEN).pack(
            anchor="w", padx=16, pady=(14, 4))
        self.plan_label = ctk.CTkLabel(plan_box, text="", font=theme.F_BODY_BOLD, text_color=theme.CYAN)
        self.plan_label.pack(anchor="w", padx=16, pady=(0, 10))

        btn_row = ctk.CTkFrame(plan_box, fg_color="transparent")
        btn_row.pack(anchor="w", padx=16, pady=(0, 16))
        ctk.CTkButton(btn_row, text="Set FREE", height=38, font=theme.F_BODY_BOLD, fg_color="transparent",
                      text_color=theme.GREEN, border_width=1, border_color=theme.BORDER_BRIGHT,
                      hover_color=theme.PANEL_ALT, command=lambda: self._set_plan("free")).pack(
            side="left", padx=(0, 8))
        ctk.CTkButton(btn_row, text="Set PRO (+30 days)", height=38, font=theme.F_BODY_BOLD, fg_color=theme.GREEN,
                      text_color=theme.BLACK, text_color_disabled=theme.BLACK, hover_color=theme.GREEN_SOFT,
                      command=lambda: self._set_plan("pro")).pack(side="left")

        self._refresh_plan_label()

        # --- danger zone: delete account ----------------------------------
        danger_box = ctk.CTkFrame(scroll, fg_color=theme.PANEL, corner_radius=4,
                                   border_width=1, border_color=theme.RED)
        danger_box.pack(fill="x", pady=(0, 16))
        ctk.CTkLabel(danger_box, text="DANGER ZONE", font=theme.F_SUBHEADER, text_color=theme.RED).pack(
            anchor="w", padx=16, pady=(14, 4))
        ctk.CTkLabel(
            danger_box,
            text="Permanently deletes this account and all of their scans, subscriptions, and payment records.",
            font=theme.F_SMALL, text_color=theme.GREEN_DIM, wraplength=650, justify="left",
        ).pack(anchor="w", padx=16, pady=(0, 10))
        ctk.CTkButton(danger_box, text="🗑 DELETE USER", height=38, font=theme.F_BODY_BOLD,
                      fg_color=theme.RED, text_color=theme.BLACK, hover_color="#CC2E2E",
                      command=self._delete_user).pack(anchor="w", padx=16, pady=(0, 16))

        # --- scan history (read-only) ------------------------------------
        ctk.CTkLabel(scroll, text="SCAN HISTORY", font=theme.F_SUBHEADER, text_color=theme.GREEN).pack(
            anchor="w", pady=(4, 8))
        scans = self.app.db.get_scans_for_user(str(user_doc["_id"]))
        if not scans:
            ctk.CTkLabel(scroll, text="No scans yet.", font=theme.F_BODY, text_color=theme.GREEN_DIM).pack(
                anchor="w")
        for scan in scans:
            self._scan_row(scroll, scan)

    def _refresh_plan_label(self):
        user = self.app.db.get_user_by_id(str(self.user_doc["_id"]))
        self.user_doc = user
        expires = user.get("plan_expires_at")
        expiry_text = f"  (expires {expires.strftime('%b %d, %Y')})" if expires else ""
        self.plan_label.configure(text=f"Current plan: {user.get('plan', 'free').upper()}{expiry_text}")

    def _set_plan(self, plan):
        user_id = str(self.user_doc["_id"])
        expires_at = datetime.now(timezone.utc) + timedelta(days=30) if plan == "pro" else None
        self.app.db.set_user_plan(user_id, plan, expires_at=expires_at)
        self._refresh_plan_label()
        if self.on_change:
            self.on_change()
        messagebox.showinfo("Plan updated", f"@{self.user_doc['username']} is now on the {plan.upper()} plan.")

    def _delete_user(self):
        username = self.user_doc["username"]
        if not messagebox.askyesno(
            "Delete user",
            f"Permanently delete @{username}?\n\n"
            "This also deletes all of their scans, subscriptions, and payment records. "
            "This cannot be undone.",
            icon="warning",
        ):
            return

        self.app.db.delete_user(str(self.user_doc["_id"]))
        if self.on_change:
            self.on_change()
        messagebox.showinfo("User deleted", f"@{username} has been permanently deleted.")
        self.destroy()

    def _scan_row(self, parent, scan):
        row = ctk.CTkFrame(parent, fg_color=theme.PANEL_ALT, corner_radius=4)
        row.pack(fill="x", pady=3)
        icon = "🌐" if scan["scan_type"] == "vuln_scan" else "🔌"
        type_label = "Website Audit" if scan["scan_type"] == "vuln_scan" else "Port Scan"
        results = scan.get("results", {})
        if scan["scan_type"] == "vuln_scan":
            summary = f"Grade {results.get('grade', 'N/A')}"
            color = theme.grade_color(results.get("grade", ""))
        else:
            n = len(results.get("open_ports", []))
            summary = f"{n} open port(s)"
            color = theme.AMBER if n else theme.GREEN

        ctk.CTkLabel(row, text=f"{icon} {scan['target']}", font=theme.F_BODY_BOLD, text_color=theme.GREEN,
                     anchor="w").pack(side="left", padx=12, pady=10)
        ctk.CTkLabel(row, text=f"{type_label} • {scan['created_at'].strftime('%b %d, %Y')}", font=theme.F_SMALL,
                     text_color=theme.GREEN_DIM).pack(side="left", padx=8)
        ctk.CTkLabel(row, text=summary, font=theme.F_SMALL, text_color=color).pack(side="right", padx=12)


class AdminUsersPage(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=theme.BLACK)
        self.app = app
        self.all_users = []

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=32, pady=(28, 10))
        ctk.CTkLabel(header, text="MANAGE USERS", font=theme.F_TITLE, text_color=theme.GREEN).pack(anchor="w")

        search_row = ctk.CTkFrame(self, fg_color="transparent")
        search_row.pack(fill="x", padx=32, pady=(0, 10))
        self.search_entry = ctk.CTkEntry(
            search_row, placeholder_text="search by username or email...", width=400, height=40,
            font=theme.F_BODY, fg_color=theme.PANEL_ALT, border_color=theme.BORDER, border_width=1,
            text_color=theme.GREEN, placeholder_text_color=theme.TEXT_MUTED,
        )
        self.search_entry.pack(side="left")
        self.search_entry.bind("<KeyRelease>", lambda e: self._render_list())

        self.count_label = ctk.CTkLabel(search_row, text="", font=theme.F_SMALL, text_color=theme.GREEN_DIM)
        self.count_label.pack(side="left", padx=16)

        self.list_frame = ctk.CTkScrollableFrame(self, fg_color=theme.PANEL, corner_radius=4,
                                                   border_width=1, border_color=theme.BORDER)
        self.list_frame.pack(fill="both", expand=True, padx=32, pady=(0, 24))

    def on_show(self):
        self.all_users = self.app.db.get_all_users()
        self.search_entry.delete(0, "end")
        self._render_list()

    def _render_list(self):
        query = self.search_entry.get().strip().lower()
        for w in self.list_frame.winfo_children():
            w.destroy()

        filtered = [
            u for u in self.all_users
            if query in u["username"].lower() or query in u.get("email", "").lower()
        ] if query else self.all_users

        self.count_label.configure(text=f"{len(filtered)} of {len(self.all_users)} user(s)")

        if not filtered:
            ctk.CTkLabel(self.list_frame, text="No users found.", font=theme.F_BODY,
                         text_color=theme.GREEN_DIM).pack(pady=30)
            return

        for user in filtered:
            self._user_row(user)

    def _user_row(self, user):
        row = ctk.CTkFrame(self.list_frame, fg_color=theme.PANEL_ALT, corner_radius=4)
        row.pack(fill="x", padx=8, pady=4)

        left = ctk.CTkFrame(row, fg_color="transparent")
        left.pack(side="left", fill="x", expand=True, padx=16, pady=10)
        ctk.CTkLabel(left, text=f"@{user['username']}", font=theme.F_BODY_BOLD, text_color=theme.GREEN,
                     anchor="w").pack(anchor="w")
        verified_mark = "✓ verified" if user.get("email_verified") else "✗ unverified"
        verified_color = theme.GREEN_DIM if user.get("email_verified") else theme.RED
        ctk.CTkLabel(left, text=f"{user.get('email', '')}  •  {verified_mark}", font=theme.F_SMALL,
                     text_color=verified_color, anchor="w").pack(anchor="w")

        plan = user.get("plan", "free").upper()
        plan_color = theme.CYAN if plan == "PRO" else theme.GREEN_DIM
        ctk.CTkLabel(row, text=plan, font=theme.F_BADGE, text_color=theme.BLACK, fg_color=plan_color,
                     corner_radius=4, width=75, height=28).pack(side="left", padx=8)

        ctk.CTkButton(row, text="VIEW", width=90, height=34, font=theme.F_SMALL, fg_color="transparent",
                      text_color=theme.GREEN, border_width=1, border_color=theme.BORDER_BRIGHT,
                      hover_color=theme.PANEL_ALT, command=lambda u=user: self._open_detail(u)).pack(
            side="right", padx=16, pady=10)
        ctk.CTkButton(row, text="🗑", width=38, height=34, fg_color="transparent", text_color=theme.RED,
                      border_width=1, border_color=theme.RED, hover_color=theme.PANEL_ALT,
                      command=lambda u=user: self._quick_delete(u)).pack(side="right", padx=(0, 4), pady=10)

    def _open_detail(self, user):
        UserDetailModal(self, self.app, user, on_change=self.on_show)

    def _quick_delete(self, user):
        """One-click delete straight from the list row, for when you don't need the full detail view first."""
        if not messagebox.askyesno(
            "Delete user",
            f"Permanently delete @{user['username']}?\n\n"
            "This also deletes all of their scans, subscriptions, and payment records. "
            "This cannot be undone.",
            icon="warning",
        ):
            return
        self.app.db.delete_user(str(user["_id"]))
        messagebox.showinfo("User deleted", f"@{user['username']} has been permanently deleted.")
        self.on_show()
