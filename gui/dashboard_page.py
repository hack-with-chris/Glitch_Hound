import customtkinter as ctk
import config
from gui import theme


class StatCard(ctk.CTkFrame):
    def __init__(self, parent, title, value, accent=None):
        super().__init__(parent, corner_radius=4, fg_color=theme.PANEL,
                          border_width=1, border_color=theme.BORDER)
        ctk.CTkLabel(self, text=title.upper(), font=theme.F_SMALL, text_color=theme.GREEN_DIM).pack(
            anchor="w", padx=18, pady=(16, 2))
        self.value_label = ctk.CTkLabel(self, text=value, font=theme.F_STAT, text_color=accent or theme.GREEN)
        self.value_label.pack(anchor="w", padx=18, pady=(0, 16))

    def set_value(self, value):
        self.value_label.configure(text=value)


class DashboardPage(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=theme.BLACK)
        self.app = app

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=32, pady=(28, 10))
        self.welcome_label = ctk.CTkLabel(header, text="", font=theme.F_TITLE, text_color=theme.GREEN)
        self.welcome_label.pack(anchor="w")
        ctk.CTkLabel(header, text="root@glitchhound:~$ status --overview", font=theme.F_MONO_SMALL,
                     text_color=theme.GREEN_DIM).pack(anchor="w", pady=(2, 0))

        cards_row = ctk.CTkFrame(self, fg_color="transparent")
        cards_row.pack(fill="x", padx=32, pady=14)
        for i in range(3):
            cards_row.grid_columnconfigure(i, weight=1)

        self.plan_card = StatCard(cards_row, "Current Plan", "—", accent=theme.CYAN)
        self.plan_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        self.usage_card = StatCard(cards_row, "Scans This Month", "—")
        self.usage_card.grid(row=0, column=1, sticky="nsew", padx=10)

        self.total_card = StatCard(cards_row, "Total Scans", "—")
        self.total_card.grid(row=0, column=2, sticky="nsew", padx=(10, 0))

        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.pack(fill="x", padx=32, pady=20)
        ctk.CTkButton(actions, text="▶ RUN NEW SCAN", height=46, width=230, font=theme.F_BODY_BOLD,
                      fg_color=theme.GREEN, text_color=theme.BLACK, hover_color=theme.GREEN_SOFT,
                      command=lambda: app.show_page("scan")).pack(side="left", padx=(0, 12))
        ctk.CTkButton(actions, text="VIEW SCAN HISTORY", height=46, width=230, font=theme.F_BODY_BOLD,
                  fg_color="transparent", text_color=theme.GREEN, border_width=1, border_color=theme.BORDER_BRIGHT,
                  hover_color=theme.PANEL_ALT,
                  command=lambda: app.show_page("history")).pack(side="left")
        ctk.CTkButton(actions, text="AI RISK PREDICTION", height=46, width=230, font=theme.F_BODY_BOLD,
                  fg_color="transparent", text_color=theme.CYAN, border_width=1, border_color=theme.CYAN,
                  hover_color=theme.PANEL_ALT,
                  command=lambda: app.show_page("risk_prediction")).pack(side="left", padx=(12, 0))

        ctk.CTkLabel(self, text="RECENT ACTIVITY", font=theme.F_SUBHEADER, text_color=theme.GREEN).pack(
            anchor="w", padx=32, pady=(6, 6))
        self.recent_frame = ctk.CTkScrollableFrame(self, fg_color=theme.PANEL, corner_radius=4,
                                                     border_width=1, border_color=theme.BORDER)
        self.recent_frame.pack(fill="both", expand=True, padx=32, pady=(0, 28))

    def on_show(self):
        self.refresh()

    def refresh(self):
        user = self.app.auth.current_user
        if not user:
            return
        limits = config.PLAN_LIMITS[user.get("plan", "free")]

        self.welcome_label.configure(text=f"WELCOME, {(user.get('full_name') or user.get('username')).upper()}")
        self.plan_card.set_value(limits["label"].upper())

        used = user.get("scans_used_this_period", 0)
        cap = limits["scans_per_month"]
        self.usage_card.set_value(f"{used} / {'∞' if cap is None else cap}")

        scans = self.app.db.get_scans_for_user(str(user["_id"]))
        self.total_card.set_value(str(len(scans)))

        for widget in self.recent_frame.winfo_children():
            widget.destroy()

        if not scans:
            ctk.CTkLabel(self.recent_frame, text="No scans yet — run your first scan to see it here.",
                         font=theme.F_BODY, text_color=theme.GREEN_DIM).pack(pady=24)
            return

        for scan in scans[:6]:
            row = ctk.CTkFrame(self.recent_frame, fg_color=theme.PANEL_ALT, corner_radius=4)
            row.pack(fill="x", pady=4, padx=6)
            icon = "🌐" if scan["scan_type"] == "vuln_scan" else "🔌"
            ctk.CTkLabel(row, text=f"{icon}  {scan['target']}", font=theme.F_BODY_BOLD,
                         text_color=theme.GREEN, anchor="w").pack(side="left", padx=14, pady=12)
            ctk.CTkLabel(row, text=scan["created_at"].strftime("%b %d, %Y  %H:%M"), font=theme.F_SMALL,
                         text_color=theme.GREEN_DIM).pack(side="right", padx=14)
