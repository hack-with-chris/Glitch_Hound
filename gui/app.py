"""
Main application window — owns navigation, the DB connection, and the
logged-in auth session. Every page is a CTkFrame that this controller
shows/hides; pages never navigate directly, they call app.show_page(...).

Two separate "shells" can be built after login, never both at once:
  - user shell  (Sidebar)      -> dashboard/scan/history/profile/subscription
  - admin shell (AdminSidebar) -> admin_dashboard/admin_users
Which one gets built is decided by AuthManager.login()'s result — the admin
shares the same login form as everyone else, but if the credentials match
the single predefined admin account, the admin shell opens instead.
"""
import customtkinter as ctk
from tkinter import messagebox

from database.db import Database
from auth.auth_manager import AuthManager
import config
from gui import theme

from gui.login_page import LoginPage
from gui.register_page import RegisterPage
from gui.forgot_password_page import ForgotPasswordPage
from gui.otp_verify_page import OtpVerifyPage
from gui.reset_password_page import ResetPasswordPage
from gui.dashboard_page import DashboardPage
from gui.scan_page import ScanPage
from gui.history_page import HistoryPage
from gui.profile_page import ProfilePage
from gui.subscription_page import SubscriptionPage
from gui.admin_dashboard_page import AdminDashboardPage
from gui.admin_users_page import AdminUsersPage
from gui.risk_prediction_page import RiskPredictionPage
from gui.security_chatbot_page import SecurityChatbotPage

ctk.set_appearance_mode("dark")

USER_PAGES = ["dashboard", "scan", "history", "risk_prediction", "security_chatbot", "profile", "subscription"]
ADMIN_PAGES = ["admin_dashboard", "admin_users", "admin_risk_prediction"]


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"{config.APP_NAME} :: Security Scanner v{config.APP_VERSION}")
        self.geometry("1180x740")
        self.minsize(1000, 640)
        self.configure(fg_color=theme.BLACK)

        try:
            self.db = Database.instance()
        except ConnectionError as e:
            messagebox.showerror("Database Connection Error", str(e))
            self.after(100, self.destroy)
            return

        self.auth = AuthManager(self.db)
        self.sidebar = None
        self.shell_mode = None  # None | "user" | "admin"

        self.content_container = ctk.CTkFrame(self, fg_color=theme.BLACK, corner_radius=0)
        self.content_container.pack(side="right", fill="both", expand=True)

        self.pages = {}
        self.pages["login"] = LoginPage(self.content_container, self)
        self.pages["register"] = RegisterPage(self.content_container, self)
        self.pages["forgot_password"] = ForgotPasswordPage(self.content_container, self)
        self.pages["otp_verify"] = OtpVerifyPage(self.content_container, self)
        self.pages["reset_password"] = ResetPasswordPage(self.content_container, self)
        self.show_page("login")

    # ------------------------------------------------------------ #
    def _build_user_shell(self):
        if self.shell_mode == "user":
            return
        self._teardown_shell()
        self.sidebar = Sidebar(self, self)
        self.sidebar.pack(side="left", fill="y")

        self.pages["dashboard"] = DashboardPage(self.content_container, self)
        self.pages["scan"] = ScanPage(self.content_container, self)
        self.pages["history"] = HistoryPage(self.content_container, self)
        self.pages["risk_prediction"] = RiskPredictionPage(self.content_container, self)
        self.pages["security_chatbot"] = SecurityChatbotPage(self.content_container, self)
        self.pages["profile"] = ProfilePage(self.content_container, self)
        self.pages["subscription"] = SubscriptionPage(self.content_container, self)
        self.shell_mode = "user"

    def _build_admin_shell(self):
        if self.shell_mode == "admin":
            return
        self._teardown_shell()
        self.sidebar = AdminSidebar(self, self)
        self.sidebar.pack(side="left", fill="y")

        self.pages["admin_dashboard"] = AdminDashboardPage(self.content_container, self)
        self.pages["admin_users"] = AdminUsersPage(self.content_container, self)
        self.pages["admin_risk_prediction"] = RiskPredictionPage(
            self.content_container, self, admin=True
        )
        self.shell_mode = "admin"

    def _teardown_shell(self):
        if self.sidebar:
            self.sidebar.destroy()
            self.sidebar = None
        pages_to_remove = USER_PAGES if self.shell_mode == "user" else ADMIN_PAGES if self.shell_mode == "admin" else []
        for name in pages_to_remove:
            if name in self.pages:
                self.pages[name].destroy()
                del self.pages[name]
        self.shell_mode = None

    def on_login_success(self, is_admin=False):
        if is_admin:
            self._build_admin_shell()
            self.show_page("admin_dashboard")
        else:
            self._build_user_shell()
            self.show_page("dashboard")

    def on_logout(self):
        self.auth.logout()
        self._teardown_shell()
        self.show_page("login")

    def refresh_plan_everywhere(self):
        """Call after a plan change (e.g. successful upgrade) to sync the UI."""
        self.auth.refresh_current_user()
        if self.sidebar and self.shell_mode == "user":
            self.sidebar.refresh_plan_badge()

    def show_page(self, name):
        for key, page in self.pages.items():
            if key == name:
                continue
            page.pack_forget()
            if hasattr(page, "on_hide"):
                page.on_hide()
        self.pages[name].pack(fill="both", expand=True)
        if hasattr(self.pages[name], "on_show"):
            self.pages[name].on_show()
        if self.sidebar:
            self.sidebar.highlight(name)

    def current_plan_limits(self):
        plan = self.auth.current_user.get("plan", "free") if self.auth.current_user else "free"
        return config.PLAN_LIMITS[plan]

    def can_use_risk_predictor(self):
        """Risk prediction is restricted to active yearly Pro subscriptions."""
        user = self.auth.current_user
        return bool(
            user
            and user.get("plan") == "pro"
            and self.db.has_yearly_pro_access(str(user["_id"]))
        )


class Sidebar(ctk.CTkFrame):
    NAV_ITEMS = [
        ("dashboard", "~/dashboard"),
        ("scan", "~/new_scan"),
        ("history", "~/history"),
        ("risk_prediction", "~/ai_prediction"),
        ("security_chatbot", "~/security_assistant"),
        ("subscription", "~/billing"),
        ("profile", "~/profile"),
    ]

    def __init__(self, parent, app):
        super().__init__(parent, width=255, corner_radius=0, fg_color=theme.PANEL,
                          border_width=0)
        self.app = app
        self.buttons = {}
        self.pack_propagate(False)

        ctk.CTkFrame(self, height=2, fg_color=theme.GREEN).pack(fill="x", side="top")

        ctk.CTkLabel(self, text="🛡 GLITCH HOUND", font=(theme.FONT, 18, "bold"),
                     text_color=theme.GREEN).pack(pady=(22, 2), padx=20, anchor="w")
        ctk.CTkLabel(self, text=f"v{config.APP_VERSION}", font=theme.F_SMALL,
                     text_color=theme.TEXT_MUTED).pack(padx=20, anchor="w")

        self.plan_badge = ctk.CTkLabel(self, text="", font=theme.F_SMALL, anchor="w")
        self.plan_badge.pack(padx=20, anchor="w", pady=(6, 22))
        self.refresh_plan_badge()

        ctk.CTkFrame(self, height=1, fg_color=theme.BORDER).pack(fill="x", padx=16, pady=(0, 14))

        for key, label in self.NAV_ITEMS:
            btn = ctk.CTkButton(
                self, text=f"$ {label}", anchor="w", font=theme.F_BODY,
                fg_color="transparent", text_color=theme.GREEN_DIM,
                hover_color=theme.PANEL_ALT, corner_radius=4,
                command=lambda k=key: app.show_page(k),
            )
            btn.pack(fill="x", padx=12, pady=3)
            self.buttons[key] = btn

        ctk.CTkButton(
            self, text="[ logout ]", fg_color="transparent", text_color=theme.RED,
            hover_color=theme.PANEL_ALT, border_width=1, border_color=theme.RED,
            font=theme.F_BODY, command=app.on_logout,
        ).pack(side="bottom", fill="x", padx=12, pady=20)

    def highlight(self, active_key):
        for key, btn in self.buttons.items():
            if key == active_key:
                btn.configure(fg_color=theme.PANEL_ALT, text_color=theme.GREEN)
            else:
                btn.configure(fg_color="transparent", text_color=theme.GREEN_DIM)

    def refresh_plan_badge(self):
        user = self.app.auth.current_user
        plan_label = (user.get("plan", "free") if user else "free").upper()
        color = theme.CYAN if plan_label == "PRO" else theme.TEXT_MUTED
        self.plan_badge.configure(text=f"● PLAN: {plan_label}", text_color=color)


class AdminSidebar(ctk.CTkFrame):
    NAV_ITEMS = [
        ("admin_dashboard", "~/overview"),
        ("admin_users", "~/users"),
        ("admin_risk_prediction", "~/ai_prediction"),
    ]

    def __init__(self, parent, app):
        super().__init__(parent, width=255, corner_radius=0, fg_color=theme.PANEL, border_width=0)
        self.app = app
        self.buttons = {}
        self.pack_propagate(False)

        ctk.CTkFrame(self, height=2, fg_color=theme.CYAN).pack(fill="x", side="top")

        ctk.CTkLabel(self, text="🛡 GLITCH HOUND", font=(theme.FONT, 18, "bold"),
                     text_color=theme.GREEN).pack(pady=(22, 2), padx=20, anchor="w")
        ctk.CTkLabel(self, text="● ADMIN MODE", font=theme.F_SMALL, text_color=theme.CYAN).pack(
            padx=20, anchor="w", pady=(0, 22))

        ctk.CTkFrame(self, height=1, fg_color=theme.BORDER).pack(fill="x", padx=16, pady=(0, 14))

        for key, label in self.NAV_ITEMS:
            btn = ctk.CTkButton(
                self, text=f"$ {label}", anchor="w", font=theme.F_BODY,
                fg_color="transparent", text_color=theme.GREEN_DIM,
                hover_color=theme.PANEL_ALT, corner_radius=4,
                command=lambda k=key: app.show_page(k),
            )
            btn.pack(fill="x", padx=12, pady=3)
            self.buttons[key] = btn

        ctk.CTkButton(
            self, text="[ logout ]", fg_color="transparent", text_color=theme.RED,
            hover_color=theme.PANEL_ALT, border_width=1, border_color=theme.RED,
            font=theme.F_BODY, command=app.on_logout,
        ).pack(side="bottom", fill="x", padx=12, pady=20)

    def highlight(self, active_key):
        for key, btn in self.buttons.items():
            if key == active_key:
                btn.configure(fg_color=theme.PANEL_ALT, text_color=theme.GREEN)
            else:
                btn.configure(fg_color="transparent", text_color=theme.GREEN_DIM)

    def refresh_plan_badge(self):
        pass  # admin has no plan — present so App.refresh_plan_everywhere() can call it safely
