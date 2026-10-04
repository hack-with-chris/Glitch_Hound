import customtkinter as ctk

from gui import theme


class StatCard(ctk.CTkFrame):
    def __init__(self, parent, title, value, accent=None):
        super().__init__(parent, corner_radius=4, fg_color=theme.PANEL, border_width=1, border_color=theme.BORDER)
        ctk.CTkLabel(self, text=title.upper(), font=theme.F_SMALL, text_color=theme.GREEN_DIM).pack(
            anchor="w", padx=18, pady=(16, 2))
        self.value_label = ctk.CTkLabel(self, text=value, font=theme.F_STAT, text_color=accent or theme.GREEN)
        self.value_label.pack(anchor="w", padx=18, pady=(0, 16))

    def set_value(self, value):
        self.value_label.configure(text=value)


class AdminDashboardPage(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=theme.BLACK)
        self.app = app

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=32, pady=(28, 10))
        ctk.CTkLabel(header, text="ADMIN OVERVIEW", font=theme.F_TITLE, text_color=theme.GREEN).pack(anchor="w")
        ctk.CTkLabel(header, text="root@glitchhound:~$ admin --overview", font=theme.F_MONO_SMALL,
                     text_color=theme.GREEN_DIM).pack(anchor="w", pady=(2, 0))

        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=32, pady=(10, 24))

        row1 = ctk.CTkFrame(scroll, fg_color="transparent")
        row1.pack(fill="x", pady=(0, 12))
        for i in range(4):
            row1.grid_columnconfigure(i, weight=1)
        self.total_users_card = StatCard(row1, "Total Users", "—")
        self.total_users_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.verified_card = StatCard(row1, "Email Verified", "—")
        self.verified_card.grid(row=0, column=1, sticky="nsew", padx=8)
        self.free_card = StatCard(row1, "Free Plan Users", "—")
        self.free_card.grid(row=0, column=2, sticky="nsew", padx=8)
        self.pro_card = StatCard(row1, "Pro Plan Users", "—", accent=theme.CYAN)
        self.pro_card.grid(row=0, column=3, sticky="nsew", padx=(8, 0))

        row2 = ctk.CTkFrame(scroll, fg_color="transparent")
        row2.pack(fill="x", pady=12)
        for i in range(4):
            row2.grid_columnconfigure(i, weight=1)
        self.total_scans_card = StatCard(row2, "Total Scans", "—")
        self.total_scans_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.port_scans_card = StatCard(row2, "Port Scans", "—")
        self.port_scans_card.grid(row=0, column=1, sticky="nsew", padx=8)
        self.vuln_scans_card = StatCard(row2, "Website Audits", "—")
        self.vuln_scans_card.grid(row=0, column=2, sticky="nsew", padx=8)
        self.vulnerable_card = StatCard(row2, "Vulnerable Websites", "—", accent=theme.RED)
        self.vulnerable_card.grid(row=0, column=3, sticky="nsew", padx=(8, 0))

        ctk.CTkLabel(scroll, text="WEBSITE SECURITY GRADE DISTRIBUTION", font=theme.F_SUBHEADER,
                     text_color=theme.GREEN).pack(anchor="w", pady=(16, 8))
        grade_row = ctk.CTkFrame(scroll, fg_color=theme.PANEL, corner_radius=4,
                                  border_width=1, border_color=theme.BORDER)
        grade_row.pack(fill="x", pady=(0, 4))
        self.grade_labels = {}
        for i, letter in enumerate(["A", "B", "C", "D", "F"]):
            cell = ctk.CTkFrame(grade_row, fg_color="transparent")
            cell.grid(row=0, column=i, sticky="nsew", padx=10, pady=14)
            grade_row.grid_columnconfigure(i, weight=1)
            ctk.CTkLabel(cell, text=letter, font=theme.F_GRADE, text_color=theme.grade_color(letter)).pack()
            lbl = ctk.CTkLabel(cell, text="0", font=theme.F_BODY_BOLD, text_color=theme.GREEN_DIM)
            lbl.pack()
            self.grade_labels[letter] = lbl

        ctk.CTkLabel(scroll, text="OPEN PORT RISK ACROSS ALL SCANS", font=theme.F_SUBHEADER,
                     text_color=theme.GREEN).pack(anchor="w", pady=(20, 8))
        risk_row = ctk.CTkFrame(scroll, fg_color=theme.PANEL, corner_radius=4,
                                 border_width=1, border_color=theme.BORDER)
        risk_row.pack(fill="x", pady=(0, 4))
        self.risk_labels = {}
        risk_colors = {"HIGH": theme.RED, "MEDIUM": theme.AMBER, "LOW": theme.GREEN}
        for i, level in enumerate(["HIGH", "MEDIUM", "LOW"]):
            cell = ctk.CTkFrame(risk_row, fg_color="transparent")
            cell.grid(row=0, column=i, sticky="nsew", padx=10, pady=14)
            risk_row.grid_columnconfigure(i, weight=1)
            ctk.CTkLabel(cell, text=level, font=theme.F_BODY_BOLD, text_color=risk_colors[level]).pack()
            lbl = ctk.CTkLabel(cell, text="0", font=theme.F_STAT, text_color=risk_colors[level])
            lbl.pack()
            self.risk_labels[level] = lbl

        # pbi_box = ctk.CTkFrame(scroll, fg_color=theme.PANEL_ALT, corner_radius=4,
        #                         border_width=1, border_color=theme.CYAN)
        # pbi_box.pack(fill="x", pady=(20, 10))
        # ctk.CTkLabel(pbi_box, text="ℹ CONNECT TO POWER BI", font=theme.F_SUBHEADER, text_color=theme.CYAN).pack(
        #     anchor="w", padx=16, pady=(14, 6))
        # ctk.CTkLabel(
        #     pbi_box,
        #     text="These numbers come straight from the users / scans / subscriptions / payments collections "
        #          "in MongoDB Atlas. Enable the Atlas SQL Interface (Atlas \u2192 Data Federation), then in Power "
        #          "BI Desktop use Get Data \u2192 MongoDB Atlas SQL and connect with your Atlas URI + DB user to "
        #          "build live dashboards on the same data.",
        #     font=theme.F_SMALL, text_color=theme.GREEN_DIM, wraplength=900, justify="left",
        # ).pack(anchor="w", padx=16, pady=(0, 14))

    def on_show(self):
        self.refresh()

    def refresh(self):
        overview = self.app.db.get_admin_overview()

        self.total_users_card.set_value(str(overview["total_users"]))
        self.verified_card.set_value(str(overview["verified_users"]))
        self.free_card.set_value(str(overview["free_users"]))
        self.pro_card.set_value(str(overview["pro_users"]))

        self.total_scans_card.set_value(str(overview["total_scans"]))
        self.port_scans_card.set_value(str(overview["port_scan_count"]))
        self.vuln_scans_card.set_value(str(overview["vuln_scan_count"]))
        self.vulnerable_card.set_value(str(overview["vulnerable_site_count"]))

        for letter, lbl in self.grade_labels.items():
            lbl.configure(text=str(overview["grade_counts"].get(letter, 0)))

        for level, lbl in self.risk_labels.items():
            lbl.configure(text=str(overview["port_risk_counts"].get(level, 0)))
