import asyncio
import threading

import customtkinter as ctk
from tkinter import messagebox

from gui import theme
from scanner.risk_predictor import RiskPredictor


class RiskPredictionPage(ctk.CTkFrame):
    """Yearly-Pro prediction UI shared by customers and administrators."""

    def __init__(self, parent, app, admin=False):
        super().__init__(parent, fg_color=theme.BLACK)
        self.app = app
        self.admin = admin
        self._busy = False
        self._build()

    def _build(self):
        ctk.CTkLabel(self, text="AI RISK PREDICTION", font=theme.F_TITLE,
                     text_color=theme.GREEN).pack(anchor="w", padx=32, pady=(28, 4))
        ctk.CTkLabel(
            self,
            text="root@glitchhound:~$ predict --epss --exposure",
            font=theme.F_MONO_SMALL, text_color=theme.GREEN_DIM,
        ).pack(anchor="w", padx=32)

        self.access_label = ctk.CTkLabel(self, text="", font=theme.F_BODY,
                                         text_color=theme.AMBER, wraplength=1000,
                                         justify="left")
        self.access_label.pack(anchor="w", padx=32, pady=(12, 8))

        explanation = ctk.CTkFrame(self, fg_color=theme.PANEL_ALT, corner_radius=4,
                                   border_width=1, border_color=theme.CYAN)
        explanation.pack(fill="x", padx=32, pady=(0, 12))
        ctk.CTkLabel(explanation, text="WHAT THIS PREDICTS", font=theme.F_BODY_BOLD,
                     text_color=theme.CYAN).pack(anchor="w", padx=16, pady=(12, 3))
        ctk.CTkLabel(
            explanation,
            text="This estimates how exposed the scanned assets may be based on saved findings. "
                 "It combines vulnerability exploit likelihood, exposed services, and missing web protections. "
                 "It does not confirm that a target is hackable and never exploits it.",
            font=theme.F_SMALL, text_color=theme.GREEN_DIM, wraplength=1000,
            justify="left",
        ).pack(anchor="w", padx=16, pady=(0, 10))

        guide = ctk.CTkFrame(explanation, fg_color="transparent")
        guide.pack(fill="x", padx=16, pady=(0, 12))
        for column in range(3):
            guide.grid_columnconfigure(column, weight=1)
        self._guide_item(
            guide, 0, "INPUT SIGNALS",
            "CVE CVSS + EPSS\nOpen high-risk ports\nMissing critical headers",
        )
        self._guide_item(
            guide, 1, "SCORING",
            "CVE: CVSS x EPSS x 10\nPorts: +15 once\nHeaders: +10 once\nMaximum: 100",
        )
        self._guide_item(
            guide, 2, "SEVERITY",
            "0-29  LOW\n30-59  MODERATE\n60-79  HIGH\n80-100  CRITICAL",
        )

        history = ctk.CTkFrame(self, fg_color=theme.PANEL, corner_radius=4,
                               border_width=2, border_color=theme.CYAN)
        history.pack(fill="x", padx=32, pady=(0, 14))
        ctk.CTkLabel(history, text="HISTORICAL FORECAST / NEXT WEBSITE",
                     font=theme.F_HEADER, text_color=theme.CYAN).pack(
            anchor="w", padx=18, pady=(14, 2))
        ctk.CTkLabel(
            history,
            text="Uses your previous website audits to estimate how likely the next audited website is to be at risk "
                 "and which weaknesses are most likely to appear again.",
            font=theme.F_SMALL, text_color=theme.GREEN_DIM, wraplength=1000,
            justify="left",
        ).pack(anchor="w", padx=18, pady=(0, 12))
        forecast_metrics = ctk.CTkFrame(history, fg_color="transparent")
        forecast_metrics.pack(fill="x", padx=12, pady=(0, 12))
        for column in range(3):
            forecast_metrics.grid_columnconfigure(column, weight=1)
        self.history_rate_label = self._forecast_metric(
            forecast_metrics, 0, "HISTORICAL AT-RISK RATE", "--", theme.RED
        )
        self.history_baseline_label = self._forecast_metric(
            forecast_metrics, 1, "NEXT WEBSITE BASELINE", "WAITING", theme.AMBER
        )
        self.history_sample_label = self._forecast_metric(
            forecast_metrics, 2, "PAST WEBSITE AUDITS", "0", theme.GREEN
        )
        self.history_issues_label = ctk.CTkLabel(
            history, text="COMMON FUTURE ISSUES: Run prediction to load historical patterns.",
            font=theme.F_BODY, text_color=theme.GREEN_DIM, wraplength=1000,
            justify="left",
        )
        self.history_issues_label.pack(anchor="w", padx=18, pady=(0, 14))

        body = ctk.CTkFrame(self, fg_color=theme.PANEL, corner_radius=4,
                            border_width=1, border_color=theme.BORDER)
        body.pack(fill="both", expand=True, padx=32, pady=(0, 24))

        controls = ctk.CTkFrame(body, fg_color="transparent")
        controls.pack(fill="x", padx=18, pady=18)
        self.scope_label = ctk.CTkLabel(controls, text="", font=theme.F_BODY_BOLD,
                                        text_color=theme.CYAN)
        self.scope_label.pack(side="left")
        self.predict_button = ctk.CTkButton(
            controls, text="RUN PREDICTION", width=190, height=42,
            font=theme.F_BODY_BOLD, fg_color=theme.GREEN, text_color=theme.BLACK,
            hover_color=theme.GREEN_SOFT, command=self.run_prediction,
        )
        self.predict_button.pack(side="right")

        self.status_label = ctk.CTkLabel(body, text="", font=theme.F_SMALL,
                                         text_color=theme.GREEN_DIM)
        self.status_label.pack(anchor="w", padx=18, pady=(0, 10))

        result = ctk.CTkFrame(body, fg_color=theme.PANEL_ALT, corner_radius=4,
                              border_width=1, border_color=theme.BORDER)
        result.pack(fill="x", padx=18, pady=(0, 18))
        self.score_label = ctk.CTkLabel(result, text="--", font=theme.F_GRADE,
                                       text_color=theme.GREEN)
        self.score_label.pack(side="left", padx=22, pady=18)
        result_text = ctk.CTkFrame(result, fg_color="transparent")
        result_text.pack(side="left", fill="x", expand=True, pady=18)
        self.severity_label = ctk.CTkLabel(result_text, text="WAITING FOR ANALYSIS",
                                           font=theme.F_HEADER, text_color=theme.GREEN)
        self.severity_label.pack(anchor="w")
        self.breakdown_label = ctk.CTkLabel(result_text, text="CVE: --   PORTS: --   HEADERS: --",
                                            font=theme.F_BODY, text_color=theme.GREEN_DIM)
        self.breakdown_label.pack(anchor="w", pady=(4, 0))

        ctk.CTkLabel(
            body,
            text="The score is an explainable heuristic: CVSS x EPSS x 10, plus port and header penalties. "
                 "It is not proof that a target is exploitable and does not perform exploitation.",
            font=theme.F_SMALL, text_color=theme.TEXT_MUTED, wraplength=900,
            justify="left",
        ).pack(anchor="w", padx=18, pady=(0, 18))

    def _guide_item(self, parent, column, title, text):
        item = ctk.CTkFrame(parent, fg_color=theme.PANEL, corner_radius=3)
        item.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 5, 5))
        ctk.CTkLabel(item, text=title, font=theme.F_SMALL,
                     text_color=theme.GREEN).pack(anchor="w", padx=10, pady=(8, 2))
        ctk.CTkLabel(item, text=text, font=theme.F_SMALL,
                     text_color=theme.GREEN_DIM, justify="left", anchor="w").pack(
            anchor="w", padx=10, pady=(0, 8))

    def _forecast_metric(self, parent, column, title, value, color):
        metric = ctk.CTkFrame(parent, fg_color=theme.PANEL_ALT, corner_radius=4,
                              border_width=1, border_color=theme.BORDER)
        metric.grid(row=0, column=column, sticky="nsew", padx=5)
        ctk.CTkLabel(metric, text=title, font=theme.F_SMALL,
                     text_color=theme.GREEN_DIM).pack(anchor="w", padx=14, pady=(10, 2))
        label = ctk.CTkLabel(metric, text=value, font=theme.F_HEADER, text_color=color)
        label.pack(anchor="w", padx=14, pady=(0, 10))
        return label

    def on_show(self):
        if self.admin:
            self.access_label.configure(text="ADMIN MODE: prediction uses all stored scans.", text_color=theme.CYAN)
            self.scope_label.configure(text="SCOPE: ALL USERS / ALL STORED SCANS")
            self.predict_button.configure(state="normal")
            return
        allowed = self.app.can_use_risk_predictor()
        if allowed:
            self.access_label.configure(text="YEARLY PRO ACTIVE: prediction is available for your saved scans.",
                                        text_color=theme.GREEN)
            self.scope_label.configure(text="SCOPE: YOUR SAVED SCANS")
            self.predict_button.configure(state="normal")
        else:
            self.access_label.configure(
                text="YEARLY PRO REQUIRED: this feature is available only with an active yearly Pro subscription.",
                text_color=theme.AMBER,
            )
            self.scope_label.configure(text="SCOPE LOCKED")
            self.predict_button.configure(state="disabled")

    def run_prediction(self):
        if self._busy:
            return
        if not self.admin and not self.app.can_use_risk_predictor():
            messagebox.showinfo("Yearly Pro required", "AI risk prediction requires an active yearly Pro subscription.")
            return
        self._busy = True
        self.predict_button.configure(state="disabled", text="FETCHING EPSS...")
        self.status_label.configure(text="Fetching exploit probability for each CVE and calculating exposure...")
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self):
        try:
            scans = self.app.db.get_all_scans() if self.admin else self.app.db.get_scans_for_user(
                str(self.app.auth.current_user["_id"])
            )
            cves, ports, headers = [], [], []
            for scan in scans:
                results = scan.get("results", {})
                cves.extend(results.get("cve_list", results.get("cves", [])))
                ports.extend(item.get("port") for item in results.get("open_ports", []))
                headers.extend(item.get("header", item) for item in results.get("headers", {}).get("missing", []))
            predictor = RiskPredictor()
            prediction = asyncio.run(predictor.predict(cves, ports, headers))
            historical = predictor.historical_summary(scans)
            self.after(0, lambda: self._show_result(prediction, historical, len(scans)))
        except Exception as exc:
            self.after(0, lambda: self._show_error(str(exc)))

    def _show_result(self, prediction, historical, scan_count):
        self._busy = False
        self.predict_button.configure(state="normal", text="RUN PREDICTION")
        self.status_label.configure(text=f"Analyzed {scan_count} stored scan(s).")
        severity_colors = {
            "Low": theme.GREEN,
            "Moderate": theme.AMBER,
            "High": theme.RED,
            "Critical": theme.RED,
        }
        self.score_label.configure(
            text=f"{prediction['total_score']:.1f}",
            text_color=severity_colors.get(prediction["risk_severity"], theme.GREEN),
        )
        self.severity_label.configure(text=prediction["risk_severity"].upper())
        breakdown = prediction["breakdown"]
        self.breakdown_label.configure(
            text=f"CVEs: {breakdown['cves']:.1f}   PORTS: {breakdown['ports']:.1f}   "
                 f"HEADERS: {breakdown['headers']:.1f}"
        )
        audit_count = historical["website_audits"]
        self.history_rate_label.configure(text=f"{historical['at_risk_rate_pct']:.1f}%")
        self.history_baseline_label.configure(text=historical["next_site_baseline"].upper())
        self.history_sample_label.configure(text=str(audit_count))
        issues = historical["common_issues"]
        self.history_issues_label.configure(
            text="COMMON FUTURE ISSUES: " + (
                "   |   ".join(f"{item['issue']} ({item['frequency_pct']:.1f}%)" for item in issues)
                if issues else "No recurring issues recorded yet. This forecast needs past website audits."
            )
        )
        if prediction.get("errors"):
            self.status_label.configure(text=f"Analyzed {scan_count} scan(s), with {len(prediction['errors'])} EPSS lookup error(s).")

    def _show_error(self, error):
        self._busy = False
        self.predict_button.configure(state="normal", text="RUN PREDICTION")
        self.status_label.configure(text=f"Prediction failed: {error}", text_color=theme.RED)