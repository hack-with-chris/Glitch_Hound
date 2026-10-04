import threading
from tkinter import filedialog, messagebox

import customtkinter as ctk

from scanner import impact_knowledge, network_scanner, vuln_scanner
from scanner.risk_predictor import RiskPredictor
from gui import theme
from gui.widgets import TerminalSpinner, MatrixRain

NETWORK_PHASES = [
    "Resolving target hostname...",
    "Checking host reachability...",
    "Opening TCP probes...",
    "Scanning port range...",
    "Grabbing service banners...",
    "Compiling results...",
]

VULN_PHASES = [
    "Fetching target response...",
    "Inspecting HTTP headers...",
    "Validating SSL/TLS certificate...",
    "Checking cookie security flags...",
    "Probing common sensitive paths...",
    "Scoring security grade...",
]

# ---------------------------------------------------------------------------
# Port knowledge base — plain-English description + risk level + a one-line
# "attack this enables / how to prevent it" for commonly seen ports. This is
# purely presentation logic layered on top of the scan results; it doesn't
# change what network_scanner.py actually finds.
# ---------------------------------------------------------------------------
PORT_DETAILS = {
    21: {"name": "FTP", "desc": "File Transfer Protocol — uploads/downloads files, usually unencrypted.",
         "risk": "HIGH", "attack": "Credential sniffing & anonymous data theft (cleartext).",
         "fix": "Disable FTP or switch to SFTP/FTPS."},
    22: {"name": "SSH", "desc": "Secure Shell — encrypted remote server login.",
         "risk": "LOW", "attack": "Brute-force login attempts against weak passwords.",
         "fix": "Use key-based auth, disable password login, rate-limit attempts."},
    23: {"name": "Telnet", "desc": "Legacy remote login — sends everything, including passwords, in plain text.",
         "risk": "HIGH", "attack": "Cleartext credential interception.",
         "fix": "Disable Telnet entirely; use SSH instead."},
    25: {"name": "SMTP", "desc": "Sends email between mail servers.",
         "risk": "MEDIUM", "attack": "Open-relay abuse for spam/phishing campaigns.",
         "fix": "Require authentication; confirm the relay is closed to anonymous senders."},
    53: {"name": "DNS", "desc": "Resolves domain names to IP addresses.",
         "risk": "MEDIUM", "attack": "DNS amplification DDoS or unauthorized zone transfers.",
         "fix": "Disable recursive queries & zone transfers for untrusted clients."},
    80: {"name": "HTTP", "desc": "Unencrypted website traffic.",
         "risk": "MEDIUM", "attack": "Traffic interception/tampering — nothing here is encrypted.",
         "fix": "Redirect all traffic to HTTPS (443)."},
    110: {"name": "POP3", "desc": "Downloads email from a mail server.",
          "risk": "MEDIUM", "attack": "Cleartext credential interception if not using POP3S.",
          "fix": "Use POP3S (port 995) with TLS instead."},
    139: {"name": "NetBIOS", "desc": "Legacy Windows file/printer sharing name service.",
          "risk": "HIGH", "attack": "Information leakage & an entry point for SMB-based attacks.",
          "fix": "Block from the internet; restrict to the internal LAN only."},
    143: {"name": "IMAP", "desc": "Syncs email with a mail server.",
          "risk": "MEDIUM", "attack": "Cleartext credential interception if not using IMAPS.",
          "fix": "Use IMAPS (port 993) with TLS instead."},
    443: {"name": "HTTPS", "desc": "Encrypted website traffic.",
          "risk": "LOW", "attack": "Exploiting outdated TLS versions or weak cipher suites.",
          "fix": "Keep TLS config current; disable TLS 1.0/1.1 and weak ciphers."},
    445: {"name": "SMB", "desc": "Windows file & printer sharing.",
          "risk": "HIGH", "attack": "Ransomware propagation (e.g. EternalBlue-style worms).",
          "fix": "Block from the internet; patch regularly; firewall to internal-only."},
    1433: {"name": "MSSQL", "desc": "Microsoft SQL Server database.",
           "risk": "HIGH", "attack": "Direct database compromise via credential brute-force.",
           "fix": "Never expose to the internet; restrict to VPN/internal network."},
    3306: {"name": "MySQL", "desc": "MySQL/MariaDB database.",
           "risk": "HIGH", "attack": "Direct database compromise via credential brute-force.",
           "fix": "Never expose to the internet; restrict to VPN/internal network."},
    3389: {"name": "RDP", "desc": "Windows Remote Desktop.",
           "risk": "HIGH", "attack": "Brute-force login — a top ransomware entry point.",
           "fix": "Put behind a VPN, enable MFA, restrict by source IP."},
    5432: {"name": "PostgreSQL", "desc": "PostgreSQL database.",
           "risk": "HIGH", "attack": "Direct database compromise via credential brute-force.",
           "fix": "Never expose to the internet; restrict to VPN/internal network."},
    5900: {"name": "VNC", "desc": "Remote desktop screen sharing.",
           "risk": "HIGH", "attack": "Unauthorized remote desktop takeover (often weak/no auth).",
           "fix": "Require strong auth and tunnel over SSH/VPN."},
    6379: {"name": "Redis", "desc": "In-memory data store / cache.",
           "risk": "HIGH", "attack": "Unauthenticated data access or remote code execution.",
           "fix": "Enable auth, bind to localhost only, firewall it off."},
    8080: {"name": "HTTP-Alt", "desc": "Alternate/proxied web service port.",
           "risk": "MEDIUM", "attack": "Same risks as HTTP if traffic isn't encrypted upstream.",
           "fix": "Confirm it's proxied behind HTTPS, not exposed raw."},
    27017: {"name": "MongoDB", "desc": "MongoDB database.",
            "risk": "HIGH", "attack": "Unauthenticated database access / data theft.",
            "fix": "Enable auth, bind to localhost only, firewall it off."},
}
DEFAULT_PORT_INFO = {"name": None, "desc": "Uncommon or unclassified service.", "risk": "REVIEW",
                      "attack": "Unknown purpose — verify what's actually running here.",
                      "fix": "Confirm this port is intentional and needed; close it if not."}

RISK_COLOR = {"LOW": theme.GREEN, "MEDIUM": theme.AMBER, "HIGH": theme.RED, "REVIEW": theme.AMBER}
RISK_ORDER = ["HIGH", "MEDIUM", "LOW", "REVIEW"]

PORT_SCAN_DISCLAIMER = ("This scan only checks whether a port answers a TCP connection and reads its banner — "
                         "it does not test the service itself for weak credentials or exploitable bugs.")

# ---------------------------------------------------------------------------
# Vulnerability knowledge base — for every check the audit performs, map a
# failing finding to the attack it enables and a one-line fix.
# ---------------------------------------------------------------------------
HEADER_ATTACK_INFO = {
    "Strict-Transport-Security": ("SSL-stripping / protocol-downgrade MITM",
                                   "Add Strict-Transport-Security: max-age=63072000; includeSubDomains"),
    "Content-Security-Policy": ("Cross-Site Scripting (XSS) & data injection",
                                 "Define a strict CSP that whitelists trusted script/style sources"),
    "X-Content-Type-Options": ("MIME-sniffing based content injection",
                                "Add X-Content-Type-Options: nosniff"),
    "X-Frame-Options": ("Clickjacking",
                         "Add X-Frame-Options: DENY or a CSP frame-ancestors rule"),
    "Referrer-Policy": ("Sensitive URL/data leakage via the Referer header",
                         "Set Referrer-Policy: strict-origin-when-cross-origin"),
    "Permissions-Policy": ("Unauthorized use of camera/mic/geolocation by embedded scripts",
                            "Add a Permissions-Policy header restricting unneeded features"),
}
COOKIE_ATTACK_INFO = {
    "Secure": ("Session/cookie theft over an unencrypted connection", "Set the Secure flag on every cookie"),
    "HttpOnly": ("Session hijacking via XSS reading the cookie", "Set the HttpOnly flag on session cookies"),
}
DIRLIST_ATTACK = ("Information disclosure via file/directory enumeration",
                   "Disable autoindexing (e.g. Options -Indexes in Apache)")
BANNER_ATTACK = ("Targeted exploitation using known CVEs for that exact software version",
                  "Suppress version headers (ServerTokens Prod / server_tokens off;)")
SSL_INVALID_ATTACK = ("Man-in-the-Middle (MITM) interception",
                       "Install a valid TLS cert (e.g. Let's Encrypt) and force HTTPS")
SSL_EXPIRING_ATTACK = ("Expired-cert browser warnings train users to click through security prompts (phishing risk)",
                        "Renew the certificate now and automate future renewals")


def _exposed_path_attack(path: str):
    p = path.lower()
    if ".git" in p or ".env" in p or "config" in p:
        return ("Source code / credential disclosure", "Remove from the web root; block dotfiles in server config")
    if "backup" in p or p.endswith(".zip") or p.endswith(".bak"):
        return ("Full source or database leak via backup files", "Never store backups inside the public web root")
    if "admin" in p or "server-status" in p:
        return ("Reconnaissance for targeted admin-panel brute-force", "Restrict admin paths by IP/VPN; require MFA")
    return ("Information disclosure", "Remove or restrict public access to this path")


def _count_issues(results):
    n = len(results.get("headers", {}).get("missing", []))
    if "ssl" in results and not results["ssl"].get("has_valid_cert"):
        n += 1
    n += len(results.get("cookie_issues", []))
    n += len(results.get("exposed_paths", []))
    if results.get("directory_listing_enabled"):
        n += 1
    if results.get("banner", {}).get("discloses_version"):
        n += 1
    return n


PENTEST_NOTES = [
    "This is passive, automated reconnaissance — it reads what the server already exposes.",
    "It does NOT attempt SQL injection, XSS payloads, brute-forcing, or authentication bypass.",
    "A full penetration test adds authenticated testing, fuzzing (Burp Suite / OWASP ZAP), and manual business-logic review.",
    "Cross-reference findings against the OWASP Top 10 (owasp.org/Top10) for broader context.",
    "Always get written authorization before testing any system you don't own.",
]


class ScanPage(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=theme.BLACK)
        self.app = app
        self.net_rain = None
        self.vuln_rain = None

        ctk.CTkLabel(self, text="NEW SCAN", font=theme.F_TITLE, text_color=theme.GREEN).pack(
            anchor="w", padx=32, pady=(28, 4))
        self.limit_label = ctk.CTkLabel(self, text="", font=theme.F_SMALL, text_color=theme.GREEN_DIM,
                                         wraplength=1000, justify="left")
        self.limit_label.pack(anchor="w", padx=32, pady=(0, 10))

        # Custom tab selector — CTkTabview's built-in segmented button applies
        # one text color to every segment regardless of selection state, so
        # the selected (green) tab's text wasn't reliably visible. This
        # custom pair of buttons guarantees bold black text on the selected
        # tab and dim green text on the unselected one.
        tabs_container = ctk.CTkFrame(self, fg_color=theme.PANEL, corner_radius=4,
                                       border_width=1, border_color=theme.BORDER)
        tabs_container.pack(fill="both", expand=True, padx=32, pady=(0, 24))

        selector_row = ctk.CTkFrame(tabs_container, fg_color="transparent")
        selector_row.pack(fill="x", padx=12, pady=12)
        selector_row.grid_columnconfigure(0, weight=1)
        selector_row.grid_columnconfigure(1, weight=1)

        self.tab_buttons = {}
        self._make_tab_button(selector_row, "network", "NETWORK / PORT SCAN", column=0)
        self._make_tab_button(selector_row, "vuln", "WEBSITE VULNERABILITY AUDIT", column=1)

        content_area = ctk.CTkFrame(tabs_container, fg_color="transparent")
        content_area.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        network_tab = ctk.CTkFrame(content_area, fg_color="transparent")
        vuln_tab = ctk.CTkFrame(content_area, fg_color="transparent")
        self.tab_frames = {"network": network_tab, "vuln": vuln_tab}

        self._build_network_tab(network_tab)
        self._build_vuln_tab(vuln_tab)

        self._select_tab("network")

    def _make_tab_button(self, parent, key, label, column):
        btn = ctk.CTkButton(
            parent, text=label, font=theme.F_HEADER, height=48, corner_radius=4,
            fg_color=theme.PANEL_ALT, text_color=theme.GREEN_DIM, text_color_disabled=theme.GREEN_DIM,
            hover_color=theme.PANEL_ALT, command=lambda: self._select_tab(key),
        )
        btn.grid(row=0, column=column, sticky="ew", padx=4)
        self.tab_buttons[key] = btn

    def _select_tab(self, key):
        for k, btn in self.tab_buttons.items():
            if k == key:
                btn.configure(fg_color=theme.GREEN, text_color=theme.BLACK, hover_color=theme.GREEN_SOFT)
            else:
                btn.configure(fg_color=theme.PANEL_ALT, text_color=theme.GREEN_DIM, hover_color=theme.PANEL_ALT)
        for k, frame in self.tab_frames.items():
            if k == key:
                frame.pack(fill="both", expand=True)
            else:
                frame.pack_forget()

    def on_show(self):
        limits = self.app.current_plan_limits()
        user = self.app.auth.current_user
        used = user.get("scans_used_this_period", 0)
        cap = limits["scans_per_month"]
        cap_text = "unlimited" if cap is None else f"{used}/{cap} used this month"
        self.limit_label.configure(
            text=f"PLAN: {limits['label'].upper()}   •   SCANS: {cap_text}   •   "
                 f"PORT RANGE UP TO {limits['max_port']}   •   "
                 f"AUDIT DEPTH: {', '.join(limits['vuln_checks'])}"
        )

    def on_hide(self):
        # stop any in-flight rain animation cleanly if the user navigates away mid-scan
        if self.net_rain:
            self.net_rain.stop()
        if self.vuln_rain:
            self.vuln_rain.stop()

    def _scans_remaining(self):
        limits = self.app.current_plan_limits()
        cap = limits["scans_per_month"]
        if cap is None:
            return True
        used = self.app.auth.current_user.get("scans_used_this_period", 0)
        return used < cap

    def _record_scan_usage_and_save(self, scan_type, target, results, duration):
        user_id = str(self.app.auth.current_user["_id"])
        self.app.db.save_scan(user_id, scan_type, target, results, duration)
        self.app.db.increment_scan_usage(user_id)
        self.app.auth.refresh_current_user()
        self.on_show()

    # ---------------------------------------------------------------- #
    # Shared building blocks
    # ---------------------------------------------------------------- #
    def _entry(self, parent, placeholder, width=460):
        return ctk.CTkEntry(parent, placeholder_text=placeholder, width=width, height=42, font=theme.F_BODY,
                             fg_color=theme.PANEL_ALT, border_color=theme.BORDER, border_width=1,
                             text_color=theme.GREEN, placeholder_text_color=theme.TEXT_MUTED)

    def _primary_btn(self, parent, text, command):
        return ctk.CTkButton(parent, text=text, height=44, font=theme.F_BODY_BOLD, fg_color=theme.GREEN,
                              text_color=theme.BLACK, text_color_disabled=theme.BLACK,
                              hover_color=theme.GREEN_SOFT, command=command)

    def _outline_btn(self, parent, text, command, state="disabled"):
        return ctk.CTkButton(parent, text=text, height=40, font=theme.F_BODY_BOLD, fg_color="transparent",
                              text_color=theme.GREEN, border_width=1, border_color=theme.BORDER_BRIGHT,
                              hover_color=theme.PANEL_ALT, state=state, command=command)

    def _results_container(self, parent):
        return ctk.CTkScrollableFrame(parent, fg_color=theme.PANEL, corner_radius=4,
                                       border_width=1, border_color=theme.BORDER, height=420)

    def _clear(self, container):
        for w in container.winfo_children():
            w.destroy()

    def _placeholder(self, container, text):
        ctk.CTkLabel(container, text=text, font=theme.F_BODY, text_color=theme.GREEN_DIM).pack(pady=30)

    def _section(self, container, title):
        ctk.CTkLabel(container, text=title, font=theme.F_SUBHEADER, text_color=theme.GREEN).pack(
            anchor="w", padx=10, pady=(14, 6))

    def _show_scanning_animation(self, container):
        """
        Fills the results panel with a Matrix-rain 'hacking' animation while
        a scan/audit is running, instead of a plain 'in progress...' label.
        Purely a visual flourish — driven by the same widgets.py MatrixRain
        used on the login screen, not by any real scan progress signal
        (network_scanner.py / vuln_scanner.py don't expose incremental
        progress and are intentionally left untouched).
        """
        self._clear(container)
        rain = MatrixRain(container, font_size=14, speed_ms=45)
        rain.pack(fill="both", expand=True)
        rain.start()
        return rain

    # ---------------------------------------------------------------- #
    # Network / Port scan tab
    # ---------------------------------------------------------------- #
    def _build_network_tab(self, tab):
        form = ctk.CTkFrame(tab, fg_color="transparent")
        form.pack(fill="x", pady=16)
        self.net_target_entry = self._entry(form, "IP address or hostname you own/manage (e.g. scanme.nmap.org)")
        self.net_target_entry.pack(side="left", padx=(0, 10))
        self.net_scan_btn = self._primary_btn(form, "▶ START SCAN", self._start_network_scan)
        self.net_scan_btn.pack(side="left")

        self.net_status = ctk.CTkLabel(tab, text="", font=theme.F_BODY, text_color=theme.GREEN_DIM, anchor="w")
        self.net_status.pack(anchor="w", pady=(4, 2), fill="x")
        self.net_progress = ctk.CTkProgressBar(tab, mode="indeterminate", progress_color=theme.GREEN,
                                                fg_color=theme.PANEL_ALT, height=6)
        self.net_spinner = TerminalSpinner(self.net_status, NETWORK_PHASES)

        self.net_results = self._results_container(tab)
        self.net_results.pack(fill="both", expand=True, pady=12)
        self._placeholder(self.net_results, "Run a scan to see results here.")

        actions = ctk.CTkFrame(tab, fg_color="transparent")
        actions.pack(fill="x")
        self.net_download_btn = self._outline_btn(actions, "⬇ DOWNLOAD REPORT",
                                                    lambda: self._download_current("port_scan"))
        self.net_download_btn.pack(side="left")

    def _start_network_scan(self):
        target = self.net_target_entry.get().strip()
        if not target:
            messagebox.showwarning("Missing target", "Enter an IP address or hostname first.")
            return
        if not self._scans_remaining():
            messagebox.showinfo("Monthly limit reached",
                                 "You've used all your Free plan scans this month. Upgrade to Pro for unlimited scans.")
            return

        self.net_scan_btn.configure(state="disabled")
        self.net_download_btn.configure(state="disabled")
        self.net_progress.pack(fill="x", pady=(0, 4))
        self.net_progress.start()
        self.net_spinner.start()
        self.net_rain = self._show_scanning_animation(self.net_results)

        threading.Thread(target=self._run_network_scan_thread, args=(target,), daemon=True).start()

    def _run_network_scan_thread(self, target):
        limits = self.app.current_plan_limits()
        try:
            results = network_scanner.run_full_scan(target, limits)
            error = None
        except ValueError as e:
            results, error = None, str(e)
        self.after(0, lambda: self._finish_network_scan(target, results, error))

    def _finish_network_scan(self, target, results, error):
        self.net_progress.stop()
        self.net_progress.pack_forget()
        self.net_scan_btn.configure(state="normal")
        if self.net_rain:
            self.net_rain.stop()
            self.net_rain = None

        if error:
            self.net_spinner.stop(f"✗ {error}", theme.RED)
            self._clear(self.net_results)
            self._placeholder(self.net_results, f"✗ {error}")
            return

        status_text = f"✓ Done in {results['duration_seconds']}s — host is {'UP' if results['host_up'] else 'DOWN'}"
        self.net_spinner.stop(status_text, theme.GREEN if results["host_up"] else theme.RED)

        self._render_port_results(self.net_results, target, results)

        self._record_scan_usage_and_save("port_scan", target, results, results["duration_seconds"])

        limits = self.app.current_plan_limits()
        if limits["can_download_reports"]:
            self.net_download_btn.configure(state="normal", text="⬇ DOWNLOAD REPORT")
        else:
            self.net_download_btn.configure(state="disabled", text="⬇ DOWNLOAD (PRO ONLY)")

    def _render_port_results(self, container, target, results):
        self._clear(container)

        summary = ctk.CTkFrame(container, fg_color=theme.PANEL_ALT, corner_radius=4)
        summary.pack(fill="x", padx=10, pady=(10, 6))
        up = results["host_up"]
        badge_text, badge_color = ("● HOST UP", theme.GREEN) if up else ("● HOST DOWN", theme.RED)
        ctk.CTkLabel(summary, text=badge_text, font=theme.F_BODY_BOLD, text_color=badge_color).grid(
            row=0, column=0, sticky="w", padx=16, pady=12)
        ctk.CTkLabel(summary, text=f"{target}  ({results['resolved_ip']})", font=theme.F_BODY,
                     text_color=theme.GREEN_DIM).grid(row=0, column=1, sticky="w", padx=16, pady=12)
        ctk.CTkLabel(summary, text=f"{results['ports_scanned']} ports scanned  •  "
                                    f"{results['duration_seconds']}s", font=theme.F_SMALL,
                     text_color=theme.TEXT_MUTED).grid(row=0, column=2, sticky="e", padx=16, pady=12)
        summary.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(container, text=f"ℹ {PORT_SCAN_DISCLAIMER}", font=theme.F_SMALL, text_color=theme.TEXT_MUTED,
                     wraplength=760, justify="left").pack(anchor="w", padx=12, pady=(2, 12))

        if not results["open_ports"]:
            self._placeholder(container, "✓ No open ports found in the scanned range.")
            return

        counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "REVIEW": 0}
        for p in results["open_ports"]:
            info = PORT_DETAILS.get(p["port"], DEFAULT_PORT_INFO)
            counts[info["risk"]] += 1

        rollup = ctk.CTkFrame(container, fg_color="transparent")
        rollup.pack(anchor="w", padx=10, pady=(0, 10))
        ctk.CTkLabel(rollup, text=f"OPEN PORTS ({len(results['open_ports'])})", font=theme.F_SUBHEADER,
                     text_color=theme.GREEN).pack(side="left", padx=(0, 16))
        for level in RISK_ORDER:
            if counts[level]:
                ctk.CTkLabel(rollup, text=f"{counts[level]} {level}", font=theme.F_BADGE, text_color=theme.BLACK,
                             fg_color=RISK_COLOR[level], corner_radius=4, width=110, height=28).pack(
                    side="left", padx=4)

        for p in results["open_ports"]:
            self._port_row(container, p)

    def _port_row(self, container, p):
        info = PORT_DETAILS.get(p["port"], DEFAULT_PORT_INFO)
        impact = impact_knowledge.port_impact(p["port"])
        risk = info["risk"]
        risk_color = RISK_COLOR[risk]

        row = ctk.CTkFrame(container, fg_color=theme.PANEL_ALT, corner_radius=4)
        row.pack(fill="x", padx=10, pady=5)

        top = ctk.CTkFrame(row, fg_color="transparent")
        top.pack(fill="x", padx=16, pady=(12, 4))
        ctk.CTkLabel(top, text=str(p["port"]), font=theme.F_PORT, text_color=theme.GREEN, width=85).pack(side="left")
        name = info.get("name") or p["service"].upper()
        ctk.CTkLabel(top, text=name, font=theme.F_BODY_BOLD, text_color=theme.CYAN).pack(side="left", padx=(8, 0))
        ctk.CTkLabel(top, text=f"{risk} RISK", font=theme.F_BADGE, text_color=theme.BLACK, fg_color=risk_color,
                     corner_radius=4, width=120, height=32).pack(side="right")

        body = ctk.CTkFrame(row, fg_color="transparent")
        body.pack(fill="x", padx=16, pady=(0, 12))
        ctk.CTkLabel(body, text=info["desc"], font=theme.F_BODY, text_color=theme.GREEN_DIM, anchor="w",
                     wraplength=700, justify="left").pack(anchor="w")
        ctk.CTkLabel(body, text=f"⚔ Attack: {info['attack']}   🛡 Fix: {info['fix']}", font=theme.F_SMALL,
                     text_color=risk_color, anchor="w", wraplength=700, justify="left").pack(anchor="w", pady=(3, 0))
        if p["banner"]:
            ctk.CTkLabel(body, text=f"banner: {p['banner'][:80]}", font=theme.F_MONO_SMALL,
                         text_color=theme.TEXT_MUTED, anchor="w").pack(anchor="w", pady=(3, 0))
        self._impact_block(body, impact)

    # ---------------------------------------------------------------- #
    # Website vulnerability audit tab
    # ---------------------------------------------------------------- #
    def _build_vuln_tab(self, tab):
        form = ctk.CTkFrame(tab, fg_color="transparent")
        form.pack(fill="x", pady=16)
        self.vuln_target_entry = self._entry(form, "Website URL you own/manage (e.g. https://example.com)")
        self.vuln_target_entry.pack(side="left", padx=(0, 10))
        self.vuln_scan_btn = self._primary_btn(form, "▶ RUN AUDIT", self._start_vuln_scan)
        self.vuln_scan_btn.pack(side="left")

        self.vuln_status = ctk.CTkLabel(tab, text="", font=theme.F_BODY, text_color=theme.GREEN_DIM, anchor="w")
        self.vuln_status.pack(anchor="w", pady=(4, 2), fill="x")
        self.vuln_progress = ctk.CTkProgressBar(tab, mode="indeterminate", progress_color=theme.GREEN,
                                                 fg_color=theme.PANEL_ALT, height=6)
        self.vuln_spinner = TerminalSpinner(self.vuln_status, VULN_PHASES)

        self.vuln_results = self._results_container(tab)
        self.vuln_results.pack(fill="both", expand=True, pady=12)
        self._placeholder(self.vuln_results, "Run an audit to see results here.")

        actions = ctk.CTkFrame(tab, fg_color="transparent")
        actions.pack(fill="x")
        self.vuln_armor_btn = self._outline_btn(actions, "🛡 GENERATE ARMOR FILE",
                                               self._export_armor_script, state="disabled")
        self.vuln_armor_btn.pack(side="left", padx=(0, 10))
        self.vuln_download_btn = self._outline_btn(actions, "⬇ DOWNLOAD REPORT",
                                                     lambda: self._download_current("vuln_scan"))
        self.vuln_download_btn.pack(side="left")

    def _start_vuln_scan(self):
        url = self.vuln_target_entry.get().strip()
        if not url:
            messagebox.showwarning("Missing URL", "Enter a website URL first.")
            return
        if not self._scans_remaining():
            messagebox.showinfo("Monthly limit reached",
                                 "You've used all your Free plan scans this month. Upgrade to Pro for unlimited scans.")
            return

        self.vuln_scan_btn.configure(state="disabled")
        self.vuln_download_btn.configure(state="disabled")
        self.vuln_progress.pack(fill="x", pady=(0, 4))
        self.vuln_progress.start()
        self.vuln_spinner.start()
        self.vuln_rain = self._show_scanning_animation(self.vuln_results)

        threading.Thread(target=self._run_vuln_scan_thread, args=(url,), daemon=True).start()

    def _run_vuln_scan_thread(self, url):
        limits = self.app.current_plan_limits()
        results = vuln_scanner.run_audit(url, limits["vuln_checks"])
        self.after(0, lambda: self._finish_vuln_scan(url, results))

    def _finish_vuln_scan(self, url, results):
        self.vuln_progress.stop()
        self.vuln_progress.pack_forget()
        self.vuln_scan_btn.configure(state="normal")
        if self.vuln_rain:
            self.vuln_rain.stop()
            self.vuln_rain = None

        if results.get("error"):
            self.vuln_spinner.stop(f"✗ {results['error']}", theme.RED)
            self._clear(self.vuln_results)
            self._placeholder(self.vuln_results, f"✗ {results['error']}")
            return

        grade = results.get("grade", "N/A")
        self.vuln_spinner.stop(f"✓ Done in {results['duration_seconds']}s — Grade {grade}", theme.grade_color(grade))

        self._last_vuln_results = results
        self.vuln_armor_btn.configure(state="normal")
        self._render_vuln_results(self.vuln_results, results)

        self._record_scan_usage_and_save("vuln_scan", url, results, results["duration_seconds"])

        limits = self.app.current_plan_limits()
        if limits["can_download_reports"]:
            self.vuln_download_btn.configure(state="normal", text="⬇ DOWNLOAD REPORT")
        else:
            self.vuln_download_btn.configure(state="disabled", text="⬇ DOWNLOAD (PRO ONLY)")

    def _export_armor_script(self):
        if not getattr(self, "_last_vuln_results", None):
            return
        file_path = filedialog.asksaveasfilename(
            title="Save Glitch Hound armor file",
            defaultextension=".htaccess",
            filetypes=[("Apache config", "*.htaccess"), ("IIS config", "*.config"), ("Text file", "*.txt")],
            initialfile=".htaccess",
        )
        if not file_path:
            return
        server = "apache" if file_path.lower().endswith(".htaccess") else "iis"
        script = RiskPredictor.generate_armor_script(self._last_vuln_results, server=server)
        with open(file_path, "w", encoding="utf-8") as handle:
            handle.write(script)
        messagebox.showinfo("Armor file ready", f"Saved a browser-safe remediation file to:\n{file_path}")

    def _render_vuln_results(self, container, results):
        self._clear(container)
        self._impact_targets = {}

        header = ctk.CTkFrame(container, fg_color=theme.PANEL_ALT, corner_radius=4)
        header.pack(fill="x", padx=10, pady=(10, 14))
        left = ctk.CTkFrame(header, fg_color="transparent")
        left.pack(side="left", padx=16, pady=14, fill="x", expand=True)
        ctk.CTkLabel(left, text=results.get("final_url", results.get("target", "")), font=theme.F_BODY_BOLD,
                     text_color=theme.GREEN, anchor="w").pack(anchor="w")
        ctk.CTkLabel(left, text=f"HTTP {results.get('status_code', '—')}   •   "
                                 f"{_count_issues(results)} issue(s) found", font=theme.F_SMALL,
                     text_color=theme.GREEN_DIM, anchor="w").pack(anchor="w")

        grade = results.get("grade", "N/A")
        ctk.CTkLabel(header, text=grade, font=theme.F_GRADE, text_color=theme.grade_color(grade),
                     width=95).pack(side="right", padx=20, pady=6)

        self._section(container, "DIGITAL HOUSE VISUALIZER")
        house_panel = ctk.CTkFrame(container, fg_color=theme.PANEL_ALT, corner_radius=8,
                                  border_width=1, border_color=theme.BORDER)
        house_panel.pack(fill="x", padx=10, pady=(0, 10))

        house_left = ctk.CTkFrame(house_panel, fg_color="transparent")
        house_left.grid(row=0, column=0, padx=20, pady=18, sticky="nsew")
        house_right = ctk.CTkFrame(house_panel, fg_color="#1e1e1e", corner_radius=8)
        house_right.grid(row=0, column=1, padx=(0, 20), pady=18, sticky="nsew")
        house_panel.grid_columnconfigure(0, weight=1)
        house_panel.grid_columnconfigure(1, weight=0)

        ctk.CTkLabel(house_left, text="Digital House Visualizer", font=("Consolas", 20, "bold"),
                     text_color=theme.GREEN).grid(row=0, column=0, columnspan=2, pady=(0, 16))

        safe_color = theme.GREEN
        danger_color = theme.RED
        missing_headers = results.get("headers", {}).get("missing", []) if isinstance(results.get("headers"), dict) else []
        risky_ports = [int(item.get("port")) for item in results.get("open_ports", []) if isinstance(item, dict) and item.get("port") is not None]
        has_risky_port = any(port in {22, 3389} for port in risky_ports)
        dir_issue = bool(results.get("directory_listing_enabled"))
        ssl_issue = bool(results.get("ssl") and not results.get("ssl", {}).get("has_valid_cert"))
        cookie_issue = bool(results.get("cookie_issues"))
        exposed_paths = bool(results.get("exposed_paths"))

        roof = ctk.CTkLabel(
            house_left,
            text="▲",
            font=("Consolas", 40, "bold"),
            text_color=theme.GREEN,
            width=200,
            height=40,
        )
        roof.grid(row=1, column=0, columnspan=2, pady=(0, 0), sticky="ew")

        roof_banner = ctk.CTkLabel(
            house_left,
            text="SERVER: " + results.get("target", "example.com"),
            font=("Consolas", 13, "bold"),
            text_color=theme.BLACK,
            width=320,
            height=30,
            fg_color=theme.GREEN,
            corner_radius=8,
        )
        roof_banner.grid(row=2, column=0, columnspan=2, pady=(0, 10), sticky="ew")

        house_shape = ctk.CTkFrame(house_left, fg_color="transparent")
        house_shape.grid(row=3, column=0, columnspan=2, padx=6, pady=(0, 8), sticky="nsew")
        house_shape.grid_columnconfigure(0, weight=1)
        house_shape.grid_columnconfigure(1, weight=1)
        house_shape.grid_rowconfigure(0, weight=1)
        house_shape.grid_rowconfigure(1, weight=1)

        def make_window(label, state_color, text, row, col):
            frame = ctk.CTkFrame(
                house_shape,
                fg_color=theme.PANEL,
                border_width=2,
                border_color=state_color,
                corner_radius=10,
            )
            frame.grid(row=row, column=col, padx=6, pady=6, sticky="nsew")
            ctk.CTkLabel(frame, text=label, font=("Consolas", 12, "bold"), text_color=state_color).pack(pady=(10, 2))
            ctk.CTkLabel(frame, text=text, font=("Consolas", 11), text_color=theme.GREEN_DIM,
                         justify="center", wraplength=110).pack(pady=(0, 10))

        def make_door(label, state_color, text):
            frame = ctk.CTkFrame(
                house_shape,
                fg_color=theme.PANEL,
                border_width=2,
                border_color=state_color,
                corner_radius=12,
            )
            frame.grid(row=2, column=0, columnspan=2, padx=6, pady=8, sticky="nsew")
            ctk.CTkLabel(frame, text=label, font=("Consolas", 12, "bold"), text_color=state_color).pack(pady=(10, 2))
            ctk.CTkLabel(frame, text=text, font=("Consolas", 11), text_color=theme.GREEN_DIM,
                         justify="center", wraplength=220).pack(pady=(0, 10))

        window_state = danger_color if has_risky_port else safe_color
        dir_state = danger_color if dir_issue else safe_color
        ssl_state = danger_color if ssl_issue else safe_color
        roof_state = danger_color if missing_headers or cookie_issue or exposed_paths else safe_color

        make_window(
            "WINDOW",
            window_state,
            f"🔓 Open\n({len([p for p in risky_ports if p in {22, 3389}])} risky port(s))" if has_risky_port else "🔒 Locked\n(Ports Secured)",
            row=0,
            col=0,
        )
        make_window(
            "BLINDS",
            dir_state,
            "📂 Open\n(Directory Listing)" if dir_issue else "🪟 Closed\n(Files Hidden)",
            row=0,
            col=1,
        )
        make_door(
            "FRONT DOOR",
            ssl_state,
            "🚪 Unlocked\n(Missing SSL)" if ssl_issue else "🚪 Locked\n(Valid SSL)",
        )

        foundation = ctk.CTkFrame(house_shape, fg_color=theme.PANEL, border_width=2, border_color=roof_state,
                                  corner_radius=10)
        foundation.grid(row=3, column=0, columnspan=2, padx=6, pady=(0, 6), sticky="nsew")
        ctk.CTkLabel(foundation, text="ROOF", font=("Consolas", 12, "bold"), text_color=roof_state).pack(pady=(10, 2))
        ctk.CTkLabel(foundation, text="🏚 Leak\n(Missing headers)" if missing_headers else "🏠 Secure\n(All protections in place)",
                     font=("Consolas", 11), text_color=theme.GREEN_DIM,
                     justify="center", wraplength=220).pack(pady=(0, 10))

        ctk.CTkLabel(house_right, text="Security Translation", font=("Consolas", 16, "bold"),
                     text_color=theme.CYAN).pack(pady=(12, 8), padx=14, anchor="w")

        explanation = ""
        if ssl_issue:
            explanation += "⚠️ The front door is unlocked. Anyone on the internet can intercept data entering or leaving your site.\n\n"
        if has_risky_port:
            explanation += "⚠️ A ground-floor window is wide open. Attackers can bypass the website and target the server directly.\n\n"
        if dir_issue:
            explanation += "⚠️ Your filing cabinets are visible from the street. Internal files and backups are exposed.\n\n"
        if missing_headers:
            explanation += "⚠️ The roof has gaps: " + ", ".join(item.get("header", str(item)) for item in missing_headers[:3]) + ". These missing protections are leaving your site exposed.\n\n"
        if cookie_issue:
            explanation += "⚠️ Window locks are weak. Some cookies are missing Secure and HttpOnly protections.\n\n"
        if exposed_paths:
            explanation += "⚠️ Sensitive rooms are left open. Publicly reachable paths were detected.\n\n"
        if not explanation:
            explanation = "✅ Your digital house is fully secured. All entry points are locked."

        ctk.CTkLabel(house_right, text=explanation, justify="left", wraplength=220,
                     font=("Consolas", 13), text_color=theme.GREEN_DIM).pack(anchor="w", padx=14, pady=(0, 14))

        if "headers" in results:
            self._section(container, "SECURITY HEADERS")
            for h in results["headers"]["present"]:
                self._check_row(container, True, h, "")
            for h in results["headers"]["missing"]:
                impact_title = f"Missing header: {h['header']}"
                self._check_row(container, False, h["header"], h["why_it_matters"],
                                 attack_fix=HEADER_ATTACK_INFO.get(h["header"]),
                                 on_click=lambda title=impact_title: self._jump_to_impact(container, title))

        if "ssl" in results:
            self._section(container, "SSL / TLS CERTIFICATE")
            ssl_info = results["ssl"]
            if ssl_info.get("has_valid_cert"):
                days = ssl_info.get("days_until_expiry")
                warn = days is not None and days < 14
                label = f"Valid — issuer {ssl_info['issuer']}, expires {ssl_info['expires']} ({days} days left)"
                self._check_row(container, not warn, "Certificate", "", override_text=label,
                                 attack_fix=SSL_EXPIRING_ATTACK if warn else None)
            else:
                self._check_row(container, False, "Certificate",
                                 ssl_info.get("error", "Could not verify certificate."),
                                 attack_fix=SSL_INVALID_ATTACK)

        if "email_trust" in results:
            self._section(container, "DNS EMAIL TRUST SHIELD")
            email_trust = results["email_trust"]
            if email_trust.get("status") != "ok":
                self._check_row(
                    container,
                    False,
                    "Email trust check unavailable",
                    email_trust.get("error", "DNS records could not be checked."),
                )
            else:
                spf_details = "; ".join(email_trust.get("spf_details", [])) or "No SPF TXT record found."
                dmarc_details = "; ".join(email_trust.get("dmarc_details", [])) or "No DMARC TXT record found."
                self._check_row(container, email_trust.get("spf_record", False), "SPF record", spf_details)
                self._check_row(container, email_trust.get("dmarc_record", False), "DMARC record", dmarc_details)

        if "cookie_issues" in results:
            self._section(container, "COOKIE FLAGS")
            if results["cookie_issues"]:
                for c in results["cookie_issues"]:
                    attack_fix = COOKIE_ATTACK_INFO.get(c["missing_flags"][0])
                    self._check_row(container, False, c["cookie"], f"missing: {', '.join(c['missing_flags'])}",
                                     attack_fix=attack_fix)
            else:
                self._check_row(container, True, "All cookies", "Secure / HttpOnly flags look good.")

        if "exposed_paths" in results:
            self._section(container, "EXPOSED SENSITIVE PATHS")
            if results["exposed_paths"]:
                for p in results["exposed_paths"]:
                    self._check_row(container, False, p["path"], f"HTTP {p['status_code']} — publicly reachable",
                                     attack_fix=_exposed_path_attack(p["path"]))
            else:
                self._check_row(container, True, "No exposed paths",
                                 "None of the commonly checked paths were reachable.")

        if "directory_listing_enabled" in results:
            self._section(container, "DIRECTORY LISTING")
            enabled = results["directory_listing_enabled"]
            self._check_row(container, not enabled, "Directory listing",
                             "Listing is enabled — this can leak file structure." if enabled else "Disabled.",
                             attack_fix=DIRLIST_ATTACK if enabled else None)

        if "banner" in results:
            b = results["banner"]
            self._section(container, "SERVER BANNER")
            server = b.get("server_header") or "not disclosed"
            discloses = b.get("discloses_version")
            self._check_row(container, not discloses, f"Server: {server}",
                             "Discloses version info — consider hiding it." if discloses else "",
                             attack_fix=BANNER_ATTACK if discloses else None)

        self._render_pentest_notes(container)
        findings = impact_knowledge.vuln_findings(results)
        if findings:
            self._section(container, "IMPACT, DATA AND RESPONSE GUIDE")
            for finding in findings:
                self._impact_block(container, finding["details"], finding["title"])

    def _check_row(self, container, is_good, label, detail, override_text=None, attack_fix=None, on_click=None):
        icon, color = ("✓", theme.GREEN) if is_good else ("✗", theme.RED)
        row = ctk.CTkFrame(container, fg_color=theme.PANEL_ALT, corner_radius=4)
        row.pack(fill="x", padx=10, pady=3)

        ctk.CTkLabel(row, text=icon, font=theme.F_HEADER, text_color=color, width=36).pack(
            side="left", padx=(14, 4), pady=10)

        text_frame = ctk.CTkFrame(row, fg_color="transparent")
        text_frame.pack(side="left", fill="x", expand=True, padx=(0, 14), pady=10)
        ctk.CTkLabel(text_frame, text=override_text or label, font=theme.F_BODY_BOLD,
                     text_color=theme.GREEN if is_good else theme.GREEN_DIM, anchor="w",
                     wraplength=700, justify="left").pack(anchor="w")
        if detail:
            ctk.CTkLabel(text_frame, text=detail, font=theme.F_SMALL,
                         text_color=theme.AMBER if not is_good else theme.TEXT_MUTED, anchor="w",
                         wraplength=700, justify="left").pack(anchor="w")
        if attack_fix and not is_good:
            attack, fix = attack_fix
            ctk.CTkLabel(text_frame, text=f"⚔ Attack: {attack}   🛡 Fix: {fix}", font=theme.F_SMALL,
                         text_color=theme.RED, anchor="w", wraplength=700, justify="left").pack(
                anchor="w", pady=(3, 0))
        if on_click:
            row.configure(cursor="hand2")
            self._bind_click(row, on_click)
            self._bind_click(text_frame, on_click)

    def _impact_block(self, parent, impact, title=None):
        box = ctk.CTkFrame(parent, fg_color=theme.BLACK, corner_radius=3,
                           border_width=1, border_color=theme.BORDER)
        box.pack(fill="x", pady=(8, 0))
        if title:
            self._impact_targets[title] = box
            ctk.CTkLabel(box, text=title, font=theme.F_BODY_BOLD, text_color=theme.CYAN,
                         anchor="w", wraplength=700, justify="left").pack(anchor="w", padx=10, pady=(8, 3))
        fields = [
            ("WHAT", impact["what"]),
            ("WHY IT HAPPENS", impact["why"]),
            ("IMPACT", impact["impact"]),
            ("DATA AT RISK", impact["data"]),
            ("MONEY / RECOVERY", impact["money"]),
            ("AFTER AN ATTACK", impact["response"]),
            ("POSSIBLE FIXES", " | ".join(impact["fixes"])),
        ]
        for label, value in fields:
            ctk.CTkLabel(box, text=f"{label}: {value}", font=theme.F_IMPACT, text_color=theme.GREEN_DIM,
                         anchor="w", wraplength=700, justify="left").pack(anchor="w", padx=10, pady=2)
        ctk.CTkLabel(box, text=" ").pack(pady=(0, 3))

    def _bind_click(self, widget, command):
        widget.bind("<Button-1>", lambda _event: command())

    def _jump_to_impact(self, container, title):
        target = self._impact_targets.get(title)
        if not target:
            return
        container.update_idletasks()
        content_height = max(container._parent_frame.winfo_height(), 1)
        position = max(0.0, min(1.0, target.winfo_y() / content_height))
        container._parent_canvas.yview_moveto(position)
        target.configure(border_color=theme.GREEN, border_width=2)
        self.after(900, lambda: target.configure(border_color=theme.BORDER, border_width=1))

    def _render_pentest_notes(self, container):
        box = ctk.CTkFrame(container, fg_color=theme.PANEL_ALT, corner_radius=4,
                            border_width=1, border_color=theme.CYAN)
        box.pack(fill="x", padx=10, pady=(18, 10))
        ctk.CTkLabel(box, text="ℹ PENETRATION TESTING NOTES", font=theme.F_SUBHEADER, text_color=theme.CYAN).pack(
            anchor="w", padx=16, pady=(14, 6))
        for note in PENTEST_NOTES:
            ctk.CTkLabel(box, text=f"•  {note}", font=theme.F_SMALL, text_color=theme.GREEN_DIM, anchor="w",
                         wraplength=740, justify="left").pack(anchor="w", padx=16, pady=2)
        ctk.CTkLabel(box, text=" ").pack(pady=(0, 4))

    # ---------------------------------------------------------------- #
    # Shared
    # ---------------------------------------------------------------- #
    def _download_current(self, scan_type):
        user_id = str(self.app.auth.current_user["_id"])
        scans = self.app.db.get_scans_for_user(user_id)
        matching = [s for s in scans if s["scan_type"] == scan_type]
        if not matching:
            return
        from gui.history_page import prompt_and_export
        prompt_and_export(self, self.app, matching[0])
