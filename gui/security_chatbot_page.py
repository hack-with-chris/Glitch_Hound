import re

import customtkinter as ctk

from gui import theme
from scanner import impact_knowledge


CHAT_TOPICS = {
    "ransomware": {
        "keywords": ("ransomware", "encrypted files", "files encrypted"),
        "title": "Ransomware response",
        "answer": "Ransomware encrypts files or systems so the attacker can demand payment. Do not pay or reconnect infected devices automatically.",
        "steps": [
            "Disconnect the affected computer from Wi-Fi and wired networks, but do not turn it off if your incident-response team needs its memory.",
            "Stop shared-drive access and isolate other devices that show the same symptoms.",
            "Contact your IT administrator, managed security provider, or local cybercrime authority.",
            "Preserve ransom notes, timestamps, suspicious emails, and logs. Do not delete evidence.",
            "Recover from a clean, tested offline backup only after the entry point is closed and systems are patched.",
            "Reset credentials and enable MFA after checking that attacker accounts and remote tools are removed.",
        ],
        "next": "After recovery, test backups regularly and restrict SMB/RDP access to trusted networks.",
    },
    "phishing": {
        "keywords": ("phishing", "fake email", "suspicious email", "scam link", "phishing link"),
        "title": "Phishing protection",
        "answer": "Phishing is a fake message or website designed to make you reveal credentials, payment details, or one-time codes.",
        "steps": [
            "Do not click further links, download attachments, or reply. Open the real service using a known bookmark.",
            "If you entered a password, change it immediately from the real website and change it anywhere else you reused it.",
            "Revoke unknown sessions, review mailbox forwarding rules, and contact your bank if payment data was entered.",
            "Report the message to your email provider or organization and preserve the original message headers.",
            "Turn on MFA, preferably with an authenticator app or security key.",
        ],
        "next": "Check the sender address carefully and verify urgent requests through a separate trusted channel.",
    },
    "website_hacked": {
        "keywords": ("website hacked", "website was hacked", "my website hacked", "site hacked", "web site hacked", "website attack", "defaced"),
        "title": "Website compromise response",
        "answer": "Treat an altered or suspicious website as a possible compromise. The priority is containment, evidence, and safe recovery.",
        "steps": [
            "Put the website into maintenance mode or restrict it to administrators. Do not overwrite logs.",
            "Take a clean snapshot of files, database, server logs, and the timeline of changes.",
            "Rotate hosting, CMS, database, API, SSH, and deployment credentials from a clean device.",
            "Find and remove unauthorized users, scheduled jobs, plugins, web shells, and changed files.",
            "Patch the CMS, framework, server, and plugins. Restore known-clean files and verify database integrity.",
            "Bring the site back gradually, monitor requests, and notify affected users if data may have been accessed.",
        ],
        "next": "Run a fresh vulnerability audit after recovery and keep automatic backups outside the web root.",
    },
    "sql_injection": {
        "keywords": ("sql injection", "prevent sql injection", "database injection", "sql attack"),
        "title": "SQL injection protection",
        "answer": "SQL injection happens when untrusted input is joined into a database query as SQL code. An attacker may read, change, or delete data, bypass login checks, or sometimes reach the server. It is prevented in application code and database permissions, not by a security header alone.",
        "steps": [
            "Replace string-built SQL with parameterized queries or prepared statements. Treat user input as a value, never as part of the SQL command.",
            "Use the database access layer provided by your framework or ORM correctly. Do not build query strings by concatenating form fields, URL parameters, cookies, or headers.",
            "Validate input using allow-lists and correct types, such as an integer ID or an approved sort-field name. Validation is helpful, but it is not a replacement for parameterized queries.",
            "Give the application database account only the permissions it needs. Do not run the website as a database administrator, and separate read and write accounts where practical.",
            "Do not show database errors, SQL statements, connection strings, or stack traces to visitors. Log detailed errors privately and return a general error message.",
            "Keep the framework, database driver, ORM, and database server patched. Review dependencies and remove unused database features.",
            "Test authorized staging systems with code review, unit tests, and a reputable DAST tool such as OWASP ZAP. Never test a system without permission.",
        ],
        "next": "If exploitation is suspected, restrict the affected endpoint, preserve logs, rotate database credentials, review database access, and assess whether data was read or changed.",
    },
    "secure_website": {
        "keywords": ("secure website", "protect website", "protect my website", "website security", "web security", "secure my site"),
        "title": "Website hardening plan",
        "answer": "Website security is layered: reduce exposure, protect accounts, keep software current, and monitor for changes.",
        "steps": [
            "Force HTTPS with a valid certificate and enable HSTS after confirming every important page works over HTTPS.",
            "Update the CMS, framework, plugins, operating system, and dependencies. Remove unused components.",
            "Use MFA for administrators, unique passwords, least privilege, and a separate admin account.",
            "Add security headers such as Content-Security-Policy, X-Content-Type-Options, and a suitable frame policy.",
            "Keep secrets and backups outside the public web folder. Block .env, .git, backup, and directory-listing access.",
            "Enable logging, alert on unusual admin activity, and test clean backups before an emergency.",
        ],
        "next": "Run the Website Vulnerability Audit in New Scan to check the controls this assistant describes.",
    },
    "secure_network": {
        "keywords": ("secure network", "protect network", "protect my network", "network security", "home wifi", "secure wifi", "router"),
        "title": "Network hardening plan",
        "answer": "A safer network exposes fewer services, uses strong access controls, and separates important devices.",
        "steps": [
            "Update the router, firewall, computers, phones, cameras, and other connected devices.",
            "Replace default administrator and Wi-Fi passwords with long, unique passwords and enable WPA2/WPA3.",
            "Disable remote administration, UPnP, Telnet, and services you do not use.",
            "Put guest and smart-home devices on a separate guest network when possible.",
            "Allow management services such as SSH or RDP only through a VPN or approved internal addresses.",
            "Review open ports periodically and keep offline backups of important files.",
        ],
        "next": "Use Network / Port Scan only on systems you own or are authorized to test.",
    },
    "password": {
        "keywords": ("password", "strong password", "account security", "mfa", "2fa", "two factor"),
        "title": "Account protection",
        "answer": "Strong account protection combines a unique password with multi-factor authentication and recovery controls.",
        "steps": [
            "Use a password manager to create a different long password for every important account.",
            "Enable MFA, prioritizing email, banking, hosting, domain, administrator, and password-manager accounts.",
            "Review active sessions, recovery email addresses, forwarding rules, and connected applications.",
            "Never share OTP codes or approve an MFA prompt you did not start.",
            "Store recovery codes offline and update your recovery contact details.",
        ],
        "next": "Start with your email account because it can be used to reset many other accounts.",
    },
    "open_port": {
        "keywords": ("open port", "port open", "close port", "rdp", "ssh", "smb", "database exposed"),
        "title": "Open-port guidance",
        "answer": "An open port means a service answered a connection. It is not proof that the service was hacked, but unnecessary exposure increases risk.",
        "steps": [
            "Identify the service and confirm that it is required. Do not close a business-critical service without checking its owner.",
            "Restrict the port with a firewall to trusted IP addresses, a private network, or a VPN.",
            "Update the service and disable password login or enable MFA where supported.",
            "Review authentication and application logs for unusual access.",
            "Close the port and remove the service if it is not needed, then scan again to verify.",
        ],
        "next": "A port scan checks exposure only; it does not prove weak credentials or exploitability.",
    },
    "security_headers": {
        "keywords": ("security header", "security headers", "csp", "content security policy", "hsts", "clickjacking"),
        "title": "Security headers",
        "answer": "Security headers tell browsers how to handle your website. They reduce common browser attacks but do not replace secure code, patching, or access controls.",
        "steps": [
            "Serve the website through a valid HTTPS certificate and redirect HTTP to HTTPS.",
            "Add Strict-Transport-Security after confirming HTTPS works on every required subdomain.",
            "Create a tested Content-Security-Policy that allows only the scripts, styles, images, and connections the site needs.",
            "Add X-Content-Type-Options: nosniff and a frame policy such as frame-ancestors in CSP to reduce content injection and clickjacking.",
            "Set Referrer-Policy and Permissions-Policy to limit unnecessary information and browser capabilities.",
            "Test headers in staging first, then retest the production site and monitor browser reports where available.",
        ],
        "next": "The vulnerability audit identifies missing headers and explains the specific risk of each one.",
    },
    "data_breach": {
        "keywords": ("data breach", "data stolen", "data leaked", "breached", "personal data exposed", "database leaked"),
        "title": "Data-breach response",
        "answer": "A data breach means information may have been accessed, changed, or taken without permission. Confirm the facts carefully and avoid guessing what was exposed.",
        "steps": [
            "Contain the suspected access by disabling affected accounts, restricting the service, and preserving logs and system images.",
            "Create an incident timeline and identify which systems, time period, and data types may be involved.",
            "Rotate exposed passwords, API keys, tokens, database credentials, and encryption keys from a clean device.",
            "Have legal, privacy, and security professionals determine notification duties under the applicable laws and contracts.",
            "Notify affected people with confirmed facts, protective actions, and a trusted contact channel. Do not include secret information in the notice.",
            "Patch the entry point, remove persistence, monitor for misuse, and document lessons learned.",
        ],
        "next": "Do not claim that no data was accessed merely because you found no evidence; logs may be incomplete.",
    },
}


class SecurityChatbotPage(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=theme.BLACK)
        self.app = app
        self._build_ui()

    def _build_ui(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=32, pady=(28, 10))
        ctk.CTkLabel(header, text="SECURITY ASSISTANT", font=theme.F_TITLE,
                     text_color=theme.GREEN).pack(anchor="w")
        ctk.CTkLabel(header, text="Plain-language, step-by-step guidance for protecting networks and websites.",
                     font=theme.F_BODY, text_color=theme.GREEN_DIM).pack(anchor="w", pady=(3, 0))
        ctk.CTkLabel(header, text="● LOCAL SECURITY KNOWLEDGE BASE  /  NO DATA SENT TO AN ONLINE CHAT SERVICE",
                 font=theme.F_SMALL, text_color=theme.CYAN).pack(anchor="w", pady=(8, 0))

        self.chat_frame = ctk.CTkScrollableFrame(self, fg_color=theme.PANEL, corner_radius=4,
                                                  border_width=1, border_color=theme.BORDER)
        self.chat_frame.pack(fill="both", expand=True, padx=32, pady=(0, 12))

        suggestions = ctk.CTkFrame(self, fg_color=theme.PANEL_ALT, corner_radius=4,
                       border_width=1, border_color=theme.BORDER)
        suggestions.pack(fill="x", padx=32, pady=(0, 8))
        ctk.CTkLabel(suggestions, text="QUICK TOPICS", font=theme.F_SMALL,
                 text_color=theme.TEXT_MUTED).pack(side="left", padx=(12, 8))
        for label, prompt in (("WEBSITE", "How do I secure my website?"),
                      ("NETWORK", "How do I secure my network?"),
                      ("SQL INJECTION", "How do I secure my website from SQL injection?"),
                      ("INCIDENT", "What should I do if my website is hacked?"),
                      ("LATEST SCAN", "Explain my latest scan")):
            ctk.CTkButton(suggestions, text=label, height=30, font=theme.F_BADGE,
                  fg_color="transparent", text_color=theme.CYAN,
                  border_width=1, border_color=theme.BORDER,
                  hover_color=theme.BLACK,
                  command=lambda p=prompt: self._ask(p)).pack(side="left", padx=3, pady=7)

        composer = ctk.CTkFrame(self, fg_color="transparent")
        composer.pack(fill="x", padx=32, pady=(0, 24))
        self.input_entry = ctk.CTkEntry(composer, height=44, font=theme.F_BODY,
                                        placeholder_text="Ask how to protect a network, website, account, or scan finding...",
                                        fg_color=theme.PANEL_ALT, border_color=theme.BORDER,
                                        text_color=theme.GREEN, placeholder_text_color=theme.TEXT_MUTED)
        self.input_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.input_entry.bind("<Return>", lambda _event: self._ask())
        ctk.CTkButton(composer, text="▶ ASK", width=110, height=44, font=theme.F_BODY_BOLD,
                      fg_color=theme.GREEN, text_color=theme.BLACK,
                      hover_color=theme.GREEN_SOFT, command=self._ask).pack(side="right")

        self._add_message("assistant", "Hello. Ask me about protecting a website, network, account, or responding to an attack. I give practical steps and clearly state when a question needs a security professional.")

    def on_show(self):
        self.input_entry.focus_set()

    def _ask(self, question=None):
        question = (question if question is not None else self.input_entry.get()).strip()
        if not question:
            return
        self.input_entry.delete(0, "end")
        self._add_message("you", question)
        self._add_message("assistant", self._answer(question))

    def _answer(self, question):
        normalized = re.sub(r"[^a-z0-9 ]", " ", question.lower())
        if "latest scan" in normalized or "my scan" in normalized or "scan result" in normalized:
            return self._latest_scan_answer()

        if "sql injection" in normalized or ("sql" in normalized and "injection" in normalized):
            details = CHAT_TOPICS["sql_injection"]
            lines = [details["title"].upper(), details["answer"], "", "STEP-BY-STEP:"]
            lines.extend(f"{index}. {step}" for index, step in enumerate(details["steps"], 1))
            lines.extend(["", f"NEXT: {details['next']}"])
            return "\n".join(lines)

        topic = None
        best_score = 0
        for candidate, details in CHAT_TOPICS.items():
            score = sum(1 for keyword in details["keywords"] if keyword in normalized)
            if score > best_score:
                topic, best_score = candidate, score
        if not topic:
            return ("I can give reliable guidance about website hardening, network and Wi-Fi security, open ports, "
                    "passwords/MFA, phishing, ransomware, website compromise, and your latest scan. "
                    "Please ask one of those specific questions.")

        details = CHAT_TOPICS[topic]
        lines = [details["title"].upper(), details["answer"], "", "STEP-BY-STEP:"]
        lines.extend(f"{index}. {step}" for index, step in enumerate(details["steps"], 1))
        lines.extend(["", f"NEXT: {details['next']}"])
        return "\n".join(lines)

    def _latest_scan_answer(self):
        user = self.app.auth.current_user
        if not user:
            return "Please sign in before asking about saved scans."
        scans = self.app.db.get_scans_for_user(str(user["_id"]))
        if not scans:
            return "There is no saved scan yet. Run a Website Vulnerability Audit or Network / Port Scan, then ask me to explain your latest scan."

        scan = scans[0]
        results = scan.get("results", {})
        lines = [f"LATEST {scan['scan_type'].replace('_', ' ').upper()}", f"Target: {scan.get('target', 'unknown')}"]
        if scan["scan_type"] == "vuln_scan":
            findings = impact_knowledge.vuln_findings(results)
            lines.append(f"Grade: {results.get('grade', 'N/A')} | Findings: {len(findings)}")
            if not findings:
                lines.append("No failing findings were saved in this scan. Keep patching, monitoring, and retest regularly.")
            else:
                lines.append("Priorities:")
                for finding in findings[:5]:
                    lines.append(f"- {finding['title']}: {finding['details']['impact']}")
                lines.append("\nNext steps:")
                lines.append("1. Address exposed files, authentication, or transport issues first.")
                lines.append("2. Apply the possible fixes shown in the scan impact guide.")
                lines.append("3. Run the audit again and review server logs for suspicious activity.")
        else:
            findings = impact_knowledge.port_findings(results)
            lines.append(f"Open ports: {len(findings)}")
            if not findings:
                lines.append("No open ports were found in the scanned range. Keep firewall rules and devices updated.")
            else:
                lines.append("Priorities:")
                for finding in findings[:5]:
                    lines.append(f"- {finding['title']}: {finding['details']['impact']}")
                lines.append("\nNext steps:")
                lines.append("1. Confirm every open service is required.")
                lines.append("2. Restrict administration and databases to VPN or trusted addresses.")
                lines.append("3. Close unnecessary ports and scan again.")
        return "\n".join(lines)

    def _add_message(self, sender, text):
        is_assistant = sender == "assistant"
        row = ctk.CTkFrame(self.chat_frame, fg_color=theme.PANEL_ALT if is_assistant else theme.BLACK,
                           corner_radius=5, border_width=1,
                           border_color=theme.CYAN if is_assistant else theme.BORDER_BRIGHT)
        left_pad = 8 if is_assistant else 150
        right_pad = 150 if is_assistant else 8
        row.pack(fill="x", padx=(left_pad, right_pad), pady=5)
        label = "SECURITY ASSISTANT" if is_assistant else "YOU"
        label_color = theme.CYAN if is_assistant else theme.GREEN
        ctk.CTkLabel(row, text=label, font=theme.F_BADGE,
                     text_color=label_color).pack(anchor="w", padx=14, pady=(9, 2))
        ctk.CTkLabel(row, text=text, font=theme.F_BODY,
                     text_color=theme.GREEN if is_assistant else theme.GREEN_DIM,
                     anchor="w", justify="left", wraplength=760).pack(anchor="w", padx=14, pady=(0, 12))
        self.chat_frame.update_idletasks()
        self.chat_frame._parent_canvas.yview_moveto(1.0)