from tkinter import filedialog, messagebox

import customtkinter as ctk

from utils import report_generator
from gui import theme


def prompt_and_export(widget, app, scan_doc):
    """Shared by ScanPage and HistoryPage so both 'Download' buttons behave identically."""
    limits = app.current_plan_limits()
    if not limits["can_download_reports"]:
        messagebox.showinfo("Pro feature", "Downloading reports is available on the Pro plan.")
        return

    fmt = FormatDialog(widget, limits["report_formats"]).show()
    if not fmt:
        return

    safe_target = scan_doc["target"].replace("://", "_").replace("/", "_").replace(":", "_")
    default_name = f"{scan_doc['scan_type']}_{safe_target}.{fmt}"
    filepath = filedialog.asksaveasfilename(
        defaultextension=f".{fmt}", initialfile=default_name, filetypes=[(fmt.upper(), f"*.{fmt}")]
    )
    if not filepath:
        return

    try:
        report_generator.export(scan_doc, fmt, filepath)
        messagebox.showinfo("Report saved", f"Saved to:\n{filepath}")
    except Exception as e:
        messagebox.showerror("Export failed", str(e))


class FormatDialog(ctk.CTkToplevel):
    """Small modal that asks which format to export as."""

    def __init__(self, parent, formats):
        super().__init__(parent)
        self.title("Choose format")
        self.geometry("300x220")
        self.configure(fg_color=theme.PANEL)
        self.resizable(False, False)
        self.result = None
        self.grab_set()

        ctk.CTkLabel(self, text="EXPORT AS:", font=theme.F_SUBHEADER, text_color=theme.GREEN).pack(pady=(18, 10))
        for fmt in formats:
            ctk.CTkButton(self, text=fmt.upper(), width=180, font=theme.F_BODY_BOLD,
                          fg_color=theme.GREEN, text_color=theme.BLACK, hover_color=theme.GREEN_SOFT,
                          command=lambda f=fmt: self._choose(f)).pack(pady=5)

    def _choose(self, fmt):
        self.result = fmt
        self.destroy()

    def show(self):
        self.wait_window()
        return self.result


class HistoryPage(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=theme.BLACK)
        self.app = app

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=32, pady=(28, 10))
        ctk.CTkLabel(header, text="SCAN HISTORY", font=theme.F_TITLE, text_color=theme.GREEN).pack(anchor="w")
        self.info_label = ctk.CTkLabel(header, text="", font=theme.F_BODY, text_color=theme.GREEN_DIM)
        self.info_label.pack(anchor="w", pady=(2, 0))

        self.list_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.list_frame.pack(fill="both", expand=True, padx=32, pady=(0, 24))

    def on_show(self):
        self.refresh()

    def refresh(self):
        for w in self.list_frame.winfo_children():
            w.destroy()

        user = self.app.auth.current_user
        limits = self.app.current_plan_limits()
        user_id = str(user["_id"])
        all_scans = self.app.db.get_scans_for_user(user_id)

        visible_cap = limits["history_visible"]
        visible = all_scans if visible_cap is None else all_scans[:visible_cap]

        if visible_cap is not None and len(all_scans) > visible_cap:
            self.info_label.configure(
                text=f"Showing your {visible_cap} most recent scans — upgrade to Pro to see full history "
                     f"({len(all_scans)} total)."
            )
        else:
            self.info_label.configure(text=f"{len(all_scans)} total scan(s).")

        if not visible:
            ctk.CTkLabel(self.list_frame, text="No scans yet — run your first scan to see it here.",
                         font=theme.F_BODY, text_color=theme.GREEN_DIM).pack(pady=30)
            return

        for scan in visible:
            self._build_row(scan, limits)

    def _build_row(self, scan, limits):
        row = ctk.CTkFrame(self.list_frame, fg_color=theme.PANEL, corner_radius=4,
                            border_width=1, border_color=theme.BORDER)
        row.pack(fill="x", pady=6)

        icon = "🌐" if scan["scan_type"] == "vuln_scan" else "🔌"
        type_label = "WEBSITE AUDIT" if scan["scan_type"] == "vuln_scan" else "PORT SCAN"
        summary, summary_color = self._summary(scan)

        left = ctk.CTkFrame(row, fg_color="transparent")
        left.pack(side="left", fill="x", expand=True, padx=16, pady=12)
        ctk.CTkLabel(left, text=f"{icon}  {scan['target']}", font=theme.F_BODY_BOLD,
                     text_color=theme.GREEN, anchor="w").pack(anchor="w")
        meta_row = ctk.CTkFrame(left, fg_color="transparent")
        meta_row.pack(anchor="w", pady=(4, 0))
        ctk.CTkLabel(meta_row, text=f"{type_label}", font=theme.F_SMALL, text_color=theme.CYAN).pack(side="left")
        ctk.CTkLabel(meta_row, text=f"  •  {scan['created_at'].strftime('%b %d, %Y %H:%M')}  •  ",
                     font=theme.F_SMALL, text_color=theme.GREEN_DIM).pack(side="left")
        ctk.CTkLabel(meta_row, text=summary, font=theme.F_SMALL, text_color=summary_color).pack(side="left")

        right = ctk.CTkFrame(row, fg_color="transparent")
        right.pack(side="right", padx=16)

        dl_text = "⬇ DOWNLOAD" if limits["can_download_reports"] else "⬇ PRO ONLY"
        ctk.CTkButton(right, text=dl_text, width=130, font=theme.F_SMALL, fg_color="transparent",
                      text_color=theme.GREEN, border_width=1, border_color=theme.BORDER_BRIGHT,
                      hover_color=theme.PANEL_ALT,
                      command=lambda s=scan: prompt_and_export(self, self.app, s)).pack(side="left", padx=4)
        ctk.CTkButton(right, text="🗑", width=38, fg_color="transparent", text_color=theme.RED,
                      border_width=1, border_color=theme.RED, hover_color=theme.PANEL_ALT,
                      command=lambda s=scan: self._delete(s)).pack(side="left", padx=4)

    def _summary(self, scan):
        results = scan.get("results", {})
        if scan["scan_type"] == "port_scan":
            n = len(results.get("open_ports", []))
            color = theme.AMBER if n > 0 else theme.GREEN
            return f"{n} open port(s)", color
        grade = results.get("grade", "N/A")
        return f"Grade {grade}", theme.grade_color(grade)

    def _delete(self, scan):
        if messagebox.askyesno("Delete scan", "Remove this scan from your history? This can't be undone."):
            self.app.db.delete_scan(str(scan["_id"]), str(self.app.auth.current_user["_id"]))
            self.refresh()
