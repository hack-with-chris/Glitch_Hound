"""
Generates downloadable scan reports. Pro-plan feature.
Supports PDF (reportlab), CSV, and JSON.
"""
import csv
import json
from html import escape
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import inch
from scanner import impact_knowledge


def _flatten_for_csv(scan_doc: dict) -> list:
    rows = [["Field", "Value"]]
    rows.append(["Scan Type", scan_doc.get("scan_type", "")])
    rows.append(["Target", scan_doc.get("target", "")])
    rows.append(["Date", str(scan_doc.get("created_at", ""))])
    rows.append(["Duration (s)", scan_doc.get("duration_seconds", "")])

    results = scan_doc.get("results", {})
    if scan_doc.get("scan_type") == "port_scan":
        rows.append([])
        rows.append(["Open Port", "Service", "Banner"])
        for p in results.get("open_ports", []):
            rows.append([p.get("port"), p.get("service"), p.get("banner", "")[:60]])
    else:
        rows.append([])
        rows.append(["Grade", results.get("grade", "")])
        for header in results.get("headers", {}).get("missing", []):
            rows.append(["Missing Header", header.get("header")])
        for path in results.get("exposed_paths", []):
            rows.append(["Exposed Path", path.get("path")])

    return rows


def export_csv(scan_doc: dict, filepath: str):
    rows = _flatten_for_csv(scan_doc)
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows(rows)
    return filepath


def export_json(scan_doc: dict, filepath: str):
    def default(o):
        if isinstance(o, datetime):
            return o.isoformat()
        return str(o)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(scan_doc, f, indent=2, default=default)
    return filepath


def export_pdf(scan_doc: dict, filepath: str):
    doc = SimpleDocTemplate(filepath, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleCustom", parent=styles["Title"], textColor=colors.HexColor("#0B5FFF"))
    story = []

    story.append(Paragraph("Glitch Hound — Security Report", title_style))
    story.append(Spacer(1, 12))

    meta = [
        ["Scan Type", scan_doc.get("scan_type", "")],
        ["Target", scan_doc.get("target", "")],
        ["Date", str(scan_doc.get("created_at", ""))],
        ["Duration", f"{scan_doc.get('duration_seconds', '')} s"],
    ]
    meta_table = Table(meta, colWidths=[1.5 * inch, 4.5 * inch])
    meta_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.grey),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 16))

    results = scan_doc.get("results", {})

    if scan_doc.get("scan_type") == "port_scan":
        story.append(Paragraph(f"Host: {results.get('resolved_ip', '')} — "
                                f"{'UP' if results.get('host_up') else 'DOWN'}", styles["Heading3"]))
        story.append(Spacer(1, 8))
        data = [["Port", "Service", "Banner"]]
        for p in results.get("open_ports", []):
            data.append([str(p.get("port")), p.get("service", ""), (p.get("banner") or "")[:40]])
        if len(data) == 1:
            data.append(["—", "No open ports found", ""])
        table = Table(data, colWidths=[0.8 * inch, 1.8 * inch, 3.4 * inch])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B5FFF")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
        ]))
        story.append(table)

        findings = impact_knowledge.port_findings(results)
        _append_impact_guide(story, styles, findings)

    else:  # vuln_scan
        story.append(Paragraph(f"Security Grade: {results.get('grade', 'N/A')}", styles["Heading2"]))
        story.append(Spacer(1, 10))

        if "headers" in results:
            story.append(Paragraph("Missing Security Headers", styles["Heading4"]))
            for h in results["headers"].get("missing", []):
                story.append(Paragraph(f"• {h['header']} — {h['why_it_matters']}", styles["Normal"]))
            story.append(Spacer(1, 8))

        if "ssl" in results:
            ssl_info = results["ssl"]
            story.append(Paragraph("SSL/TLS Certificate", styles["Heading4"]))
            story.append(Paragraph(f"Valid: {ssl_info.get('has_valid_cert')} | "
                                    f"Issuer: {ssl_info.get('issuer')} | "
                                    f"Expires: {ssl_info.get('expires')}", styles["Normal"]))
            story.append(Spacer(1, 8))

        if results.get("exposed_paths"):
            story.append(Paragraph("Exposed Sensitive Paths", styles["Heading4"]))
            for p in results["exposed_paths"]:
                story.append(Paragraph(f"• {p['path']} (HTTP {p['status_code']})", styles["Normal"]))
            story.append(Spacer(1, 8))

        if results.get("cookie_issues"):
            story.append(Paragraph("Cookie Flag Issues", styles["Heading4"]))
            for c in results["cookie_issues"]:
                story.append(Paragraph(f"• {c['cookie']} missing: {', '.join(c['missing_flags'])}", styles["Normal"]))

        _append_impact_guide(story, styles, impact_knowledge.vuln_findings(results))

    doc.build(story)
    return filepath


def _append_impact_guide(story, styles, findings):
    """Add the same non-technical impact guidance shown on the results page."""
    impact_style = ParagraphStyle(
        "ImpactNormal", parent=styles["Normal"], fontSize=10.5, leading=14
    )
    story.append(Spacer(1, 14))
    story.append(Paragraph("Impact, Data and Response Guide", styles["Heading2"]))
    if not findings:
        story.append(Paragraph("No open-port or failing-vulnerability impact findings were detected.", styles["Normal"]))
        return

    for finding in findings:
        title = escape(str(finding.get("title", "Finding")))
        impact = finding["details"]
        story.append(Paragraph(title, styles["Heading4"]))
        fields = [
            ("What it is", impact["what"]),
            ("Why it happened", impact["why"]),
            ("Attack and impact", f"{impact['attack']} {impact['impact']}"),
            ("Data that can be affected", impact["data"]),
            ("Money / recovery estimate", impact["money"]),
            ("What to do after an attack", impact["response"]),
            ("Possible fixes", " ".join(impact["fixes"])),
        ]
        for label, value in fields:
            story.append(Paragraph(f"<b>{escape(label)}:</b> {escape(str(value))}", impact_style))
        story.append(Spacer(1, 8))


def export(scan_doc: dict, fmt: str, filepath: str):
    fmt = fmt.lower()
    if fmt == "pdf":
        return export_pdf(scan_doc, filepath)
    if fmt == "csv":
        return export_csv(scan_doc, filepath)
    if fmt == "json":
        return export_json(scan_doc, filepath)
    raise ValueError(f"Unsupported export format: {fmt}")
