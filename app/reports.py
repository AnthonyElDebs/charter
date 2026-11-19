from base64 import b64decode
from io import BytesIO
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

from jinja2 import Environment, FileSystemLoader, select_autoescape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate


templates = Environment(loader=FileSystemLoader(Path(__file__).with_name("templates")),
                        autoescape=select_autoescape(["html"]))
templates.filters["utc"] = lambda value: value.strftime("%Y-%m-%d %H:%M UTC") if value else "Pending"


def exchange_text(evidence):
    result = {}
    for label, msg in evidence.items():
        line = (f"{msg['method']} {msg['path']} {msg['http_version']}" if label == "request"
                else f"{msg['http_version']} {msg['status']} {msg['reason']}")
        headers = "\n".join(f"{k}: {v}" for k, v in msg["headers"])
        preview = b64decode(msg["body_base64"])[:2048].decode("utf-8", errors="replace")
        result[label] = dict(head=line + "\n" + headers, preview=preview)
    return result


def pdf(run):
    stream = BytesIO()
    doc = SimpleDocTemplate(stream, title="Charter engagement report", author="Charter",
                            leftMargin=20*mm, rightMargin=20*mm, topMargin=16*mm, bottomMargin=16*mm)
    styles = getSampleStyleSheet()
    styles["Heading1"].textColor = colors.HexColor("#173b30")
    story = []

    def paragraph(value, style="BodyText"):
        text = xml_escape(str(value))
        story.append(Paragraph(text, styles[style]))

    paragraph("Charter engagement report", "Title")
    paragraph(run["details"]["engagement"], "Heading1")
    paragraph(f"Run {run['id']} | {templates.filters['utc'](run['started'])}")
    scope = run["details"]["charter"]
    paragraph(f"Approved by {scope['approver']} for {scope['operator']}. Window {scope['starts_at']} to {scope['ends_at']}.")
    paragraph("Scope: " + ", ".join(scope["allow"]) + " | Denied: " + ", ".join(scope["deny"]))
    paragraph("Signed charter SHA-256: " + run["details"]["charter_sha256"])
    report = (run.get("details") or {}).get("report") if isinstance(run.get("details"), dict) else None
    if isinstance(report, dict) and report.get("executive_summary"):
        paragraph("Executive summary", "Heading2")
        paragraph(report.get("executive_summary"))
        paragraph("Attack chain", "Heading3")
        paragraph(report.get("attack_chain") or "")
        for item in report.get("findings") or []:
            if not isinstance(item, dict):
                continue
            paragraph(item.get("title") or item.get("check") or "Finding", "Heading3")
            paragraph(item.get("narrative") or "")
            if item.get("cvss"):
                paragraph(item.get("cvss"))
            if item.get("run_id"):
                paragraph("Evidence run " + str(item.get("run_id")))
    finding = run["finding"]
    if finding:
        paragraph(finding["title"], "Heading2")
        paragraph("Severity: " + finding["severity"])
        if finding.get("check"):
            paragraph("Check: " + finding["check"])
        if finding.get("proven"):
            paragraph("Proven against the captured HTTP exchange.")
        for key, label in (("evidence","Observation"),("impact","Impact"),
                           ("reproduce","Verification"),("remediation","Remediation")):
            paragraph(label, "Heading3")
            paragraph(finding[key])
    else:
        paragraph("No header finding in the captured response.", "Heading2")
    for label, part in exchange_text(run["evidence"]).items():
        msg = run["evidence"][label]
        paragraph(label.title() + " evidence", "Heading2")
        for line in part["head"].splitlines():
            paragraph(line, "Code")
        paragraph(f"Body: {msg['body_bytes']} bytes. SHA-256: {msg['body_sha256']}")
    paragraph("The HTML report includes the full base64-encoded message bodies. Match their digests to this PDF.")
    doc.build(story)
    return stream.getvalue()
