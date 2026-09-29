"""
PDF executive brief.

The UI has always offered an "Executive Report (PDF)" action and the download
endpoint advertised a PDF format, but the backend only ever produced .docx,
Markdown, JSON and printable HTML. This module produces an actual PDF.

reportlab is used rather than an HTML-to-PDF converter: the HTML report relies on
modern CSS (flex layout, CSS variables) that pure-Python converters render badly,
and WeasyPrint would add native system libraries to the container image.
"""

import io
from datetime import datetime, timezone
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

VERDICT_COLORS = {
    "TRUE_POSITIVE": colors.HexColor("#B91C1C"),
    "FALSE_POSITIVE": colors.HexColor("#15803D"),
    "SUSPICIOUS_ESCALATE": colors.HexColor("#B45309"),
    "BENIGN": colors.HexColor("#0F766E"),
}
INK = colors.HexColor("#0F172A")
MUTED = colors.HexColor("#64748B")
RULE = colors.HexColor("#CBD5E1")
AMBER = colors.HexColor("#B45309")


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontName="Helvetica-Bold",
                                fontSize=17, leading=21, textColor=INK, spaceAfter=2),
        "sub": ParagraphStyle("s", parent=base["Normal"], fontName="Helvetica",
                              fontSize=8.5, textColor=MUTED, spaceAfter=10),
        "h": ParagraphStyle("h", parent=base["Heading2"], fontName="Helvetica-Bold",
                            fontSize=10.5, leading=13, textColor=INK,
                            spaceBefore=12, spaceAfter=5),
        "body": ParagraphStyle("b", parent=base["Normal"], fontName="Helvetica",
                               fontSize=9, leading=13.5, textColor=INK,
                               alignment=TA_LEFT, spaceAfter=4),
        "mono": ParagraphStyle("m", parent=base["Normal"], fontName="Courier",
                               fontSize=7.5, leading=10, textColor=INK, spaceAfter=3),
        "gap": ParagraphStyle("g", parent=base["Normal"], fontName="Helvetica",
                              fontSize=8.5, leading=12, textColor=AMBER, spaceAfter=3),
        "small": ParagraphStyle("sm", parent=base["Normal"], fontName="Helvetica",
                                fontSize=7.5, leading=10, textColor=MUTED),
    }


def _esc(text: Any) -> str:
    s = "" if text is None else str(text)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _bullets(items: List[Any], style, prefix: str = "•") -> List[Any]:
    out = []
    for item in items or []:
        out.append(Paragraph(f"{prefix} {_esc(item)}", style))
    if not items:
        out.append(Paragraph("None recorded.", style))
    return out


def generate_pdf_report(incident: Dict[str, Any], report: Dict[str, Any], analyst_name: str) -> io.BytesIO:
    buf = io.BytesIO()
    st = _styles()
    inc_num = incident.get("incidentNumber", "—")
    verdict = report.get("verdict", "UNDETERMINED")
    completeness = report.get("evidence_completeness", report.get("confidence_score", 0))
    gaps = report.get("evidence_gaps") or []
    rca = report.get("root_cause_analysis") or {}
    mitre = report.get("mitre_attack") or {}
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"Incident {inc_num} - Executive Brief", author="AI SOC Triage Agent",
    )

    flow: List[Any] = []
    flow.append(Paragraph("Security Incident — Executive Brief", st["title"]))
    flow.append(Paragraph(
        f"Incident #{_esc(inc_num)} &nbsp;·&nbsp; Generated {generated} &nbsp;·&nbsp; Reviewed by {_esc(analyst_name)}",
        st["sub"]))
    flow.append(HRFlowable(width="100%", color=RULE, spaceAfter=8))

    # Verdict banner. Evidence completeness is deliberately labelled as such: it
    # states how much of the required evidence was available, not a probability
    # that the verdict is correct.
    vcolor = VERDICT_COLORS.get(verdict, MUTED)
    banner = Table(
        [[Paragraph(f'<font color="{vcolor.hexval()}"><b>{_esc(verdict.replace("_", " "))}</b></font>', st["h"]),
          Paragraph(f'<b>{_esc(completeness)}%</b><br/><font size="7" color="#64748B">EVIDENCE COMPLETENESS</font>',
                    st["body"])]],
        colWidths=[118 * mm, 56 * mm])
    banner.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.7, vcolor),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
    ]))
    flow.extend([banner, Spacer(1, 10)])

    meta = [
        ["Title", _esc(incident.get("title", "—"))],
        ["Severity", f'{_esc(incident.get("severity", "—"))}  (assessed: {_esc(report.get("severity_assessment", "—"))})'],
        ["Status", _esc(incident.get("status", "—"))],
        ["Model", _esc(report.get("model_used", "—"))],
    ]
    mt = Table([[Paragraph(f'<font color="#64748B">{k}</font>', st["small"]),
                 Paragraph(v, st["body"])] for k, v in meta], colWidths=[28 * mm, 146 * mm])
    mt.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3), ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("LINEBELOW", (0, 0), (-1, -2), 0.3, RULE),
    ]))
    flow.extend([mt, Spacer(1, 6)])

    flow.append(Paragraph("1. Executive Summary", st["h"]))
    flow.append(Paragraph(_esc(report.get("executive_summary", "No summary provided.")), st["body"]))

    flow.append(Paragraph("2. MITRE ATT&amp;CK Mapping", st["h"]))
    flow.append(Paragraph(f'<b>Tactics:</b> {_esc(", ".join(mitre.get("tactics", [])) or "—")}', st["body"]))
    flow.extend(_bullets(mitre.get("techniques", []), st["body"]))

    flow.append(Paragraph("3. Root Cause", st["h"]))
    flow.append(Paragraph(f'<b>Patient zero:</b> {_esc(rca.get("patient_zero", "—"))}', st["body"]))
    flow.append(Paragraph(f'<b>Initial access vector:</b> {_esc(rca.get("initial_access_vector", "—"))}', st["body"]))
    for stage in (rca.get("kill_chain_progression") or [])[:8]:
        if isinstance(stage, dict):
            flow.append(Paragraph(
                f'• <b>{_esc(stage.get("stage", "—"))}</b> ({_esc(stage.get("tactic", "—"))}): '
                f'{_esc(stage.get("description", ""))}', st["body"]))

    flow.append(Paragraph("4. Evidence", st["h"]))
    flow.extend(_bullets(report.get("evidence_findings", []), st["body"]))

    # Evidence gaps are given equal prominence to findings. A brief that lists only
    # what was found, and not what could not be checked, overstates its own basis.
    flow.append(Paragraph("4b. Evidence Gaps — Not Verified", st["h"]))
    flow.append(Paragraph(
        "The following checks could not be completed or returned no data. The verdict above "
        "does not rest on confirmed evidence for these points.", st["small"]))
    flow.append(Spacer(1, 3))
    flow.extend(_bullets(gaps, st["gap"], prefix="!"))

    flow.append(Paragraph("5. Recommended Actions", st["h"]))
    flow.extend(_bullets(report.get("recommended_actions", []), st["body"]))

    queries = report.get("kql_queries_used") or []
    if queries:
        flow.append(PageBreak())
        flow.append(Paragraph("Appendix — Queries Executed", st["h"]))
        for q in queries:
            flow.append(Paragraph(_esc(q), st["mono"]))
            flow.append(Spacer(1, 3))

    def _footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, 10 * mm,
                          f"Incident {inc_num} · AI-assisted triage · generated {generated}")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    doc.build(flow, onFirstPage=_footer, onLaterPages=_footer)
    buf.seek(0)
    return buf
