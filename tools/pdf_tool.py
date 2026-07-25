"""
PDF report builder. Renders a clean, structured security audit report using
reportlab tables and styled sections instead of a wall of text.

The report agent passes structured data (a dict) via `build_report`. The old
string-based `create_pdf_report` tool is kept as a thin wrapper for anything
that still calls it.
"""

from html import escape

from langchain_core.tools import tool
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

_ACCENT = colors.HexColor("#1f3a5f")
_LIGHT = colors.HexColor("#eef2f7")
_RED = colors.HexColor("#c0392b")
_AMBER = colors.HexColor("#d68910")
_GREEN = colors.HexColor("#1e8449")

_LEVEL_COLOR = {"Critical": _RED, "High": _RED, "Medium": _AMBER, "Low": _GREEN}


def _styles():
    s = getSampleStyleSheet()
    s.add(ParagraphStyle("H", parent=s["Heading2"], textColor=_ACCENT, spaceBefore=14, spaceAfter=6))
    s.add(ParagraphStyle("Cell", parent=s["BodyText"], fontSize=8.5, leading=11))
    s.add(ParagraphStyle("CellB", parent=s["BodyText"], fontSize=8.5, leading=11, fontName="Helvetica-Bold"))
    s.add(ParagraphStyle("Mono", parent=s["BodyText"], fontName="Courier", fontSize=7.5, leading=9.5))
    s.add(ParagraphStyle("Sub", parent=s["BodyText"], fontSize=9, textColor=colors.grey))
    return s


def _p(text, style):
    return Paragraph(escape(str(text)).replace("\n", "<br/>"), style)


def _table(rows, col_widths, header=True):
    t = Table(rows, colWidths=col_widths, hAlign="LEFT")
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c8d0da")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _LIGHT]),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    if header:
        style += [
            ("BACKGROUND", (0, 0), (-1, 0), _ACCENT),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8.5),
        ]
    t.setStyle(TableStyle(style))
    return t


def build_report(data: dict, filename: str = "audit_report.pdf") -> str:
    """Build a structured PDF from the audit `data` dict:
        generated, devices (list), risk {score,level}, breaches (list),
        findings (list of dicts), mitre (list of {finding,device,technique,
        technique_name}), recommendations (list).
    """
    st = _styles()
    doc = SimpleDocTemplate(filename, pagesize=A4,
                            topMargin=18 * mm, bottomMargin=16 * mm,
                            leftMargin=16 * mm, rightMargin=16 * mm)
    story = []

    # --- Title ---
    story.append(Paragraph("Network Security Audit Report", st["Title"]))
    story.append(_p(f"Generated: {data.get('generated', '')}", st["Sub"]))
    story.append(Spacer(1, 6))

    # --- Executive summary box ---
    risk = data.get("risk") or {}
    level = risk.get("level", "Low")
    findings = data.get("findings") or []
    summary_rows = [[
        _p("Devices scanned", st["CellB"]),
        _p(", ".join(data.get("devices", [])) or "none", st["Cell"]),
        _p("Findings", st["CellB"]),
        _p(str(len(findings)), st["Cell"]),
        _p("Overall risk", st["CellB"]),
        Paragraph(f'<font color="{_LEVEL_COLOR.get(level, colors.black)}">'
                  f'<b>{risk.get("score", 0)}/100 ({level})</b></font>', st["Cell"]),
    ]]
    story.append(_table(summary_rows, [26*mm, 40*mm, 16*mm, 12*mm, 20*mm, 30*mm], header=False))

    # --- Breach alert ---
    breaches = data.get("breaches") or []
    if breaches:
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            f'<para backColor="#fdecea"><font color="{_RED}"><b>⚠ BREACH ALERT: '
            f'successful login after brute force. {"; ".join(breaches)}</b></font></para>',
            st["BodyText"]))

    # --- Findings table ---
    story.append(Paragraph("Findings", st["H"]))
    head = ["#", "Type", "Device", "Risk", "Attempts", "Source IP(s)", "Usernames tried", "Window"]
    rows = [head]
    for i, f in enumerate(findings, 1):
        rl = f.get("risk_level", "")
        rows.append([
            _p(i, st["Cell"]),
            _p(f.get("title", ""), st["CellB"]),
            _p(f.get("device", ""), st["Cell"]),
            Paragraph(f'<font color="{_LEVEL_COLOR.get(rl, colors.black)}"><b>'
                      f'{f.get("risk_value","")}/25 {rl}</b></font>', st["Cell"]),
            _p(f.get("attempts", "—"), st["Cell"]),
            _p(", ".join(f.get("source_ips") or []) or "—", st["Cell"]),
            _p(", ".join(f.get("usernames") or []) or "—", st["Cell"]),
            _p(f'{f.get("first_seen","")}\n→ {f.get("last_seen","")}' if f.get("first_seen") else "—", st["Cell"]),
        ])
    story.append(_table(rows, [7*mm, 22*mm, 20*mm, 20*mm, 15*mm, 26*mm, 30*mm, 28*mm]))

    # --- MITRE table ---
    mitre = data.get("mitre") or []
    if mitre:
        story.append(Paragraph("MITRE ATT&amp;CK Techniques", st["H"]))
        mrows = [["Technique", "ID", "Finding", "Device"]]
        for m in mitre:
            mrows.append([_p(m.get("technique_name", ""), st["Cell"]),
                          _p(m.get("technique", ""), st["CellB"]),
                          _p(m.get("finding", ""), st["Cell"]),
                          _p(m.get("device", ""), st["Cell"])])
        story.append(_table(mrows, [45*mm, 18*mm, 40*mm, 30*mm]))

    # --- Recommendations ---
    recs = data.get("recommendations") or []
    if recs:
        story.append(Paragraph("Recommended Actions", st["H"]))
        for r in recs:
            story.append(_p(f"•  {r}", st["BodyText"]))

    # --- Evidence appendix (compact, monospace) ---
    ev_any = any(f.get("evidence") for f in findings)
    if ev_any:
        story.append(Paragraph("Evidence (raw log lines)", st["H"]))
        for f in findings:
            if not f.get("evidence"):
                continue
            story.append(_p(f"{f.get('title')} on {f.get('device')}:", st["CellB"]))
            for ev in f["evidence"]:
                story.append(_p(ev, st["Mono"]))
            story.append(Spacer(1, 4))

    doc.build(story)
    return filename


@tool
def create_pdf_report(findings: str, risk: str, recommendations: str,
                      mitre: str = "", filename: str = "audit_report.pdf"):
    """Legacy string-based entry point (kept for compatibility). Prefer
    build_report(data) for the structured, tabular report."""
    styles = _styles()
    doc = SimpleDocTemplate(filename)
    story = [Paragraph("Network Security Audit Report", styles["Title"]), Spacer(1, 12)]
    for title, body in [("Findings", findings), ("Risk", risk),
                        ("MITRE ATT&CK", mitre or "None."),
                        ("Recommendations", recommendations)]:
        story.append(Paragraph(title, styles["H"]))
        story.append(_p(body, styles["BodyText"]))
        story.append(Spacer(1, 8))
    doc.build(story)
    return filename
