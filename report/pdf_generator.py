"""Professional multi-section PDF report for vulnerability assessment results."""

from __future__ import annotations

import html
from collections import Counter
from datetime import datetime, timezone

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents

from utils.owasp_top10 import (
    OWASP_2025_ROWS,
    finding_count_for_code,
    modules_exercising_code,
    was_category_tested,
)

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#dc2626"),
    "HIGH": colors.HexColor("#ea580c"),
    "MEDIUM": colors.HexColor("#ca8a04"),
    "LOW": colors.HexColor("#2563eb"),
    "INFO": colors.HexColor("#1f2937"),
}

NAVY = colors.HexColor("#1a2744")
ACCENT = colors.HexColor("#e94560")


def _p(text: str | int | float | None) -> str:
    if text is None:
        return ""
    s = html.escape(str(text), quote=False)
    return s.replace("\n", "<br/>")


def _mono(text: str | None) -> str:
    if not text:
        return ""
    inner = html.escape(str(text), quote=False).replace("\n", "<br/>")
    return f'<font face="Courier" size="8">{inner}</font>'


def _header_footer(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, A4[1] - 1.15 * cm, A4[0], 1.15 * cm, stroke=0, fill=1)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.drawString(1.2 * cm, A4[1] - 0.72 * cm, "OWASP Top 10 (2025) - Vulnerability Assessment")
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.lightgrey)
    canvas.drawRightString(A4[0] - 1.2 * cm, A4[1] - 0.72 * cm, getattr(doc, "_target_label", ""))
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(colors.grey)
    canvas.drawRightString(A4[0] - 1.2 * cm, 1.1 * cm, f"Page {doc.page}")
    canvas.restoreState()


class ReportDocTemplate(BaseDocTemplate):
    def __init__(self, filename: str, target_label: str, **kwargs):
        super().__init__(filename, **kwargs)
        self._target_label = target_label
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="normal")
        self.addPageTemplates([PageTemplate(id="Report", frames=[frame], onPage=_header_footer)])

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph) and getattr(flowable, "style", None):
            style_name = flowable.style.name
            if style_name in ("TOCHeading", "SectionHeading", "FindingHeading"):
                level = {"TOCHeading": 0, "SectionHeading": 0, "FindingHeading": 1}[style_name]
                self.notify("TOCEntry", (level, flowable.getPlainText(), self.page))


def _risk_score(findings: list[dict]) -> int:
    weights = {"CRITICAL": 20, "HIGH": 12, "MEDIUM": 7, "LOW": 3, "INFO": 1}
    score = sum(weights.get(f.get("severity", "INFO"), 0) for f in findings)
    return max(0, min(100, score))


def _get_risk_label(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    elif score >= 15:
        return "LOW"
    return "MINIMAL"


def _severity_badge(severity: str) -> Table:
    color = SEVERITY_COLORS.get(severity, colors.black)
    badge = Table([[severity]], colWidths=[2.8 * cm], rowHeights=[0.58 * cm])
    badge.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    return badge


def _severity_bar_chart(counts: Counter) -> Drawing:
    drawing = Drawing(14 * cm, 6 * cm)
    chart = VerticalBarChart()
    chart.x = 5
    chart.y = 20
    chart.height = 90
    chart.width = 280
    ordered = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    chart.data = [[counts.get(k, 0) for k in ordered]]
    chart.categoryAxis.categoryNames = ordered
    chart.valueAxis.valueMin = 0
    mx = max(counts.get(k, 0) for k in ordered)
    chart.valueAxis.valueMax = max(3, mx + 1)
    chart.valueAxis.valueStep = 1
    chart.barWidth = 22
    chart.groupSpacing = 12
    for idx, sev in enumerate(ordered):
        chart.bars[(0, idx)].fillColor = SEVERITY_COLORS[sev]
    drawing.add(chart)
    drawing.add(String(40, 148, "Findings by severity (count)", fontSize=10, fillColor=NAVY))
    return drawing


def _severity_pie_chart(counts: Counter) -> Drawing:
    ordered = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    data = [max(0, counts.get(k, 0)) for k in ordered]
    drawing = Drawing(6.5 * cm, 6 * cm)
    pie = Pie()
    pie.x = 5
    pie.y = 15
    pie.height = pie.width = 80
    if sum(data) == 0:
        pie.data = [1]
        pie.labels = ["No findings"]
        pie.slices[0].fillColor = colors.lightgrey
    else:
        pie.data = [d for d in data if d > 0]
        pie.labels = [ordered[i] for i, d in enumerate(data) if d > 0]
        cols = [SEVERITY_COLORS[ordered[i]] for i, d in enumerate(data) if d > 0]
        for i, c in enumerate(cols):
            pie.slices[i].fillColor = c
    drawing.add(pie)
    drawing.add(String(10, 148, "Distribution", fontSize=10, fillColor=NAVY))
    return drawing


def _owasp_top10_coverage_table(findings: list[dict], modules_run: list[str]) -> Table:
    rows = [["Rank", "Category", "Tested", "Modules", "# Findings"]]
    for row in OWASP_2025_ROWS:
        code = row["code"]
        tested = "Yes" if was_category_tested(modules_run, code) else "No"
        mods = ", ".join(modules_exercising_code(modules_run, code)) or "-"
        n = finding_count_for_code(findings, code)
        # Truncate long module lists for table
        if len(mods) > 35:
            mods = mods[:32] + "..."
        rows.append([_p(row["id"]), _p(row["name"]), tested, _p(mods), str(n)])
    t = Table(rows, colWidths=[1.8 * cm, 4.5 * cm, 1.3 * cm, 5.5 * cm, 1.5 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.HexColor("#f3f4f6")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def _add_warning_box(story: list, body_style) -> None:
    warning_text = (
        "<b>WARNING: AUTHORIZED SECURITY TESTING ONLY</b><br/>"
        "<font size='8'>This report contains vulnerability findings from automated security scanning. "
        "All tests were conducted using non-destructive payloads. "
        "Findings should be validated in application context before remediation.</font>"
    )
    warning_table = Table([[Paragraph(warning_text, body_style)]], colWidths=[16 * cm])
    warning_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fff3cd")),
        ("BOX", (0, 0), (-1, -1), 1.5, colors.HexColor("#856404")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(warning_table)
    story.append(Spacer(1, 0.3 * cm))


def build_pdf_report(output_path: str, target_url: str, findings: list[dict], metadata: dict) -> None:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    doc = ReportDocTemplate(
        output_path,
        target_label=_p(target_url)[:90],
        pagesize=A4,
        topMargin=1.85 * cm,
        bottomMargin=1.55 * cm,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
    )
    styles = getSampleStyleSheet()
    title = ParagraphStyle("CoverTitle", parent=styles["Title"], fontSize=26, leading=30, textColor=NAVY, spaceAfter=12)
    subtitle = ParagraphStyle("Subtitle", parent=styles["BodyText"], fontSize=11, textColor=colors.HexColor("#4b5563"))
    h1 = ParagraphStyle("TOCHeading", parent=styles["Heading1"], textColor=NAVY, spaceAfter=10, fontSize=16)
    h2 = ParagraphStyle("SectionHeading", parent=styles["Heading2"], textColor=NAVY, spaceAfter=8, fontSize=13)
    h3 = ParagraphStyle("FindingHeading", parent=styles["Heading3"], textColor=NAVY, spaceAfter=6, fontSize=11)
    body = ParagraphStyle("Body", parent=styles["BodyText"], fontSize=9, leading=12)
    small = ParagraphStyle("Small", parent=styles["BodyText"], fontSize=8, leading=10, textColor=colors.grey)

    story = []

    # Cover
    report_title = metadata.get("report_title", "OWASP Top 10 (2025) Vulnerability Assessment")
    story.append(Spacer(1, 3.2 * cm))
    story.append(Paragraph(_p(report_title), title))
    story.append(Paragraph("Automated checks mapped to the OWASP Top 10 - 2025 with remediation guidance", subtitle))
    story.append(Spacer(1, 1.2 * cm))

    # Risk score banner
    risk = _risk_score(findings)
    risk_label = _get_risk_label(risk)
    risk_color = SEVERITY_COLORS.get(risk_label, colors.grey)

    risk_score_para = Paragraph(
        f"<b>Risk Score: {risk}/100</b>",
        ParagraphStyle("RiskScore", parent=body, fontSize=18, textColor=colors.white)
    )
    risk_level_para = Paragraph(
        f"<b>Risk Level: {risk_label}</b>",
        ParagraphStyle("RiskLevel", parent=body, fontSize=14, textColor=colors.white)
    )

    risk_banner_data = [[risk_score_para, risk_level_para]]
    risk_banner = Table(risk_banner_data, colWidths=[8 * cm, 8 * cm])
    risk_banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), risk_color),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 15),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 15),
    ]))
    story.append(risk_banner)
    story.append(Spacer(1, 0.8 * cm))

    # Metadata table
    meta_rows = [
        ["Target URL", _p(target_url)],
        ["Scan Timestamp", _p(stamp)],
        ["Scan Profile", _p(metadata.get("profile", "ecommerce").upper())],
        ["Modules Executed", _p(", ".join(metadata.get("modules", [])))],
        ["SQLi Probe Approaches", str(metadata.get("sqli_approach_count", "-"))],
        ["Total Findings", str(len(findings))],
        ["Framework", "OWASP Top 10 - 2025"],
    ]
    mt = Table([[Paragraph(_p(a), body), Paragraph(_p(b), body)] for a, b in meta_rows], colWidths=[4.2 * cm, 12 * cm])
    mt.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(mt)
    story.append(Spacer(1, 0.8 * cm))
    _add_warning_box(story, small)
    story.append(PageBreak())

    # TOC
    story.append(Paragraph("Table of Contents", h1))
    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle(name="TOC1", parent=body, leftIndent=16, firstLineIndent=-12, spaceBefore=3, fontSize=10),
        ParagraphStyle(name="TOC2", parent=body, leftIndent=28, firstLineIndent=-10, spaceBefore=2, fontSize=9, textColor=colors.grey),
    ]
    toc.dotsMinLevel = 0
    story.append(toc)
    story.append(PageBreak())

    counts = Counter(f.get("severity", "INFO") for f in findings)

    # Executive Summary
    story.append(Paragraph("Executive Summary", h2))
    story.append(Paragraph(
        f"This report summarizes an <b>OWASP Top 10 (2025)</b> oriented vulnerability scan: "
        f"<b>{len(findings)}</b> findings identified with a composite risk score of <b>{risk}/100</b> ({risk_label}).",
        body,
    ))
    story.append(Spacer(1, 0.35 * cm))

    sum_rows = [["Severity", "Count"]] + [[s, str(counts.get(s, 0))] for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")]
    st = Table(sum_rows, colWidths=[6 * cm, 3 * cm])
    st.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.lightgrey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.HexColor("#f3f4f6")]),
    ]))
    story.append(st)
    story.append(Spacer(1, 0.45 * cm))

    top3 = sorted(findings, key=lambda x: float(x.get("cvss_score", 0) or 0), reverse=True)[:3]
    story.append(Paragraph("<b>Top priority items requiring immediate attention:</b>", body))
    if not top3:
        story.append(Paragraph("No critical findings detected.", body))
    else:
        tr = [["ID", "Severity", "CVSS", "Title"]]
        for it in top3:
            tr.append([_p(it.get("id")), _p(it.get("severity")), _p(it.get("cvss_score")), _p(it.get("title"))[:70]])
        tt = Table([[Paragraph(_p(c), body) for c in row] for row in tr], colWidths=[2.6 * cm, 2.4 * cm, 1.5 * cm, 9.5 * cm])
        tt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.HexColor("#eef2ff")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(tt)

    story.append(Spacer(1, 0.35 * cm))
    _add_warning_box(story, small)
    story.append(PageBreak())

    # Methodology
    story.append(Paragraph("Methodology & Scope", h2))
    story.append(Paragraph(
        "The scanner is structured around the <b>OWASP Top 10 - 2025</b>. Each enabled module maps to one or more "
        "risk categories. All probes use non-destructive payloads (no DROP, DELETE, or mass writes).",
        body,
    ))
    story.append(Spacer(1, 0.25 * cm))
    names = metadata.get("sqli_approach_names") or []
    if names:
        story.append(Paragraph("<b>SQLi approach labels used:</b>", body))
        for name in names:
            story.append(Paragraph(f"- {name}", small))
    story.append(PageBreak())

    # Risk Overview
    story.append(Paragraph("Risk Overview", h2))
    chart_row = Table([[_severity_pie_chart(counts), _severity_bar_chart(counts)]], colWidths=[7 * cm, 9 * cm])
    chart_row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    story.append(chart_row)
    story.append(Spacer(1, 0.6 * cm))
    story.append(Paragraph("<b>OWASP Top 10 (2025) - coverage and findings</b>", body))
    story.append(Spacer(1, 0.3 * cm))
    story.append(_owasp_top10_coverage_table(findings, metadata.get("modules", [])))
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph("<i>&quot;Tested&quot;</i> means at least one enabled scanner maps to that OWASP category.", small))
    story.append(PageBreak())

    # Detailed Findings
    story.append(Paragraph("Detailed Findings", h2))
    if not findings:
        story.append(Paragraph("No findings were recorded for this run.", body))
    for idx, item in enumerate(findings, 1):
        sev = item.get("severity", "INFO")
        head = Paragraph(_p(f"{item.get('id')} - {item.get('title')}"), h3)
        meta_line = Paragraph(
            _p(f"{item.get('owasp_category')} | {item.get('cwe_id')} | CVSS {item.get('cvss_score')} | "
               f"{item.get('method')} {item.get('endpoint')} | param: {item.get('parameter')}"),
            small,
        )
        block_parts = [head, _severity_badge(sev), Spacer(1, 0.12 * cm), meta_line, Spacer(1, 0.12 * cm)]
        block_parts.append(Paragraph("<b>Description</b><br/>" + _p(item.get("description")), body))

        if item.get("payload_used"):
            block_parts.append(Paragraph("<b>Injected Payload</b>", body))
            block_parts.append(Paragraph(_mono(item["payload_used"]), body))

        block_parts.append(Paragraph("<b>Evidence</b><br/>" + _p(item.get("evidence")), body))

        if item.get("approaches_tried"):
            block_parts.append(Paragraph("<b>Successful / indicative probe styles</b><br/>" +
                                         _p(", ".join(item["approaches_tried"])), body))

        if item.get("response_snippet"):
            block_parts.append(Paragraph("<b>Response Snippet</b><br/>" + _mono(item["response_snippet"][:500]), body))

        if item.get("screenshot_path"):
            block_parts.append(Paragraph(f"<b>Exploitation Proof:</b> See {item['screenshot_path']}", small))

        block_parts.append(Paragraph("<b>Impact</b><br/>" + _p(item.get("impact")), body))

        steps = item.get("remediation_steps")
        if steps:
            numbered = "<br/>".join(f"{i+1}. {_p(s)}" for i, s in enumerate(steps))
            block_parts.append(Paragraph("<b>Remediation Steps</b><br/>" + numbered, body))

        block_parts.append(Paragraph("<b>Remediation Summary</b><br/>" + _p(item.get("remediation")), body))

        if item.get("code_example"):
            block_parts.append(Paragraph("<b>Secure Code Example</b><br/>" + _mono(item["code_example"]), body))

        refs = item.get("references") or []
        if refs:
            block_parts.append(Paragraph("<b>References</b><br/>" + "<br/>".join(_p(r) for r in refs), small))

        block_parts.append(Spacer(1, 0.35 * cm))
        story.append(KeepTogether(block_parts))

    story.append(PageBreak())

    # Remediation Roadmap
    story.append(Paragraph("Remediation Roadmap", h2))
    road = [
        ["Timeline", "Severity Focus", "Owner", "Example Actions"],
        ["0-2 Days", "CRITICAL", "App + DBA", "Stop error disclosure; patch auth; emergency config toggles."],
        ["1 Week", "HIGH", "Platform", "Access control review; header hardening; SSRF egress controls."],
        ["30 Days", "MEDIUM/LOW", "Security", "Monitoring, SRI, dependency upgrades, QA regression tests."],
    ]
    rt = Table([[Paragraph(_p(c), body) for c in row] for row in road], colWidths=[2.8 * cm, 3 * cm, 3 * cm, 7.2 * cm])
    rt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.lightgrey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.HexColor("#f3f4f6")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(rt)
    story.append(PageBreak())

    # Appendix
    story.append(Paragraph("Appendix", h2))
    story.append(Paragraph("<b>Scan Configuration</b>", body))
    story.append(Paragraph(_p(f"Mode: {metadata.get('mode')} | Profile: {metadata.get('profile')}"), small))

    if metadata.get("screenshots_dir"):
        story.append(Spacer(1, 0.25 * cm))
        story.append(Paragraph("<b>Exploitation Proofs</b>", body))
        story.append(Paragraph(_p(f"Screenshots directory: {metadata['screenshots_dir']}/"), small))

    story.append(Spacer(1, 0.25 * cm))
    story.append(Paragraph("<b>Disclaimer</b>", body))
    story.append(Paragraph(
        "Automated findings can include false positives. Validate each item in application context before remediation.",
        small,
    ))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph("<b>References</b>", body))
    story.append(Paragraph("- OWASP Top 10 (2025) - https://owasp.org/Top10/", small))
    story.append(Paragraph("- CWE/CVE Databases", small))
    story.append(Paragraph("- CVSS 3.1 Scoring Guide", small))

    doc.multiBuild(story)