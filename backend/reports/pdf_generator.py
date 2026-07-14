"""
PDF Audit Report Generator
Menjana laporan audit keselamatan AI dalam format PDF
Pematuhan: NACSA, JPDP, OWASP, AIGE
"""

import io
from datetime import datetime, timezone


def generate(
    domain: str,
    scan_result,        # cve_scanner.ScanResult
    compliance_score,   # scorer.ComplianceScore
    prompt_stats: dict,
) -> bytes:
    """
    Menjana PDF audit report dan return sebagai bytes.
    Memerlukan: pip install reportlab
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
        )
    except ImportError:
        raise RuntimeError("reportlab tidak terinstall. Jalankan: pip install reportlab")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story = []

    # ── Header ────────────────────────────────────────────────────────────
    title_style = ParagraphStyle("title", parent=styles["Title"], fontSize=18, spaceAfter=6)
    sub_style = ParagraphStyle("sub", parent=styles["Normal"], fontSize=10, textColor=colors.grey)
    h2_style = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=13, spaceBefore=14, spaceAfter=6)
    body_style = ParagraphStyle("body", parent=styles["Normal"], fontSize=9, spaceAfter=4)
    warn_style = ParagraphStyle("warn", parent=styles["Normal"], fontSize=9, textColor=colors.red)

    story.append(Paragraph("🛡️ AI Security Gateway — Laporan Audit Keselamatan", title_style))
    story.append(Paragraph(f"Domain: <b>{domain}</b> | Dijana: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", sub_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey, spaceAfter=12))

    # ── Compliance Score Summary ──────────────────────────────────────────
    story.append(Paragraph("1. Ringkasan Skor Pematuhan", h2_style))

    grade_color = {
        "A": colors.green, "B": colors.limegreen,
        "C": colors.orange, "D": colors.orangered, "F": colors.red,
    }.get(compliance_score.grade, colors.grey)

    score_data = [
        ["Framework", "Skor", "Status"],
        ["OWASP Top 10 (2021)", f"{compliance_score.owasp_score}/100", _status(compliance_score.owasp_score)],
        ["NACSA AI Security Framework", f"{compliance_score.nacsa_score}/100", _status(compliance_score.nacsa_score)],
        ["JPDP / PDPA 2010", f"{compliance_score.jpdp_score}/100", _status(compliance_score.jpdp_score)],
        ["MCMC CMA 1998", f"{compliance_score.mcmc_score}/100", _status(compliance_score.mcmc_score)],
        ["AIGE Etika AI Kebangsaan", f"{compliance_score.aige_score}/100", _status(compliance_score.aige_score)],
        ["SKOR KESELURUHAN", f"{compliance_score.overall}/100 (Gred {compliance_score.grade})", ""],
    ]

    score_table = Table(score_data, colWidths=[8*cm, 4*cm, 4*cm])
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.HexColor("#f8fafc"), colors.white]),
        ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, -1), (-1, -1), grade_color),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 12))

    # ── Prompt Stats ──────────────────────────────────────────────────────
    story.append(Paragraph("2. Statistik Imbasan Prompt AI", h2_style))
    total = prompt_stats.get("total_requests", 0)
    blocked = prompt_stats.get("total_blocked", 0)
    rate = f"{(blocked/total*100):.2f}%" if total > 0 else "0%"

    stats_data = [
        ["Metrik", "Nilai"],
        ["Jumlah Imbasan Prompt", str(total)],
        ["Ancaman Disekat", str(blocked)],
        ["Kadar Ancaman", rate],
        ["Status Engine", "AKTIF"],
    ]
    stats_table = Table(stats_data, colWidths=[8*cm, 8*cm])
    stats_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(stats_table)
    story.append(Spacer(1, 12))

    # ── CVE/CWE Vulnerabilities ───────────────────────────────────────────
    story.append(Paragraph("3. Kelemahan CVE/CWE Dikesan", h2_style))

    if not scan_result.vulnerabilities:
        story.append(Paragraph("✅ Tiada kelemahan kritikal dikesan.", body_style))
    else:
        vuln_data = [["CWE", "Tajuk", "Severity", "OWASP", "Lokasi"]]
        for v in scan_result.vulnerabilities:
            sev_color = {
                "CRITICAL": colors.red, "HIGH": colors.orangered,
                "MEDIUM": colors.orange, "LOW": colors.green,
            }.get(v.severity, colors.grey)
            vuln_data.append([v.cwe_id, v.title, v.severity, v.owasp_ref, v.line_hint[:40]])

        vuln_table = Table(vuln_data, colWidths=[2*cm, 5*cm, 2.5*cm, 2.5*cm, 5*cm])
        vuln_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#fff1f2"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("WORDWRAP", (0, 0), (-1, -1), True),
        ]))
        story.append(vuln_table)

    story.append(Spacer(1, 12))

    # ── Compliance Flags ──────────────────────────────────────────────────
    story.append(Paragraph("4. Isu Pematuhan Perundangan Malaysia", h2_style))

    if not scan_result.compliance_flags:
        story.append(Paragraph("✅ Tiada isu pematuhan dikesan.", body_style))
    else:
        for flag in scan_result.compliance_flags:
            story.append(Paragraph(f"<b>[{flag['ref']}]</b> {flag['title']}", warn_style))
            story.append(Paragraph(f"Cadangan: {flag['recommendation']}", body_style))
            story.append(Paragraph(f"Lokasi: {flag['line_hint']}", body_style))
            story.append(Spacer(1, 4))

    # ── Recommendations ───────────────────────────────────────────────────
    if compliance_score.recommendations:
        story.append(Paragraph("5. Cadangan Pembaikan", h2_style))
        for i, rec in enumerate(compliance_score.recommendations[:10], 1):
            story.append(Paragraph(f"{i}. {rec}", body_style))

    # ── Footer ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
    story.append(Paragraph(
        "Laporan ini dijana secara automatik oleh AI Security Gateway. "
        "Rujukan: OWASP Top 10 (2021), NACSA AI Security Framework, JPDP/PDPA 2010, "
        "MCMC CMA 1998, AIGE Garis Panduan Etika AI Kebangsaan, MY-AI Standards.",
        sub_style,
    ))

    doc.build(story)
    return buffer.getvalue()


def _status(score: float) -> str:
    if score >= 90:
        return "✅ Patuh"
    elif score >= 60:
        return "⚠️ Perlu Perhatian"
    else:
        return "❌ Tidak Patuh"
