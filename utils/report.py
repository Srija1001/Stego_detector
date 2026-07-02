"""
PDF Report Generator — works for images, documents, audio, and video.
"""
from PIL import Image
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import os
from datetime import datetime
from io import BytesIO

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable, Image as RLImage,
    PageBreak, KeepTogether,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

# ── Palette ──────────────────────────────────────────────────────────────────
C_DARK   = colors.HexColor("#0d1117")
C_PANEL  = colors.HexColor("#1e2530")
C_ACCENT = colors.HexColor("#00d4aa")
C_RED    = colors.HexColor("#e53935")
C_YELLOW = colors.HexColor("#f9a825")
C_BLUE   = colors.HexColor("#1565c0")
C_LIGHT  = colors.HexColor("#e6edf3")
C_MID    = colors.HexColor("#607d8b")
C_WHITE  = colors.white
C_BLACK  = colors.black
C_BG     = colors.HexColor("#f4f6f8")
C_BORDER = colors.HexColor("#cfd8dc")

W_PAGE = A4[0] - 4 * cm   # usable width


def _risk_color(level):
    return {"HIGH": C_RED, "MEDIUM": C_YELLOW, "LOW": C_ACCENT, "CLEAN": C_ACCENT}.get(level, C_MID)

def _risk_bg(level):
    return {
        "HIGH":   colors.HexColor("#ffebee"),
        "MEDIUM": colors.HexColor("#fffde7"),
        "LOW":    colors.HexColor("#e8f5e9"),
        "CLEAN":  colors.HexColor("#e8f5e9"),
    }.get(level, colors.HexColor("#f5f5f5"))


def _styles():
    return {
        "title": ParagraphStyle("rpt_title", fontSize=22, textColor=C_DARK,
            alignment=TA_CENTER, leading=28, spaceAfter=8, fontName="Helvetica-Bold"),
        "subtitle": ParagraphStyle("rpt_sub", fontSize=10, textColor=C_MID,
            alignment=TA_CENTER, leading=14, spaceBefore=4, spaceAfter=14),
        "h1": ParagraphStyle("rpt_h1", fontSize=14, textColor=C_DARK,
            fontName="Helvetica-Bold", spaceBefore=16, spaceAfter=5),
        "h2": ParagraphStyle("rpt_h2", fontSize=11, textColor=C_DARK,
            fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4),
        "h3": ParagraphStyle("rpt_h3", fontSize=9, textColor=C_BLUE,
            fontName="Helvetica-Bold", spaceBefore=7, spaceAfter=3),
        "body": ParagraphStyle("rpt_body", fontSize=9,
            textColor=colors.HexColor("#263238"), leading=14,
            alignment=TA_JUSTIFY, fontName="Helvetica"),
        "mono": ParagraphStyle("rpt_mono", fontSize=8,
            textColor=colors.HexColor("#1a237e"), fontName="Courier",
            leading=11, backColor=colors.HexColor("#e8eaf6"),
            leftIndent=8, rightIndent=8),
        "small": ParagraphStyle("rpt_small", fontSize=7.5, textColor=C_MID, leading=11),
    }


def _kv_table(rows, col1=4*cm):
    t = Table(rows, colWidths=[col1, W_PAGE - col1])
    t.setStyle(TableStyle([
        ("FONTSIZE",       (0,0),(-1,-1), 8.5),
        ("TEXTCOLOR",      (0,0),(0,-1),  C_MID),
        ("TEXTCOLOR",      (1,0),(1,-1),  C_BLACK),
        ("FONTNAME",       (0,0),(0,-1),  "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0,0),(-1,-1), [C_BG, C_WHITE]),
        ("BOX",            (0,0),(-1,-1), 0.4, C_BORDER),
        ("INNERGRID",      (0,0),(-1,-1), 0.25, C_BORDER),
        ("LEFTPADDING",    (0,0),(-1,-1), 6),
        ("RIGHTPADDING",   (0,0),(-1,-1), 6),
        ("TOPPADDING",     (0,0),(-1,-1), 4),
        ("BOTTOMPADDING",  (0,0),(-1,-1), 4),
    ]))
    return t


def _verdict_banner(level, verdict, score, st):
    rc = _risk_color(level)
    bg = _risk_bg(level)
    t = Table([[
        Paragraph(f'<font color="{rc.hexval()}"><b>{level} RISK</b></font>', st["h2"]),
        Paragraph(verdict, st["body"]),
        Paragraph(f'<b>{score*100:.0f}%</b>', st["h2"]),
    ]], colWidths=[3*cm, W_PAGE-6*cm, 3*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,-1), bg),
        ("BOX",           (0,0),(-1,-1), 1.0, rc),
        ("LEFTPADDING",   (0,0),(-1,-1), 10),
        ("TOPPADDING",    (0,0),(-1,-1), 8),
        ("BOTTOMPADDING", (0,0),(-1,-1), 8),
        ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
        ("ALIGN",         (2,0),(2,0),   "CENTER"),
    ]))
    return t


def _checks_table(checks, st):
    """Render a checks dict (doc/audio/video) as a table."""
    rows = [[
        Paragraph("<b>Check</b>",  st["small"]),
        Paragraph("<b>Result</b>", st["small"]),
        Paragraph("<b>Detail</b>", st["small"]),
    ]]
    for key, check in checks.items():
        detected = check.get("detected", False)
        col      = C_RED if detected else C_ACCENT
        label    = "DETECTED" if detected else "CLEAN"
        rows.append([
            Paragraph(key.replace("_"," ").title(), st["small"]),
            Paragraph(f'<font color="{col.hexval()}"><b>{label}</b></font>', st["small"]),
            Paragraph(str(check.get("info",""))[:120], st["small"]),
        ])
    t = Table(rows, colWidths=[4*cm, 2.5*cm, W_PAGE-6.5*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",     (0,0),(-1,0),  C_DARK),
        ("TEXTCOLOR",      (0,0),(-1,0),  C_WHITE),
        ("FONTNAME",       (0,0),(-1,0),  "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0,1),(-1,-1), [C_BG, C_WHITE]),
        ("BOX",            (0,0),(-1,-1), 0.4, C_BORDER),
        ("INNERGRID",      (0,0),(-1,-1), 0.25, C_BORDER),
        ("LEFTPADDING",    (0,0),(-1,-1), 5),
        ("TOPPADDING",     (0,0),(-1,-1), 3),
        ("BOTTOMPADDING",  (0,0),(-1,-1), 3),
        ("FONTSIZE",       (0,0),(-1,-1), 7.5),
    ]))
    return t


def _image_detection_table(detections, st):
    rows = [[
        Paragraph("<b>Test</b>",   st["small"]),
        Paragraph("<b>Result</b>", st["small"]),
    ]]
    for name, detected in detections.items():
        col   = C_RED if detected else C_ACCENT
        label = "DETECTED" if detected else "CLEAN"
        rows.append([
            Paragraph(name.replace(" Analysis","").replace(" Test",""), st["small"]),
            Paragraph(f'<font color="{col.hexval()}"><b>{label}</b></font>', st["small"]),
        ])
    t = Table(rows, colWidths=[6*cm, 4*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",     (0,0),(-1,0),  C_DARK),
        ("TEXTCOLOR",      (0,0),(-1,0),  C_WHITE),
        ("FONTNAME",       (0,0),(-1,0),  "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0,1),(-1,-1), [C_BG, C_WHITE]),
        ("BOX",            (0,0),(-1,-1), 0.4, C_BORDER),
        ("INNERGRID",      (0,0),(-1,-1), 0.25, C_BORDER),
        ("LEFTPADDING",    (0,0),(-1,-1), 5),
        ("TOPPADDING",     (0,0),(-1,-1), 3),
        ("BOTTOMPADDING",  (0,0),(-1,-1), 3),
        ("FONTSIZE",       (0,0),(-1,-1), 7.5),
        ("ALIGN",          (1,0),(-1,-1), "CENTER"),
    ]))
    return t


def _aggregate_chart(batch_results):
    names  = [os.path.basename(r["image_path"])[:22] for r in batch_results]
    scores = [r["overall"]["risk_score"] * 100 for r in batch_results]
    col_map = {"HIGH":"#e53935","MEDIUM":"#f9a825","LOW":"#00d4aa","CLEAN":"#00d4aa"}
    bar_colors = [col_map.get(r["overall"]["risk_level"],"#607d8b") for r in batch_results]

    fig, ax = plt.subplots(figsize=(10, max(3, len(names)*0.5+1.5)), dpi=110)
    fig.patch.set_facecolor("white")
    ax.set_facecolor("#f4f6f8")
    bars = ax.barh(names, scores, color=bar_colors, height=0.6, edgecolor="white")
    ax.set_xlim(0, 115)
    ax.set_xlabel("Risk Score (%)", fontsize=9)
    ax.set_title("Risk Score per File", fontsize=11, fontweight="bold", pad=8)
    for bar, score in zip(bars, scores):
        ax.text(score+1, bar.get_y()+bar.get_height()/2,
                f"{score:.0f}%", va="center", fontsize=8)
    for spine in ["top","right"]:
        ax.spines[spine].set_visible(False)
    ax.xaxis.grid(True, alpha=0.4)
    fig.tight_layout()
    buf = BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", facecolor="white")
    buf.seek(0)
    plt.close(fig)
    img = Image.open(buf)
    buf2 = BytesIO()
    img.save(buf2, format="PNG")
    buf2.seek(0)
    w, h = img.size
    scale = min(W_PAGE/w, 10*cm/h, 1.0)
    return RLImage(buf2, width=w*scale, height=h*scale)


def _pil_to_rl(pil_img, max_w, max_h):
    buf = BytesIO()
    pil_img.save(buf, format="PNG")
    buf.seek(0)
    w, h = pil_img.size
    scale = min(max_w/w, max_h/h, 1.0)
    return RLImage(buf, width=w*scale, height=h*scale)


def _extraction_section(extraction, st):
    flowables = []
    if not extraction or not extraction.get("extraction_attempted"):
        return flowables
    best   = extraction.get("best_result", {})
    best_ch = extraction.get("best_channel","—")
    likely = best.get("likely_message", False)
    col    = C_ACCENT if likely else C_MID
    label  = "YES" if likely else "NO"
    flowables.append(Paragraph(
        f"Best channel: <b>{best_ch}</b>  |  "
        f"Printable ratio: <b>{best.get('printable_ratio',0):.1%}</b>  |  "
        f"Chars: <b>{best.get('length',0)}</b>  |  "
        f"Likely message: <font color='{col.hexval()}'><b>{label}</b></font>",
        st["body"]))
    if likely:
        txt = best.get("text","")[:400]
        flowables.append(Spacer(1, 0.1*cm))
        for i in range(0, len(txt), 80):
            flowables.append(Paragraph(txt[i:i+80], st["mono"]))
    return flowables


# ── Public entry points ───────────────────────────────────────────────────────

def generate_pdf_report(image_path, analysis_results, overall, output_path,
                        extraction_result=None):
    """Single-file wrapper."""
    return generate_batch_report([{
        "image_path":       image_path,
        "analysis_results": analysis_results,
        "overall":          overall,
        "extraction":       extraction_result,
    }], output_path)


def generate_batch_report(batch_results, output_path):
    """
    Works for any mix of images, documents, audio, and video.
    Each entry: {image_path, analysis_results, overall, extraction (optional)}
    """
    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2.2*cm, bottomMargin=2*cm,
        title="Steganography Analysis Report",
        author="Stego Detector",
    )
    st    = _styles()
    story = []
    n     = len(batch_results)
    now   = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")

    high   = sum(1 for r in batch_results if r["overall"].get("risk_level") == "HIGH")
    medium = sum(1 for r in batch_results if r["overall"].get("risk_level") == "MEDIUM")
    low    = n - high - medium

    # ── Cover ────────────────────────────────────────────────────────────────
    story += [
        Spacer(1, 1.2*cm),
        Paragraph("STEGANOGRAPHY ANALYSIS REPORT", st["title"]),
        Paragraph("Universal Forensic Analyzer  ·  Stego Detector", st["subtitle"]),
        HRFlowable(width=W_PAGE, thickness=2.5, color=C_ACCENT, spaceAfter=10),
        Spacer(1, 0.3*cm),
        _kv_table([
            ["Report Generated", now],
            ["Files Analysed",   str(n)],
            ["HIGH Risk",        str(high)],
            ["MEDIUM Risk",      str(medium)],
            ["LOW / CLEAN",      str(low)],
        ], col1=4.5*cm),
        Spacer(1, 0.6*cm),
    ]

    if n > 1:
        story.append(Paragraph("Risk Score Overview", st["h2"]))
        story.append(_aggregate_chart(batch_results))
        story.append(Spacer(1, 0.4*cm))

    story.append(PageBreak())

    # ── Per-file sections ─────────────────────────────────────────────────────
    for idx, result in enumerate(batch_results):
        path       = result["image_path"]
        overall    = result["overall"]
        ar         = result.get("analysis_results", {})
        extraction = result.get("extraction")
        fname      = os.path.basename(path)
        kind       = overall.get("kind", "image")
        ftype      = overall.get("analyzer_type", overall.get("file_type","?"))
        level      = overall.get("risk_level", "LOW")
        verdict    = overall.get("verdict", "Unknown")
        score      = overall.get("risk_score", 0)
        fsize      = overall.get("file_size_bytes", os.path.getsize(path) if os.path.exists(path) else 0)

        story += [
            HRFlowable(width=W_PAGE, thickness=2, color=C_ACCENT, spaceBefore=8, spaceAfter=4),
            Paragraph(f"File {idx+1}: {fname}", st["h1"]),
        ]

        # File info table
        info_rows = [
            ["Filename",    fname],
            ["Type",        ftype],
            ["File size",   f"{fsize/1024:.1f} KB"],
            ["SHA-256",     overall.get("file_hash","?")[:40]+"…"],
        ]
        if kind == "image":
            sz = overall.get("image_size", ("?","?"))
            info_rows.insert(2, ["Dimensions", f"{sz[0]} × {sz[1]} px"])
            info_rows.insert(3, ["Mode", overall.get("image_mode","?")])

        # Try to show image thumbnail
        if kind == "image" and os.path.exists(path):
            try:
                thumb = _pil_to_rl(Image.open(path).convert("RGB"), 5*cm, 4*cm)
                info_t = _kv_table(info_rows, col1=3*cm)
                layout = Table([[thumb, info_t]], colWidths=[5.5*cm, W_PAGE-5.5*cm])
                layout.setStyle(TableStyle([
                    ("VALIGN",      (0,0),(-1,-1), "TOP"),
                    ("LEFTPADDING", (1,0),(1,0),   12),
                ]))
                story.append(layout)
            except Exception:
                story.append(_kv_table(info_rows))
        else:
            story.append(_kv_table(info_rows))

        story += [
            Spacer(1, 0.3*cm),
            _verdict_banner(level, verdict, score, st),
            Spacer(1, 0.3*cm),
            Paragraph(
                f"<b>Tests positive:</b> {overall.get('positive_count',0)}/"
                f"{overall.get('total_tests',0)}   "
                f"<b>Risk score:</b> {score*100:.0f}%   "
                f"<b>Summary:</b> {overall.get('summary','')}",
                st["body"]),
            Spacer(1, 0.3*cm),
        ]

        # Detection results
        story.append(Paragraph("Detection Results", st["h3"]))
        if kind == "image":
            detections = overall.get("detections", {})
            if detections:
                story.append(_image_detection_table(detections, st))
                # Key metrics
                story.append(Spacer(1, 0.2*cm))
                rs_payload = ar.get("rs_analysis",{}).get("average_payload_estimate",0)*100
                lsb_corr   = ar.get("lsb",{}).get("avg_correlation",0)
                chi_p      = ar.get("chi_square",{}).get("average_p_value",1.0)
                story.append(Paragraph(
                    f"<b>Key Metrics:</b> RS payload: <b>{rs_payload:.2f}%</b>  |  "
                    f"LSB correlation: <b>{lsb_corr:.4f}</b>  |  "
                    f"Chi-square p: <b>{chi_p:.4f}</b>  |  "
                    f"Estimated payload: <b>{overall.get('estimated_payload_pct',0):.2f}%</b>",
                    st["body"]))
        else:
            checks = overall.get("checks", {})
            if checks:
                story.append(_checks_table(checks, st))

        story.append(Spacer(1, 0.3*cm))

        # Message extraction (images only)
        if kind == "image" and extraction:
            story.append(Paragraph("LSB Message Extraction", st["h3"]))
            story.extend(_extraction_section(extraction, st))

        story.append(Spacer(1, 0.5*cm))
        if idx < n - 1:
            story.append(PageBreak())

    # ── Footer ────────────────────────────────────────────────────────────────
    story += [
        Spacer(1, 0.8*cm),
        HRFlowable(width=W_PAGE, thickness=0.5, color=C_MID, spaceBefore=8),
        Paragraph(
            "This report is generated automatically by Stego Detector. "
            "Results are probabilistic and based on statistical analysis; "
            "they are not legally conclusive. Findings should be interpreted "
            "alongside domain expertise and corroborated with additional forensic tools.",
            st["small"]),
    ]

    doc.build(story)
    return output_path
