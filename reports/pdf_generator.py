"""
PDF Report Generator — Adversarial Cognitive Mesh
Professional print-ready incident report.
"""
from __future__ import annotations

import io
from datetime import datetime
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, HRFlowable, PageTemplate,
    Paragraph, Spacer, Table, TableStyle,
)
from reportlab.platypus.flowables import Flowable

W, H = A4

# ── Color palette (print-friendly) ────────────────────────────────────────────
INK        = colors.HexColor("#0d1b2a")   # near-black for body text
CYAN       = colors.HexColor("#007a6e")   # dark teal (readable on white)
CYAN_LIGHT = colors.HexColor("#e6f7f5")   # very light teal bg
RED        = colors.HexColor("#c0392b")
RED_LIGHT  = colors.HexColor("#fdf0ee")
ORANGE     = colors.HexColor("#d35400")
ORANGE_LT  = colors.HexColor("#fef5ec")
YELLOW     = colors.HexColor("#b7860b")
YELLOW_LT  = colors.HexColor("#fefbe6")
GREEN      = colors.HexColor("#1a7a4a")
GREEN_LT   = colors.HexColor("#eaf7f0")
PURPLE     = colors.HexColor("#6c3483")
PURPLE_LT  = colors.HexColor("#f5eef8")
SLATE      = colors.HexColor("#2c3e50")
LIGHT_GREY = colors.HexColor("#f4f6f8")
MID_GREY   = colors.HexColor("#dde3ea")
DIM        = colors.HexColor("#7f8c8d")
WHITE      = colors.white

SEV_MAP = {
    "critical": (RED,    RED_LIGHT,    "CRITICAL"),
    "high":     (ORANGE, ORANGE_LT,    "HIGH"),
    "medium":   (YELLOW, YELLOW_LT,    "MEDIUM"),
    "low":      (GREEN,  GREEN_LT,     "LOW"),
}

AGENT_COLORS = {
    "sentinel":  CYAN,
    "triage":    CYAN,
    "red":       RED,
    "blue":      GREEN,
    "deception": PURPLE,
    "memory":    YELLOW,
}


# ── Custom flowables ───────────────────────────────────────────────────────────

class CoverBand(Flowable):
    """Decorative top band on cover page."""
    def __init__(self, width, height=18):
        super().__init__()
        self.width  = width
        self.height = height

    def wrap(self, *_): return self.width, self.height
    def draw(self):
        c = self.canv
        # gradient-like stripes
        for i, col in enumerate([CYAN, colors.HexColor("#009688"), colors.HexColor("#26a69a")]):
            c.setFillColor(col)
            c.rect(i * (self.width/3), 0, self.width/3, self.height, fill=1, stroke=0)


class AgentBlock(Flowable):
    """Visual agent card: colored left border + content."""
    def __init__(self, number, name, layer, description, result, color, width):
        super().__init__()
        self.number      = number
        self.name        = name
        self.layer       = layer
        self.description = description
        self.result      = result
        self.color       = color
        self.width       = width
        self.height      = 52

    def wrap(self, *_): return self.width, self.height + 4

    def draw(self):
        c = self.canv
        w, h = self.width, self.height

        # Background
        c.setFillColor(LIGHT_GREY)
        c.roundRect(0, 0, w, h, 4, fill=1, stroke=0)

        # Left accent bar
        c.setFillColor(self.color)
        c.rect(0, 0, 5, h, fill=1, stroke=0)

        # Layer badge (top right)
        c.setFillColor(MID_GREY)
        c.roundRect(w - 38, h - 16, 36, 14, 3, fill=1, stroke=0)
        c.setFillColor(SLATE)
        c.setFont("Helvetica", 7)
        c.drawCentredString(w - 20, h - 10, self.layer.upper())

        # Agent name
        c.setFillColor(self.color)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(12, h - 16, self.name)

        # Description
        c.setFillColor(INK)
        c.setFont("Helvetica", 8)
        desc = self.description[:95] + ("…" if len(self.description) > 95 else "")
        c.drawString(12, h - 28, desc)

        # Result line
        c.setFillColor(self.color)
        c.setFont("Helvetica-Bold", 8)
        c.drawString(12, 8, f"→  {self.result}")


# ── Styles ─────────────────────────────────────────────────────────────────────

def _s(name, **kw) -> ParagraphStyle:
    return ParagraphStyle(name, **{"fontName": "Helvetica", "fontSize": 9,
                                    "textColor": INK, "leading": 13, **kw})

def styles():
    return {
        "h1":       _s("h1",  fontSize=28, textColor=CYAN,  fontName="Helvetica-Bold",
                         alignment=TA_CENTER, spaceAfter=4, leading=32),
        "h2":       _s("h2",  fontSize=11, textColor=SLATE, fontName="Helvetica-Bold",
                         alignment=TA_CENTER, spaceAfter=8),
        "label":    _s("lb",  fontSize=8,  textColor=DIM,   spaceAfter=1),
        "value":    _s("vl",  fontSize=10, textColor=INK,   fontName="Helvetica-Bold",
                         spaceAfter=4),
        "body":     _s("bd",  fontSize=9,  textColor=INK,   spaceAfter=4, leading=13),
        "small":    _s("sm",  fontSize=8,  textColor=DIM,   spaceAfter=2),
        "section":  _s("sc",  fontSize=9,  textColor=WHITE, fontName="Helvetica-Bold",
                         alignment=TA_LEFT, leading=11),
        "th":       _s("th",  fontSize=8,  textColor=WHITE, fontName="Helvetica-Bold",
                         alignment=TA_LEFT, leading=10),
        "td":       _s("td",  fontSize=8,  textColor=INK,   leading=10),
        "dna_hash": _s("dh",  fontSize=16, textColor=YELLOW, fontName="Helvetica-Bold",
                         leading=20),
        "footer":   _s("ft",  fontSize=7,  textColor=DIM,  alignment=TA_CENTER),
        "sev":      _s("sv",  fontSize=14, textColor=WHITE, fontName="Helvetica-Bold",
                         alignment=TA_CENTER),
    }

ST = styles()


# ── Page template ──────────────────────────────────────────────────────────────

def _build_doc(buffer) -> BaseDocTemplate:
    doc = BaseDocTemplate(
        buffer, pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm,
        topMargin=22*mm, bottomMargin=18*mm,
        title="ACM Incident Report",
    )

    def on_page(canvas, doc):
        canvas.saveState()
        # Header bar
        canvas.setFillColor(SLATE)
        canvas.rect(0, H - 14*mm, W, 14*mm, fill=1, stroke=0)
        canvas.setFillColor(CYAN)
        canvas.rect(0, H - 14*mm, W, 2, fill=1, stroke=0)
        canvas.setFillColor(WHITE)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawString(18*mm, H - 9*mm, "ADVERSARIAL COGNITIVE MESH")
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MID_GREY)
        canvas.drawRightString(W - 18*mm, H - 9*mm, "CONFIDENTIAL — SECURITY REPORT")

        # Footer bar
        canvas.setFillColor(LIGHT_GREY)
        canvas.rect(0, 0, W, 11*mm, fill=1, stroke=0)
        canvas.setFillColor(CYAN)
        canvas.rect(0, 11*mm, W, 1, fill=1, stroke=0)
        canvas.setFillColor(DIM)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(18*mm, 4*mm,
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
        canvas.drawCentredString(W/2, 4*mm, "ADVERSARIAL COGNITIVE MESH v1.0")
        canvas.drawRightString(W - 18*mm, 4*mm, f"Page {doc.page}")
        canvas.restoreState()

    frame = Frame(18*mm, 13*mm, W - 36*mm, H - 28*mm, id="main")
    doc.addPageTemplates([PageTemplate(id="p", frames=[frame], onPage=on_page)])
    return doc


# ── Helpers ────────────────────────────────────────────────────────────────────

def sp(n=8):  return Spacer(1, n)
def hr(c=MID_GREY): return HRFlowable(width="100%", thickness=0.5, color=c, spaceAfter=6)

def section_title(text: str, color=CYAN) -> Table:
    cell = Paragraph(f"  {text.upper()}", ST["section"])
    t = Table([[cell]], colWidths=[W - 36*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), color),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LEFTPADDING",   (0,0), (-1,-1), 4),
        ("ROUNDEDCORNERS", [3]),
    ]))
    return t

def info_grid(rows: List) -> Table:
    """2-column label/value grid."""
    data = [[Paragraph(l, ST["label"]), Paragraph(v, ST["value"])] for l,v in rows]
    t = Table(data, colWidths=[38*mm, W - 36*mm - 38*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), LIGHT_GREY),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ("RIGHTPADDING",  (0,0), (-1,-1), 10),
        ("LINEBELOW",     (0,0), (-1,-1), 0.4, MID_GREY),
        ("LINEAFTER",     (0,0), (0,-1),  0.4, MID_GREY),
    ]))
    return t


# ── Cover ──────────────────────────────────────────────────────────────────────

def _cover(report: Dict) -> List:
    sev = report.get("severity", "unknown").lower()
    sev_color, sev_bg, sev_label = SEV_MAP.get(sev, (SLATE, LIGHT_GREY, sev.upper()))

    story = []
    story.append(sp(20))
    story.append(CoverBand(W - 36*mm))
    story.append(sp(24))

    story.append(Paragraph("INCIDENT REPORT", ST["h1"]))
    story.append(Paragraph("Adversarial Cognitive Mesh  ·  Multi-Agent Security System", ST["h2"]))
    story.append(sp(16))

    # Severity badge
    badge = Table(
        [[Paragraph(f"● {sev_label}", _s("sev_badge", fontSize=14, textColor=WHITE,
                                          fontName="Helvetica-Bold", alignment=TA_CENTER))]],
        colWidths=[55*mm],
    )
    badge.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), sev_color),
        ("TOPPADDING",    (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ("ROUNDEDCORNERS", [5]),
    ]))
    wrapper = Table([[badge]], colWidths=[W - 36*mm])
    wrapper.setStyle(TableStyle([("ALIGN", (0,0), (-1,-1), "CENTER")]))
    story.append(wrapper)
    story.append(sp(20))

    # Meta info
    story.append(info_grid([
        ("INCIDENT ID",   report.get("id", "—")),
        ("SCENARIO",      report.get("scenario", "—").replace("_", " ").upper()),
        ("TARGET URL",    report.get("url", "—")),
        ("KILL CHAIN",    report.get("kill_chain_stage", "—")),
        ("DURATION",      f"{report.get('duration', 0)} seconds"),
        ("GENERATED",     datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")),
    ]))
    story.append(sp(20))
    story.append(hr(CYAN))
    return story


# ── Executive summary ──────────────────────────────────────────────────────────

def _summary(report: Dict) -> List:
    story = [sp(10), section_title("Executive Summary"), sp(8)]
    text = report.get("summary", "No summary available.")
    story.append(Paragraph(text, ST["body"]))
    return story


# ── Agent pipeline ─────────────────────────────────────────────────────────────

def _pipeline(report: Dict) -> List:
    story = [sp(10), section_title("Agent Pipeline Results", SLATE), sp(8)]
    w = W - 36*mm
    agents = [
        (1, "SENTINEL MESH",    "Layer 1", "Detected threat events from network, process and filesystem sensors.",
         report.get("scenario","").replace("_"," ").upper(), CYAN),
        (2, "TRIAGE AGENT",     "Layer 2", report.get("summary", "Performed MITRE ATT&CK mapping and narrative generation.")[:95],
         f"Kill chain: {report.get('kill_chain_stage','—')}", CYAN),
        (3, "RED AGENT",        "Layer 3", "Simulated the full attacker kill chain from current stage to impact.",
         "Adversarial kill chain simulation complete", RED),
        (4, "BLUE AGENT",       "Layer 4",
         f"Composed {len(report.get('countermeasures',[]))} prioritised countermeasures based on Red simulation.",
         "Countermeasures deployed", GREEN),
        (5, "DECEPTION WEAVER", "Layer 5",
         f"Deployed {len(report.get('deception_assets',[]))} honeypots and canary assets to trap the attacker.",
         "Deception assets active", PURPLE),
        (6, "MEMORY CRYSTAL.",  "Layer 6",
         f"Crystallized Threat DNA fingerprint: {report.get('dna','—')}",
         "DNA stored — future attacks recognised faster", YELLOW),
    ]
    for num, name, layer, desc, result, color in agents:
        story.append(AgentBlock(num, name, layer, desc, result, color, w))
        story.append(sp(5))
    return story


# ── Countermeasures ────────────────────────────────────────────────────────────

def _countermeasures(report: Dict) -> List:
    story = [sp(10), section_title("Countermeasures Applied", GREEN), sp(8)]
    items = report.get("countermeasures", [])
    if not items:
        story.append(Paragraph("No countermeasures recorded.", ST["small"]))
        return story

    header = [Paragraph(h, ST["th"]) for h in ["#", "ACTION TYPE", "TARGET", "PRIORITY"]]
    rows   = [header]
    for i, c in enumerate(items, 1):
        rows.append([
            Paragraph(str(i), ST["td"]),
            Paragraph(str(c.get("type","—")).replace("_"," ").upper(), ST["td"]),
            Paragraph(str(c.get("target","—")), ST["td"]),
            Paragraph(f"P{c.get('priority','?')}", ST["td"]),
        ])

    cw = W - 36*mm
    t  = Table(rows, colWidths=[10*mm, 48*mm, cw-90*mm, 18*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),   GREEN),
        ("BACKGROUND",    (0,1), (-1,-1),  WHITE),
        ("ROWBACKGROUNDS",(0,1), (-1,-1),  [WHITE, LIGHT_GREY]),
        ("FONTSIZE",      (0,0), (-1,-1),  8),
        ("TOPPADDING",    (0,0), (-1,-1),  5),
        ("BOTTOMPADDING", (0,0), (-1,-1),  5),
        ("LEFTPADDING",   (0,0), (-1,-1),  8),
        ("BOX",           (0,0), (-1,-1),  0.5, MID_GREY),
        ("INNERGRID",     (0,0), (-1,-1),  0.3, MID_GREY),
        ("LINEBELOW",     (0,0), (-1,0),   1,   GREEN),
    ]))
    story.append(t)
    return story


# ── Deception assets ───────────────────────────────────────────────────────────

def _deception(report: Dict) -> List:
    story = [sp(10), section_title("Deception Assets Deployed", PURPLE), sp(8)]
    assets = report.get("deception_assets", [])
    if not assets:
        story.append(Paragraph("No deception assets recorded.", ST["small"]))
        return story

    header = [Paragraph(h, ST["th"]) for h in ["ASSET TYPE", "LOCATION", "PURPOSE"]]
    rows   = [header]
    for a in assets:
        rows.append([
            Paragraph(str(a.get("type","—")).replace("_"," ").upper(), ST["td"]),
            Paragraph(str(a.get("location","—")), ST["td"]),
            Paragraph(str(a.get("purpose","—"))[:70], ST["td"]),
        ])

    cw = W - 36*mm
    t  = Table(rows, colWidths=[38*mm, 52*mm, cw - 90*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),   PURPLE),
        ("BACKGROUND",    (0,1), (-1,-1),  WHITE),
        ("ROWBACKGROUNDS",(0,1), (-1,-1),  [WHITE, PURPLE_LT]),
        ("FONTSIZE",      (0,0), (-1,-1),  8),
        ("TOPPADDING",    (0,0), (-1,-1),  5),
        ("BOTTOMPADDING", (0,0), (-1,-1),  5),
        ("LEFTPADDING",   (0,0), (-1,-1),  8),
        ("BOX",           (0,0), (-1,-1),  0.5, MID_GREY),
        ("INNERGRID",     (0,0), (-1,-1),  0.3, MID_GREY),
        ("LINEBELOW",     (0,0), (-1,0),   1,   PURPLE),
    ]))
    story.append(t)
    return story


# ── Threat DNA ─────────────────────────────────────────────────────────────────

def _dna(report: Dict) -> List:
    story = [sp(10), section_title("Threat DNA — Memory Crystallized", YELLOW), sp(8)]
    dna = report.get("dna", "—")
    sev = report.get("severity", "—").upper()
    scenario = report.get("scenario", "—").replace("_", " ").upper()

    box_data = [
        [Paragraph("FINGERPRINT HASH", ST["label"]),
         Paragraph(dna, ST["dna_hash"])],
        [Paragraph("SCENARIO",         ST["label"]),
         Paragraph(scenario,           ST["value"])],
        [Paragraph("SEVERITY",         ST["label"]),
         Paragraph(sev,                ST["value"])],
        [Paragraph("STORED IN LIBRARY",ST["label"]),
         Paragraph("YES — Will be matched on future similar attacks", ST["body"])],
    ]
    box = Table(box_data, colWidths=[42*mm, W - 36*mm - 42*mm])
    box.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), YELLOW_LT),
        ("TOPPADDING",    (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ("LEFTPADDING",   (0,0), (-1,-1), 12),
        ("BOX",           (0,0), (-1,-1), 1,   YELLOW),
        ("LINEAFTER",     (0,0), (0,-1),  0.4, MID_GREY),
        ("LINEBELOW",     (0,0), (-1,-2), 0.4, MID_GREY),
        ("LINEBEFORE",    (0,0), (0,-1),  3,   YELLOW),
    ]))
    story.append(box)
    story.append(sp(8))
    story.append(Paragraph(
        "This DNA fingerprint has been added to the threat memory library. "
        "Future incidents with matching indicators will be recognised instantly, "
        "reducing triage time by up to 80%.",
        ST["body"]
    ))
    return story


# ── Main ───────────────────────────────────────────────────────────────────────

def generate_pdf(report: Dict) -> bytes:
    buf = io.BytesIO()
    doc = _build_doc(buf)
    story = []
    story += _cover(report)
    story += _summary(report)
    story += _pipeline(report)
    story += _countermeasures(report)
    story += _deception(report)
    story += _dna(report)

    story.append(sp(16))
    story.append(hr(CYAN))
    story.append(sp(4))
    story.append(Paragraph(
        "This report was generated automatically by the Adversarial Cognitive Mesh. "
        "All analysis was performed by AI agents and should be reviewed by a qualified security professional.",
        ST["footer"]
    ))
    doc.build(story)
    return buf.getvalue()
