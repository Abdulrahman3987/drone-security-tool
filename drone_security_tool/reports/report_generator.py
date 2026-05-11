"""
PDF report generator for the Drone Security Assessment Tool.

Uses reportlab.platypus for a clean, responsive layout:
    - Risk-score card with color-coded band (Normal / Suspicious / Attack)
    - Score breakdown (ISOT-informed weights that contributed to the score)
    - Ranked list of likely ISOT attack categories
    - Drone fingerprint table
    - Vulnerability cards with severity pill + attack-category tag
    - Safe-test results table
    - AI analysis section
    - Page footer with page numbers
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from ai.vulnerability_engine import AnalysisReport, VulnerabilityFinding
from scanner.fingerprint import DroneFingerprint
from tests.safe_tests import SafeTestResults


# ---------------------------------------------------------------------------
# Palette
# ---------------------------------------------------------------------------
PRIMARY      = colors.HexColor("#1a365d")   # navy
ACCENT       = colors.HexColor("#0d9488")   # teal
TEXT_DARK    = colors.HexColor("#0f172a")
TEXT_MED     = colors.HexColor("#475569")
TEXT_LIGHT   = colors.HexColor("#94a3b8")
CARD_BG      = colors.HexColor("#f8fafc")
CARD_BORDER  = colors.HexColor("#e2e8f0")
ROW_ALT      = colors.HexColor("#f1f5f9")

BAND_COLORS = {
    "Normal":     colors.HexColor("#10b981"),   # green
    "Suspicious": colors.HexColor("#f59e0b"),   # amber
    "Attack":     colors.HexColor("#ef4444"),   # red
}

SEVERITY_COLORS = {
    "Low":      colors.HexColor("#3b82f6"),
    "Medium":   colors.HexColor("#f59e0b"),
    "High":     colors.HexColor("#f97316"),
    "Critical": colors.HexColor("#dc2626"),
}


def _risk_band(score: int) -> str:
    if score <= 30:
        return "Normal"
    if score <= 69:
        return "Suspicious"
    return "Attack"


def _band_description(band: str) -> str:
    return {
        "Normal":     "No significant attack surface detected.",
        "Suspicious": "Exploitable conditions present. Investigate.",
        "Attack":     "One or more attacks are trivially feasible.",
    }.get(band, "")


# ---------------------------------------------------------------------------
# Page header / footer
# ---------------------------------------------------------------------------
def _on_page(canvas, doc) -> None:
    canvas.saveState()
    template = getattr(doc, "report_template", {})
    footer = template.get("footer", "Drone Security Assessment Tool")
    accent = colors.HexColor(template.get("accent_color", "#0d9488"))

    # Thin accent stripe at the top of every page
    canvas.setFillColor(accent)
    canvas.rect(0, LETTER[1] - 6, LETTER[0], 6, stroke=0, fill=1)

    # Footer
    canvas.setFillColor(TEXT_LIGHT)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(0.75 * inch, 0.4 * inch, footer)
    canvas.drawRightString(
        LETTER[0] - 0.75 * inch, 0.4 * inch, f"Page {doc.page}"
    )
    canvas.setStrokeColor(CARD_BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(
        0.75 * inch, 0.55 * inch, LETTER[0] - 0.75 * inch, 0.55 * inch
    )

    canvas.restoreState()


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------
class ReportGenerator:
    def __init__(
        self,
        output_dir: str = "reports",
        template_path: Optional[str] = None,
    ) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        default_template = Path(__file__).resolve().parent / "report_template.json"
        self.template_path = Path(template_path) if template_path else default_template
        self.template = self._load_template()
        self.styles = self._make_styles()

    def _load_template(self) -> dict:
        if not self.template_path.exists():
            return {}
        try:
            with open(self.template_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return {}

    # ---- style registry ---------------------------------------------------
    def _make_styles(self) -> dict:
        base = getSampleStyleSheet()
        return {
            "title": ParagraphStyle(
                "title", parent=base["Title"],
                fontName="Helvetica-Bold", fontSize=22, leading=26,
                textColor=PRIMARY, spaceAfter=4,
            ),
            "subtitle": ParagraphStyle(
                "subtitle", parent=base["Normal"],
                fontName="Helvetica", fontSize=10, leading=13,
                textColor=TEXT_MED, spaceAfter=2,
            ),
            "h1": ParagraphStyle(
                "h1", parent=base["Heading1"],
                fontName="Helvetica-Bold", fontSize=14, leading=18,
                textColor=PRIMARY, spaceBefore=10, spaceAfter=6,
            ),
            "h2": ParagraphStyle(
                "h2", parent=base["Heading2"],
                fontName="Helvetica-Bold", fontSize=12, leading=16,
                textColor=TEXT_DARK, spaceBefore=4, spaceAfter=4,
            ),
            "body": ParagraphStyle(
                "body", parent=base["Normal"],
                fontName="Helvetica", fontSize=10, leading=14,
                textColor=TEXT_DARK, spaceAfter=3,
            ),
            "body_muted": ParagraphStyle(
                "body_muted", parent=base["Normal"],
                fontName="Helvetica", fontSize=9.5, leading=13,
                textColor=TEXT_MED, spaceAfter=3,
            ),
            "bullet": ParagraphStyle(
                "bullet", parent=base["Normal"],
                fontName="Helvetica", fontSize=10, leading=14,
                textColor=TEXT_DARK, leftIndent=14, bulletIndent=4, spaceAfter=2,
            ),
            "score_big": ParagraphStyle(
                "score_big", parent=base["Title"],
                fontName="Helvetica-Bold", fontSize=44, leading=48,
                textColor=colors.white, alignment=TA_CENTER,
            ),
            "score_slash": ParagraphStyle(
                "score_slash", parent=base["Normal"],
                fontName="Helvetica", fontSize=11, leading=13,
                textColor=colors.whitesmoke, alignment=TA_CENTER,
            ),
            "band_label": ParagraphStyle(
                "band_label", parent=base["Normal"],
                fontName="Helvetica-Bold", fontSize=16, leading=20,
                textColor=colors.white,
            ),
            "band_desc": ParagraphStyle(
                "band_desc", parent=base["Normal"],
                fontName="Helvetica", fontSize=10, leading=13,
                textColor=colors.whitesmoke,
            ),
        }

    # ---- public entry point ----------------------------------------------
    def generate(
        self,
        filepath: str,
        fingerprint: DroneFingerprint,
        analysis: AnalysisReport,
        tests: Optional[SafeTestResults] = None,
        ai_explanation: str = "",
        sim_source: Optional[str] = None,
    ) -> Path:
        path = Path(filepath)
        if not path.is_absolute():
            path = self.output_dir / path
            self.output_dir.mkdir(parents=True, exist_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(
            str(path),
            pagesize=LETTER,
            leftMargin=0.75 * inch,
            rightMargin=0.75 * inch,
            topMargin=0.7 * inch,
            bottomMargin=0.75 * inch,
            title=self.template.get("title", "Drone Security Assessment Report"),
            author="Drone Security Assessment Tool",
        )
        doc.report_template = self.template

        story: list = []
        story += self._header(sim_source)
        story += self._score_card(analysis)
        story += self._score_breakdown(analysis)
        story += self._likely_attacks(analysis)
        story += self._fingerprint_section(fingerprint)
        story += self._vulnerabilities_section(analysis.vulnerabilities)
        story += self._safe_tests_section(tests)
        story += self._ai_section(ai_explanation)

        doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
        return path

    # ----------------------------------------------------------------------
    # Section builders
    # ----------------------------------------------------------------------
    def _header(self, sim_source: Optional[str]) -> list:
        s = self.styles
        title = self.template.get("title", "Drone Security Assessment Report")
        subtitle = self.template.get(
            "subtitle",
            "Security posture summary for live and simulated drone scans",
        )
        classification = self.template.get("classification", "Assessment Report")
        analyst = self.template.get("analyst", "")
        flow: list = [
            Paragraph(title, s["title"]),
            Paragraph(subtitle, s["subtitle"]),
            Paragraph(
                f"{classification} - generated {datetime.utcnow():%Y-%m-%d %H:%M UTC}",
                s["subtitle"],
            ),
        ]
        if analyst:
            flow.append(Paragraph(f"<b>Analyst:</b> {analyst}", s["subtitle"]))
        if sim_source:
            flow.append(Paragraph(
                f"<b>Scan type:</b> Simulated — source: {sim_source}",
                s["subtitle"],
            ))
        else:
            flow.append(Paragraph(
                "<b>Scan type:</b> Live drone scan", s["subtitle"]
            ))
        flow.append(Spacer(1, 6))
        flow.append(HRFlowable(
            width="100%", thickness=0.6, color=CARD_BORDER,
            spaceAfter=10,
        ))
        return flow

    def _score_card(self, analysis: AnalysisReport) -> list:
        s = self.styles
        score = int(analysis.risk_score or 0)
        band = _risk_band(score)
        band_color = BAND_COLORS[band]
        source = (
            "Machine Learning (ISOT trained)"
            if analysis.ml_available
            else "Rule-based (ISOT-informed)"
        )

        # Left: the big number. Right: band label + description + source.
        score_cell = [
            Paragraph(f"<b>{score}</b>", s["score_big"]),
            Paragraph("/ 100", s["score_slash"]),
        ]
        right_cell = [
            Paragraph(band.upper(), s["band_label"]),
            Paragraph(_band_description(band), s["band_desc"]),
            Spacer(1, 4),
            Paragraph(f"<i>Scoring method: {source}</i>", s["band_desc"]),
        ]

        if analysis.ml_available and analysis.ml_prediction:
            conf = (analysis.ml_confidence or 0) * 100
            right_cell.append(Paragraph(
                f"<i>ML verdict: {analysis.ml_prediction} "
                f"({conf:.1f}% confidence)</i>",
                s["band_desc"],
            ))

        card = Table(
            [[score_cell, right_cell]],
            colWidths=[1.8 * inch, 5.2 * inch],
        )
        card.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), band_color),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 16),
            ("RIGHTPADDING", (0, 0), (-1, -1), 16),
            ("TOPPADDING", (0, 0), (-1, -1), 14),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
            ("ROUNDEDCORNERS", [8, 8, 8, 8]),
        ]))
        return [card, Spacer(1, 12)]

    def _score_breakdown(self, analysis: AnalysisReport) -> list:
        if not analysis.score_breakdown:
            return []
        s = self.styles
        heading = (
            "Risk Factors Observed"
            if analysis.ml_available
            else "Score Breakdown"
        )
        note = (
            "The ML model produced the score above. "
            "These are the rule-based factors observed in the same scan."
            if analysis.ml_available
            else "Each factor below contributed directly to the score."
        )
        flow = [
            Paragraph(heading, s["h1"]),
            Paragraph(note, s["body_muted"]),
            Spacer(1, 4),
        ]
        for item in analysis.score_breakdown:
            flow.append(Paragraph(f"• {item}", s["bullet"]))
        flow.append(Spacer(1, 8))
        return flow

    def _likely_attacks(self, analysis: AnalysisReport) -> list:
        if not analysis.likely_attacks:
            return []
        s = self.styles

        # Build a row of colored "chips" for each attack category.
        chips = []
        for name in analysis.likely_attacks:
            chip = Table(
                [[Paragraph(f"<b>{name}</b>", ParagraphStyle(
                    "chip", fontName="Helvetica-Bold",
                    fontSize=9, textColor=colors.white, alignment=TA_CENTER,
                ))]],
                colWidths=[max(0.9 * inch, 0.12 * inch * len(name) + 0.45 * inch)],
            )
            chip.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), PRIMARY),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            chips.append(chip)

        # Layout chips in a horizontal row table
        chip_row = Table([chips], colWidths=[None] * len(chips))
        chip_row.setStyle(TableStyle([
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))

        return [
            Paragraph("Likely Attack Vectors", s["h1"]),
            Paragraph(
                "ISOT attack categories that are feasible given the observed posture, "
                "ranked from most to least feasible.",
                s["body_muted"],
            ),
            Spacer(1, 4),
            chip_row,
            Spacer(1, 12),
        ]

    def _fingerprint_section(self, fp: DroneFingerprint) -> list:
        s = self.styles
        rows = []
        for line in fp.summary().splitlines():
            if ":" in line:
                key, val = line.split(":", 1)
                rows.append([
                    Paragraph(f"<b>{key.strip()}</b>", s["body"]),
                    Paragraph(val.strip() or "—", s["body"]),
                ])
            else:
                rows.append([Paragraph(line, s["body"]), Paragraph("", s["body"])])

        if not rows:
            rows = [[Paragraph("No fingerprint data collected.", s["body_muted"]), ""]]

        tbl = Table(rows, colWidths=[1.8 * inch, 5.2 * inch])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), CARD_BG),
            ("BOX", (0, 0), (-1, -1), 0.5, CARD_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, CARD_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [CARD_BG, ROW_ALT]),
        ]))

        return [
            Paragraph("Drone Fingerprint", s["h1"]),
            tbl,
            Spacer(1, 12),
        ]

    def _vulnerabilities_section(
        self, findings: List[VulnerabilityFinding]
    ) -> list:
        s = self.styles
        flow: list = [Paragraph("Vulnerabilities", s["h1"])]

        if not findings:
            flow.append(Paragraph(
                "No rule-based findings were generated for this scan.",
                s["body_muted"],
            ))
            flow.append(Spacer(1, 10))
            return flow

        for finding in findings:
            flow.append(self._finding_card(finding))
            flow.append(Spacer(1, 8))
        return flow

    def _finding_card(self, f: VulnerabilityFinding):
        s = self.styles
        sev_color = SEVERITY_COLORS.get(f.severity, TEXT_MED)

        # Severity pill (small, right-aligned on header row)
        pill = Table(
            [[Paragraph(
                f"<b>{f.severity.upper()}</b>",
                ParagraphStyle(
                    "pill", fontName="Helvetica-Bold", fontSize=8,
                    textColor=colors.white, alignment=TA_CENTER,
                ),
            )]],
            colWidths=[0.75 * inch],
        )
        pill.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), sev_color),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))

        header_row = Table(
            [[Paragraph(f"<b>{f.title}</b>", s["h2"]), pill]],
            colWidths=[5.6 * inch, 0.85 * inch],
        )
        header_row.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))

        inner: list = [header_row]
        if f.attack_category:
            inner.append(Paragraph(
                f"<b>Enables:</b> {f.attack_category}  "
                f"<font color='#94a3b8'>·</font>  "
                f"<b>Feasibility:</b> {f.attack_feasibility}",
                s["body_muted"],
            ))
        else:
            inner.append(Paragraph(
                f"<b>Feasibility:</b> {f.attack_feasibility}",
                s["body_muted"],
            ))
        inner.append(Spacer(1, 3))
        inner.append(Paragraph(f.explanation, s["body"]))
        inner.append(Spacer(1, 3))
        inner.append(Paragraph(
            f"<b>Recommendation:</b> {f.recommendation}", s["body_muted"]
        ))

        card = Table([[inner]], colWidths=[6.6 * inch])
        card.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), CARD_BG),
            ("BOX", (0, 0), (-1, -1), 0.5, CARD_BORDER),
            ("LINEBEFORE", (0, 0), (0, -1), 3, sev_color),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]))
        return KeepTogether(card)

    def _safe_tests_section(self, tests: Optional[SafeTestResults]) -> list:
        s = self.styles
        flow: list = [Paragraph("Safe Test Results", s["h1"])]

        if not tests or not tests.ping:
            flow.append(Paragraph(
                "Safe tests were not performed (simulation or no connectivity).",
                s["body_muted"],
            ))
            flow.append(Spacer(1, 10))
            return flow

        ping_status = "Success" if tests.ping.success else "Failed"
        loss = (
            f"{tests.ping.packet_loss:.1f}%"
            if tests.ping.packet_loss is not None
            else "n/a"
        )
        latency = (
            f"{tests.latency.average_ms:.1f} ms ({tests.latency.samples} samples)"
            if tests.latency and tests.latency.average_ms is not None
            else f"{tests.latency.samples if tests.latency else 0} samples"
        )
        packet = (
            f"{'OK' if tests.packet.success else 'Failed'} — {tests.packet.note}"
            if tests.packet
            else "Not run"
        )

        rows = [
            [Paragraph("<b>Test</b>", s["body"]),
             Paragraph("<b>Result</b>", s["body"])],
            [Paragraph("Ping reachability", s["body"]),
             Paragraph(f"{ping_status} (loss: {loss})", s["body"])],
            [Paragraph("Round-trip latency", s["body"]),
             Paragraph(latency, s["body"])],
            [Paragraph("Diagnostic packet", s["body"]),
             Paragraph(packet, s["body"])],
        ]
        tbl = Table(rows, colWidths=[2.2 * inch, 4.8 * inch])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BOX", (0, 0), (-1, -1), 0.5, CARD_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, CARD_BORDER),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ROW_ALT]),
        ]))
        flow.append(tbl)
        flow.append(Spacer(1, 12))
        return flow

    def _ai_section(self, ai_explanation: str) -> list:
        s = self.styles
        if not ai_explanation or not ai_explanation.strip():
            return []

        flow: list = [Paragraph("AI Analysis", s["h1"])]
        for paragraph in ai_explanation.split("\n"):
            paragraph = paragraph.strip()
            if paragraph:
                # Escape angle-bracket chars so reportlab doesn't parse them as tags.
                safe = paragraph.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                flow.append(Paragraph(safe, s["body"]))
            else:
                flow.append(Spacer(1, 4))
        return flow
