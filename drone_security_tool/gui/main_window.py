"""
PyQt5 main window for the Drone Security Assessment Tool.

Layout:
    - Hero header with title + subtitle
    - Risk-score card with colored band + status text
    - Left column: Live Scan controls + Simulation controls + Report button
    - Right column: Tabs -> Scan Log / Vulnerabilities / Risk Breakdown / AI Analysis
"""
from __future__ import annotations

import html
import json
import random
from pathlib import Path
from typing import List, Optional

from PyQt5.QtCore import QObject, Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QFileDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ai.vulnerability_engine import AnalysisReport, VulnerabilityEngine, VulnerabilityFinding
from ai.ai_explainer import generate_ai_explanation
from reports.report_generator import ReportGenerator
from scanner.fake_scan import FakeDroneScenario
from scanner.fingerprint import DroneFingerprint
from scanner.port_scanner import PortScanner, PortStatus
from scanner.protocol_detector import ProtocolDetector, ProtocolObservation
from scanner.wifi_scanner import WiFiNetwork, WiFiScanner
from tests.safe_tests import (
    LatencyResult,
    PacketSendResult,
    PingTestResult,
    SafeTestResults,
    SafeTestRunner,
)
from utils.helpers import friendly_join, LOGGER


# ---------------------------------------------------------------------------
# Persistent user config
# ---------------------------------------------------------------------------
_USER_CONFIG_PATH = Path(__file__).resolve().parent.parent / "user_config.json"


def _load_user_config() -> dict:
    if _USER_CONFIG_PATH.exists():
        try:
            with open(_USER_CONFIG_PATH, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_user_config(cfg: dict) -> None:
    with open(_USER_CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)


# ---------------------------------------------------------------------------
# Palette — refined dark theme with deeper navy + vivid accents
# ---------------------------------------------------------------------------
BG_APP        = "#0a0d1c"   # deeper background
BG_GRADIENT_2 = "#10142a"   # gradient stop
BG_CARD       = "#161a33"   # card surface
BG_CARD_HI    = "#1f2447"   # elevated card / inputs
BG_CARD_HOVER = "#252b54"
BORDER        = "#2d335c"
BORDER_HI     = "#3b4280"
TEXT_PRIMARY  = "#eef1fb"
TEXT_MUTED    = "#8c97bd"
TEXT_DIM      = "#5f6993"
ACCENT_TEAL   = "#2dd4bf"
ACCENT_TEAL_HI= "#5eead4"
ACCENT_PURPLE = "#a78bfa"
ACCENT_BLUE   = "#3b82f6"
ACCENT_PINK   = "#f472b6"

BAND_NORMAL     = "#22c55e"
BAND_SUSPICIOUS = "#f59e0b"
BAND_ATTACK     = "#ef4444"

SEVERITY_COLOR = {
    "Low":      "#3b82f6",
    "Medium":   "#f59e0b",
    "High":     "#f97316",
    "Critical": "#dc2626",
}


STYLESHEET = f"""
QMainWindow {{
    background-color: {BG_APP};
}}
QWidget#central {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 {BG_APP}, stop:1 {BG_GRADIENT_2}
    );
}}

QLabel {{
    color: {TEXT_PRIMARY};
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 14px;
}}
QLabel#title_label {{
    font-size: 30px;
    font-weight: 800;
    color: {TEXT_PRIMARY};
    letter-spacing: 0.3px;
    padding-bottom: 0;
}}
QLabel#title_glyph {{
    font-size: 34px;
    color: {ACCENT_TEAL};
    padding-right: 6px;
}}
QLabel#subtitle_label {{
    font-size: 14px;
    color: {TEXT_MUTED};
    font-weight: 500;
    letter-spacing: 0.2px;
}}
QLabel#status_pill {{
    background-color: rgba(45, 212, 191, 0.12);
    color: {ACCENT_TEAL};
    font-weight: 700;
    font-size: 13px;
    letter-spacing: 0.6px;
    padding: 7px 14px;
    border-radius: 13px;
    border: 1px solid rgba(45, 212, 191, 0.35);
}}
QLabel#score_label {{
    font-size: 64px;
    font-weight: 900;
}}
QLabel#score_slash {{
    font-size: 13px;
    color: {TEXT_DIM};
    letter-spacing: 1px;
}}
QLabel#band_label {{
    font-size: 20px;
    font-weight: 800;
    letter-spacing: 2px;
}}
QLabel#band_desc {{
    font-size: 14px;
    color: {TEXT_MUTED};
}}
QLabel#section_label {{
    font-size: 12px;
    font-weight: 700;
    color: {TEXT_DIM};
    letter-spacing: 1px;
}}
QLabel#group_desc {{
    font-size: 13px;
    color: {TEXT_MUTED};
    line-height: 1.5;
}}
QLabel#source_label {{
    color: {TEXT_DIM};
    font-size: 12px;
    font-style: italic;
}}

QFrame#score_card {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 {BG_CARD}, stop:1 {BG_CARD_HI}
    );
    border: 1px solid {BORDER};
    border-radius: 14px;
}}
QFrame#score_chip {{
    background-color: rgba(255, 255, 255, 0.03);
    border: 1px solid {BORDER};
    border-radius: 14px;
}}
QFrame#vline {{
    background-color: {BORDER};
    max-width: 1px;
    min-width: 1px;
}}

QGroupBox {{
    color: {TEXT_PRIMARY};
    font-family: "Segoe UI", sans-serif;
    font-weight: 700;
    font-size: 13px;
    background-color: {BG_CARD};
    border: 1px solid {BORDER};
    border-radius: 12px;
    margin-top: 18px;
    padding: 16px 14px 14px 14px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 14px;
    padding: 3px 12px;
    color: {ACCENT_TEAL};
    background-color: {BG_CARD};
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 1.5px;
    border: 1px solid {BORDER};
    border-radius: 6px;
}}

QPushButton {{
    background-color: {ACCENT_BLUE};
    color: #ffffff;
    border: none;
    border-radius: 8px;
    padding: 12px 18px;
    font-size: 14px;
    font-weight: 700;
    font-family: "Segoe UI", sans-serif;
    letter-spacing: 0.3px;
}}
QPushButton:hover       {{ background-color: #4f8ef7; }}
QPushButton:pressed     {{ background-color: #2563eb; }}
QPushButton:disabled    {{ background-color: #363c62; color: #7c88ad; }}


QPushButton#fake_btn              {{ background-color: #10b981; color: #062e26; }}
QPushButton#fake_btn:hover        {{ background-color: #34d399; }}
QPushButton#fake_btn:pressed      {{ background-color: #059669; }}

QPushButton#report_btn {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 {ACCENT_PURPLE}, stop:1 {ACCENT_PINK}
    );
    color: #1a1033;
    padding: 15px 18px;
    font-size: 15px;
    font-weight: 800;
}}
QPushButton#report_btn:hover    {{ background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 #c4b5fd, stop:1 #f9a8d4
    ); }}
QPushButton#report_btn:pressed  {{ background-color: #8b5cf6; }}

QPushButton#ghost_btn {{
    background-color: transparent;
    color: {TEXT_MUTED};
    border: 1px solid {BORDER};
    font-weight: 600;
    font-size: 13px;
    padding: 10px 14px;
}}
QPushButton#ghost_btn:hover {{
    color: {ACCENT_TEAL};
    border-color: {ACCENT_TEAL};
    background-color: rgba(45, 212, 191, 0.06);
}}

QComboBox, QLineEdit {{
    background-color: {BG_CARD_HI};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 10px 14px;
    font-size: 14px;
    font-family: "Segoe UI", sans-serif;
    selection-background-color: {ACCENT_BLUE};
}}
QComboBox:hover, QLineEdit:hover {{
    border: 1px solid {BORDER_HI};
}}
QComboBox:focus, QLineEdit:focus {{
    border: 1px solid {ACCENT_TEAL};
    background-color: {BG_CARD_HOVER};
}}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox::down-arrow {{
    image: none;
    width: 0; height: 0;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid {TEXT_MUTED};
    margin-right: 8px;
}}
QComboBox QAbstractItemView {{
    background-color: {BG_CARD_HI};
    color: {TEXT_PRIMARY};
    selection-background-color: {ACCENT_BLUE};
    border: 1px solid {BORDER_HI};
    padding: 4px;
    border-radius: 6px;
    outline: none;
}}

QTextEdit {{
    background-color: {BG_CARD};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER};
    border-radius: 10px;
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 14px;
    padding: 14px;
    selection-background-color: {ACCENT_BLUE};
}}
QTextEdit#log_panel {{
    font-family: "Consolas", "Cascadia Mono", "JetBrains Mono", monospace;
    font-size: 13px;
    color: #c7d0e6;
    background-color: #0c0f20;
}}

QProgressBar {{
    background-color: {BG_CARD_HI};
    border: 1px solid {BORDER};
    border-radius: 11px;
    text-align: center;
    color: {TEXT_PRIMARY};
    font-weight: 800;
    font-size: 13px;
    height: 26px;
}}
QProgressBar::chunk {{ border-radius: 7px; margin: 1px; }}

QTabWidget::pane {{
    border: 1px solid {BORDER};
    border-radius: 12px;
    background-color: {BG_CARD};
    top: -1px;
    padding: 4px;
}}
QTabBar {{
    qproperty-drawBase: 0;
}}
QTabBar::tab {{
    background: transparent;
    color: {TEXT_MUTED};
    padding: 12px 22px;
    margin-right: 4px;
    border-top-left-radius: 9px;
    border-top-right-radius: 9px;
    font-weight: 700;
    font-size: 13px;
    letter-spacing: 0.5px;
    min-width: 110px;
}}
QTabBar::tab:selected {{
    background: {BG_CARD};
    color: {ACCENT_TEAL};
    border: 1px solid {BORDER};
    border-bottom: 1px solid {BG_CARD};
}}
QTabBar::tab:hover:!selected {{
    color: {TEXT_PRIMARY};
    background: rgba(255, 255, 255, 0.03);
}}

QScrollBar:vertical {{
    background: transparent;
    width: 10px;
    border-radius: 5px;
    margin: 4px 2px;
}}
QScrollBar::handle:vertical {{
    background: {BORDER};
    border-radius: 4px;
    min-height: 36px;
}}
QScrollBar::handle:vertical:hover {{ background: {TEXT_DIM}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: transparent; }}

QToolTip {{
    background-color: {BG_CARD_HI};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_HI};
    padding: 6px 10px;
    border-radius: 6px;
    font-size: 11px;
}}
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _risk_band(score: int) -> tuple[str, str, str]:
    """Return (band, color, description)."""
    if score <= 30:
        return "NORMAL", BAND_NORMAL, "No significant attack surface detected."
    if score <= 69:
        return "SUSPICIOUS", BAND_SUSPICIOUS, "Exploitable conditions present. Investigate."
    return "ATTACK", BAND_ATTACK, "One or more attacks are trivially feasible."


# ---------------------------------------------------------------------------
# Background workers (unchanged behavior)
# ---------------------------------------------------------------------------
class ScanWorker(QObject):
    progress = pyqtSignal(str)
    finished = pyqtSignal(list, list, list, DroneFingerprint)
    failed = pyqtSignal(str)

    def __init__(self, target_ip: str):
        super().__init__()
        self.target_ip = target_ip

    def run(self) -> None:
        try:
            wifi_scanner = WiFiScanner()
            wifi_results = wifi_scanner.scan_networks()
            self.progress.emit(f"Detected {len(wifi_results)} Wi-Fi networks.")

            fingerprint = DroneFingerprint()
            fingerprint.update_wifi(wifi_results)
            fingerprint.behavior_info = f"Target IP: {self.target_ip}"

            port_scanner = PortScanner()
            port_results = port_scanner.scan_ports(self.target_ip)
            open_ports = [s.port for s in port_results if s.is_open]
            fingerprint.update_ports(open_ports)
            self.progress.emit(
                f"Open ports: {friendly_join(str(p) for p in open_ports) or 'None'}"
            )

            protocol_detector = ProtocolDetector()
            protocols = protocol_detector.detect_protocols(self.target_ip)
            fingerprint.update_protocols([obs.protocol for obs in protocols])

            self.finished.emit(wifi_results, port_results, protocols, fingerprint)
        except Exception as exc:
            self.failed.emit(str(exc))


class SafeTestWorker(QObject):
    progress = pyqtSignal(str)
    finished = pyqtSignal(SafeTestResults)
    failed = pyqtSignal(str)

    def __init__(self, target_ip: str):
        super().__init__()
        self.target_ip = target_ip

    def run(self) -> None:
        try:
            runner = SafeTestRunner()
            results = runner.run_all(self.target_ip)
            self.progress.emit("Safe tests completed.")
            self.finished.emit(results)
        except Exception as exc:
            self.failed.emit(str(exc))


class AIExplainerWorker(QObject):
    finished = pyqtSignal(str)

    def __init__(self, fingerprint, analysis, tests):
        super().__init__()
        self.fingerprint = fingerprint
        self.analysis = analysis
        self.tests = tests

    def run(self) -> None:
        result = generate_ai_explanation(self.fingerprint, self.analysis, self.tests)
        self.finished.emit(result)



# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------
class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Drone Security Assessment Tool")
        self.resize(1280, 860)
        self.setMinimumSize(1140, 760)
        self.setStyleSheet(STYLESHEET)

        self.target_ip: Optional[str] = None
        self.fingerprint = DroneFingerprint()
        self.analysis_report: Optional[AnalysisReport] = None
        self.wifi_results: List[WiFiNetwork] = []
        self.port_results: List[PortStatus] = []
        self.protocol_results: List[ProtocolObservation] = []
        self.safe_test_results: SafeTestResults = self._empty_test_results()
        self.vuln_engine = VulnerabilityEngine()
        self.report_generator = ReportGenerator(output_dir="reports")
        self.ai_explanation: str = ""
        self._sim_source: Optional[str] = None

        self._user_config = _load_user_config()
        self._setup_ui()

    # ------------------------------------------------------------------ UI
    def _setup_ui(self) -> None:
        central = QWidget()
        central.setObjectName("central")
        root = QVBoxLayout()
        root.setContentsMargins(28, 22, 28, 22)
        root.setSpacing(18)
        central.setLayout(root)

        root.addLayout(self._build_header())
        root.addWidget(self._build_score_card())

        # ---- Two-column main area: fixed sidebar + flexible workspace ----
        columns = QHBoxLayout()
        columns.setSpacing(18)

        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(340)
        sidebar.setLayout(self._build_controls_column())
        columns.addWidget(sidebar, 0)

        columns.addWidget(self._build_tabs(), 1)
        root.addLayout(columns, 1)

        self.setCentralWidget(central)

    # ------------------------------------------------------------------ Header
    def _build_header(self) -> QHBoxLayout:
        outer = QHBoxLayout()
        outer.setSpacing(14)

        # Glyph + title block
        glyph = QLabel("\u2708")  # airplane glyph
        glyph.setObjectName("title_glyph")
        glyph.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
        outer.addWidget(glyph, 0, Qt.AlignVCenter)

        text_col = QVBoxLayout()
        text_col.setSpacing(2)

        title = QLabel("Drone Security Assessment")
        title.setObjectName("title_label")
        text_col.addWidget(title)

        subtitle = QLabel(
            "ISOT-informed risk analysis  \u2022  DJI / Tello / MAVLink drones"
        )
        subtitle.setObjectName("subtitle_label")
        text_col.addWidget(subtitle)

        outer.addLayout(text_col, 1)

        # Status pill on the right
        self.status_label = QLabel("\u25CF  READY")
        self.status_label.setObjectName("status_pill")
        self.status_label.setAlignment(Qt.AlignCenter)
        outer.addWidget(self.status_label, 0, Qt.AlignVCenter | Qt.AlignRight)
        return outer

    # ------------------------------------------------------------------ Score card
    def _build_score_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("score_card")
        outer = QHBoxLayout()
        outer.setContentsMargins(24, 20, 24, 20)
        outer.setSpacing(24)
        card.setLayout(outer)

        # ── Left: hero score chip ──
        chip = QFrame()
        chip.setObjectName("score_chip")
        chip.setFixedSize(170, 170)
        chip_lay = QVBoxLayout()
        chip_lay.setContentsMargins(0, 0, 0, 0)
        chip_lay.setSpacing(0)
        chip_lay.setAlignment(Qt.AlignCenter)
        chip.setLayout(chip_lay)

        self.score_label = QLabel("--")
        self.score_label.setObjectName("score_label")
        self.score_label.setAlignment(Qt.AlignCenter)
        chip_lay.addWidget(self.score_label)

        self.score_slash = QLabel("OUT OF 100")
        self.score_slash.setObjectName("score_slash")
        self.score_slash.setAlignment(Qt.AlignCenter)
        chip_lay.addWidget(self.score_slash)

        outer.addWidget(chip, 0, Qt.AlignVCenter)

        # ── Vertical divider ──
        divider = QFrame()
        divider.setObjectName("vline")
        divider.setFixedWidth(1)
        outer.addWidget(divider)

        # ── Right: band, description, progress, source ──
        band_box = QVBoxLayout()
        band_box.setSpacing(8)
        band_box.setContentsMargins(0, 4, 0, 4)

        risk_caption = QLabel("CURRENT RISK LEVEL")
        risk_caption.setObjectName("section_label")
        band_box.addWidget(risk_caption)

        self.band_label = QLabel("\u2014")
        self.band_label.setObjectName("band_label")
        band_box.addWidget(self.band_label)

        self.band_desc = QLabel("Run a scan to compute a risk score.")
        self.band_desc.setObjectName("band_desc")
        self.band_desc.setWordWrap(True)
        band_box.addWidget(self.band_desc)

        self.score_bar = QProgressBar()
        self.score_bar.setRange(0, 100)
        self.score_bar.setValue(0)
        self.score_bar.setFormat("%v / 100")
        self.score_bar.setMinimumWidth(320)
        band_box.addWidget(self.score_bar)

        self.source_label = QLabel("")
        self.source_label.setObjectName("source_label")
        band_box.addWidget(self.source_label)

        outer.addLayout(band_box, 1)
        return card

    # ------------------------------------------------------------------ Controls column
    def _build_controls_column(self) -> QVBoxLayout:
        left = QVBoxLayout()
        left.setSpacing(14)

        # -- Live scan --
        live_group = QGroupBox("\U0001F4E1  LIVE SCAN")
        live_lay = QVBoxLayout()
        live_lay.setSpacing(10)

        live_desc = QLabel("Scan a real drone on your network for open ports, protocols & WiFi posture.")
        live_desc.setObjectName("group_desc")
        live_desc.setWordWrap(True)
        live_lay.addWidget(live_desc)

        self.scan_btn = QPushButton("\u25B6  Scan My Drone")
        self.scan_btn.clicked.connect(self._handle_scan_clicked)
        live_lay.addWidget(self.scan_btn)

        self.safe_tests_btn = QPushButton("\u2713  Run Safe Tests")
        self.safe_tests_btn.setObjectName("ghost_btn")
        self.safe_tests_btn.clicked.connect(self._handle_safe_tests_clicked)
        live_lay.addWidget(self.safe_tests_btn)
        live_group.setLayout(live_lay)
        left.addWidget(live_group)

        # -- Local fake drone --
        fake_group = QGroupBox("\U0001F3B2  FAKE DRONE  \u00B7  RANDOM")
        fake_lay = QVBoxLayout()
        fake_lay.setSpacing(10)

        fake_desc = QLabel(
            "Generates a unique drone profile every run \u2014 random ports, WiFi security and network health. No real drone required."
        )
        fake_desc.setObjectName("group_desc")
        fake_desc.setWordWrap(True)
        fake_lay.addWidget(fake_desc)

        self.fake_btn = QPushButton("\u2728  Generate Random Drone")
        self.fake_btn.setObjectName("fake_btn")
        self.fake_btn.clicked.connect(self._handle_fake_drone)
        fake_lay.addWidget(self.fake_btn)

        fake_group.setLayout(fake_lay)
        left.addWidget(fake_group)

        # -- Report --
        self.report_btn = QPushButton("\U0001F4C4  Generate PDF Report")
        self.report_btn.setObjectName("report_btn")
        self.report_btn.clicked.connect(self._handle_report)
        left.addWidget(self.report_btn)

        left.addStretch()
        return left

    # ------------------------------------------------------------------ Tabs
    def _build_tabs(self) -> QTabWidget:
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        # Scan log
        self.log_panel = QTextEdit()
        self.log_panel.setObjectName("log_panel")
        self.log_panel.setReadOnly(True)
        self.log_panel.setPlaceholderText("Scan output appears here...")
        self.tabs.addTab(self.log_panel, "\u25B6  SCAN LOG")

        # Vulnerabilities
        self.vuln_panel = QTextEdit()
        self.vuln_panel.setReadOnly(True)
        self.vuln_panel.setPlaceholderText(
            "Vulnerability findings appear here after a scan."
        )
        self.tabs.addTab(self.vuln_panel, "\u26A0  VULNERABILITIES")

        # Risk breakdown
        self.breakdown_panel = QTextEdit()
        self.breakdown_panel.setReadOnly(True)
        self.breakdown_panel.setPlaceholderText(
            "Risk factors and likely attack categories appear here."
        )
        self.tabs.addTab(self.breakdown_panel, "\u25A4  RISK BREAKDOWN")

        # AI analysis
        self.ai_panel = QTextEdit()
        self.ai_panel.setReadOnly(True)
        self.ai_panel.setPlaceholderText(
            "AI-powered explanation (Ollama) appears here after a scan."
        )
        self.tabs.addTab(self.ai_panel, "\u2728  AI ANALYSIS")

        return self.tabs

    # ------------------------------------------------------------------ Helpers
    def _set_status(self, text: str) -> None:
        self.status_label.setText(f"\u25CF  {text.upper()}")

    def _append_log(self, text: str) -> None:
        self.log_panel.append(text)

    def _update_score_display(self, score: int, source: str) -> None:
        band, colour, desc = _risk_band(score)

        # Number — gradient color tied to band
        self.score_label.setText(str(score))
        self.score_label.setStyleSheet(
            f"font-size:64px; font-weight:900; color:{colour};"
        )
        # Hero chip border tinted with band color
        for w in (self.findChild(QFrame, "score_chip"),):
            if w is not None:
                w.setStyleSheet(
                    f"QFrame#score_chip {{"
                    f"  background-color: rgba(255,255,255,0.02);"
                    f"  border: 1.5px solid {colour};"
                    f"  border-radius: 14px;"
                    f"}}"
                )
        self.score_bar.setValue(score)
        self.score_bar.setStyleSheet(
            f"QProgressBar::chunk {{ background-color:{colour}; border-radius:7px; margin:1px; }}"
        )
        self.band_label.setText(band)
        self.band_label.setStyleSheet(
            f"font-size:22px; font-weight:800; letter-spacing:2px; color:{colour};"
        )
        self.band_desc.setText(desc)
        self.source_label.setText(f"\u25C6  Scoring method: {source}")
        self._set_status(f"Risk {score}/100  \u00B7  {band.title()}")

    def _empty_test_results(self) -> SafeTestResults:
        return SafeTestResults(
            ping=PingTestResult(success=False, packet_loss=None, details="Not run"),
            latency=LatencyResult(average_ms=None, samples=0),
            packet=PacketSendResult(success=False, bytes_sent=0, note="Not run"),
        )

    # ------------------------------------------------------------------ Panel refresh
    def _refresh_all_panels(self) -> None:
        """Rebuild the Vulnerabilities and Risk Breakdown tabs from the current report."""
        if not self.analysis_report:
            return
        self.vuln_panel.setHtml(self._render_vulnerabilities_html())
        self.breakdown_panel.setHtml(self._render_breakdown_html())

    def _render_vulnerabilities_html(self) -> str:
        report = self.analysis_report
        if not report or not report.vulnerabilities:
            return (
                f"<div style='color:{TEXT_MUTED}; padding:28px; text-align:center; "
                f"font-size:15px;'>"
                f"<div style='font-size:34px; margin-bottom:10px;'>\u2713</div>"
                f"No vulnerability findings for this scan."
                f"</div>"
            )

        # Count findings by severity for the header strip
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in report.vulnerabilities:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        parts: list[str] = []
        parts.append(f"<div style='color:{TEXT_PRIMARY};'>")

        # Summary strip
        chips = []
        for sev, count in sev_counts.items():
            if count == 0:
                continue
            c = SEVERITY_COLOR.get(sev, TEXT_MUTED)
            chips.append(
                f"<span style='display:inline-block; background:transparent; "
                f"border:1px solid {c}; color:{c}; padding:5px 13px; "
                f"border-radius:12px; font-size:13px; font-weight:700; "
                f"margin-right:8px; letter-spacing:0.4px;'>"
                f"{count}&nbsp;{sev.upper()}</span>"
            )
        if chips:
            parts.append(
                f"<div style='margin:0 0 16px 0; padding-bottom:12px; "
                f"border-bottom:1px solid {BORDER};'>"
                f"<span style='color:{TEXT_DIM}; font-size:12px; "
                f"font-weight:700; letter-spacing:1.2px; margin-right:12px;'>"
                f"FINDINGS</span>"
                f"{''.join(chips)}</div>"
            )

        for f in report.vulnerabilities:
            sev = f.severity or "Low"
            sev_color = SEVERITY_COLOR.get(sev, TEXT_MUTED)
            title = html.escape(f.title or "Finding")
            explanation = html.escape(f.explanation or "")
            recommendation = html.escape(f.recommendation or "")
            feasibility = html.escape(f.attack_feasibility or "\u2014")
            category = html.escape(f.attack_category or "")

            category_line = (
                f"<span style='color:{TEXT_DIM}; font-size:12px; letter-spacing:1px; "
                f"font-weight:700;'>ENABLES</span>&nbsp;&nbsp;"
                f"<b style='color:{ACCENT_TEAL}; font-size:13px;'>{category}</b>"
                f"<span style='color:{BORDER}; margin:0 8px;'>|</span>"
                if category else ""
            )

            parts.append(
                f"<table width='100%' cellspacing='0' cellpadding='0' "
                f"style='margin:0 0 14px 0; background:{BG_CARD_HI}; "
                f"border-left:3px solid {sev_color};'>"
                f"<tr><td style='padding:16px 20px;'>"
                f"<table width='100%' cellspacing='0'><tr>"
                f"<td><b style='font-size:16px; color:{TEXT_PRIMARY}; "
                f"letter-spacing:0.2px;'>{title}</b></td>"
                f"<td align='right'>"
                f"<span style='background:{sev_color}; color:#fff; "
                f"padding:4px 12px; border-radius:5px; font-size:12px; "
                f"font-weight:800; letter-spacing:0.8px;'>{sev.upper()}</span>"
                f"</td></tr></table>"
                f"<div style='color:{TEXT_MUTED}; font-size:13px; margin-top:10px;'>"
                f"{category_line}"
                f"<span style='color:{TEXT_DIM}; font-size:12px; letter-spacing:1px; "
                f"font-weight:700;'>FEASIBILITY</span>&nbsp;&nbsp;"
                f"<b style='color:{TEXT_PRIMARY}; font-size:13px;'>{feasibility}</b>"
                f"</div>"
                f"<div style='margin-top:12px; font-size:14px; color:{TEXT_PRIMARY}; "
                f"line-height:1.5;'>{explanation}</div>"
                f"<div style='margin-top:12px; padding:10px 14px; "
                f"background:rgba(45,212,191,0.06); border-left:2px solid {ACCENT_TEAL}; "
                f"font-size:13px; color:{TEXT_PRIMARY};'>"
                f"<span style='color:{ACCENT_TEAL}; font-weight:700; font-size:12px; "
                f"letter-spacing:0.5px;'>\u25C6 RECOMMENDATION</span><br/>"
                f"<span style='color:{TEXT_PRIMARY}; font-size:13px;'>{recommendation}</span>"
                f"</div>"
                f"</td></tr></table>"
            )

        parts.append("</div>")
        return "".join(parts)

    def _render_breakdown_html(self) -> str:
        report = self.analysis_report
        if not report:
            return ""

        parts: list[str] = [f"<div style='color:{TEXT_PRIMARY};'>"]

        # ----- Likely attacks -----
        parts.append(
            f"<div style='font-size:12px; color:{TEXT_DIM}; "
            f"letter-spacing:1.4px; font-weight:700; margin-bottom:12px;'>"
            f"\u25C6 &nbsp;LIKELY ATTACK VECTORS</div>"
        )
        if report.likely_attacks:
            chips = []
            # Rank colors: first = strongest
            ranks = [ACCENT_PINK, ACCENT_PURPLE, ACCENT_BLUE, ACCENT_TEAL]
            for i, name in enumerate(report.likely_attacks):
                col = ranks[min(i, len(ranks) - 1)]
                chips.append(
                    f"<span style='display:inline-block; background:transparent; "
                    f"border:1px solid {col}; color:{col}; "
                    f"padding:7px 16px; border-radius:16px; "
                    f"font-size:13px; font-weight:700; margin:0 8px 8px 0; "
                    f"letter-spacing:0.4px;'>"
                    f"#{i+1}&nbsp;&nbsp;{html.escape(name)}</span>"
                )
            parts.append(
                f"<div style='margin-bottom:22px;'>{''.join(chips)}</div>"
            )
        else:
            parts.append(
                f"<div style='color:{TEXT_MUTED}; font-size:14px; margin-bottom:22px;'>"
                f"No specific attack vectors identified.</div>"
            )

        # ----- Score breakdown -----
        heading = (
            "OBSERVED RISK FACTORS"
            if report.ml_available
            else "SCORE BREAKDOWN"
        )
        note = (
            "The ML model produced the score above. These rule-based factors were observed in the same scan."
            if report.ml_available
            else "Each factor below contributed directly to the score."
        )
        parts.append(
            f"<div style='font-size:12px; color:{TEXT_DIM}; "
            f"letter-spacing:1.4px; font-weight:700; margin-bottom:8px;'>"
            f"\u25C6 &nbsp;{heading}</div>"
            f"<div style='color:{TEXT_MUTED}; font-size:13px; margin-bottom:14px; "
            f"line-height:1.5;'>{note}</div>"
        )
        if report.score_breakdown:
            parts.append(
                f"<table width='100%' cellspacing='0' cellpadding='0' "
                f"style='background:{BG_CARD_HI}; border:1px solid {BORDER};'>"
            )
            for i, item in enumerate(report.score_breakdown):
                item_esc = html.escape(item)
                bg = "transparent" if i % 2 == 0 else "rgba(255,255,255,0.02)"
                parts.append(
                    f"<tr><td style='padding:12px 18px; "
                    f"border-bottom:1px solid {BORDER}; background:{bg};'>"
                    f"<span style='color:{ACCENT_TEAL}; font-weight:700; font-size:14px; "
                    f"margin-right:12px;'>\u25B8</span>"
                    f"<span style='color:{TEXT_PRIMARY}; font-size:14px; "
                    f"line-height:1.5;'>{item_esc}</span>"
                    f"</td></tr>"
                )
            parts.append("</table>")
        else:
            parts.append(
                f"<div style='color:{TEXT_MUTED}; font-size:14px;'>"
                f"No scoring factors recorded.</div>"
            )

        parts.append("</div>")
        return "".join(parts)

    def _compose_log_text(self) -> str:
        """Short plain-text summary appended to the scan log."""
        report = self.analysis_report
        if not report:
            return ""
        lines: list[str] = []
        if report.ml_available and report.ml_prediction:
            lines.append(
                f"Risk Score: {report.risk_score}/100 (ML: "
                f"{report.ml_prediction}, conf {report.ml_confidence:.1%})"
            )
        else:
            lines.append(f"Risk Score: {report.risk_score}/100 (rule-based)")
        if report.likely_attacks:
            lines.append(f"Likely attacks: {', '.join(report.likely_attacks)}")
        for f in report.vulnerabilities:
            lines.append(f"  [{f.severity}] {f.title}")
        return "\n".join(lines)

    # ------------------------------------------------------------------ Live scan
    def _handle_scan_clicked(self) -> None:
        ip, ok = QInputDialog.getText(
            self, "Drone IP",
            "Enter the drone IP (e.g. 192.168.10.1):",
            text=self.target_ip or "",
        )
        if not ok or not ip.strip():
            return
        self.target_ip = ip.strip()
        self._sim_source = None
        self.log_panel.clear()
        self.vuln_panel.clear()
        self.breakdown_panel.clear()
        self.ai_panel.clear()
        self._append_log(f"Scanning {self.target_ip} ...")
        self._set_status("Scanning...")
        self.scan_btn.setEnabled(False)

        self._scan_thread = QThread(self)
        self._scan_worker = ScanWorker(self.target_ip)
        self._scan_worker.moveToThread(self._scan_thread)
        self._scan_thread.started.connect(self._scan_worker.run)
        self._scan_worker.progress.connect(self._append_log)
        self._scan_worker.finished.connect(self._on_scan_done)
        self._scan_worker.failed.connect(self._on_worker_error)
        self._scan_worker.finished.connect(lambda *_: self._scan_thread.quit())
        self._scan_worker.finished.connect(lambda *_: self._scan_worker.deleteLater())
        self._scan_thread.finished.connect(self._scan_thread.deleteLater)
        self._scan_thread.start()

    def _on_scan_done(self, wifi, ports, protocols, fingerprint) -> None:
        self.scan_btn.setEnabled(True)
        self.wifi_results = wifi
        self.port_results = ports
        self.protocol_results = protocols
        self.fingerprint = fingerprint
        self.analysis_report = self.vuln_engine.analyze(
            fingerprint=fingerprint,
            wifi_data=wifi,
            ports=ports,
            protocols=protocols,
            safe_tests=self.safe_test_results,
        )
        score = self.analysis_report.risk_score
        source = (
            "Machine Learning (ISOT)"
            if self.analysis_report.ml_available
            else "Rule-based (ISOT-informed)"
        )
        self._update_score_display(score, source)
        self._append_log(self._compose_log_text())
        self._refresh_all_panels()
        self._request_ai_explanation()

    def _on_worker_error(self, msg: str) -> None:
        self.scan_btn.setEnabled(True)
        self.safe_tests_btn.setEnabled(True)
        self.fake_btn.setEnabled(True)
        QMessageBox.critical(self, "Error", msg)
        self._set_status("Error")

    # ------------------------------------------------------------------ Safe tests
    def _handle_safe_tests_clicked(self) -> None:
        if not self.target_ip:
            QMessageBox.information(
                self, "IP Required",
                "Run a live scan first to set the target IP.",
            )
            return
        self.safe_tests_btn.setEnabled(False)
        self._append_log("Running safe connectivity tests...")
        self._safe_thread = QThread(self)
        self._safe_worker = SafeTestWorker(self.target_ip)
        self._safe_worker.moveToThread(self._safe_thread)
        self._safe_thread.started.connect(self._safe_worker.run)
        self._safe_worker.progress.connect(self._append_log)
        self._safe_worker.finished.connect(self._on_safe_tests_done)
        self._safe_worker.failed.connect(self._on_worker_error)
        self._safe_worker.finished.connect(lambda *_: self._safe_thread.quit())
        self._safe_worker.finished.connect(lambda *_: self._safe_worker.deleteLater())
        self._safe_thread.finished.connect(self._safe_thread.deleteLater)
        self._safe_thread.start()

    def _on_safe_tests_done(self, results: SafeTestResults) -> None:
        self.safe_tests_btn.setEnabled(True)
        self.safe_test_results = results
        self._append_log(
            f"Ping: {'OK' if results.ping.success else 'FAIL'}  "
            f"Loss: {results.ping.packet_loss or 'n/a'}%  "
            f"Latency: {(results.latency.average_ms or 0):.1f} ms"
        )
        if self.analysis_report:
            self.analysis_report = self.vuln_engine.analyze(
                fingerprint=self.fingerprint,
                wifi_data=self.wifi_results,
                ports=self.port_results,
                protocols=self.protocol_results,
                safe_tests=results,
            )
            score = self.analysis_report.risk_score
            source = (
                "Machine Learning (ISOT)"
                if self.analysis_report.ml_available
                else "Rule-based (ISOT-informed)"
            )
            self._update_score_display(score, source)
            self._append_log(self._compose_log_text())
            self._refresh_all_panels()
            self._request_ai_explanation()

    # ------------------------------------------------------------------ Local fake drone
    def _handle_fake_drone(self) -> None:
        """
        Generate a fully random drone scenario and run it through the
        real vulnerability engine — same pipeline as a live scan.
        Every click produces different ports, WiFi security, and network
        health values, so the score changes each time.
        """
        self.log_panel.clear()
        self.vuln_panel.clear()
        self.breakdown_panel.clear()
        self.ai_panel.clear()
        self._set_status("Generating random fake drone...")

        # Generate random scenario — no seed so it's different every run
        scenario = FakeDroneScenario().generate()

        self._sim_source = (
            f"Random fake drone / {scenario.fingerprint.model} "
            f"({scenario.fingerprint.wifi_network.ssid if scenario.fingerprint.wifi_network else '?'})"
        )
        self.target_ip = None   # no real IP for fake scans

        # Store scan data
        self.wifi_results      = scenario.wifi
        self.port_results      = scenario.ports
        self.protocol_results  = scenario.protocols
        self.fingerprint       = scenario.fingerprint
        self.safe_test_results = scenario.tests

        # Log the random values so the user can see what was generated
        self._append_log("══ Random Fake Drone Scan ══")
        self._append_log(scenario.description)
        self._append_log("")

        # Run the full analysis pipeline with rule-based scoring.
        # force_rule_based=True because the trained ISOT ML model expects
        # network-flow statistics, not the simple boolean flags we collect —
        # it returns 100/100 on everything otherwise.
        self.analysis_report = self.vuln_engine.analyze(
            fingerprint=self.fingerprint,
            wifi_data=self.wifi_results,
            ports=self.port_results,
            protocols=self.protocol_results,
            safe_tests=self.safe_test_results,
            force_rule_based=True,
        )

        source = (
            "Machine Learning (ISOT)"
            if self.analysis_report.ml_available
            else "Rule-based (ISOT-informed)"
        )
        self._update_score_display(self.analysis_report.risk_score, source)
        self._append_log(self._compose_log_text())
        self._refresh_all_panels()
        # Switch to Vulnerabilities tab so results are immediately visible
        self.tabs.setCurrentIndex(1)
        self._request_ai_explanation()

    # ------------------------------------------------------------------ AI explanation
    def _request_ai_explanation(self) -> None:
        if not self.analysis_report:
            return
        self.ai_panel.setPlainText("Generating AI explanation (Ollama)...")
        self._ai_thread = QThread(self)
        self._ai_worker = AIExplainerWorker(
            self.fingerprint,
            self.analysis_report,
            self.safe_test_results,
        )
        self._ai_worker.moveToThread(self._ai_thread)
        self._ai_thread.started.connect(self._ai_worker.run)
        self._ai_worker.finished.connect(self._on_ai_done)
        self._ai_worker.finished.connect(lambda *_: self._ai_thread.quit())
        self._ai_worker.finished.connect(lambda *_: self._ai_worker.deleteLater())
        self._ai_thread.finished.connect(self._ai_thread.deleteLater)
        self._ai_thread.start()

    def _on_ai_done(self, text: str) -> None:
        self.ai_explanation = text
        self.ai_panel.setPlainText(text)

    # ------------------------------------------------------------------ PDF Report
    def _handle_report(self) -> None:
        if not self.analysis_report:
            QMessageBox.information(self, "No Data",
                                    "Run a scan or simulation first.")
            return
        default_name = "drone_security_report.pdf"
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Save Report",
            str(Path.home() / default_name),
            "PDF Files (*.pdf)",
        )
        if not save_path:
            return
        path = self.report_generator.generate(
            filepath=save_path,
            fingerprint=self.fingerprint,
            analysis=self.analysis_report,
            tests=self.safe_test_results,
            ai_explanation=self.ai_explanation,
            sim_source=self._sim_source,
        )
        QMessageBox.information(self, "Report Saved", f"Saved to {path}")
