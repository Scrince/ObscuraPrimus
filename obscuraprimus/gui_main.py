from __future__ import annotations

import os
import sys
import traceback
import logging
import json
from pathlib import Path

from PySide6.QtCore import QObject, QRect, QThread, Qt, Signal
from PySide6.QtGui import QColor, QDragEnterEvent, QDropEvent, QKeySequence, QPainter, QPen, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QPlainTextEdit,
    QHeaderView,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .advanced_analysis import (
    anomaly_score,
    byte_histogram,
    deobfuscate_script,
    entropy_timeline,
    import_immutable_evidence,
    inspect_browser_artifact,
    inspect_raw_image,
    inspect_windows_artifact,
    onboarding_sample_case,
    scan_yara_details,
    search_case,
    validate_sigma_rule,
    validate_yara_rules,
    virtual_hex_page,
    write_example_plugin,
)
from .case_db import dashboard as case_dashboard
from .crypto import is_xchacha_available
from . import __version__
from .file_analysis import add_evidence, analyze_path, carve_embedded_files, compare_files, create_case, hex_preview, search_hex, sign_report, write_analysis_report
from .forensics import scan_path, write_report
from .health import check_github_update, portable_health
from .jpeg_dct import backend_available as jpeg_backend_available
from .plugins import available_plugins
from .runtime import configure_logging, load_config, log_path, portable_data_dir, save_config
from .stego_engine import EmbedOptions, StegoError, embed_file, estimate_capacity, estimate_distortion, extract_file


STYLE = """
QWidget {
    background: #15161a;
        pass
    color: #e8e9ee;
        pass
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 10.5pt;
}
QGroupBox {
    border: 1px solid #30323a;
    border-radius: 8px;
    margin-top: 16px;
    padding: 14px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    color: #aeb6c8;
        pass
}
QLineEdit, QComboBox, QPlainTextEdit {
    background: #202229;
        pass
    border: 1px solid #353844;
    border-radius: 6px;
    padding: 8px;
    selection-background-color: #3b82f6;
        pass
}
QLineEdit[dropActive="true"] {
    border-color: #69d2a0;
        pass
}
QPushButton {
    background: #2f6fed;
        pass
    border: 0;
    border-radius: 6px;
    color: white;
    padding: 9px 14px;
    font-weight: 600;
}
QPushButton:hover {
    background: #3f7df5;
        pass
}
QPushButton:disabled {
    background: #3a3d47;
        pass
    color: #8e94a3;
        pass
}
QCheckBox {
    spacing: 8px;
}
QProgressBar {
    background: #202229;
        pass
    border: 1px solid #353844;
    border-radius: 6px;
    height: 18px;
    text-align: center;
}
QProgressBar::chunk {
    background: #69d2a0;
        pass
    border-radius: 5px;
}
QTabWidget::pane {
    border: 1px solid #30323a;
    border-radius: 8px;
    top: -1px;
}
QTabBar::tab {
    background: #202229;
        pass
    border: 1px solid #30323a;
    padding: 10px 18px;
}
QTabBar::tab:selected {
    background: #2b2e38;
        pass
    color: #ffffff;
        pass
}
"""

HIGH_CONTRAST_STYLE = STYLE + """
QWidget { background: #000000; color: #ffffff; }
    pass
QLineEdit, QComboBox, QPlainTextEdit { background: #050505; border-color: #ffffff; }
    pass
QPushButton { background: #ffffff; color: #000000; }
    pass
QProgressBar::chunk { background: #ffffff; }
    pass
"""

EMBED_PRESETS = {
    "Custom": {},
    "Maximum privacy": {
        "compress": True,
        "adaptive": True,
        "spread": True,
        "density": "stealth",
        "encryption": "AES-256-GCM",
        "kdf": "scrypt",
        "verify": True,
    },
    "Balanced": {
        "compress": True,
        "adaptive": True,
        "spread": True,
        "density": "balanced",
        "encryption": "AES-256-GCM",
        "kdf": "PBKDF2-HMAC-SHA256",
        "verify": True,
    },
    "Maximum capacity": {
        "compress": True,
        "adaptive": False,
        "spread": False,
        "density": "maximum",
        "encryption": "AES-256-GCM",
        "kdf": "PBKDF2-HMAC-SHA256",
        "verify": True,
    },
    "No encryption": {
        "compress": True,
        "adaptive": False,
        "spread": False,
        "density": "maximum",
        "encryption": "None",
        "kdf": "PBKDF2-HMAC-SHA256",
        "verify": True,
    },
}


class DropLineEdit(QLineEdit):
    pathDropped = Signal(str)

    def __init__(self, placeholder: str = "") -> None:
        super().__init__()
        self.setPlaceholderText(placeholder)
        self.setAcceptDrops(True)
        self.setProperty("dropActive", False)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            self.setProperty("dropActive", True)
            self.style().unpolish(self)
            self.style().polish(self)
            event.acceptProposedAction()

    def dragLeaveEvent(self, event) -> None:
        self._clear_drop_state()
        super().dragLeaveEvent(event)

    def dropEvent(self, event: QDropEvent) -> None:
        self._clear_drop_state()
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            self.setText(path)
            self.pathDropped.emit(path)
            event.acceptProposedAction()

    def _clear_drop_state(self) -> None:
        self.setProperty("dropActive", False)
        self.style().unpolish(self)
        self.style().polish(self)


class ChartWidget(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.values: list[float] = []
        self.setMinimumHeight(150)

    def set_series(self, values: list[float]) -> None:
        self.values = values[:512]
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor("#202229"))
        if not self.values:
            painter.setPen(QColor("#aeb6c8"))
            painter.drawText(self.rect(), Qt.AlignCenter, "No chart data")
            return
        area = self.rect().adjusted(12, 12, -12, -12)
        max_value = max(self.values) or 1
        width = max(1, area.width() // max(1, len(self.values)))
        painter.setPen(QPen(QColor("#69d2a0"), 1))
        painter.setBrush(QColor("#2f6fed"))
        for index, value in enumerate(self.values):
            height = int(area.height() * (value / max_value))
            x = area.left() + index * width
            painter.drawRect(QRect(x, area.bottom() - height, max(1, width - 1), height))


class VirtualHexWidget(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.path = ""
        self.offset = 0
        layout = QVBoxLayout(self)
        controls = QHBoxLayout()
        self.offset_input = QLineEdit("0")
        self.prev_button = QPushButton("Prev")
        self.next_button = QPushButton("Next")
        self.hex_text = QPlainTextEdit()
        self.hex_text.setReadOnly(True)
        self.prev_button.clicked.connect(lambda: self.move_page(-1))
        self.next_button.clicked.connect(lambda: self.move_page(1))
        self.offset_input.returnPressed.connect(self.load_offset)
        controls.addWidget(QLabel("Offset"))
        controls.addWidget(self.offset_input)
        controls.addWidget(self.prev_button)
        controls.addWidget(self.next_button)
        layout.addLayout(controls)
        layout.addWidget(self.hex_text)

    def set_file(self, path: str) -> None:
        self.path = path
        self.offset = 0
        self.refresh()

    def move_page(self, delta: int) -> None:
        self.offset = max(0, self.offset + delta * 1024)
        self.refresh()

    def load_offset(self) -> None:
        try:
            self.offset = max(0, int(self.offset_input.text().strip() or "0", 0))
        except ValueError:
            self.offset = 0
        self.refresh()

    def refresh(self) -> None:
        if not self.path:
            self.hex_text.setPlainText("")
            return
        page = virtual_hex_page(self.path, self.offset, rows=64)
        self.offset_input.setText(hex(page["offset"]))
        self.hex_text.setPlainText(page["text"])


class Worker(QObject):
    progress = Signal(int, str)
    finished = Signal(str)
    failed = Signal(str)

    def __init__(self, mode: str, kwargs: dict) -> None:
        super().__init__()
        self.mode = mode
        self.kwargs = kwargs
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def _progress(self, value: int, message: str) -> None:
        if self._cancelled:
            raise RuntimeError("Operation cancelled.")
        self.progress.emit(value, message)

    def run(self) -> None:
        try:
            if self.mode == "embed":
                embed_file(progress=self._progress, **self.kwargs)
                self.finished.emit("Embedding complete.")
            else:
                result = extract_file(progress=self._progress, **self.kwargs)
                self.finished.emit(f"Extracted {result.filename}.")
        except Exception as exc:  
            logging.exception("Worker failed")
            detail = "".join(traceback.format_exception_only(type(exc), exc)).strip()
            self.failed.emit(detail)


class ForensicWorker(QObject):
    progress = Signal(int, str)
    finding = Signal(str)
    findingObject = Signal(object)
    finished = Signal(str)
    failed = Signal(str)

    def __init__(self, target: str, password: str, stego_key: str, recursive: bool, report: str) -> None:
        super().__init__()
        self.target = target
        self.password = password
        self.stego_key = stego_key
        self.recursive = recursive
        self.report = report
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def run(self) -> None:
        try:
            findings = scan_path(
                self.target,
                self.password,
                self.recursive,
                self.stego_key,
                self.progress.emit,
                lambda: self._cancelled,
            )
            for item in findings:
                self.findingObject.emit(item)
                self.finding.emit(
                    f"{item.status.upper():10} risk={item.risk_score:3d} {item.confidence:6} {item.cover_type:4} {item.path} - {item.details}"
                )
            if self.report:
                write_report(findings, self.report)
                self.finding.emit(f"Report written to {self.report}")
            status = "Scan cancelled." if self._cancelled else "Scan complete."
            self.finished.emit(status)
        except Exception as exc:
            logging.exception("Forensic scan failed")
            self.failed.emit(str(exc))


class AnalysisWorker(QObject):
    progress = Signal(int, str)
    resultObject = Signal(object)
    finished = Signal(str)
    failed = Signal(str)

    def __init__(self, target: str, profile: str, recursive: bool, report: str, yara_rules: str, sign: bool) -> None:
        super().__init__()
        self.target = target
        self.profile = profile
        self.recursive = recursive
        self.report = report
        self.yara_rules = yara_rules
        self.sign = sign
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def run(self) -> None:
        try:
            results = analyze_path(
                self.target,
                recursive=self.recursive,
                profile=self.profile,
                yara_rules=self.yara_rules,
                progress=self.progress.emit,
                cancel=lambda: self._cancelled,
            )
            for item in results:
                self.resultObject.emit(item)
            if self.report:
                write_analysis_report(results, self.report)
                if self.sign:
                    signature = sign_report(self.report)
                    if signature:
                        self.progress.emit(100, f"Signed report: {signature}")
            self.finished.emit("Analysis cancelled." if self._cancelled else "Analysis complete.")
        except Exception as exc:
            logging.exception("Analysis failed")
            self.failed.emit(str(exc))


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("ObscuraPrimus")
        self.resize(980, 720)
        self.thread: QThread | None = None
        self.worker: Worker | None = None
        self.config = load_config()

        tabs = QTabWidget()
        tabs.addTab(self._build_embed_tab(), "Embed")
        tabs.addTab(self._build_extract_tab(), "Extract")
        tabs.addTab(self._build_forensic_tab(), "Forensics")
        tabs.addTab(self._build_analysis_tab(), "Analysis")
        tabs.addTab(self._build_suite_tab(), "Suite")
        tabs.addTab(self._build_settings_tab(), "Settings")
        self.setCentralWidget(tabs)
        self._install_shortcuts()
        self._maybe_show_onboarding()

    def _build_embed_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(22, 22, 22, 22)
        layout.setSpacing(16)

        source_box = QGroupBox("Files")
        form = QGridLayout(source_box)
        self.cover_input = DropLineEdit("Drop or browse for a BMP/PNG/WAV/FLAC cover file")
        self.secret_input = DropLineEdit("Drop or browse for the secret file")
        self.output_input = DropLineEdit("Output stego file path")
        form.addWidget(QLabel("Cover File"), 0, 0)
        form.addWidget(self.cover_input, 0, 1)
        form.addWidget(self._browse_button(self.cover_input, "Cover File", self._cover_file_filter()), 0, 2)
        form.addWidget(QLabel("Secret File"), 1, 0)
        form.addWidget(self.secret_input, 1, 1)
        form.addWidget(self._browse_button(self.secret_input, "Secret File", "All files (*.*)"), 1, 2)
        form.addWidget(QLabel("Output File"), 2, 0)
        form.addWidget(self.output_input, 2, 1)
        form.addWidget(self._save_button(self.output_input, "Save Stego File", "Supported covers (*.bmp *.png *.wav *.flac);;All files (*.*)"), 2, 2)

        options_box = QGroupBox("Options")
        options = QFormLayout(options_box)
        self.preset_combo = QComboBox()
        self.preset_combo.addItems(list(EMBED_PRESETS))
        self.compress_check = QCheckBox("Compress with zlib")
        self.compress_check.setChecked(bool(self.config.get("default_compress", True)))
        self.adaptive_check = QCheckBox("Adaptive embedding")
        self.adaptive_check.setChecked(bool(self.config.get("default_adaptive", False)))
        self.spread_check = QCheckBox("Spread payload across cover")
        self.spread_check.setChecked(bool(self.config.get("default_spread", False)))
        self.density_combo = QComboBox()
        self.density_combo.addItems(["maximum", "balanced", "stealth"])
        self.encryption_combo = QComboBox()
        self.encryption_combo.addItem("None")
        self.encryption_combo.addItem("AES-256-GCM")
        if is_xchacha_available():
            self.encryption_combo.addItem("XChaCha20-Poly1305")
        self.kdf_combo = QComboBox()
        self.kdf_combo.addItems(["PBKDF2-HMAC-SHA256", "scrypt"])
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Required when encryption is enabled")
        self.password_confirm_input = QLineEdit()
        self.password_confirm_input.setEchoMode(QLineEdit.Password)
        self.password_confirm_input.setPlaceholderText("Repeat encryption password")
        self.stego_key_input = QLineEdit()
        self.stego_key_input.setEchoMode(QLineEdit.Password)
        self.stego_key_input.setPlaceholderText("Optional separate key for adaptive/spread carrier ordering")
        self.verify_check = QCheckBox("Verify after embed")
        self.security_summary_label = QLabel("")
        self.security_summary_label.setWordWrap(True)
        options.addRow("Preset", self.preset_combo)
        options.addRow(self.compress_check)
        options.addRow(self.adaptive_check)
        options.addRow(self.spread_check)
        options.addRow("Density", self.density_combo)
        options.addRow(self.verify_check)
        options.addRow("Encryption", self.encryption_combo)
        options.addRow("KDF", self.kdf_combo)
        options.addRow("Password", self.password_input)
        options.addRow("Confirm", self.password_confirm_input)
        options.addRow("Stego Key", self.stego_key_input)
        self.password_strength_label = QLabel("Password strength: not evaluated")
        self.distortion_label = QLabel("Distortion estimate: choose cover and secret files.")
        options.addRow(self.password_strength_label)
        options.addRow("Security", self.security_summary_label)

        self.capacity_label = QLabel("Capacity: choose a cover file to estimate usable payload.")
        self.cover_input.textChanged.connect(self._update_capacity)
        self.secret_input.textChanged.connect(self._update_capacity)
        self.adaptive_check.stateChanged.connect(self._update_capacity)
        self.spread_check.stateChanged.connect(self._update_capacity)
        self.density_combo.currentTextChanged.connect(self._update_capacity)
        self.password_input.textChanged.connect(self._update_password_strength)
        self.preset_combo.currentTextChanged.connect(self._apply_embed_preset)
        for widget in (
            self.compress_check,
            self.adaptive_check,
            self.spread_check,
            self.verify_check,
        ):
            widget.stateChanged.connect(self._update_security_summary)
        self.density_combo.currentTextChanged.connect(self._update_security_summary)
        self.encryption_combo.currentTextChanged.connect(self._update_security_summary)
        self.kdf_combo.currentTextChanged.connect(self._update_security_summary)
        self.stego_key_input.textChanged.connect(self._update_security_summary)
        self._update_security_summary()

        self.embed_progress = QProgressBar()
        self.embed_log = self._log_widget()
        self.embed_button = QPushButton("Embed File")
        self.embed_button.clicked.connect(self._start_embed)
        self.embed_cancel_button = QPushButton("Cancel")
        self.embed_cancel_button.setEnabled(False)
        self.embed_cancel_button.clicked.connect(self._cancel_active_job)

        layout.addWidget(source_box)
        layout.addWidget(options_box)
        layout.addWidget(self.capacity_label)
        layout.addWidget(self.distortion_label)
        layout.addWidget(self.embed_progress)
        embed_buttons = QHBoxLayout()
        embed_buttons.addStretch(1)
        embed_buttons.addWidget(self.embed_cancel_button)
        embed_buttons.addWidget(self.embed_button)
        layout.addLayout(embed_buttons)
        layout.addWidget(self.embed_log, stretch=1)
        return page

    def _build_extract_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(22, 22, 22, 22)
        layout.setSpacing(16)

        files_box = QGroupBox("Files")
        form = QGridLayout(files_box)
        self.extract_cover_input = DropLineEdit("Drop or browse for a stego BMP/PNG/WAV/FLAC file")
        self.extract_output_input = DropLineEdit("Output file path")
        form.addWidget(QLabel("Stego File"), 0, 0)
        form.addWidget(self.extract_cover_input, 0, 1)
        form.addWidget(self._browse_button(self.extract_cover_input, "Stego File", self._cover_file_filter()), 0, 2)
        form.addWidget(QLabel("Output File"), 1, 0)
        form.addWidget(self.extract_output_input, 1, 1)
        form.addWidget(self._save_button(self.extract_output_input, "Save Extracted File", "All files (*.*)"), 1, 2)

        password_box = QGroupBox("Password")
        password_form = QFormLayout(password_box)
        self.extract_password_input = QLineEdit()
        self.extract_password_input.setEchoMode(QLineEdit.Password)
        self.extract_password_input.setPlaceholderText("Leave empty if the payload was not encrypted")
        self.extract_stego_key_input = QLineEdit()
        self.extract_stego_key_input.setEchoMode(QLineEdit.Password)
        self.extract_stego_key_input.setPlaceholderText("Required only if a separate stego key was used")
        password_form.addRow("Password", self.extract_password_input)
        password_form.addRow("Stego Key", self.extract_stego_key_input)

        self.extract_progress = QProgressBar()
        self.extract_log = self._log_widget()
        self.extract_button = QPushButton("Extract File")
        self.extract_button.clicked.connect(self._start_extract)
        self.extract_cancel_button = QPushButton("Cancel")
        self.extract_cancel_button.setEnabled(False)
        self.extract_cancel_button.clicked.connect(self._cancel_active_job)

        layout.addWidget(files_box)
        layout.addWidget(password_box)
        layout.addWidget(self.extract_progress)
        extract_buttons = QHBoxLayout()
        extract_buttons.addStretch(1)
        extract_buttons.addWidget(self.extract_cancel_button)
        extract_buttons.addWidget(self.extract_button)
        layout.addLayout(extract_buttons)
        layout.addWidget(self.extract_log, stretch=1)
        return page

    def _build_forensic_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(22, 22, 22, 22)
        layout.setSpacing(16)

        files_box = QGroupBox("Scan Target")
        form = QGridLayout(files_box)
        self.forensic_target_input = DropLineEdit("Drop or browse for a file or folder")
        self.forensic_password_input = QLineEdit()
        self.forensic_password_input.setEchoMode(QLineEdit.Password)
        self.forensic_password_input.setPlaceholderText("Optional; improves metadata parsing for protected payloads")
        self.forensic_stego_key_input = QLineEdit()
        self.forensic_stego_key_input.setEchoMode(QLineEdit.Password)
        self.forensic_stego_key_input.setPlaceholderText("Optional separate stego key")
        self.forensic_recursive_check = QCheckBox("Scan folders recursively")
        self.forensic_recursive_check.setChecked(True)
        self.forensic_report_input = DropLineEdit("Optional CSV or JSON report output path")
        form.addWidget(QLabel("Target"), 0, 0)
        form.addWidget(self.forensic_target_input, 0, 1)
        browse_file = QPushButton("Browse File")
        browse_file.clicked.connect(lambda: self._choose_open_file(self.forensic_target_input, "Scan File", "All files (*.*)"))
        browse_folder = QPushButton("Browse Folder")
        browse_folder.clicked.connect(self._choose_forensic_folder)
        button_row = QHBoxLayout()
        button_row.addWidget(browse_file)
        button_row.addWidget(browse_folder)
        form.addLayout(button_row, 0, 2)
        form.addWidget(QLabel("Password"), 1, 0)
        form.addWidget(self.forensic_password_input, 1, 1)
        form.addWidget(QLabel("Stego Key"), 2, 0)
        form.addWidget(self.forensic_stego_key_input, 2, 1)
        form.addWidget(self.forensic_recursive_check, 3, 1)
        form.addWidget(QLabel("Report"), 4, 0)
        form.addWidget(self.forensic_report_input, 4, 1)
        form.addWidget(self._save_button(self.forensic_report_input, "Save Forensic Report", "Reports (*.csv *.json);;All files (*.*)"), 4, 2)

        self.forensic_log = self._log_widget()
        self.forensic_table = QTableWidget(0, 7)
        self.forensic_table.setHorizontalHeaderLabels(["Risk", "Status", "Confidence", "Type", "Path", "Entropy", "LSB 1s"])
        self.forensic_table.setSortingEnabled(True)
        self.forensic_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.forensic_button = QPushButton("Scan")
        self.forensic_button.clicked.connect(self._start_forensic_scan)
        self.forensic_cancel_button = QPushButton("Cancel")
        self.forensic_cancel_button.setEnabled(False)
        self.forensic_cancel_button.clicked.connect(self._cancel_forensic_scan)
        self.forensic_progress = QProgressBar()

        layout.addWidget(files_box)
        layout.addWidget(self.forensic_progress)
        button_layout = QHBoxLayout()
        button_layout.addStretch(1)
        button_layout.addWidget(self.forensic_cancel_button)
        button_layout.addWidget(self.forensic_button)
        layout.addLayout(button_layout)
        layout.addWidget(self.forensic_table, stretch=2)
        layout.addWidget(self.forensic_log, stretch=1)
        return page

    def _build_settings_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(22, 22, 22, 22)
        layout.setSpacing(16)

        defaults_box = QGroupBox("Defaults")
        defaults = QFormLayout(defaults_box)
        self.default_compress_check = QCheckBox("Compress payloads by default")
        self.default_compress_check.setChecked(bool(self.config.get("default_compress", True)))
        self.default_adaptive_check = QCheckBox("Enable adaptive embedding by default")
        self.default_adaptive_check.setChecked(bool(self.config.get("default_adaptive", False)))
        self.default_spread_check = QCheckBox("Enable spread mode by default")
        self.default_spread_check.setChecked(bool(self.config.get("default_spread", False)))
        self.high_contrast_check = QCheckBox("High contrast theme")
        self.high_contrast_check.setChecked(self.config.get("theme") == "high_contrast")
        defaults.addRow(self.default_compress_check)
        defaults.addRow(self.default_adaptive_check)
        defaults.addRow(self.default_spread_check)
        defaults.addRow(self.high_contrast_check)

        save_button = QPushButton("Save Settings")
        save_button.clicked.connect(self._save_settings)
        data_button = QPushButton("Open Data Folder")
        data_button.clicked.connect(lambda: self._open_folder(portable_data_dir()))
        log_button = QPushButton("Open Log Folder")
        log_button.clicked.connect(lambda: self._open_folder(log_path().parent))
        health_button = QPushButton("Health Check")
        health_button.clicked.connect(self._show_health)
        plugins_button = QPushButton("Plugins")
        plugins_button.clicked.connect(self._show_plugins)
        update_button = QPushButton("Check Updates")
        update_button.clicked.connect(self._check_updates)

        about = QPlainTextEdit()
        about.setReadOnly(True)
        about.setPlainText(
            "ObscuraPrimus 1.0.0\n"
            "Release signing fingerprint:\n"
            "323D 123C BF92 E8C9 62AA A846 3B4C CEFE CA58 0B4D\n\n"
            "Supported carriers: BMP, PNG, WAV, FLAC.\n"
            "JPEG-DCT requires OBSCURAPRIMUS_JPEG_DCT_BACKEND."
        )

        buttons = QHBoxLayout()
        buttons.addWidget(save_button)
        buttons.addWidget(data_button)
        buttons.addWidget(log_button)
        buttons.addWidget(health_button)
        buttons.addWidget(plugins_button)
        buttons.addWidget(update_button)
        buttons.addStretch(1)
        layout.addWidget(defaults_box)
        layout.addLayout(buttons)
        layout.addWidget(about, stretch=1)
        return page

    def _build_analysis_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(22, 22, 22, 22)
        layout.setSpacing(16)

        target_box = QGroupBox("Analysis Target")
        form = QGridLayout(target_box)
        self.analysis_target_input = DropLineEdit("Drop or browse for a file or folder")
        self.analysis_report_input = DropLineEdit("Optional .csv, .json, or .html report")
        self.analysis_yara_input = DropLineEdit("Optional YARA rules file")
        self.analysis_sign_report_check = QCheckBox("Sign report with local GPG key")
        self.analysis_profile_combo = QComboBox()
        self.analysis_profile_combo.addItems(["quick", "deep", "stego-focused", "malware-triage"])
        self.analysis_recursive_check = QCheckBox("Scan folders recursively")
        self.analysis_recursive_check.setChecked(True)
        form.addWidget(QLabel("Target"), 0, 0)
        form.addWidget(self.analysis_target_input, 0, 1)
        browse_file = QPushButton("Browse File")
        browse_file.clicked.connect(lambda: self._choose_open_file(self.analysis_target_input, "Analyze File", "All files (*.*)"))
        browse_folder = QPushButton("Browse Folder")
        browse_folder.clicked.connect(self._choose_analysis_folder)
        buttons = QHBoxLayout()
        buttons.addWidget(browse_file)
        buttons.addWidget(browse_folder)
        form.addLayout(buttons, 0, 2)
        form.addWidget(QLabel("Profile"), 1, 0)
        form.addWidget(self.analysis_profile_combo, 1, 1)
        form.addWidget(self.analysis_recursive_check, 2, 1)
        form.addWidget(QLabel("YARA Rules"), 3, 0)
        form.addWidget(self.analysis_yara_input, 3, 1)
        form.addWidget(self._browse_button(self.analysis_yara_input, "YARA Rules", "YARA files (*.yar *.yara);;All files (*.*)"), 3, 2)
        form.addWidget(QLabel("Report"), 4, 0)
        form.addWidget(self.analysis_report_input, 4, 1)
        form.addWidget(self._save_button(self.analysis_report_input, "Save Analysis Report", "Reports (*.csv *.json *.html);;All files (*.*)"), 4, 2)
        form.addWidget(self.analysis_sign_report_check, 5, 1)

        self.analysis_table = QTableWidget(0, 7)
        self.analysis_table.setHorizontalHeaderLabels(["Risk", "Type", "Size", "Path", "SHA-256", "Mismatch", "Explanation"])
        self.analysis_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.analysis_table.setSortingEnabled(True)
        self.analysis_table.itemSelectionChanged.connect(self._analysis_selection_changed)
        self.analysis_log = self._log_widget()
        self.analysis_progress = QProgressBar()
        self.analysis_start_button = QPushButton("Analyze")
        self.analysis_start_button.clicked.connect(self._start_analysis)
        self.analysis_cancel_button = QPushButton("Cancel")
        self.analysis_cancel_button.setEnabled(False)
        self.analysis_cancel_button.clicked.connect(self._cancel_active_job)

        self.hex_offset_input = QLineEdit("0")
        self.hex_search_input = QLineEdit()
        self.hex_search_input.setPlaceholderText("Search text in selected file")
        hex_button = QPushButton("Hex Preview")
        hex_button.clicked.connect(self._show_hex_preview)
        search_button = QPushButton("Search")
        search_button.clicked.connect(self._search_selected_file)
        carve_button = QPushButton("Carve")
        carve_button.clicked.connect(self._carve_selected_file)
        compare_button = QPushButton("Compare")
        compare_button.clicked.connect(self._compare_selected_file)

        self.case_dir_input = DropLineEdit("Optional case workspace folder")
        self.tag_input = QLineEdit()
        self.tag_input.setPlaceholderText("Comma-separated tags")
        self.notes_input = QLineEdit()
        self.notes_input.setPlaceholderText("Analyst notes")
        case_button = QPushButton("Create Case")
        case_button.clicked.connect(self._create_case)
        evidence_button = QPushButton("Add Selected Evidence")
        evidence_button.clicked.connect(self._add_selected_evidence)

        layout.addWidget(target_box)
        layout.addWidget(self.analysis_progress)
        action_row = QHBoxLayout()
        action_row.addStretch(1)
        action_row.addWidget(self.analysis_cancel_button)
        action_row.addWidget(self.analysis_start_button)
        layout.addLayout(action_row)
        layout.addWidget(self.analysis_table, stretch=3)
        hex_row = QHBoxLayout()
        hex_row.addWidget(QLabel("Offset"))
        hex_row.addWidget(self.hex_offset_input)
        hex_row.addWidget(hex_button)
        hex_row.addWidget(self.hex_search_input)
        hex_row.addWidget(search_button)
        hex_row.addWidget(carve_button)
        hex_row.addWidget(compare_button)
        layout.addLayout(hex_row)
        case_row = QHBoxLayout()
        case_row.addWidget(self.case_dir_input)
        case_row.addWidget(self._save_button(self.case_dir_input, "Case Folder", "All files (*.*)"))
        case_row.addWidget(self.tag_input)
        case_row.addWidget(self.notes_input)
        case_row.addWidget(case_button)
        case_row.addWidget(evidence_button)
        layout.addLayout(case_row)
        layout.addWidget(self.analysis_log, stretch=1)
        return page

    def _build_suite_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(22, 22, 22, 22)
        layout.setSpacing(16)

        inputs = QGroupBox("Suite Inputs")
        form = QGridLayout(inputs)
        self.suite_file_input = DropLineEdit("File, artifact, script, disk image, or browser database")
        self.suite_case_input = DropLineEdit("Case workspace folder")
        self.suite_rules_input = DropLineEdit("YARA or Sigma rule file")
        self.suite_query_input = QLineEdit()
        self.suite_query_input.setPlaceholderText("Case search query")
        form.addWidget(QLabel("File"), 0, 0)
        form.addWidget(self.suite_file_input, 0, 1)
        form.addWidget(self._browse_button(self.suite_file_input, "Suite File", "All files (*.*)"), 0, 2)
        form.addWidget(QLabel("Case"), 1, 0)
        form.addWidget(self.suite_case_input, 1, 1)
        case_browse = QPushButton("Browse")
        case_browse.clicked.connect(lambda: self._choose_suite_folder(self.suite_case_input))
        form.addWidget(case_browse, 1, 2)
        form.addWidget(QLabel("Rules"), 2, 0)
        form.addWidget(self.suite_rules_input, 2, 1)
        form.addWidget(self._browse_button(self.suite_rules_input, "Rules", "Rule files (*.yar *.yara *.yml *.yaml);;All files (*.*)"), 2, 2)
        form.addWidget(QLabel("Search"), 3, 0)
        form.addWidget(self.suite_query_input, 3, 1)

        action_box = QGroupBox("Actions")
        actions = QGridLayout(action_box)
        buttons = [
            ("Validate YARA", self._suite_validate_yara),
            ("YARA Matches", self._suite_yara_matches),
            ("Validate Sigma", self._suite_validate_sigma),
            ("Entropy Chart Data", self._suite_entropy),
            ("Byte Histogram", self._suite_histogram),
            ("Virtual Hex Page", self._suite_hex_page),
            ("Import Immutable", self._suite_import_immutable),
            ("Case Search", self._suite_case_search),
            ("Raw/DD Image", self._suite_raw_image),
            ("Browser Artifact", self._suite_browser_artifact),
            ("Windows Artifact", self._suite_windows_artifact),
            ("Anomaly Score", self._suite_anomaly),
            ("Deobfuscate Script", self._suite_deobfuscate),
            ("Sample Case", self._suite_sample_case),
            ("Example Plugin", self._suite_example_plugin),
        ]
        for index, (label, handler) in enumerate(buttons):
            button = QPushButton(label)
            button.clicked.connect(handler)
            actions.addWidget(button, index // 3, index % 3)

        self.suite_chart = ChartWidget()
        self.suite_hex = VirtualHexWidget()
        self.suite_log = self._log_widget()
        self.suite_dashboard = QLabel("Dashboard: no case loaded.")
        self.command_input = QLineEdit()
        self.command_input.setPlaceholderText("Command: entropy, histogram, hex, anomaly, case-search")
        self.command_input.returnPressed.connect(self._run_suite_command)
        layout.addWidget(inputs)
        layout.addWidget(self.suite_dashboard)
        layout.addWidget(self.command_input)
        layout.addWidget(action_box)
        layout.addWidget(self.suite_chart)
        layout.addWidget(self.suite_hex, stretch=1)
        layout.addWidget(self.suite_log, stretch=1)
        return page

    def _install_shortcuts(self) -> None:
        QShortcut(QKeySequence("Ctrl+E"), self, activated=self._start_embed)
        QShortcut(QKeySequence("Ctrl+R"), self, activated=self._start_extract)
        QShortcut(QKeySequence("Ctrl+F"), self, activated=self._start_analysis)
        QShortcut(QKeySequence("Ctrl+L"), self, activated=lambda: self.command_input.setFocus() if hasattr(self, "command_input") else None)

    def _run_suite_command(self) -> None:
        command = self.command_input.text().strip().lower()
        if command == "entropy":
            self._suite_entropy()
        elif command == "histogram":
            self._suite_histogram()
        elif command == "hex":
            self._suite_hex_page()
        elif command == "anomaly":
            self._suite_anomaly()
        elif command == "case-search":
            self._suite_case_search()
        else:
            self.suite_log.appendPlainText("Available commands: entropy, histogram, hex, anomaly, case-search")

    def _choose_suite_folder(self, target: QLineEdit) -> None:
        path = QFileDialog.getExistingDirectory(self, "Choose Folder", self.config.get("last_directory", ""))
        if path:
            target.setText(path)
            self.config["last_directory"] = path
            save_config(self.config)

    def _suite_file(self) -> str:
        path = self.suite_file_input.text().strip()
        if not path or not Path(path).exists():
            self._warn("Choose an existing file first.")
            return ""
        return path

    def _suite_case(self) -> str:
        path = self.suite_case_input.text().strip()
        if not path:
            self._warn("Choose a case workspace folder first.")
            return ""
        return path

    def _refresh_suite_dashboard(self) -> None:
        case_dir = self.suite_case_input.text().strip()
        if not case_dir:
            return
        try:
            data = case_dashboard(case_dir)
            self.suite_dashboard.setText(
                f"Dashboard: evidence {data['evidence_count']} | open findings {data['open_findings']} | high risk {data['high_risk_files']} | duplicate groups {len(data['duplicate_hashes'])}"
            )
        except Exception as exc:
            self.suite_dashboard.setText(f"Dashboard unavailable: {exc}")

    def _suite_rules(self) -> str:
        path = self.suite_rules_input.text().strip()
        if not path or not Path(path).exists():
            self._warn("Choose an existing rule file first.")
            return ""
        return path

    def _suite_dump(self, value) -> None:
        self.suite_log.appendPlainText(json.dumps(value, indent=2, sort_keys=True, default=str)[:12000])

    def _suite_validate_yara(self) -> None:
        rules = self._suite_rules()
        if rules:
            self._suite_dump(validate_yara_rules(rules))

    def _suite_yara_matches(self) -> None:
        path = self._suite_file()
        rules = self._suite_rules()
        if path and rules:
            self._suite_dump([match.__dict__ for match in scan_yara_details(path, rules)])

    def _suite_validate_sigma(self) -> None:
        rules = self._suite_rules()
        if rules:
            self._suite_dump(validate_sigma_rule(rules))

    def _suite_entropy(self) -> None:
        path = self._suite_file()
        if path:
            data = entropy_timeline(path)[:512]
            self.suite_chart.set_series([entry["entropy"] for entry in data])
            self._suite_dump(data)

    def _suite_histogram(self) -> None:
        path = self._suite_file()
        if path:
            histogram = byte_histogram(path)
            self.suite_chart.set_series(histogram)
            self._suite_dump({"histogram": histogram})

    def _suite_hex_page(self) -> None:
        path = self._suite_file()
        if path:
            self.suite_hex.set_file(path)
            self._suite_dump(virtual_hex_page(path))

    def _suite_import_immutable(self) -> None:
        path = self._suite_file()
        case_dir = self._suite_case()
        if path and case_dir:
            self._suite_dump(import_immutable_evidence(case_dir, path, ["immutable"], self.notes_input.text() if hasattr(self, "notes_input") else ""))
            self._refresh_suite_dashboard()

    def _suite_case_search(self) -> None:
        case_dir = self._suite_case()
        query = self.suite_query_input.text().strip()
        if case_dir and query:
            self._suite_dump(search_case(case_dir, query))
            self._refresh_suite_dashboard()

    def _suite_raw_image(self) -> None:
        path = self._suite_file()
        if path:
            self._suite_dump(inspect_raw_image(path))

    def _suite_browser_artifact(self) -> None:
        path = self._suite_file()
        if path:
            self._suite_dump(inspect_browser_artifact(path))

    def _suite_windows_artifact(self) -> None:
        path = self._suite_file()
        if path:
            self._suite_dump(inspect_windows_artifact(path))

    def _suite_anomaly(self) -> None:
        path = self._suite_file()
        if path:
            self._suite_dump(anomaly_score(path))

    def _suite_deobfuscate(self) -> None:
        path = self._suite_file()
        if path:
            self._suite_dump(deobfuscate_script(path))

    def _suite_sample_case(self) -> None:
        case_dir = self.suite_case_input.text().strip() or str(portable_data_dir() / "sample-case")
        self._suite_dump({"sample_case": str(onboarding_sample_case(case_dir))})
        self._refresh_suite_dashboard()

    def _suite_example_plugin(self) -> None:
        case_dir = self.suite_case_input.text().strip() or str(portable_data_dir() / "plugins" / "example_plugin")
        self._suite_dump(write_example_plugin(case_dir))

    def _browse_button(self, target: QLineEdit, title: str, file_filter: str) -> QPushButton:
        button = QPushButton("Browse")
        button.clicked.connect(lambda: self._choose_open_file(target, title, file_filter))
        return button

    def _cover_file_filter(self) -> str:
        filters = ["Supported covers (*.bmp *.png *.wav *.flac)"]
        if jpeg_backend_available():
            filters.append("JPEG-DCT backend (*.jpg *.jpeg)")
        filters.append("All files (*.*)")
        return ";;".join(filters)

    def _save_button(self, target: QLineEdit, title: str, file_filter: str) -> QPushButton:
        button = QPushButton("Save As")
        button.clicked.connect(lambda: self._choose_save_file(target, title, file_filter))
        return button

    def _choose_open_file(self, target: QLineEdit, title: str, file_filter: str) -> None:
        path, _ = QFileDialog.getOpenFileName(self, title, self.config.get("last_directory", ""), file_filter)
        if path:
            target.setText(path)
            self._remember_directory(path)
            if target is self.cover_input and not self.output_input.text():
                suffix = Path(path).suffix
                self.output_input.setText(str(Path(path).with_name(f"{Path(path).stem}_obscura{suffix}")))

    def _choose_save_file(self, target: QLineEdit, title: str, file_filter: str) -> None:
        path, _ = QFileDialog.getSaveFileName(self, title, self.config.get("last_directory", ""), file_filter)
        if path:
            target.setText(path)
            self._remember_directory(path)

    def _log_widget(self) -> QPlainTextEdit:
        log = QPlainTextEdit()
        log.setReadOnly(True)
        log.setMaximumBlockCount(500)
        return log

    def _start_embed(self) -> None:
        cover = self.cover_input.text().strip()
        secret = self.secret_input.text().strip()
        output = self.output_input.text().strip()
        algorithm = self.encryption_combo.currentText()
        password = self.password_input.text()

        if not self._paths_exist([(cover, "Cover file"), (secret, "Secret file")]):
            return
        if not output:
            self._warn("Choose an output file path.")
            return
        if algorithm != "None" and not password:
            self._warn("Enter a password when encryption is enabled.")
            return
        if algorithm != "None" and self._password_strength_score(password) <= 2:
            self._warn("Use a stronger encryption password before embedding.")
            return
        if algorithm != "None" and password != self.password_confirm_input.text():
            self._warn("Password confirmation does not match.")
            return
        if algorithm == "None":
            proceed = QMessageBox.question(
                self,
                "ObscuraPrimus",
                "Embedding without encryption can expose the hidden file if discovered. Continue?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if proceed != QMessageBox.Yes:
                return

        kwargs = {
            "cover_path": cover,
            "secret_path": secret,
            "output_path": output,
            "options": EmbedOptions(
                compress=self.compress_check.isChecked(),
                encryption=algorithm,
                password=password,
                adaptive=self.adaptive_check.isChecked(),
                spread=self.spread_check.isChecked(),
                verify_after_embed=self.verify_check.isChecked(),
                stego_key=self.stego_key_input.text(),
                kdf=self.kdf_combo.currentText(),
                density=self.density_combo.currentText(),
            ),
        }
        self.embed_log.clear()
        self._run_worker("embed", kwargs, self.embed_progress, self.embed_log, self.embed_button, self.embed_cancel_button)

    def _start_extract(self) -> None:
        cover = self.extract_cover_input.text().strip()
        output = self.extract_output_input.text().strip()
        if not self._paths_exist([(cover, "Stego file")]):
            return
        if not output:
            self._warn("Choose where to save the extracted file.")
            return

        output_path = Path(output)
        kwargs = {
            "cover_path": cover,
            "output_dir": str(output_path.parent),
            "output_name": output_path.name,
            "password": self.extract_password_input.text(),
            "stego_key": self.extract_stego_key_input.text(),
        }
        self.extract_log.clear()
        self._run_worker("extract", kwargs, self.extract_progress, self.extract_log, self.extract_button, self.extract_cancel_button)

    def _start_forensic_scan(self) -> None:
        target = self.forensic_target_input.text().strip()
        if not target or not Path(target).exists():
            self._warn("Choose a file or folder to scan.")
            return
        if self.thread and self.thread.isRunning():
            self._warn("A job is already running.")
            return
        self.forensic_log.clear()
        self.forensic_table.setSortingEnabled(False)
        self.forensic_table.setRowCount(0)
        self.forensic_table.setSortingEnabled(True)
        self.forensic_progress.setValue(0)
        self.forensic_button.setEnabled(False)
        self.forensic_cancel_button.setEnabled(True)
        self.thread = QThread()
        self.worker = ForensicWorker(
            target,
            self.forensic_password_input.text(),
            self.forensic_stego_key_input.text(),
            self.forensic_recursive_check.isChecked(),
            self.forensic_report_input.text().strip(),
        )
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(lambda value, msg: self._on_progress(self.forensic_progress, self.forensic_log, value, f"Scanning {msg}"))
        self.worker.finding.connect(self.forensic_log.appendPlainText)
        self.worker.findingObject.connect(self._add_forensic_table_row)
        self.worker.finished.connect(lambda msg: self._on_finished(self.forensic_progress, self.forensic_log, self.forensic_button, msg))
        self.worker.failed.connect(lambda msg: self._on_failed(self.forensic_progress, self.forensic_log, self.forensic_button, msg))
        self.worker.finished.connect(lambda _msg: self.forensic_cancel_button.setEnabled(False))
        self.worker.failed.connect(lambda _msg: self.forensic_cancel_button.setEnabled(False))
        self.worker.finished.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.failed.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    def _cancel_forensic_scan(self) -> None:
        if self.worker and hasattr(self.worker, "cancel"):
            self.worker.cancel()
            self.forensic_log.appendPlainText("Cancellation requested...")

    def _add_forensic_table_row(self, finding) -> None:
        self.forensic_table.setSortingEnabled(False)
        row = self.forensic_table.rowCount()
        self.forensic_table.insertRow(row)
        values = [
            finding.risk_score,
            finding.status,
            finding.confidence,
            finding.cover_type,
            finding.path,
            f"{finding.entropy:.3f}",
            f"{finding.lsb_one_ratio:.3f}",
        ]
        for column, value in enumerate(values):
            item = QTableWidgetItem(str(value))
            if isinstance(value, int):
                item.setData(Qt.UserRole, value)
            self.forensic_table.setItem(row, column, item)
        self.forensic_table.setSortingEnabled(True)

    def _choose_forensic_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Scan Folder", self.config.get("last_directory", ""))
        if path:
            self.forensic_target_input.setText(path)
            self._remember_directory(path)

    def _choose_analysis_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Analyze Folder", self.config.get("last_directory", ""))
        if path:
            self.analysis_target_input.setText(path)
            self._remember_directory(path)

    def _start_analysis(self) -> None:
        target = self.analysis_target_input.text().strip()
        if not target or not Path(target).exists():
            self._warn("Choose a file or folder to analyze.")
            return
        if self.thread and self.thread.isRunning():
            self._warn("A job is already running.")
            return
        self.analysis_table.setSortingEnabled(False)
        self.analysis_table.setRowCount(0)
        self.analysis_table.setSortingEnabled(True)
        self.analysis_log.clear()
        self.analysis_progress.setValue(0)
        self.analysis_start_button.setEnabled(False)
        self.analysis_cancel_button.setEnabled(True)
        self.thread = QThread()
        self.worker = AnalysisWorker(
            target,
            self.analysis_profile_combo.currentText(),
            self.analysis_recursive_check.isChecked(),
            self.analysis_report_input.text().strip(),
            self.analysis_yara_input.text().strip(),
            self.analysis_sign_report_check.isChecked(),
        )
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(lambda value, msg: self._on_progress(self.analysis_progress, self.analysis_log, value, f"Analyzing {msg}"))
        self.worker.resultObject.connect(self._add_analysis_table_row)
        self.worker.finished.connect(lambda msg: self._on_finished(self.analysis_progress, self.analysis_log, self.analysis_start_button, msg))
        self.worker.failed.connect(lambda msg: self._on_failed(self.analysis_progress, self.analysis_log, self.analysis_start_button, msg))
        self.worker.finished.connect(lambda _msg: self.analysis_cancel_button.setEnabled(False))
        self.worker.failed.connect(lambda _msg: self.analysis_cancel_button.setEnabled(False))
        self.worker.finished.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.failed.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    def _add_analysis_table_row(self, analysis) -> None:
        self.analysis_table.setSortingEnabled(False)
        row = self.analysis_table.rowCount()
        self.analysis_table.insertRow(row)
        values = [
            analysis.risk_score,
            analysis.magic_type,
            analysis.size,
            analysis.path,
            analysis.hashes.get("sha256", ""),
            "yes" if analysis.signature_mismatch else "no",
            analysis.explanation,
        ]
        for column, value in enumerate(values):
            item = QTableWidgetItem(str(value))
            if isinstance(value, int):
                item.setData(Qt.UserRole, value)
            item.setData(Qt.UserRole + 1, analysis.path)
            self.analysis_table.setItem(row, column, item)
        self.analysis_table.setSortingEnabled(True)

    def _selected_analysis_path(self) -> str:
        items = self.analysis_table.selectedItems()
        if not items:
            return ""
        return items[0].data(Qt.UserRole + 1) or ""

    def _analysis_selection_changed(self) -> None:
        path = self._selected_analysis_path()
        if path:
            self.analysis_log.appendPlainText(f"Selected {path}")

    def _show_hex_preview(self) -> None:
        path = self._selected_analysis_path()
        if not path:
            self._warn("Select a file in the analysis table first.")
            return
        try:
            offset = int(self.hex_offset_input.text().strip() or "0", 0)
            self.analysis_log.appendPlainText(hex_preview(path, offset=offset, length=512))
        except Exception as exc:
            self._warn(str(exc))

    def _search_selected_file(self) -> None:
        path = self._selected_analysis_path()
        needle = self.hex_search_input.text()
        if not path or not needle:
            self._warn("Select a file and enter search text.")
            return
        offsets = search_hex(path, needle.encode("utf-8"))
        if offsets:
            self.analysis_log.appendPlainText("Search offsets: " + ", ".join(hex(offset) for offset in offsets[:50]))
        else:
            self.analysis_log.appendPlainText("Search text not found.")

    def _carve_selected_file(self) -> None:
        path = self._selected_analysis_path()
        if not path:
            self._warn("Select a file first.")
            return
        output = Path(self.case_dir_input.text().strip() or str(portable_data_dir())) / "carved"
        carved = carve_embedded_files(path, output)
        self.analysis_log.appendPlainText(f"Carved {len(carved)} embedded candidates to {output}")

    def _compare_selected_file(self) -> None:
        path = self._selected_analysis_path()
        other, _ = QFileDialog.getOpenFileName(self, "Compare With", self.config.get("last_directory", ""), "All files (*.*)")
        if not path or not other:
            return
        self._remember_directory(other)
        comparison = compare_files(path, other, max_diffs=50)
        self.analysis_log.appendPlainText(json.dumps(comparison, indent=2)[:8000])

    def _create_case(self) -> None:
        case_dir = self.case_dir_input.text().strip()
        if not case_dir:
            self._warn("Choose a case folder.")
            return
        create_case(case_dir, "ObscuraPrimus case")
        self.analysis_log.appendPlainText(f"Case workspace ready: {case_dir}")

    def _add_selected_evidence(self) -> None:
        path = self._selected_analysis_path()
        case_dir = self.case_dir_input.text().strip()
        if not path or not case_dir:
            self._warn("Select a file and choose a case folder.")
            return
        tags = [tag.strip() for tag in self.tag_input.text().split(",") if tag.strip()]
        entry = add_evidence(case_dir, path, tags, self.notes_input.text())
        self.analysis_log.appendPlainText(f"Evidence added: {entry['sha256']} {entry['path']}")

    def _run_worker(
        self,
        mode: str,
        kwargs: dict,
        progress_bar: QProgressBar,
        log: QPlainTextEdit,
        button: QPushButton,
        cancel_button: QPushButton | None = None,
    ) -> None:
        if self.thread and self.thread.isRunning():
            self._warn("A job is already running.")
            return

        progress_bar.setValue(0)
        button.setEnabled(False)
        if cancel_button:
            cancel_button.setEnabled(True)
        self.thread = QThread()
        self.worker = Worker(mode, kwargs)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(lambda value, msg: self._on_progress(progress_bar, log, value, msg))
        self.worker.finished.connect(lambda msg: self._on_finished(progress_bar, log, button, msg))
        self.worker.failed.connect(lambda msg: self._on_failed(progress_bar, log, button, msg))
        if cancel_button:
            self.worker.finished.connect(lambda _msg: cancel_button.setEnabled(False))
            self.worker.failed.connect(lambda _msg: cancel_button.setEnabled(False))
        self.worker.finished.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.failed.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    def _cancel_active_job(self) -> None:
        if self.worker and hasattr(self.worker, "cancel"):
            self.worker.cancel()

    def _on_progress(self, progress_bar: QProgressBar, log: QPlainTextEdit, value: int, message: str) -> None:
        progress_bar.setValue(value)
        log.appendPlainText(message)

    def _on_finished(self, progress_bar: QProgressBar, log: QPlainTextEdit, button: QPushButton, message: str) -> None:
        progress_bar.setValue(100)
        log.appendPlainText(message)
        button.setEnabled(True)

    def _on_failed(self, progress_bar: QProgressBar, log: QPlainTextEdit, button: QPushButton, message: str) -> None:
        progress_bar.setValue(0)
        log.appendPlainText(f"Error: {message}")
        button.setEnabled(True)
        QMessageBox.critical(self, "ObscuraPrimus", message)

    def _paths_exist(self, paths: list[tuple[str, str]]) -> bool:
        for path, label in paths:
            if not path or not Path(path).is_file():
                self._warn(f"{label} does not exist.")
                return False
        return True

    def _update_capacity(self) -> None:
        cover = self.cover_input.text().strip()
        if not Path(cover).is_file():
            self.capacity_label.setText("Capacity: choose a cover file to estimate usable payload.")
            self.distortion_label.setText("Distortion estimate: choose cover and secret files.")
            return
        try:
            capacity = estimate_capacity(
                cover,
                self.adaptive_check.isChecked(),
                self.spread_check.isChecked(),
                self.density_combo.currentText(),
            )
            self.capacity_label.setText(f"Capacity: exactly {capacity:,} payload bytes before compression/encryption overhead.")
            secret = self.secret_input.text().strip()
            if Path(secret).is_file():
                payload_size = Path(secret).stat().st_size
                estimate = estimate_distortion(cover, payload_size, self.adaptive_check.isChecked(), self.density_combo.currentText())
                ratio = estimate["estimated_change_ratio"] * 100
                self.distortion_label.setText(
                    f"Distortion estimate: up to {estimate['estimated_lsb_changes']:,} LSB flips, about {ratio:.4f}% carrier change."
                )
            else:
                self.distortion_label.setText("Distortion estimate: choose a secret file.")
        except Exception as exc:
            self.capacity_label.setText(f"Capacity: unavailable ({exc}).")
            self.distortion_label.setText("Distortion estimate: unavailable.")

    def _warn(self, message: str) -> None:
        QMessageBox.warning(self, "ObscuraPrimus", message)

    def _remember_directory(self, path: str) -> None:
        self.config["last_directory"] = str(Path(path).parent)
        save_config(self.config)

    def _save_settings(self) -> None:
        self.config["default_compress"] = self.default_compress_check.isChecked()
        self.config["default_adaptive"] = self.default_adaptive_check.isChecked()
        self.config["default_spread"] = self.default_spread_check.isChecked()
        self.config["theme"] = "high_contrast" if self.high_contrast_check.isChecked() else "dark"
        save_config(self.config)
        QApplication.instance().setStyleSheet(HIGH_CONTRAST_STYLE if self.config["theme"] == "high_contrast" else STYLE)
        self._warn("Settings saved.")

    def _open_folder(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        if sys.platform.startswith("win"):
            os.startfile(path)
        else:
            QMessageBox.information(self, "ObscuraPrimus", str(path))

    def _show_health(self) -> None:
        QMessageBox.information(self, "Portable Health", json.dumps(portable_health(), indent=2))

    def _show_plugins(self) -> None:
        text = "\n".join(f"{plugin.name}: {', '.join(plugin.extensions)} - {plugin.description}" for plugin in available_plugins())
        QMessageBox.information(self, "Analyzer Plugins", text)

    def _check_updates(self) -> None:
        result = check_github_update(self.config.get("update_repo", ""), __version__)
        QMessageBox.information(self, "Update Check", json.dumps(result, indent=2))

    def _maybe_show_onboarding(self) -> None:
        if os.environ.get("QT_QPA_PLATFORM") == "offscreen":
            return
        if self.config.get("first_run_complete"):
            return
        QMessageBox.information(
            self,
            "Welcome to ObscuraPrimus",
            "ObscuraPrimus runs in portable mode. Analysis is read-only unless you explicitly embed, extract, export, carve, or add evidence to a case.",
        )
        self.config["first_run_complete"] = True
        save_config(self.config)

    def _update_password_strength(self) -> None:
        password = self.password_input.text()
        score = self._password_strength_score(password)
        if not password:
            label = "not evaluated"
        elif score <= 2:
            label = "weak"
        elif score <= 4:
            label = "moderate"
        else:
            label = "strong"
        self.password_strength_label.setText(f"Password strength: {label}")
        self._update_security_summary()

    def _password_strength_score(self, password: str) -> int:
        score = 0
        score += len(password) >= 12
        score += len(password) >= 18
        score += any(ch.islower() for ch in password)
        score += any(ch.isupper() for ch in password)
        score += any(ch.isdigit() for ch in password)
        score += any(not ch.isalnum() for ch in password)
        return int(score)

    def _apply_embed_preset(self, name: str) -> None:
        preset = EMBED_PRESETS.get(name, {})
        if not preset:
            self._update_security_summary()
            return
        self.compress_check.setChecked(bool(preset["compress"]))
        self.adaptive_check.setChecked(bool(preset["adaptive"]))
        self.spread_check.setChecked(bool(preset["spread"]))
        self.verify_check.setChecked(bool(preset["verify"]))
        self.density_combo.setCurrentText(str(preset["density"]))
        encryption = str(preset["encryption"])
        if self.encryption_combo.findText(encryption) >= 0:
            self.encryption_combo.setCurrentText(encryption)
        self.kdf_combo.setCurrentText(str(preset["kdf"]))
        self._update_capacity()
        self._update_security_summary()

    def _update_security_summary(self, *_args) -> None:
        if not hasattr(self, "security_summary_label"):
            return
        algorithm = self.encryption_combo.currentText()
        parts = []
        if algorithm == "None":
            parts.append("No encryption; hidden bytes can be recovered if the carrier is decoded.")
        else:
            parts.append(f"{algorithm} with {self.kdf_combo.currentText()}.")
            score = self._password_strength_score(self.password_input.text())
            if score <= 2:
                parts.append("Password must be stronger before embedding.")
        if self.compress_check.isChecked():
            parts.append("Compression reduces payload size before embedding.")
        if self.spread_check.isChecked():
            carrier_key = "separate stego key" if self.stego_key_input.text() else "encryption password"
            parts.append(f"Spread mode uses a {carrier_key} for carrier ordering.")
        if self.adaptive_check.isChecked():
            parts.append("Adaptive mode avoids carrier extremes.")
        parts.append(f"Density is {self.density_combo.currentText()}.")
        if self.verify_check.isChecked():
            parts.append("Verify-after-embed will read the payload back before success.")
        self.security_summary_label.setText(" ".join(parts))


def main() -> int:
    log_file = configure_logging()
    logging.info("Starting ObscuraPrimus; log file: %s", log_file)
    app = QApplication(sys.argv)
    config = load_config()
    app.setStyleSheet(HIGH_CONTRAST_STYLE if config.get("theme") == "high_contrast" else STYLE)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
