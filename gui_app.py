"""PyQt6 desktop interface for CipherLink.

Threading model: ``PeerNode`` runs its listener and transfers on plain Python worker
threads. ``Bridge`` receives their callbacks and re-emits them as ``pyqtSignal``s; because
``Bridge`` lives in the GUI thread, Qt delivers those signals as queued events, so widgets
are only ever touched on the GUI thread. Incoming-transfer consent is the one callback
that waits: the worker blocks on a ``threading.Event`` until the user answers (or the
consent timeout passes) while the GUI thread stays free.
"""
from __future__ import annotations

import datetime as dt
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, QObject, Qt, QTimer, QUrl, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QColor, QDesktopServices, QFont, QGuiApplication
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from config import APP_NAME, APP_VERSION, Config
from crypto_engine import Identity, format_fingerprint
from network_p2p import NodeEvents, PeerNode, TransferError, TransferInfo
from peer_store import Peer, PeerStore, PeerStoreError
from transfer_history import HistoryEntry, TransferHistory

STATUS_COLORS = {"completed": "#4ade80", "failed": "#f87171", "rejected": "#fbbf24", "cancelled": "#fbbf24"}
STATUS_LABELS = {
    "queued": "Queued",
    "connecting": "Connecting…",
    "awaiting_consent": "Waiting for approval",
    "transferring": "Transferring",
    "completed": "Completed",
    "failed": "Failed",
    "rejected": "Rejected",
    "cancelled": "Cancelled",
}

STYLE = """
QWidget { background: #0f1623; color: #e6ebf2; font-size: 13px; }
QLabel { background: transparent; }
QFrame#card { background: #172133; border: 1px solid #23314a; border-radius: 12px; }
QLabel#title { font-size: 20px; font-weight: 700; color: #f8fafc; }
QLabel#cardTitle { font-size: 15px; font-weight: 600; color: #f1f5f9; }
QLabel#muted { color: #8a99b0; }
QLabel#fingerprint { color: #5eead4; }
QLabel#pill { border-radius: 10px; padding: 3px 10px; font-weight: 600; }
QLabel#pill[state="ok"] { background: #12352f; color: #5eead4; }
QLabel#pill[state="bad"] { background: #3b1d24; color: #fca5a5; }
QLabel#warning { background: #3a2a12; color: #fcd34d; border-radius: 8px; padding: 8px; }
QPushButton { background: #22304a; border: 1px solid #2e4060; border-radius: 8px; padding: 7px 14px; }
QPushButton:hover { background: #2a3b5a; }
QPushButton:focus { border: 1px solid #2dd4bf; }
QPushButton:disabled { color: #5b6b82; background: #1a2436; }
QPushButton#primary { background: #14b8a6; color: #04201c; border: none; font-weight: 600; }
QPushButton#primary:hover { background: #2dd4bf; }
QPushButton#primary:disabled { background: #1f3b3a; color: #4b6b68; }
QLineEdit, QSpinBox, QPlainTextEdit, QComboBox {
    background: #0f1623; border: 1px solid #2e4060; border-radius: 8px; padding: 6px; }
QLineEdit:focus, QSpinBox:focus, QPlainTextEdit:focus, QComboBox:focus { border: 1px solid #2dd4bf; }
QListWidget, QTableWidget, QTableView {
    background: #121b2b; border: 1px solid #23314a; border-radius: 8px;
    gridline-color: #1e2a3f; alternate-background-color: #141f31;
    selection-background-color: #1d4044; selection-color: #e6ebf2; }
QHeaderView::section { background: #172133; color: #8a99b0; border: none;
    border-bottom: 1px solid #23314a; padding: 6px; font-weight: 600; }
QProgressBar { background: #0f1623; border: 1px solid #2e4060; border-radius: 6px;
    text-align: center; min-height: 16px; }
QProgressBar::chunk { background: #14b8a6; border-radius: 5px; }
QFrame#dropZone { border: 2px dashed #2e4060; border-radius: 12px; background: #121b2b; }
QFrame#dropZone[active="true"] { border-color: #2dd4bf; background: #13283a; }
QTabWidget::pane { border: none; }
QTabBar::tab { background: transparent; color: #8a99b0; padding: 8px 16px; border-bottom: 2px solid transparent; }
QTabBar::tab:selected { color: #f1f5f9; border-bottom: 2px solid #2dd4bf; }
QStatusBar { background: #0b111b; color: #a9b6c8; }
QToolTip { background: #172133; color: #e6ebf2; border: 1px solid #2e4060; }
"""


# --------------------------------------------------------------------------- formatting


def fingerprint_block(fp: str) -> str:
    """Fingerprint as four lines of eight byte pairs, so it never needs word wrapping."""
    pairs = format_fingerprint(fp).split(":")
    return "\n".join(":".join(pairs[i : i + 8]) for i in range(0, len(pairs), 8))


def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"  # unreachable; keeps type checkers happy


def human_rate(bps: float | None) -> str:
    return "—" if not bps else f"{human_size(bps)}/s"


def human_duration(seconds: float | None) -> str:
    if seconds is None or seconds < 0:
        return "—"
    seconds = int(round(seconds))
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


# --------------------------------------------------------------------------- bridge


class Bridge(QObject, NodeEvents):
    """Thread-safe adapter from network callbacks to Qt signals."""

    transfer_started = pyqtSignal(object)
    transfer_progress = pyqtSignal(object)
    transfer_finished = pyqtSignal(object)
    offer_received = pyqtSignal(object)
    unknown_peer = pyqtSignal(str, str)

    def __init__(self, consent_timeout: float) -> None:
        super().__init__()
        self.consent_timeout = consent_timeout
        self._pending: dict[str, list] = {}  # transfer id -> [Event, accepted]
        self._lock = threading.Lock()
        self._closing = False

    # called on worker threads
    def on_transfer_started(self, info: TransferInfo) -> None:
        self.transfer_started.emit(info)

    def on_progress(self, info: TransferInfo) -> None:
        self.transfer_progress.emit(info)

    def on_transfer_finished(self, info: TransferInfo) -> None:
        self.transfer_finished.emit(info)

    def on_unknown_peer(self, fingerprint: str, address: str) -> None:
        self.unknown_peer.emit(fingerprint, address)

    def on_incoming_offer(self, info: TransferInfo) -> bool:
        event = threading.Event()
        with self._lock:
            if self._closing:
                return False
            self._pending[info.transfer_id] = [event, False]
        self.offer_received.emit(info)
        event.wait(self.consent_timeout)
        with self._lock:
            _, accepted = self._pending.pop(info.transfer_id)
        return bool(accepted)

    # called on the GUI thread
    def answer(self, transfer_id: str, accepted: bool) -> bool:
        """Deliver the user's decision. False if the request already expired."""
        with self._lock:
            slot = self._pending.get(transfer_id)
            if slot is None or slot[0].is_set():
                return False
            slot[1] = accepted
            slot[0].set()
            return True

    def is_pending(self, transfer_id: str) -> bool:
        with self._lock:
            slot = self._pending.get(transfer_id)
            return slot is not None and not slot[0].is_set()

    def decline_all(self) -> None:
        with self._lock:
            self._closing = True
            for slot in self._pending.values():
                slot[0].set()


# --------------------------------------------------------------------------- models / widgets


class HistoryModel(QAbstractTableModel):
    HEADERS = ["File", "Direction", "Peer", "Size", "Started", "Duration", "Avg speed", "Status"]

    def __init__(self) -> None:
        super().__init__()
        self._rows: list[HistoryEntry] = []

    def set_entries(self, entries: list[HistoryEntry]) -> None:
        self.beginResetModel()
        self._rows = list(entries)
        self.endResetModel()

    def rowCount(self, parent: QModelIndex | None = None) -> int:  # noqa: N802
        return 0 if parent is not None and parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex | None = None) -> int:  # noqa: N802
        return len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):  # noqa: N802
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        e = self._rows[index.row()]
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            return [
                e.saved_as or e.filename,
                "Sent" if e.direction == "send" else "Received",
                e.peer,
                human_size(e.size),
                dt.datetime.fromtimestamp(e.started_at).strftime("%d %b %H:%M"),
                human_duration(e.duration),
                human_rate(e.average_speed),
                STATUS_LABELS.get(e.status, e.status),
            ][col]
        if role == Qt.ItemDataRole.ToolTipRole:
            if col == 4:
                return dt.datetime.fromtimestamp(e.started_at).strftime("%Y-%m-%d %H:%M:%S")
            if col == 7 and e.error:
                return e.error
            if col == 0:
                return e.filename if not e.saved_as or e.saved_as == e.filename else f"{e.filename} → saved as {e.saved_as}"
        if role == Qt.ItemDataRole.ForegroundRole and col == 7 and e.status in STATUS_COLORS:
            return QColor(STATUS_COLORS[e.status])
        return None


class DropZone(QFrame):
    """Accepts local files dropped from the OS file manager."""

    files_dropped = pyqtSignal(list)

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("dropZone")
        self.setAcceptDrops(True)
        self.setMinimumHeight(90)
        layout = QVBoxLayout(self)
        label = QLabel("Drop files here")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setStyleSheet("font-size: 15px; font-weight: 600;")
        hint = QLabel("or use Browse… to pick files")
        hint.setObjectName("muted")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(label)
        layout.addWidget(hint)

    def _set_active(self, active: bool) -> None:
        self.setProperty("active", "true" if active else "false")
        self.style().unpolish(self)
        self.style().polish(self)

    @staticmethod
    def _local_files(mime) -> list[Path]:
        if not mime.hasUrls():
            return []
        return [Path(u.toLocalFile()) for u in mime.urls() if u.isLocalFile() and Path(u.toLocalFile()).is_file()]

    def dragEnterEvent(self, event) -> None:  # noqa: N802
        if self._local_files(event.mimeData()):
            self._set_active(True)
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragLeaveEvent(self, event) -> None:  # noqa: N802
        self._set_active(False)

    def dropEvent(self, event) -> None:  # noqa: N802
        self._set_active(False)
        files = self._local_files(event.mimeData())
        if files:
            event.acceptProposedAction()
            self.files_dropped.emit(files)


class PeerDialog(QDialog):
    """Add a trusted peer, or edit one. Changing a pinned fingerprint needs confirmation."""

    def __init__(self, parent: QWidget, store: PeerStore, existing: Peer | None = None) -> None:
        super().__init__(parent)
        self.store, self.existing = store, existing
        self.setWindowTitle("Edit trusted peer" if existing else "Add trusted peer")
        self.setMinimumWidth(520)
        form = QFormLayout()
        self.name = QLineEdit(existing.name if existing else "")
        self.name.setPlaceholderText("e.g. Priya's laptop")
        self.host = QLineEdit(existing.host if existing else "")
        self.host.setPlaceholderText("LAN IP address, e.g. 192.168.1.23")
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(existing.port if existing else 52520)
        self.fp = QPlainTextEdit(format_fingerprint(existing.fingerprint) if existing else "")
        self.fp.setPlaceholderText("Paste the peer's certificate fingerprint (64 hex characters)")
        self.fp.setFixedHeight(64)
        self.fp.setTabChangesFocus(True)
        for label, widget, tip in [
            ("Display name", self.name, "A local label for this peer"),
            ("Address", self.host, "The peer laptop's IP address on your network"),
            ("Port", self.port, "The port the peer's CipherLink listens on"),
            ("Fingerprint", self.fp, "SHA-256 certificate fingerprint shown in the peer's CipherLink window"),
        ]:
            widget.setToolTip(tip)
            form.addRow(label, widget)
        note = QLabel(
            "Only trust a fingerprint you received over a channel you trust: read it aloud in person, "
            "or compare it on a call. A fingerprint copied from an unverified message could belong to an attacker."
        )
        note.setWordWrap(True)
        note.setObjectName("muted")
        self.error = QLabel()
        self.error.setStyleSheet("color: #f87171;")
        self.error.setWordWrap(True)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(note)
        layout.addWidget(self.error)
        layout.addWidget(buttons)

    def _confirm(self, title: str, text: str) -> bool:
        return QMessageBox.question(self, title, text) == QMessageBox.StandardButton.Yes

    def _save(self) -> None:
        try:
            peer = Peer.create(self.name.text(), self.host.text(), self.port.value(), self.fp.toPlainText())
            if self.existing is None:
                if not self._confirm(
                    "Trust this peer?",
                    f"Trust '{peer.name}' with fingerprint\n\n{format_fingerprint(peer.fingerprint)}\n\n"
                    "Have you verified this fingerprint directly with the other person?",
                ):
                    return
                self.store.add(peer)
            else:
                name = self.existing.name
                if peer.fingerprint != self.existing.fingerprint:
                    if not self._confirm(
                        "Replace pinned fingerprint?",
                        f"You are replacing the pinned identity of '{name}'.\n\nOld: "
                        f"{format_fingerprint(self.existing.fingerprint)}\nNew: {format_fingerprint(peer.fingerprint)}\n\n"
                        "Only continue if the peer told you they created a new identity, and you verified the new "
                        "fingerprint with them directly.",
                    ):
                        return
                    self.store.replace_pin(name, peer.fingerprint, confirmed=True)
                self.store.update_address(name, peer.name, peer.host, peer.port)
        except PeerStoreError as exc:
            self.error.setText(str(exc))
            return
        self.accept()


def _card(title: str) -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setObjectName("card")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(16, 14, 16, 16)
    layout.setSpacing(10)
    label = QLabel(title)
    label.setObjectName("cardTitle")
    layout.addWidget(label)
    return frame, layout


def _muted(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("muted")
    label.setWordWrap(True)
    return label


@dataclass
class _Row:
    """GUI-side bookkeeping for one transfer row (speed is computed from real progress)."""

    info: TransferInfo
    bar: QProgressBar
    cancel: QPushButton
    last_t: float
    last_bytes: int = 0
    speed: float | None = None


# --------------------------------------------------------------------------- main window


class MainWindow(QMainWindow):
    COLS = ["File", "Direction", "Peer", "Size", "Progress", "Speed", "Elapsed", "Remaining", "Status", ""]

    def __init__(
        self,
        node: PeerNode,
        bridge: Bridge,
        identity: Identity,
        peers: PeerStore,
        history: TransferHistory,
        config: Config,
        listen_error: str | None = None,
        warnings: list[str] | None = None,
    ) -> None:
        super().__init__()
        self.node, self.bridge, self.identity = node, bridge, identity
        self.peers, self.history, self.config = peers, history, config
        self.queue: list[Path] = []
        self.rows: dict[str, _Row] = {}
        self.offer_boxes: dict[str, QMessageBox] = {}
        self._shut_down = False

        self.setWindowTitle(f"{APP_NAME} — Secure LAN File Transfer")
        self.setMinimumSize(1080, 720)
        self.setStyleSheet(STYLE)

        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(18, 14, 18, 10)
        root.setSpacing(14)
        root.addLayout(self._build_header(listen_error))
        for text in warnings or []:
            warn = QLabel(text)
            warn.setObjectName("warning")
            warn.setWordWrap(True)
            root.addWidget(warn)

        body = QHBoxLayout()
        body.setSpacing(14)
        left = QVBoxLayout()
        left.setSpacing(14)
        left.addWidget(self._build_identity_card())
        left.addWidget(self._build_peers_card(), 1)
        right = QVBoxLayout()
        right.setSpacing(14)
        right.addWidget(self._build_send_card())
        right.addWidget(self._build_tabs(), 1)
        left_w, right_w = QWidget(), QWidget()
        left_w.setLayout(left)
        right_w.setLayout(right)
        left_w.setFixedWidth(380)
        body.addWidget(left_w)
        body.addWidget(right_w, 1)
        root.addLayout(body, 1)
        self.setCentralWidget(central)

        bridge.transfer_started.connect(self._on_started)
        bridge.transfer_progress.connect(self._on_progress)
        bridge.transfer_finished.connect(self._on_finished)
        bridge.offer_received.connect(self._on_offer)
        bridge.unknown_peer.connect(self._on_unknown_peer)

        self._ticker = QTimer(self)
        self._ticker.timeout.connect(self._tick)
        self._ticker.start(1000)
        self.refresh_peers()
        self.refresh_history()
        self.statusBar().showMessage("Ready")

    # ---------------------------------------------------------------- layout

    def _build_header(self, listen_error: str | None) -> QHBoxLayout:
        row = QHBoxLayout()
        title = QLabel(f"🔐  {APP_NAME}")
        title.setObjectName("title")
        version = QLabel(f"v{APP_VERSION}  ·  RSA-OAEP + AES-256-GCM over TLS 1.3")
        version.setObjectName("muted")
        self.listen_pill = QLabel()
        self.listen_pill.setObjectName("pill")
        if listen_error:
            self.listen_pill.setText("Not listening")
            self.listen_pill.setProperty("state", "bad")
            self.listen_pill.setToolTip(listen_error)
        else:
            self.listen_pill.setText(f"Listening on port {self.node.port}")
            self.listen_pill.setProperty("state", "ok")
            self.listen_pill.setToolTip(
                f"Accepting connections from trusted peers on {self.config.listen_host}:{self.node.port}"
            )
        folder = QPushButton("Open receive folder")
        folder.setToolTip(str(self.config.receive_dir))
        folder.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.config.receive_dir))))
        row.addWidget(title)
        row.addSpacing(10)
        row.addWidget(version)
        row.addStretch(1)
        row.addWidget(self.listen_pill)
        row.addWidget(folder)
        return row

    def _build_identity_card(self) -> QFrame:
        card, layout = _card("Your identity")
        layout.addWidget(_muted("Certificate fingerprint (SHA-256):"))
        self.fp_label = QLabel(fingerprint_block(self.identity.fingerprint))
        self.fp_label.setObjectName("fingerprint")
        mono = QFont("Menlo")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self.fp_label.setFont(mono)
        self.fp_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.fp_label.setAccessibleName("Your certificate fingerprint")
        layout.addWidget(self.fp_label)
        copy = QPushButton("Copy fingerprint")
        copy.setToolTip("Copy your fingerprint to the clipboard")
        copy.clicked.connect(self.copy_fingerprint)
        layout.addWidget(copy)
        layout.addWidget(_muted("Compare fingerprints in person or on a call."))
        layout.addWidget(_muted("Your private key never leaves this computer."))
        return card

    def _build_peers_card(self) -> QFrame:
        card, layout = _card("Trusted peers")
        self.peer_list = QListWidget()
        self.peer_list.setAccessibleName("Trusted peers")
        self.peer_list.itemDoubleClicked.connect(lambda _: self.edit_peer())
        layout.addWidget(self.peer_list, 1)
        buttons = QHBoxLayout()
        for text, slot, tip in [
            ("Add…", self.add_peer, "Trust a new peer by its fingerprint"),
            ("Edit…", self.edit_peer, "Change name/address, or replace the pinned fingerprint"),
            ("Remove", self.remove_peer, "Stop trusting the selected peer"),
        ]:
            b = QPushButton(text)
            b.setToolTip(tip)
            b.clicked.connect(slot)
            buttons.addWidget(b)
        layout.addLayout(buttons)
        self.auth_label = _muted("")
        self.auth_label.setStyleSheet("color: #fca5a5;")
        self.auth_label.hide()
        layout.addWidget(self.auth_label)
        return card

    def _build_send_card(self) -> QFrame:
        card, layout = _card("Send files")
        self.drop_zone = DropZone()
        self.drop_zone.files_dropped.connect(self.add_files)
        layout.addWidget(self.drop_zone)
        self.queue_list = QListWidget()
        self.queue_list.setAccessibleName("Files queued to send")
        self.queue_list.setMaximumHeight(110)
        self.queue_list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        layout.addWidget(self.queue_list)
        row = QHBoxLayout()
        browse = QPushButton("Browse…")
        browse.setToolTip("Choose files to send")
        browse.clicked.connect(self.browse_files)
        remove = QPushButton("Remove selected")
        remove.clicked.connect(self.remove_selected_files)
        self.peer_combo = QComboBox()
        self.peer_combo.setAccessibleName("Recipient")
        self.peer_combo.setToolTip("Trusted peer to send to")
        self.peer_combo.setMinimumWidth(180)
        self.send_button = QPushButton("Send securely")
        self.send_button.setObjectName("primary")
        self.send_button.clicked.connect(self.send_queue)
        row.addWidget(browse)
        row.addWidget(remove)
        row.addStretch(1)
        row.addWidget(QLabel("To:"))
        row.addWidget(self.peer_combo)
        row.addWidget(self.send_button)
        layout.addLayout(row)
        self._update_send_state()
        return card

    def _build_tabs(self) -> QTabWidget:
        tabs = QTabWidget()
        active = QWidget()
        al = QVBoxLayout(active)
        al.setContentsMargins(0, 8, 0, 0)
        self.transfer_table = QTableWidget(0, len(self.COLS))
        self.transfer_table.setHorizontalHeaderLabels(self.COLS)
        self.transfer_table.verticalHeader().hide()
        self.transfer_table.setAlternatingRowColors(True)
        self.transfer_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.transfer_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        header = self.transfer_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        self.transfer_table.setColumnWidth(4, 150)
        al.addWidget(self.transfer_table)
        clear = QPushButton("Clear finished")
        clear.clicked.connect(self.clear_finished)
        al.addWidget(clear, 0, Qt.AlignmentFlag.AlignRight)
        tabs.addTab(active, "Active transfers")

        hist = QWidget()
        hl = QVBoxLayout(hist)
        hl.setContentsMargins(0, 8, 0, 0)
        self.history_model = HistoryModel()
        self.history_view = QTableView()
        self.history_view.setModel(self.history_model)
        self.history_view.verticalHeader().hide()
        self.history_view.setAlternatingRowColors(True)
        self.history_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.history_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.history_view.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.history_view.setWordWrap(False)
        self.history_view.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        self.history_empty = _muted("No transfers yet. Completed, failed and rejected transfers will appear here.")
        hl.addWidget(self.history_view)
        hl.addWidget(self.history_empty)
        tabs.addTab(hist, "History")
        self.tabs = tabs
        return tabs

    # ---------------------------------------------------------------- identity / peers

    def copy_fingerprint(self) -> None:
        QGuiApplication.clipboard().setText(format_fingerprint(self.identity.fingerprint))
        self.statusBar().showMessage("Fingerprint copied to clipboard", 4000)

    def refresh_peers(self) -> None:
        selected = self._selected_peer_name()
        self.peer_list.clear()
        current_combo = self.peer_combo.currentText()
        self.peer_combo.clear()
        for p in self.peers.peers():
            item = QListWidgetItem(f"{p.name}\n{p.host}:{p.port}   ·   {format_fingerprint(p.fingerprint)[:23]}…")
            item.setData(Qt.ItemDataRole.UserRole, p.name)
            item.setToolTip(f"Pinned fingerprint:\n{format_fingerprint(p.fingerprint)}")
            self.peer_list.addItem(item)
            if p.name == selected:
                self.peer_list.setCurrentItem(item)
            self.peer_combo.addItem(p.name)
        if current_combo:
            self.peer_combo.setCurrentText(current_combo)
        self._update_send_state()

    def _selected_peer_name(self) -> str | None:
        item = self.peer_list.currentItem()
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def add_peer(self) -> None:
        if PeerDialog(self, self.peers).exec():
            self.refresh_peers()
            self.statusBar().showMessage("Peer added", 4000)

    def edit_peer(self) -> None:
        name = self._selected_peer_name()
        peer = self.peers.get(name) if name else None
        if peer is None:
            self.statusBar().showMessage("Select a peer to edit", 4000)
            return
        if PeerDialog(self, self.peers, peer).exec():
            self.refresh_peers()

    def remove_peer(self) -> None:
        name = self._selected_peer_name()
        if not name:
            self.statusBar().showMessage("Select a peer to remove", 4000)
            return
        if QMessageBox.question(self, "Remove peer", f"Stop trusting '{name}'?") == QMessageBox.StandardButton.Yes:
            self.peers.remove(name)
            self.refresh_peers()

    # ---------------------------------------------------------------- queue / sending

    def browse_files(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, "Choose files to send")
        self.add_files([Path(p) for p in paths])

    @pyqtSlot(list)
    def add_files(self, paths: list[Path]) -> None:
        for path in paths:
            if path in self.queue or not path.is_file():
                continue
            self.queue.append(path)
            item = QListWidgetItem(f"{path.name}  ·  {human_size(path.stat().st_size)}")
            item.setToolTip(path.name)
            self.queue_list.addItem(item)
        self._update_send_state()

    def remove_selected_files(self) -> None:
        for row in sorted((self.queue_list.row(i) for i in self.queue_list.selectedItems()), reverse=True):
            self.queue_list.takeItem(row)
            del self.queue[row]
        self._update_send_state()

    def _update_send_state(self) -> None:
        ready = bool(self.queue) and self.peer_combo.count() > 0
        self.send_button.setEnabled(ready)
        self.send_button.setToolTip("" if ready else "Add files and a trusted peer first")

    def send_queue(self) -> None:
        peer = self.peers.get(self.peer_combo.currentText())
        if peer is None:
            self.statusBar().showMessage("Choose a trusted peer first", 5000)
            return
        errors = []
        for path in list(self.queue):
            try:
                self.node.send_file(peer, path)
            except TransferError as exc:
                errors.append(f"{path.name}: {exc}")
        self.queue.clear()
        self.queue_list.clear()
        self._update_send_state()
        self.tabs.setCurrentIndex(0)
        self.statusBar().showMessage("; ".join(errors) if errors else f"Sending to {peer.name}…", 6000)

    # ---------------------------------------------------------------- transfer rows

    @pyqtSlot(object)
    def _on_started(self, info: TransferInfo) -> None:
        if info.transfer_id in self.rows:
            return
        r = self.transfer_table.rowCount()
        self.transfer_table.insertRow(r)
        bar = QProgressBar()
        bar.setRange(0, 1000)
        bar.setAccessibleName(f"Progress for {info.filename}")
        cancel = QPushButton("Cancel")
        cancel.setToolTip("Cancel this transfer")
        cancel.clicked.connect(lambda _=False, tid=info.transfer_id: self.node.cancel(tid))
        self.transfer_table.setCellWidget(r, 4, bar)
        self.transfer_table.setCellWidget(r, 9, cancel)
        self.rows[info.transfer_id] = _Row(info, bar, cancel, time.monotonic())
        self._render(info.transfer_id)

    @pyqtSlot(object)
    def _on_progress(self, info: TransferInfo) -> None:
        row = self.rows.get(info.transfer_id)
        if row is None:
            self._on_started(info)
            row = self.rows[info.transfer_id]
        now = time.monotonic()
        dt_s = now - row.last_t
        if info.status == "transferring" and dt_s > 0 and info.bytes_done > row.last_bytes:
            instant = (info.bytes_done - row.last_bytes) / dt_s
            row.speed = instant if row.speed is None else 0.3 * instant + 0.7 * row.speed
        row.last_t, row.last_bytes = now, info.bytes_done
        row.info = info
        self._render(info.transfer_id)

    @pyqtSlot(object)
    def _on_finished(self, info: TransferInfo) -> None:
        box = self.offer_boxes.pop(info.transfer_id, None)
        if box is not None:  # request expired or sender gave up while we were asking
            box.done(0)
        self._on_progress(info)
        row = self.rows[info.transfer_id]
        row.cancel.setEnabled(False)
        self.history.record(info)
        self.refresh_history()
        verb = "Received" if info.direction == "receive" else "Sent"
        if info.status == "completed":
            msg = f"{verb} {info.saved_as or info.filename} ({human_size(info.size)})"
            if info.saved_as and info.saved_as != info.filename:
                msg += f" — a file with that name existed, saved as '{info.saved_as}'"
        else:
            msg = f"{info.filename}: {STATUS_LABELS[info.status]} — {info.error or ''}"
            if "fingerprint" in (info.error or "") or "TLS" in (info.error or ""):
                self.auth_label.setText(f"⚠ {info.peer}: {info.error}")
                self.auth_label.show()
        self.statusBar().showMessage(msg, 10000)

    def _render(self, tid: str) -> None:
        row = self.rows[tid]
        info = row.info
        r = self._row_index(tid)
        if r < 0:
            return
        elapsed = (info.finished_at or time.time()) - info.started_at
        remaining = None
        if info.status == "transferring" and row.speed:
            remaining = (info.size - info.bytes_done) / row.speed
        values = [
            info.saved_as or info.filename,
            "↑ Send" if info.direction == "send" else "↓ Receive",
            info.peer,
            human_size(info.size),
            None,
            human_rate(row.speed) if info.status == "transferring" else "—",
            human_duration(elapsed),
            human_duration(remaining),
            STATUS_LABELS.get(info.status, info.status),
        ]
        for col, text in enumerate(values):
            if text is None:
                continue
            item = self.transfer_table.item(r, col)
            if item is None:
                item = QTableWidgetItem()
                self.transfer_table.setItem(r, col, item)
            item.setText(text)
            if col == 0:
                item.setToolTip(info.filename)
            if col == 8:
                item.setToolTip(info.error or "")
                if info.status in STATUS_COLORS:
                    item.setForeground(QColor(STATUS_COLORS[info.status]))
        if info.size:
            fraction = info.bytes_done / info.size
        else:
            fraction = 1.0 if info.status == "completed" else 0.0
        row.bar.setValue(int(fraction * 1000))
        row.bar.setFormat(f"{fraction * 100:.0f}%  ·  {human_size(info.bytes_done)}")

    def _row_index(self, tid: str) -> int:
        for r in range(self.transfer_table.rowCount()):
            if self.transfer_table.cellWidget(r, 4) is self.rows[tid].bar:
                return r
        return -1

    def _tick(self) -> None:
        for tid, row in self.rows.items():
            if not row.info.finished:
                self._render(tid)

    def clear_finished(self) -> None:
        for tid in [t for t, row in self.rows.items() if row.info.finished]:
            self.transfer_table.removeRow(self._row_index(tid))
            del self.rows[tid]

    def refresh_history(self) -> None:
        entries = self.history.entries()
        self.history_model.set_entries(entries)
        self.history_empty.setVisible(not entries)

    # ---------------------------------------------------------------- incoming

    @pyqtSlot(object)
    def _on_offer(self, info: TransferInfo) -> None:
        self._on_started(info)
        box = QMessageBox(self)
        box.setWindowTitle("Incoming file")
        box.setIcon(QMessageBox.Icon.Question)
        box.setText(f"<b>{info.peer}</b> wants to send you a file.")
        box.setInformativeText(
            f"Name: {info.filename}\nSize: {human_size(info.size)}\n\n"
            f"It will be saved in your receive folder. Existing files are never overwritten."
        )
        accept = box.addButton("Accept", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Decline", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(accept)
        tid = info.transfer_id
        box.buttonClicked.connect(lambda button: self._answer_offer(tid, button is accept, info.filename))
        self.offer_boxes[tid] = box
        box.open()  # window-modal but non-blocking: other transfers keep updating

    def _answer_offer(self, tid: str, accepted: bool, filename: str) -> None:
        self.offer_boxes.pop(tid, None)
        if not self.bridge.answer(tid, accepted):
            self.statusBar().showMessage(f"The request for {filename} expired before you answered", 8000)

    @pyqtSlot(str, str)
    def _on_unknown_peer(self, fingerprint: str, address: str) -> None:
        self.auth_label.setText(
            f"⚠ Rejected a connection from {address.rsplit(':', 1)[0]} with an untrusted fingerprint "
            f"{format_fingerprint(fingerprint)[:23]}… Add it as a peer only after verifying it with its owner."
        )
        self.auth_label.setToolTip(format_fingerprint(fingerprint))
        self.auth_label.show()
        self.statusBar().showMessage("Rejected a connection from an untrusted peer", 8000)

    # ---------------------------------------------------------------- shutdown

    def shutdown(self) -> None:
        if self._shut_down:
            return
        self._shut_down = True
        self._ticker.stop()
        self.bridge.decline_all()
        self.node.stop()

    def closeEvent(self, event) -> None:  # noqa: N802
        active = [r for r in self.rows.values() if not r.info.finished]
        if active and not self._shut_down:
            answer = QMessageBox.question(
                self, "Quit CipherLink?", f"{len(active)} transfer(s) in progress will be cancelled. Quit anyway?"
            )
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
        self.shutdown()
        event.accept()
