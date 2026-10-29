"""GUI tests on Qt's offscreen platform. These exercise widgets, signals and real network
transfers, but cannot prove that the native file picker or OS drag-and-drop work."""
from __future__ import annotations

import os
import threading
import time

import pytest

pytest.importorskip("PyQt6")
from conftest import make_node  # noqa: E402
from PyQt6.QtCore import QMimeData, QPoint, QPointF, Qt, QUrl  # noqa: E402
from PyQt6.QtGui import QDragEnterEvent, QDropEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

import gui_app  # noqa: E402
import network_p2p as net  # noqa: E402
from config import Config  # noqa: E402
from crypto_engine import format_fingerprint  # noqa: E402
from peer_store import Peer, PeerStore  # noqa: E402
from transfer_history import TransferHistory  # noqa: E402


@pytest.fixture(scope="session")
def qapp():
    return QApplication.instance() or QApplication([])


def wait_until(pred, timeout=20.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        QApplication.processEvents()
        if pred():
            return
        time.sleep(0.01)
    raise AssertionError("condition not met in time")


@pytest.fixture
def gui(qapp, tmp_path, identity_a, identity_b):
    """Window for laptop A (real node) plus a headless peer node B."""
    config = Config(data_dir=tmp_path / "a", listen_host="127.0.0.1", listen_port=0)
    peers = PeerStore(config.peers_file)
    history = TransferHistory(config.history_file)
    bridge = gui_app.Bridge(consent_timeout=10)
    node = net.PeerNode(identity_a, peers, config, bridge)
    node.start()
    window = gui_app.MainWindow(node, bridge, identity_a, peers, history, config)
    window.show()
    b = make_node(identity_b, tmp_path / "b")
    peers.add(Peer.create("B", "127.0.0.1", b.node.port, identity_b.fingerprint))
    b.store.add(Peer.create("A", "127.0.0.1", node.port, identity_a.fingerprint))
    window.refresh_peers()
    yield window, b
    window.shutdown()
    window.close()
    b.node.stop()


def test_window_initial_state(gui, identity_a) -> None:
    w, _ = gui
    assert w.fp_label.text().replace("\n", ":") == format_fingerprint(identity_a.fingerprint)
    assert "Listening on port" in w.listen_pill.text()
    assert w.peer_list.count() == 1 and w.peer_combo.currentText() == "B"
    assert not w.send_button.isEnabled()  # no files yet
    assert w.history_model.rowCount() == 0 and not w.history_empty.isHidden()


def test_copy_fingerprint(gui, identity_a) -> None:
    w, _ = gui
    w.copy_fingerprint()
    assert QApplication.clipboard().text() == format_fingerprint(identity_a.fingerprint)


def test_file_queue_add_remove(gui, tmp_path) -> None:
    w, _ = gui
    f1, f2 = tmp_path / "one.txt", tmp_path / "two.txt"
    f1.write_text("1")
    f2.write_text("22")
    w.add_files([f1, f2, f1, tmp_path / "missing.txt"])
    assert w.queue == [f1, f2] and w.send_button.isEnabled()
    w.queue_list.item(0).setSelected(True)
    w.remove_selected_files()
    assert w.queue == [f2] and w.queue_list.count() == 1


def test_drag_and_drop_adds_local_files(gui, tmp_path) -> None:
    w, _ = gui
    f = tmp_path / "dropped.bin"
    f.write_bytes(b"x")
    mime = QMimeData()
    mime.setUrls([QUrl.fromLocalFile(str(f)), QUrl("https://example.com/not-local")])
    enter = QDragEnterEvent(QPoint(5, 5), Qt.DropAction.CopyAction, mime, Qt.MouseButton.LeftButton,
                            Qt.KeyboardModifier.NoModifier)
    QApplication.sendEvent(w.drop_zone, enter)
    assert enter.isAccepted()
    drop = QDropEvent(QPointF(5, 5), Qt.DropAction.CopyAction, mime, Qt.MouseButton.LeftButton,
                      Qt.KeyboardModifier.NoModifier)
    QApplication.sendEvent(w.drop_zone, drop)
    assert w.queue == [f]


def test_drag_of_non_files_is_ignored(gui) -> None:
    w, _ = gui
    mime = QMimeData()
    mime.setText("just text")
    enter = QDragEnterEvent(QPoint(5, 5), Qt.DropAction.CopyAction, mime, Qt.MouseButton.LeftButton,
                            Qt.KeyboardModifier.NoModifier)
    QApplication.sendEvent(w.drop_zone, enter)
    assert not enter.isAccepted()


def test_send_through_gui_updates_progress_and_history(gui, tmp_path) -> None:
    w, b = gui
    f = tmp_path / "report.bin"
    data = os.urandom(600_000)
    f.write_bytes(data)
    w.add_files([f])
    w.send_button.click()
    wait_until(lambda: w.history_model.rowCount() == 1)
    (row,) = w.rows.values()
    assert row.info.status == "completed"
    assert row.bar.value() == 1000
    assert w.transfer_table.item(0, 8).text() == "Completed"
    assert (b.received / "report.bin").read_bytes() == data
    assert w.history_model.data(w.history_model.index(0, 7)) == "Completed"
    assert w.history_empty.isHidden()
    assert w.queue == []


def test_incoming_offer_accept_via_dialog(gui, tmp_path, identity_b) -> None:
    w, b = gui
    f = tmp_path / "incoming.txt"
    f.write_text("hi A")
    b.node.send_file(b.store.get("A"), f)
    wait_until(lambda: w.offer_boxes)
    (box,) = w.offer_boxes.values()
    assert "incoming.txt" in box.informativeText()
    next(btn for btn in box.buttons() if btn.text() == "Accept").click()
    wait_until(lambda: w.history_model.rowCount() == 1)
    assert (w.config.receive_dir / "incoming.txt").read_text() == "hi A"
    assert b.events.wait_finished()[0].status == "completed"


def test_incoming_offer_decline_via_dialog(gui, tmp_path) -> None:
    w, b = gui
    f = tmp_path / "nope.txt"
    f.write_text("x")
    b.node.send_file(b.store.get("A"), f)
    wait_until(lambda: w.offer_boxes)
    next(btn for btn in next(iter(w.offer_boxes.values())).buttons() if btn.text() == "Decline").click()
    (sent,) = b.events.wait_finished()
    assert sent.status == "rejected"
    wait_until(lambda: w.history_model.rowCount() == 1)
    assert w.history_model.data(w.history_model.index(0, 7)) == "Rejected"
    assert not (w.config.receive_dir / "nope.txt").exists()


def test_bridge_consent_expires_and_fails_closed(qapp) -> None:
    bridge = gui_app.Bridge(consent_timeout=0.2)
    info = net.TransferInfo("ab" * 16, "receive", "P", "f", 1)
    result = []
    t = threading.Thread(target=lambda: result.append(bridge.on_incoming_offer(info)))
    t.start()
    t.join(2)
    assert result == [False]
    assert bridge.answer(info.transfer_id, True) is False  # too late


def test_bridge_decline_all_unblocks_workers(qapp) -> None:
    bridge = gui_app.Bridge(consent_timeout=30)
    info = net.TransferInfo("cd" * 16, "receive", "P", "f", 1)
    result = []
    t = threading.Thread(target=lambda: result.append(bridge.on_incoming_offer(info)))
    t.start()
    deadline = time.monotonic() + 2
    while not bridge.is_pending(info.transfer_id) and time.monotonic() < deadline:
        time.sleep(0.01)
    bridge.decline_all()
    t.join(2)
    assert result == [False]


def test_cancel_button_cancels_transfer(gui, tmp_path, monkeypatch) -> None:
    w, b = gui
    monkeypatch.setattr(net, "PROGRESS_INTERVAL", 0)
    b.events.progress_delay = 0.01  # slow receiver so the transfer is still running
    f = tmp_path / "big.bin"
    f.write_bytes(os.urandom(20 * 1024 * 1024))
    w.add_files([f])
    w.send_button.click()
    wait_until(lambda: any(r.info.bytes_done for r in w.rows.values()))
    (row,) = w.rows.values()
    row.cancel.click()
    wait_until(lambda: row.info.finished)
    assert row.info.status == "cancelled" and not row.cancel.isEnabled()
    w.clear_finished()
    assert w.transfer_table.rowCount() == 0


def test_auth_failure_is_visible(gui, tmp_path, identity_mallory) -> None:
    w, _ = gui
    w.peers.replace_pin("B", identity_mallory.fingerprint, confirmed=True)
    f = tmp_path / "x.txt"
    f.write_text("x")
    w.add_files([f])
    w.send_button.click()
    wait_until(lambda: any(r.info.finished for r in w.rows.values()))
    assert not w.auth_label.isHidden() and "fingerprint" in w.auth_label.text()


def test_unknown_peer_warning(gui) -> None:
    w, _ = gui
    w.bridge.unknown_peer.emit("AB" * 32, "10.0.0.9:5555")
    wait_until(lambda: not w.auth_label.isHidden())
    assert "10.0.0.9" in w.auth_label.text() and "untrusted" in w.auth_label.text()


def test_peer_dialog_add_validates_and_confirms(gui, monkeypatch, identity_mallory) -> None:
    w, _ = gui
    answers = []
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: answers.pop(0))
    dlg = gui_app.PeerDialog(w, w.peers)
    dlg.name.setText("C")
    dlg.host.setText("192.168.1.30")
    dlg.fp.setPlainText("not a fingerprint")
    dlg._save()
    assert "64 hexadecimal" in dlg.error.text() and w.peers.get("C") is None

    dlg.fp.setPlainText(format_fingerprint(identity_mallory.fingerprint))
    answers.append(QMessageBox.StandardButton.No)  # user does not confirm
    dlg._save()
    assert w.peers.get("C") is None

    answers.append(QMessageBox.StandardButton.Yes)
    dlg._save()
    assert w.peers.get("C").fingerprint == identity_mallory.fingerprint


def test_peer_dialog_edit_requires_confirmation_for_new_pin(gui, monkeypatch, identity_mallory) -> None:
    w, _ = gui
    old_fp = w.peers.get("B").fingerprint
    answers = [QMessageBox.StandardButton.No]
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: answers.pop(0))
    dlg = gui_app.PeerDialog(w, w.peers, w.peers.get("B"))
    dlg.host.setText("10.1.1.1")
    dlg.fp.setPlainText(identity_mallory.fingerprint)
    dlg._save()
    assert w.peers.get("B").fingerprint == old_fp and w.peers.get("B").host == "127.0.0.1"
    answers.append(QMessageBox.StandardButton.Yes)
    dlg._save()
    assert w.peers.get("B").fingerprint == identity_mallory.fingerprint
    assert w.peers.get("B").host == "10.1.1.1"


def test_remove_peer(gui, monkeypatch) -> None:
    w, _ = gui
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    w.peer_list.setCurrentRow(0)
    w.remove_peer()
    assert w.peers.peers() == [] and w.peer_combo.count() == 0


def test_history_model_formats_long_names_and_errors(qapp) -> None:
    from transfer_history import HistoryEntry

    m = gui_app.HistoryModel()
    long = "x" * 300 + ".txt"
    m.set_entries([HistoryEntry("id", long, "receive", "P", 2048, 0, 0.0, 4.0, "failed", "boom", "")])
    assert m.data(m.index(0, 0)) == long
    assert m.data(m.index(0, 1)) == "Received"
    assert m.data(m.index(0, 3)) == "2.0 KB"
    assert m.data(m.index(0, 7), Qt.ItemDataRole.ToolTipRole) == "boom"


def test_shutdown_stops_node(qapp, tmp_path, identity_a) -> None:
    config = Config(data_dir=tmp_path, listen_host="127.0.0.1", listen_port=0)
    peers = PeerStore(config.peers_file)
    bridge = gui_app.Bridge(5)
    node = net.PeerNode(identity_a, peers, config, bridge)
    node.start()
    w = gui_app.MainWindow(node, bridge, identity_a, peers, TransferHistory(config.history_file), config)
    w.show()
    assert node.listening
    w.close()
    assert not node.listening


def test_listen_error_and_warnings_shown(qapp, tmp_path, identity_a) -> None:
    config = Config(data_dir=tmp_path, listen_host="127.0.0.1", listen_port=0)
    peers = PeerStore(config.peers_file)
    node = net.PeerNode(identity_a, peers, config, gui_app.Bridge(5))
    w = gui_app.MainWindow(node, gui_app.Bridge(5), identity_a, peers, TransferHistory(config.history_file),
                           config, listen_error="port busy", warnings=["history reset"])
    assert w.listen_pill.text() == "Not listening" and w.listen_pill.toolTip() == "port busy"
    w.shutdown()


def test_formatters() -> None:
    assert gui_app.human_size(0) == "0 B" and gui_app.human_size(1536) == "1.5 KB"
    assert gui_app.human_rate(None) == "—" and gui_app.human_rate(1048576) == "1.0 MB/s"
    assert gui_app.human_duration(3725) == "1:02:05" and gui_app.human_duration(None) == "—"
