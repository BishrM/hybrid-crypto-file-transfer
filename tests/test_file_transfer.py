"""End-to-end transfers between two real nodes over localhost TCP + TLS."""
from __future__ import annotations

import hashlib
import os
import sys
import threading
import tracemalloc

import pytest
from conftest import make_node, raw_connect, raw_offer, raw_session, send_record, trust

import network_p2p as net


def _sha(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _send_and_wait(a, b, path, peer_name="B"):
    a.node.send_file(a.store.get(peer_name), path)
    (sent,) = a.events.wait_finished()
    (recv,) = b.events.wait_finished()
    return sent, recv


@pytest.mark.parametrize(
    "name,data",
    [
        ("hello.txt", b"Hello from laptop A\n"),
        ("random.bin", os.urandom(4096)),
        ("empty.dat", b""),
        ("exact-chunk.bin", os.urandom(64 * 1024)),
        ("multi-chunk.bin", os.urandom(3 * 64 * 1024 + 17)),
    ],
)
def test_transfer_preserves_bytes(pair, tmp_path, name, data) -> None:
    a, b = pair
    src = tmp_path / name
    src.write_bytes(data)
    sent, recv = _send_and_wait(a, b, src)
    assert sent.status == recv.status == "completed", (sent.error, recv.error)
    assert sent.saved_as == recv.saved_as == name
    assert _sha(b.received / name) == hashlib.sha256(data).hexdigest()
    assert recv.bytes_done == sent.bytes_done == len(data)
    assert [p.name for p in b.received.iterdir()] == [name]  # temp file gone


def test_large_file_is_streamed_with_bounded_memory(pair, tmp_path) -> None:
    a, b = pair
    src = tmp_path / "large.bin"
    size = 48 * 1024 * 1024
    with open(src, "wb") as fh:
        for _ in range(size // (1 << 20)):
            fh.write(os.urandom(1 << 20))
    tracemalloc.start()
    try:
        sent, recv = _send_and_wait(a, b, src)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert sent.status == recv.status == "completed"
    assert _sha(b.received / "large.bin") == _sha(src)
    # both sender and receiver run in this process; whole-file buffering would need >= 48 MiB
    assert peak < 8 * 1024 * 1024, f"peak traced memory {peak / 1e6:.1f} MB"
    assert len(a.events.progress) > 2  # progress was reported during the transfer


def test_duplicate_filename_is_not_overwritten(pair, tmp_path) -> None:
    a, b = pair
    (b.received / "doc.txt").write_bytes(b"original")
    src = tmp_path / "doc.txt"
    src.write_bytes(b"new version")
    sent, recv = _send_and_wait(a, b, src)
    assert recv.status == "completed" and recv.saved_as == "doc (1).txt"
    assert (b.received / "doc.txt").read_bytes() == b"original"
    assert (b.received / "doc (1).txt").read_bytes() == b"new version"


def test_receiver_declines(tmp_path, identity_a, identity_b) -> None:
    a = make_node(identity_a, tmp_path / "a")
    b = make_node(identity_b, tmp_path / "b", accept=False)
    try:
        trust(a, b, "B")
        trust(b, a, "A")
        src = tmp_path / "x.txt"
        src.write_bytes(b"x")
        sent, recv = _send_and_wait(a, b, src)
        assert sent.status == recv.status == "rejected"
        assert "declined" in sent.error.lower()
        assert list(b.received.iterdir()) == []
    finally:
        a.node.stop()
        b.node.stop()


def test_source_read_failure(pair, tmp_path, monkeypatch) -> None:
    a, b = pair
    src = tmp_path / "vanishing.txt"
    src.write_bytes(b"data")
    real_open = open

    def failing_open(path, *args, **kw):
        if str(path) == str(src):
            raise PermissionError(13, "Permission denied")
        return real_open(path, *args, **kw)

    monkeypatch.setattr("builtins.open", failing_open)
    sent, recv = _send_and_wait(a, b, src)
    assert sent.status == "failed" and "Permission denied" in sent.error
    assert recv.status == "failed"
    assert list(b.received.iterdir()) == []


def test_source_file_shrinking_detected(pair, tmp_path) -> None:
    a, b = pair
    src = tmp_path / "shrink.bin"
    src.write_bytes(os.urandom(200_000))
    original_check = net._Active.check
    truncated = threading.Event()

    def check(self):  # truncate the file after the first chunk has been read
        if self.info.direction == "send" and self.info.bytes_done and not truncated.is_set():
            truncated.set()
            src.write_bytes(b"short")
        return original_check(self)

    net._Active.check = check
    try:
        sent, recv = _send_and_wait(a, b, src)
    finally:
        net._Active.check = original_check
    assert sent.status == "failed" and "shrank" in sent.error
    assert recv.status == "failed"
    assert list(b.received.iterdir()) == []


@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="needs POSIX permissions, non-root")
def test_destination_write_failure(pair, tmp_path) -> None:
    a, b = pair
    os.chmod(b.received, 0o500)
    try:
        src = tmp_path / "f.txt"
        src.write_bytes(b"data")
        sent, recv = _send_and_wait(a, b, src)
    finally:
        os.chmod(b.received, 0o700)
    assert sent.status == "failed" and recv.status == "failed"
    assert list(b.received.iterdir()) == []


def test_disconnect_mid_transfer_cleans_up(pair) -> None:
    a, b = pair
    tls, der = raw_connect(a.identity, b.node.port)
    tid, digest = raw_offer(tls, name="partial.bin", size=100, chunk=10)
    sealer = raw_session(tls, der, tid, digest)
    send_record(tls, *sealer.seal(b"0123456789"))
    tls.close()
    (recv,) = b.events.wait_finished()
    assert recv.status == "failed"
    assert list(b.received.iterdir()) == []


def test_tampered_record_rejected_before_write(pair) -> None:
    a, b = pair
    tls, der = raw_connect(a.identity, b.node.port)
    with tls:
        tid, digest = raw_offer(tls, name="t.bin", size=10, chunk=10)
        sealer = raw_session(tls, der, tid, digest)
        seq, ct = sealer.seal(b"0123456789")
        send_record(tls, seq, bytes([ct[0] ^ 0xFF]) + ct[1:])
        (recv,) = b.events.wait_finished()
    assert recv.status == "failed" and "authentication" in recv.error
    assert recv.bytes_done == 0
    assert list(b.received.iterdir()) == []


def test_simultaneous_bidirectional_transfers(pair, tmp_path) -> None:
    a, b = pair
    fa, fb = tmp_path / "from_a.bin", tmp_path / "from_b.bin"
    fa.write_bytes(os.urandom(2 * 1024 * 1024))
    fb.write_bytes(os.urandom(2 * 1024 * 1024))
    a.node.send_file(a.store.get("B"), fa)
    b.node.send_file(b.store.get("A"), fb)
    a.events.wait_finished(2)
    b.events.wait_finished(2)
    statuses = [i.status for i in [*a.events.finished.values(), *b.events.finished.values()]]
    assert statuses == ["completed"] * 4
    # the two directions overlapped in time
    a_send = next(i for i in a.events.finished.values() if i.direction == "send")
    b_send = next(i for i in b.events.finished.values() if i.direction == "send")
    assert a_send.started_at < b_send.finished_at and b_send.started_at < a_send.finished_at
    assert _sha(b.received / "from_a.bin") == _sha(fa)
    assert _sha(a.received / "from_b.bin") == _sha(fb)


def test_several_concurrent_transfers(pair, tmp_path) -> None:
    a, b = pair
    files = []
    for i in range(4):
        f = tmp_path / f"f{i}.bin"
        f.write_bytes(os.urandom(300_000 + i))
        files.append(f)
        a.node.send_file(a.store.get("B"), f)
    a.events.wait_finished(4)
    b.events.wait_finished(4)
    assert all(i.status == "completed" for i in a.events.finished.values())
    for f in files:
        assert _sha(b.received / f.name) == _sha(f)
    assert len({i.transfer_id for i in a.events.finished.values()}) == 4


def test_connection_limit_refuses_excess(tmp_path, identity_a, identity_b) -> None:
    b = make_node(identity_b, tmp_path / "b", max_concurrent_transfers=1)
    a = make_node(identity_a, tmp_path / "a")
    try:
        trust(b, a, "A")
        tls, _ = raw_connect(a.identity, b.node.port)  # occupies the only slot
        with tls:
            peer = trust(a, b, "B")
            src = tmp_path / "x.txt"
            src.write_bytes(b"x")
            a.node.send_file(peer, src)
            (info,) = a.events.wait_finished()
            assert info.status == "failed"
    finally:
        a.node.stop()
        b.node.stop()


def test_receiver_cancel_cleans_up(tmp_path, identity_a, identity_b, monkeypatch) -> None:
    monkeypatch.setattr(net, "PROGRESS_INTERVAL", 0)
    gate = threading.Event()
    holder = {}

    def accept(info):
        holder["tid"] = info.transfer_id
        gate.set()
        return True

    a = make_node(identity_a, tmp_path / "a", chunk_size=1024)
    b = make_node(identity_b, tmp_path / "b", accept=accept)
    try:
        trust(a, b, "B")
        trust(b, a, "A")
        b.events.progress_delay = 0.01  # keep the receiver busy long enough to cancel it
        src = tmp_path / "big.bin"
        src.write_bytes(os.urandom(20 * 1024 * 1024))
        a.node.send_file(a.store.get("B"), src)
        assert gate.wait(10)
        b.events.wait(lambda: any(p.bytes_done for p in b.events.progress))
        assert b.node.cancel(holder["tid"])
        (recv,) = b.events.wait_finished()
        (sent,) = a.events.wait_finished()
        assert recv.status == "cancelled"
        assert sent.status == "failed"
        assert list(b.received.iterdir()) == []
    finally:
        a.node.stop()
        b.node.stop()


def test_sender_cancel(pair, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(net, "PROGRESS_INTERVAL", 0)
    a, b = pair
    a.events.progress_delay = 0.01
    src = tmp_path / "big.bin"
    src.write_bytes(os.urandom(30 * 1024 * 1024))
    info = a.node.send_file(a.store.get("B"), src)
    a.events.wait(lambda: any(p.bytes_done for p in a.events.progress[:]))
    assert a.node.cancel(info.transfer_id)
    (sent,) = a.events.wait_finished()
    (recv,) = b.events.wait_finished()
    assert sent.status == "cancelled"
    assert recv.status == "failed"
    assert list(b.received.iterdir()) == []


def test_unreachable_peer(tmp_path, identity_a, identity_b) -> None:
    import socket

    from peer_store import Peer

    a = make_node(identity_a, tmp_path / "a", connect_timeout=2)
    try:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()  # nothing listens here now
        peer = Peer.create("Ghost", "127.0.0.1", port, identity_b.fingerprint)
        a.store.add(peer)
        src = tmp_path / "x.txt"
        src.write_bytes(b"x")
        a.node.send_file(peer, src)
        (info,) = a.events.wait_finished()
        assert info.status == "failed" and "not reachable" in info.error
    finally:
        a.node.stop()


def test_port_in_use_reported(tmp_path, identity_a, pair) -> None:
    a, _ = pair
    with pytest.raises(OSError):
        make_node(identity_a, tmp_path / "dup", listen_port=a.node.port)


def test_stop_is_prompt_and_idempotent_for_workers(tmp_path, identity_a) -> None:
    import time

    n = make_node(identity_a, tmp_path / "n")
    assert n.node.listening
    t0 = time.monotonic()
    n.node.stop()
    assert time.monotonic() - t0 < 3
    assert not n.node.listening
    with pytest.raises(net.TransferError):
        n.node.send_file(None, tmp_path)  # type: ignore[arg-type]
