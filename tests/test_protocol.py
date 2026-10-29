"""Wire-protocol tests: framing, message validation, state enforcement, and attacks from a
hand-written malicious (but trusted) client against a real listening node."""
from __future__ import annotations

import json
import socket
import threading
import time

import pytest
from conftest import raw_connect, raw_offer, raw_session, send_record

import network_p2p as net
from config import Config

# ------------------------------------------------------------------ framing


def test_frame_roundtrip() -> None:
    a, b = socket.socketpair()
    with a, b:
        net.send_frame(a, net.MsgType.OFFER, b'{"x":1}')
        assert net.read_frame(b, 100) == (net.MsgType.OFFER, b'{"x":1}')
        net.send_frame(a, net.MsgType.ACCEPT)
        assert net.read_frame(b, 100) == (net.MsgType.ACCEPT, b"")


def test_fragmented_reads_are_reassembled() -> None:
    a, b = socket.socketpair()
    payload = bytes(range(256)) * 4
    frame = net.FRAME_HEADER.pack(1, net.MsgType.RECORD, len(payload)) + payload

    def dribble() -> None:
        for i in range(len(frame)):
            a.send(frame[i : i + 1])
            if i % 97 == 0:
                time.sleep(0.001)

    t = threading.Thread(target=dribble)
    t.start()
    with a, b:
        assert net.read_frame(b, 4096) == (net.MsgType.RECORD, payload)
        t.join()


def test_early_close_raises() -> None:
    a, b = socket.socketpair()
    a.sendall(net.FRAME_HEADER.pack(1, net.MsgType.OFFER, 50) + b"short")
    a.close()
    with b, pytest.raises(net.ProtocolError, match="closed"):
        net.read_frame(b, 100)


@pytest.mark.parametrize(
    "header,match",
    [
        (net.FRAME_HEADER.pack(2, 1, 0), "version"),
        (net.FRAME_HEADER.pack(1, 99, 0), "unknown message type"),
        (net.FRAME_HEADER.pack(1, 1, 10_000_000), "too large"),
    ],
)
def test_invalid_frame_headers(header: bytes, match: str) -> None:
    a, b = socket.socketpair()
    with a, b:
        a.sendall(header)
        with pytest.raises(net.ProtocolError, match=match):
            net.read_frame(b, 4096)


def test_expect_enforces_state_and_maps_peer_error() -> None:
    a, b = socket.socketpair()
    with a, b:
        net.send_frame(a, net.MsgType.KEY, b"x")
        with pytest.raises(net.ProtocolError, match="unexpected KEY"):
            net.expect(b, (net.MsgType.OFFER,))
        net.send_frame(a, net.MsgType.ERROR, net.encode_json({"reason": "boom\x07"}))
        with pytest.raises(net.TransferError, match="peer reported an error: boom$"):
            net.expect(b, (net.MsgType.OFFER,))


def test_read_timeout() -> None:
    a, b = socket.socketpair()
    with a, b:
        b.settimeout(0.2)
        with pytest.raises(TimeoutError):
            net.read_frame(b, 100)


@pytest.mark.parametrize("payload", [b"{not json", b"\xff\xfe", b"[1,2]", b'"str"'])
def test_malformed_json(payload: bytes) -> None:
    with pytest.raises(net.ProtocolError):
        net.decode_json(payload)


# ------------------------------------------------------------------ offer validation


def _offer(**over):
    obj = {"v": 1, "transfer_id": "ab" * 16, "name": "a.txt", "size": 5, "chunk_size": 65536}
    obj.update(over)
    return json.dumps(obj).encode()


@pytest.fixture
def cfg(tmp_path) -> Config:
    return Config(data_dir=tmp_path, max_file_size=1000)


def test_valid_offer(cfg) -> None:
    offer = net.parse_offer(_offer(), cfg)
    assert offer.name == "a.txt" and offer.size == 5 and offer.transfer_id == bytes([0xAB]) * 16


@pytest.mark.parametrize(
    "over",
    [
        {"v": 2},
        {"transfer_id": "zz" * 16},
        {"transfer_id": "ab"},
        {"transfer_id": 5},
        {"size": -1},
        {"size": "5"},
        {"size": True},
        {"chunk_size": 0},
        {"chunk_size": 10 * 1024 * 1024},
        {"name": "../x"},
        {"name": 7},
        {"extra": 1},
    ],
)
def test_invalid_offers_rejected(cfg, over) -> None:
    with pytest.raises(net.ProtocolError):
        net.parse_offer(_offer(**over), cfg)


def test_missing_offer_field(cfg) -> None:
    obj = json.loads(_offer())
    del obj["size"]
    with pytest.raises(net.ProtocolError, match="fields"):
        net.parse_offer(json.dumps(obj).encode(), cfg)


def test_oversized_file_is_rejected_not_errored(cfg) -> None:
    with pytest.raises(net.TransferRejected, match="limit"):
        net.parse_offer(_offer(size=1001), cfg)


# ------------------------------------------------------------------ live malicious client


def _expect_failed_receive(b, match: str) -> None:
    (info,) = b.events.wait_finished()
    assert info.direction == "receive" and info.status == "failed", info
    assert match in (info.error or ""), info.error
    assert list(b.received.iterdir()) == [], "no file (or temp file) may remain"


def test_oversized_metadata_frame_closes_connection(pair) -> None:
    a, b = pair
    tls, _ = raw_connect(a.identity, b.node.port)
    with tls:
        net.send_frame(tls, net.MsgType.OFFER, b"x" * 5000)
        mtype, payload = net.read_frame(tls, 4096)
        assert mtype is net.MsgType.ERROR and b"too large" in payload
    assert b.events.started == []


def test_unexpected_first_message(pair) -> None:
    a, b = pair
    tls, _ = raw_connect(a.identity, b.node.port)
    with tls:
        net.send_frame(tls, net.MsgType.RECORD, b"\x00" * 40)
        mtype, payload = net.read_frame(tls, 4096)
        assert mtype is net.MsgType.ERROR and b"unexpected RECORD" in payload
    assert b.events.started == [] and b.events.offers == []


def test_duplicate_record_rejected(pair) -> None:
    a, b = pair
    tls, der = raw_connect(a.identity, b.node.port)
    with tls:
        tid, digest = raw_offer(tls, size=10, chunk=5)
        sealer = raw_session(tls, der, tid, digest)
        seq, ct = sealer.seal(b"hello")
        send_record(tls, seq, ct)
        send_record(tls, seq, ct)  # replay
        _expect_failed_receive(b, "unexpected sequence")


def test_reordered_record_rejected(pair) -> None:
    a, b = pair
    tls, der = raw_connect(a.identity, b.node.port)
    with tls:
        tid, digest = raw_offer(tls, size=10, chunk=5)
        sealer = raw_session(tls, der, tid, digest)
        sealer.seal(b"hello")  # record 0 is never sent
        second = sealer.seal(b"world")
        send_record(tls, *second)
        _expect_failed_receive(b, "unexpected sequence")


def test_truncated_transfer_rejected(pair) -> None:
    """FINAL arrives after only part of the advertised data."""
    a, b = pair
    tls, der = raw_connect(a.identity, b.node.port)
    with tls:
        tid, digest = raw_offer(tls, size=10, chunk=5)
        sealer = raw_session(tls, der, tid, digest)
        send_record(tls, *sealer.seal(b"hello"))
        summary = net.encode_json({"size": 5, "records": 1, "sha256": "0" * 64})
        send_record(tls, *sealer.seal(summary, final=True), mtype=net.MsgType.FINAL)
        _expect_failed_receive(b, "completion check failed")


def test_invalid_completion_message_rejected(pair) -> None:
    import hashlib

    a, b = pair
    tls, der = raw_connect(a.identity, b.node.port)
    with tls:
        tid, digest = raw_offer(tls, size=5, chunk=5)
        sealer = raw_session(tls, der, tid, digest)
        send_record(tls, *sealer.seal(b"hello"))
        bad = net.encode_json({"size": 5, "records": 1, "sha256": hashlib.sha256(b"other").hexdigest()})
        send_record(tls, *sealer.seal(bad, final=True), mtype=net.MsgType.FINAL)
        _expect_failed_receive(b, "completion check failed")


def test_extra_data_beyond_offer_rejected(pair) -> None:
    a, b = pair
    tls, der = raw_connect(a.identity, b.node.port)
    with tls:
        tid, digest = raw_offer(tls, size=5, chunk=5)
        sealer = raw_session(tls, der, tid, digest)
        send_record(tls, *sealer.seal(b"hello"))
        send_record(tls, *sealer.seal(b"extra"))
        _expect_failed_receive(b, "more data than it offered")


def test_record_larger_than_chunk_rejected(pair) -> None:
    a, b = pair
    tls, der = raw_connect(a.identity, b.node.port)
    with tls:
        tid, digest = raw_offer(tls, size=10, chunk=4)
        sealer = raw_session(tls, der, tid, digest)
        send_record(tls, *sealer.seal(b"hello"))  # 5 > negotiated 4
        _expect_failed_receive(b, "outside the negotiated chunk size")


def test_record_frame_over_hard_limit_rejected(pair) -> None:
    a, b = pair
    tls, der = raw_connect(a.identity, b.node.port)
    with tls:
        tid, digest = raw_offer(tls, size=200_000, chunk=65536)
        raw_session(tls, der, tid, digest)
        tls.sendall(net.FRAME_HEADER.pack(1, net.MsgType.RECORD, 65536 + 8 + 16 + 1))
        _expect_failed_receive(b, "too large")


def test_bad_wrapped_key_rejected(pair) -> None:
    a, b = pair
    tls, _ = raw_connect(a.identity, b.node.port)
    with tls:
        raw_offer(tls, size=5)
        net.send_frame(tls, net.MsgType.KEY, b"\x01" * 384)
        _expect_failed_receive(b, "unwrapped")


def test_handshake_timeout_frees_slot(tmp_path, identity_a, identity_b) -> None:
    """A client that connects and says nothing is dropped after the handshake timeout."""
    from conftest import make_node, trust

    b = make_node(identity_b, tmp_path / "b", handshake_timeout=0.3, max_concurrent_transfers=1)
    a = make_node(identity_a, tmp_path / "a")
    try:
        trust(b, a, "A")
        idle = socket.create_connection(("127.0.0.1", b.node.port))
        time.sleep(0.8)  # idle client should now be dropped, freeing the only slot
        assert idle.recv(1) == b""
        idle.close()
        peer = trust(a, b, "B")
        a.node.send_file(peer, _write(tmp_path / "f.txt", b"ok"))
        (info,) = a.events.wait_finished()
        assert info.status == "completed", info.error
    finally:
        a.node.stop()
        b.node.stop()


def _write(path, data: bytes):
    path.write_bytes(data)
    return path
