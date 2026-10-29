"""Peer authentication: fingerprint pinning on both sides of the TLS connection."""
from __future__ import annotations

import ssl

import pytest
from conftest import make_node, raw_connect, trust

import crypto_engine as ce
import network_p2p as net
from peer_store import Peer


def _send(a, peer, tmp_path, data=b"payload"):
    f = tmp_path / "f.txt"
    f.write_bytes(data)
    a.node.send_file(peer, f)
    (info,) = a.events.wait_finished()
    return info


def test_trusted_peer_succeeds(pair, tmp_path) -> None:
    a, b = pair
    info = _send(a, a.store.get("B"), tmp_path)
    assert info.status == "completed", info.error
    assert (b.received / "f.txt").read_bytes() == b"payload"


def test_wrong_server_fingerprint_aborts_before_any_data(pair, tmp_path, identity_mallory) -> None:
    a, b = pair
    a.store.replace_pin("B", identity_mallory.fingerprint, confirmed=True)
    info = _send(a, a.store.get("B"), tmp_path)
    assert info.status == "failed"
    assert "does not match its pinned fingerprint" in info.error
    assert b.events.offers == [] and b.events.started == []
    assert list(b.received.iterdir()) == []


def test_unknown_client_rejected_and_reported_not_trusted(tmp_path, identity_a, identity_b) -> None:
    a = make_node(identity_a, tmp_path / "a")
    b = make_node(identity_b, tmp_path / "b")
    try:
        peer = trust(a, b, "B")  # B has NOT pinned A
        info = _send(a, peer, tmp_path)
        assert info.status == "failed"
        b.events.wait(lambda: b.events.unknown)
        assert b.events.unknown[0][0] == identity_a.fingerprint
        assert b.store.peers() == []  # never auto-trusted
        assert b.events.offers == []
    finally:
        a.node.stop()
        b.node.stop()


def test_changed_peer_certificate_rejected_until_pin_replaced(pair, tmp_path, identity_mallory) -> None:
    """A presents a new identity: B rejects it until B's user explicitly replaces the pin."""
    a, b = pair
    new_a = make_node(identity_mallory, tmp_path / "a2")
    try:
        trust(new_a, b, "B")
        assert _send(new_a, new_a.store.get("B"), tmp_path).status == "failed"
        b.events.wait(lambda: b.events.unknown)

        b.store.replace_pin("A", identity_mallory.fingerprint, confirmed=True)
        new_a.events.finished.clear()
        assert _send(new_a, new_a.store.get("B"), tmp_path).status == "completed"
    finally:
        new_a.node.stop()


def test_preface_cert_without_private_key_fails_tls(pair, identity_mallory) -> None:
    """Mallory replays A's (public) certificate in the preface but only has her own key."""
    a, b = pair
    with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
        tls, _ = raw_connect(identity_mallory, b.node.port, preface_identity=a.identity)
        # TLS 1.3 client-auth failures can surface on the first read after the handshake
        net.send_frame(tls, net.MsgType.OFFER, b"{}")
        tls.recv(1) or (_ for _ in ()).throw(ConnectionError("closed"))
    assert b.events.offers == [] and b.events.started == []


def test_garbage_preface_dropped_without_processing(pair) -> None:
    import socket

    a, b = pair
    s = socket.create_connection(("127.0.0.1", b.node.port))
    s.sendall(b"GET / HTTP/1.1\r\n\r\n")
    try:
        assert s.recv(10) == b""  # closed...
    except ConnectionResetError:
        pass  # ...or reset, because unread bytes were pending when the server closed
    s.close()
    assert b.events.started == [] and b.events.unknown == []


def test_sender_wraps_key_for_authenticated_recipient(pair, tmp_path, monkeypatch) -> None:
    a, b = pair
    seen = []
    real = ce.wrap_session_key

    def spy(public_key, key, tid):
        seen.append(public_key.public_numbers())
        return real(public_key, key, tid)

    monkeypatch.setattr(ce, "wrap_session_key", spy)
    assert _send(a, a.store.get("B"), tmp_path).status == "completed"
    assert seen == [b.identity.key.public_key().public_numbers()]


def test_malformed_pin_never_matches(pair) -> None:
    a, b = pair
    assert b.store.find_by_fingerprint("not-a-fingerprint") is None
    with pytest.raises(ValueError):
        Peer.create("X", "127.0.0.1", 1, "00" * 31)
