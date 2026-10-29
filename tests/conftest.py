"""Shared fixtures. RSA-3072 generation is slow, so identities are made once per session."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from crypto_engine import Identity, generate_identity  # noqa: E402


@pytest.fixture(scope="session")
def identity_a(tmp_path_factory: pytest.TempPathFactory) -> Identity:
    return generate_identity(tmp_path_factory.mktemp("id_a"))


@pytest.fixture(scope="session")
def identity_b(tmp_path_factory: pytest.TempPathFactory) -> Identity:
    return generate_identity(tmp_path_factory.mktemp("id_b"))


@pytest.fixture(scope="session")
def identity_mallory(tmp_path_factory: pytest.TempPathFactory) -> Identity:
    return generate_identity(tmp_path_factory.mktemp("id_m"))


@pytest.fixture
def home(tmp_path: Path) -> Path:
    return tmp_path


# --------------------------------------------------------------------------- network helpers

import hashlib  # noqa: E402
import socket  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
from collections.abc import Callable, Iterator  # noqa: E402
from dataclasses import dataclass  # noqa: E402

import crypto_engine as ce  # noqa: E402
import network_p2p as net  # noqa: E402
from config import Config  # noqa: E402
from peer_store import Peer, PeerStore  # noqa: E402


class Recorder(net.NodeEvents):
    """Collects node events; ``accept`` may be a bool or a callable(info) -> bool."""

    def __init__(self, accept: bool | Callable[[net.TransferInfo], bool] = True) -> None:
        self.accept = accept
        self.started: list[net.TransferInfo] = []
        self.progress: list[net.TransferInfo] = []
        self.finished: dict[str, net.TransferInfo] = {}
        self.offers: list[net.TransferInfo] = []
        self.unknown: list[tuple[str, str]] = []
        self._cv = threading.Condition()

    def on_transfer_started(self, info):
        with self._cv:
            self.started.append(info)
            self._cv.notify_all()

    progress_delay = 0.0  # tests set this to throttle a worker deterministically

    def on_progress(self, info):
        with self._cv:
            self.progress.append(info)
            self._cv.notify_all()
        if self.progress_delay:
            time.sleep(self.progress_delay)

    def on_transfer_finished(self, info):
        with self._cv:
            self.finished[info.transfer_id] = info
            self._cv.notify_all()

    def on_incoming_offer(self, info):
        self.offers.append(info)
        return self.accept(info) if callable(self.accept) else self.accept

    def on_unknown_peer(self, fingerprint, address):
        with self._cv:
            self.unknown.append((fingerprint, address))
            self._cv.notify_all()

    def wait(self, predicate: Callable[[], bool], timeout: float = 20.0) -> None:
        with self._cv:
            assert self._cv.wait_for(predicate, timeout), "timed out waiting for node event"

    def wait_finished(self, count: int = 1, timeout: float = 20.0) -> list[net.TransferInfo]:
        self.wait(lambda: len(self.finished) >= count, timeout)
        return list(self.finished.values())


@dataclass
class Node:
    node: net.PeerNode
    events: Recorder
    store: PeerStore
    config: Config
    identity: ce.Identity

    @property
    def received(self):
        return self.config.receive_dir


def make_node(identity: ce.Identity, home, accept=True, **cfg) -> Node:
    cfg.setdefault("listen_host", "127.0.0.1")
    cfg.setdefault("listen_port", 0)
    config = Config(data_dir=home, **cfg)
    store = PeerStore(config.peers_file)
    events = Recorder(accept)
    node = net.PeerNode(identity, store, config, events)
    node.start()
    return Node(node, events, store, config, identity)


def trust(a: Node, b: Node, name: str) -> Peer:
    """Make ``a`` trust ``b`` under ``name``; returns the peer record."""
    peer = Peer.create(name, "127.0.0.1", b.node.port, b.identity.fingerprint)
    a.store.add(peer)
    return peer


@pytest.fixture
def pair(tmp_path, identity_a, identity_b) -> Iterator[tuple[Node, Node]]:
    a = make_node(identity_a, tmp_path / "a")
    b = make_node(identity_b, tmp_path / "b")
    trust(a, b, "B")
    trust(b, a, "A")
    yield a, b
    a.node.stop()
    b.node.stop()


def raw_connect(identity: ce.Identity, port: int, preface_identity: ce.Identity | None = None):
    """Speak the client side of the handshake by hand; returns (tls_socket, server_der)."""
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    cert = (preface_identity or identity).cert_der
    raw.sendall(net.PREFACE.pack(net.MAGIC, 1, len(cert)) + cert)
    tls = ce.client_tls_context(identity).wrap_socket(raw)
    return tls, tls.getpeercert(binary_form=True)


def raw_offer(tls, name="evil.txt", size=10, chunk=64 * 1024, tid: bytes | None = None):
    """Send an OFFER and wait for ACCEPT; returns (tid, offer_digest)."""
    tid = tid or ce.new_transfer_id()
    offer = net.encode_json({"v": 1, "transfer_id": tid.hex(), "name": name, "size": size, "chunk_size": chunk})
    net.send_frame(tls, net.MsgType.OFFER, offer)
    mtype, _ = net.read_frame(tls, 4096)
    assert mtype is net.MsgType.ACCEPT
    return tid, hashlib.sha256(offer).digest()


def raw_session(tls, server_der, tid, digest):
    """Send a wrapped key and return a RecordSealer for crafting records."""
    key = ce.new_session_key()
    pub = ce.public_key_from_cert_der(server_der)
    net.send_frame(tls, net.MsgType.KEY, ce.wrap_session_key(pub, key, tid))
    return ce.RecordSealer(key, tid, digest)


def send_record(tls, seq, ct, mtype=net.MsgType.RECORD):
    net.send_frame(tls, mtype, seq.to_bytes(8, "big") + ct)
