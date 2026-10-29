"""CipherLink LAN peer-to-peer transfer protocol (version 1).

Connection lifecycle (client = sender, server = receiver):

1. TCP connect.
2. Client preface (cleartext, public data only): ``b"CLNK" | version | len(2) | client cert DER``.
   The server looks the certificate's SHA-256 fingerprint up in its pinned peers and closes
   the connection if it is unknown. Nothing else is read from an unknown peer.
3. TLS 1.3 handshake. The server *requires* a client certificate that chains only to the
   pinned certificate from step 2, so the client must prove it holds the private key.
   The client checks the server certificate's fingerprint against its pin before sending
   anything else.
4. Framed messages inside TLS, each ``version(1) | type(1) | length(4) | payload``:
   OFFER -> ACCEPT|REJECT -> KEY -> RECORD* -> FINAL -> RESULT. ERROR may replace any
   reply. Any other message for the current state is a protocol error.
5. The receiver writes authenticated plaintext to a private temp file and publishes it
   under a new, non-clashing name only after the FINAL record verifies.

The module is Qt-free: the GUI receives events through ``NodeEvents`` callbacks, which are
invoked on worker threads.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import os
import shutil
import socket
import ssl
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path

import crypto_engine as ce
from config import MAX_CHUNK_SIZE, PROTOCOL_VERSION, Config
from peer_store import Peer, PeerStore

log = logging.getLogger(__name__)

MAGIC = b"CLNK"
PREFACE = struct.Struct(">4sBH")  # magic, version, certificate length
MAX_CERT_BYTES = 8192
FRAME_HEADER = struct.Struct(">BBI")  # version, type, payload length
MAX_CONTROL_BYTES = 4096
MAX_KEY_BYTES = 1024
SEQ_BYTES = 8
MAX_FILENAME_BYTES = 255
PROGRESS_INTERVAL = 0.1  # seconds between progress callbacks per transfer
_WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


class MsgType(IntEnum):
    OFFER = 1
    ACCEPT = 2
    REJECT = 3
    KEY = 4
    RECORD = 5
    FINAL = 6
    RESULT = 7
    ERROR = 8


class TransferError(Exception):
    """A transfer failed; the message is safe to show to the user."""


class ProtocolError(TransferError):
    """The peer sent something malformed or unexpected for the current state."""


class PeerAuthError(TransferError):
    """The peer's certificate is unknown or does not match the pinned fingerprint."""


class TransferRejected(TransferError):
    """The receiving user (or receiver policy) declined the transfer."""


class TransferCancelled(TransferError):
    """The transfer was cancelled locally."""


# --------------------------------------------------------------------------- data


@dataclass
class TransferInfo:
    """Snapshot of one transfer's state. Never contains key material or file contents."""

    transfer_id: str
    direction: str  # "send" or "receive"
    peer: str
    filename: str
    size: int
    bytes_done: int = 0
    status: str = "queued"  # queued, connecting, awaiting_consent, transferring, completed, failed, rejected, cancelled
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    error: str | None = None
    saved_as: str | None = None

    @property
    def finished(self) -> bool:
        return self.status in ("completed", "failed", "rejected", "cancelled")


class NodeEvents:
    """Callbacks from the network layer. All are called on worker threads."""

    def on_transfer_started(self, info: TransferInfo) -> None: ...

    def on_progress(self, info: TransferInfo) -> None: ...

    def on_transfer_finished(self, info: TransferInfo) -> None: ...

    def on_incoming_offer(self, info: TransferInfo) -> bool:
        """Block until the user decides. Default declines (fail closed)."""
        return False

    def on_unknown_peer(self, fingerprint: str, address: str) -> None: ...


@dataclass(frozen=True)
class Offer:
    transfer_id: bytes
    name: str
    size: int
    chunk_size: int
    raw: bytes  # exact bytes received; hashed into every record's AAD

    @property
    def digest(self) -> bytes:
        return hashlib.sha256(self.raw).digest()


# --------------------------------------------------------------------------- framing


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly ``n`` bytes, tolerating fragmented reads."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(n - len(buf), 1 << 20))
        if not chunk:
            raise ProtocolError("connection closed by peer before the message was complete")
        buf += chunk
    return bytes(buf)


def send_frame(sock: socket.socket, mtype: MsgType, payload: bytes = b"") -> None:
    sock.sendall(FRAME_HEADER.pack(PROTOCOL_VERSION, mtype, len(payload)) + payload)


def read_frame(sock: socket.socket, max_len: int) -> tuple[MsgType, bytes]:
    version, raw_type, length = FRAME_HEADER.unpack(recv_exact(sock, FRAME_HEADER.size))
    if version != PROTOCOL_VERSION:
        raise ProtocolError(f"unsupported protocol version {version}")
    try:
        mtype = MsgType(raw_type)
    except ValueError:
        raise ProtocolError(f"unknown message type {raw_type}") from None
    if length > max_len:
        raise ProtocolError(f"{mtype.name} message too large ({length} bytes)")
    return mtype, recv_exact(sock, length)


def expect(sock: socket.socket, allowed: tuple[MsgType, ...], max_len: int = MAX_CONTROL_BYTES) -> tuple[MsgType, bytes]:
    """Read one frame and enforce the protocol state. A peer ERROR becomes TransferError."""
    mtype, payload = read_frame(sock, max(max_len, MAX_CONTROL_BYTES))
    if mtype is MsgType.ERROR and MsgType.ERROR not in allowed:
        raise TransferError(f"peer reported an error: {_peer_reason(payload)}")
    if mtype not in allowed:
        raise ProtocolError(f"unexpected {mtype.name} message (expected {'/'.join(t.name for t in allowed)})")
    if mtype not in (MsgType.RECORD, MsgType.FINAL, MsgType.KEY) and len(payload) > MAX_CONTROL_BYTES:
        raise ProtocolError(f"{mtype.name} message too large")
    return mtype, payload


def encode_json(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def decode_json(payload: bytes) -> dict:
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProtocolError("malformed JSON message") from None
    if not isinstance(obj, dict):
        raise ProtocolError("JSON message must be an object")
    return obj


def _peer_reason(payload: bytes) -> str:
    try:
        reason = decode_json(payload).get("reason", "")
    except ProtocolError:
        reason = ""
    text = "".join(c for c in str(reason) if c.isprintable())[:200]
    return text or "unspecified"


# --------------------------------------------------------------------------- validation


def validate_filename(name: object) -> str:
    """Return ``name`` if it is a safe single path component, else raise ProtocolError.

    Rejects separators of every platform, ``.``/``..``, hidden files, control characters,
    Windows-reserved names and over-long names, rather than trying to repair them.
    """
    if not isinstance(name, str) or not name:
        raise ProtocolError("filename missing")
    if len(name.encode("utf-8")) > MAX_FILENAME_BYTES:
        raise ProtocolError("filename too long")
    if any(c in name for c in '/\\:*?"<>|') or not name.isprintable():
        raise ProtocolError("filename contains path separators or reserved characters")
    if name.startswith(".") or name.endswith((" ", ".")):
        raise ProtocolError("filename must not be hidden or end with a dot/space")
    if name.split(".")[0].upper() in _WINDOWS_RESERVED:
        raise ProtocolError("filename is a reserved device name")
    return name


def parse_offer(payload: bytes, config: Config) -> Offer:
    obj = decode_json(payload)
    if set(obj) != {"v", "transfer_id", "name", "size", "chunk_size"}:
        raise ProtocolError("offer has missing or unexpected fields")
    if obj["v"] != PROTOCOL_VERSION:
        raise ProtocolError("offer protocol version mismatch")
    tid = obj["transfer_id"]
    if not isinstance(tid, str) or len(tid) != 2 * ce.TRANSFER_ID_BYTES:
        raise ProtocolError("invalid transfer id")
    try:
        tid_bytes = bytes.fromhex(tid)
    except ValueError:
        raise ProtocolError("invalid transfer id") from None
    size, chunk = obj["size"], obj["chunk_size"]
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ProtocolError("invalid file size")
    if size > config.max_file_size:
        raise TransferRejected(f"file is larger than the receiver's limit ({config.max_file_size} bytes)")
    if isinstance(chunk, bool) or not isinstance(chunk, int) or not 1 <= chunk <= MAX_CHUNK_SIZE:
        raise ProtocolError("invalid chunk size")
    if -(-size // chunk) > ce.MAX_RECORDS - 1:
        raise ProtocolError("file needs too many records for one session key")
    return Offer(tid_bytes, validate_filename(obj["name"]), size, chunk, payload)


def describe_error(exc: BaseException) -> str:
    """Translate an exception into a short message for the user (no secrets)."""
    if isinstance(exc, TransferError):
        return str(exc)
    if isinstance(exc, ConnectionRefusedError):
        return "Peer not reachable: connection refused (is CipherLink running and the port open?)"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "Connection timed out"
    if isinstance(exc, socket.gaierror):
        return "Peer address could not be resolved"
    if isinstance(exc, ssl.SSLError):
        return f"TLS handshake failed ({exc.reason or 'error'}); the peer may not trust your fingerprint yet"
    if isinstance(exc, ce.CryptoError):
        return f"Cryptographic check failed: {exc}"
    if isinstance(exc, ConnectionError):
        return "Connection lost (the peer closed it or does not trust your fingerprint)"
    if isinstance(exc, OSError):
        return f"System error: {exc.strerror or type(exc).__name__}"
    return f"Unexpected error: {type(exc).__name__}"


# --------------------------------------------------------------------------- node


class _Active:
    """Mutable per-transfer state owned by exactly one worker thread."""

    def __init__(self, info: TransferInfo) -> None:
        self.info = info
        self.cancelled = threading.Event()
        self.sock: socket.socket | None = None
        self.last_emit = 0.0

    def cancel(self) -> None:
        self.cancelled.set()
        sock = self.sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)  # unblocks a pending recv/send
            except OSError:
                pass

    def check(self) -> None:
        if self.cancelled.is_set():
            raise TransferCancelled("Transfer cancelled")


class PeerNode:
    """One laptop: a background listener plus a bounded pool of outbound senders."""

    def __init__(self, identity: ce.Identity, peers: PeerStore, config: Config, events: NodeEvents | None = None):
        self.identity = identity
        self.peers = peers
        self.config = config
        self.events = events or NodeEvents()
        self._client_ctx = ce.client_tls_context(identity)
        self._slots = threading.BoundedSemaphore(config.max_concurrent_transfers)
        self._senders = ThreadPoolExecutor(config.max_concurrent_transfers, thread_name_prefix="cl-send")
        self._active: dict[str, _Active] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._threads: set[threading.Thread] = set()
        self.port: int | None = None

    # ---------------------------------------------------------------- lifecycle

    def start(self) -> None:
        """Bind and start listening. Raises OSError (e.g. port in use) to the caller."""
        cfg = self.config
        cfg.receive_dir.mkdir(parents=True, exist_ok=True)
        family = socket.AF_INET6 if ":" in cfg.listen_host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        if sys.platform != "win32":  # on Windows SO_REUSEADDR allows port hijacking
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((cfg.listen_host, cfg.listen_port))
            sock.listen(16)
        except OSError:
            sock.close()
            raise
        sock.settimeout(0.5)
        self._listener = sock
        self.port = sock.getsockname()[1]
        self._accept_thread = threading.Thread(target=self._accept_loop, name="cl-listen", daemon=True)
        self._accept_thread.start()
        log.info("listening on %s:%s", cfg.listen_host, self.port)

    def stop(self, timeout: float = 5.0) -> None:
        """Stop listening, cancel every transfer, and wait for workers to exit."""
        self._stop.set()
        if self._listener is not None:
            self._listener.close()
        with self._lock:
            actives = list(self._active.values())
        for active in actives:
            active.cancel()
        self._senders.shutdown(wait=True, cancel_futures=True)
        deadline = time.monotonic() + timeout
        for t in [self._accept_thread, *list(self._threads)]:
            if t is not None:
                t.join(max(0.0, deadline - time.monotonic()))
        log.info("node stopped")

    @property
    def listening(self) -> bool:
        return self._accept_thread is not None and self._accept_thread.is_alive()

    # ---------------------------------------------------------------- public API

    def send_file(self, peer: Peer, path: Path) -> TransferInfo:
        """Queue ``path`` for sending to ``peer``; returns the initial snapshot."""
        if self._stop.is_set():
            raise TransferError("node is shutting down")
        path = Path(path)
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise TransferError(f"cannot read file: {exc.strerror}") from exc
        if not path.is_file():
            raise TransferError("only regular files can be sent")
        if size > self.config.max_file_size:
            raise TransferError("file exceeds the configured maximum size")
        tid = ce.new_transfer_id()
        info = TransferInfo(tid.hex(), "send", peer.name, path.name, size)
        active = self._register(info)
        self._emit("on_transfer_started", active)
        self._senders.submit(self._run_send, active, tid, peer, path)
        return dataclasses.replace(info)

    def cancel(self, transfer_id: str) -> bool:
        with self._lock:
            active = self._active.get(transfer_id)
        if active is None:
            return False
        active.cancel()
        return True

    def active_transfers(self) -> list[TransferInfo]:
        with self._lock:
            return [dataclasses.replace(a.info) for a in self._active.values()]

    # ---------------------------------------------------------------- internals

    def _register(self, info: TransferInfo) -> _Active:
        active = _Active(info)
        with self._lock:
            self._active[info.transfer_id] = active
        return active

    def _emit(self, name: str, active: _Active) -> None:
        try:
            getattr(self.events, name)(dataclasses.replace(active.info))
        except Exception:  # a GUI bug must not kill a network worker
            log.exception("event handler %s failed", name)

    def _progress(self, active: _Active, n: int) -> None:
        active.info.bytes_done += n
        now = time.monotonic()
        if now - active.last_emit >= PROGRESS_INTERVAL:
            active.last_emit = now
            self._emit("on_progress", active)

    def _finish(self, active: _Active, status: str, error: str | None = None) -> None:
        active.info.status = status
        active.info.error = error
        active.info.finished_at = time.time()
        with self._lock:
            self._active.pop(active.info.transfer_id, None)
        level = logging.INFO if status == "completed" else logging.WARNING
        log.log(level, "%s %s %s: %s%s", active.info.direction, active.info.transfer_id[:8],
                active.info.filename, status, f" ({error})" if error else "")
        self._emit("on_transfer_finished", active)

    def _fail(self, active: _Active, exc: BaseException) -> None:
        if active.cancelled.is_set() or isinstance(exc, TransferCancelled):
            self._finish(active, "cancelled", "Transfer cancelled")
        elif isinstance(exc, TransferRejected):
            self._finish(active, "rejected", str(exc))
        else:
            if not isinstance(exc, (TransferError, OSError, ce.CryptoError)):
                log.exception("unexpected error in transfer", exc_info=exc)
            self._finish(active, "failed", describe_error(exc))

    # ---------------------------------------------------------------- sending

    def _run_send(self, active: _Active, tid: bytes, peer: Peer, path: Path) -> None:
        try:
            active.check()
            active.info.status = "connecting"
            self._emit("on_progress", active)
            tls, server_der = self._connect(active, peer)
            with tls:
                self._send_over(active, tls, server_der, tid, path)
            self._finish(active, "completed")
        except BaseException as exc:  # noqa: BLE001 - every failure must be reported
            self._fail(active, exc)

    def _connect(self, active: _Active, peer: Peer) -> tuple[ssl.SSLSocket, bytes]:
        """Open a TLS connection and verify the server's pinned fingerprint."""
        cfg = self.config
        raw = socket.create_connection((peer.host, peer.port), timeout=cfg.connect_timeout)
        active.sock = raw
        try:
            raw.settimeout(cfg.handshake_timeout)
            cert = self.identity.cert_der
            raw.sendall(PREFACE.pack(MAGIC, PROTOCOL_VERSION, len(cert)) + cert)
            tls = self._client_ctx.wrap_socket(raw)
        except BaseException:
            raw.close()
            raise
        active.sock = tls
        server_der = tls.getpeercert(binary_form=True)
        if not server_der or not ce.fingerprints_match(ce.fingerprint(server_der), peer.fingerprint):
            tls.close()
            raise PeerAuthError(
                f"'{peer.name}' presented a certificate that does not match its pinned fingerprint; "
                "connection aborted before any data was sent"
            )
        tls.settimeout(cfg.io_timeout)
        return tls, server_der

    def _send_over(self, active: _Active, tls: ssl.SSLSocket, server_der: bytes, tid: bytes, path: Path) -> None:
        cfg = self.config
        info = active.info
        recipient_key = ce.public_key_from_cert_der(server_der)
        offer = encode_json(
            {"v": PROTOCOL_VERSION, "transfer_id": tid.hex(), "name": info.filename,
             "size": info.size, "chunk_size": cfg.chunk_size}
        )
        send_frame(tls, MsgType.OFFER, offer)
        info.status = "awaiting_consent"
        self._emit("on_progress", active)

        tls.settimeout(cfg.consent_timeout + cfg.io_timeout)
        mtype, payload = expect(tls, (MsgType.ACCEPT, MsgType.REJECT))
        if mtype is MsgType.REJECT:
            raise TransferRejected(f"Receiver declined: {_peer_reason(payload)}")
        tls.settimeout(cfg.io_timeout)

        session_key = ce.new_session_key()
        send_frame(tls, MsgType.KEY, ce.wrap_session_key(recipient_key, session_key, tid))
        sealer = ce.RecordSealer(session_key, tid, hashlib.sha256(offer).digest())
        del session_key

        info.status = "transferring"
        info.started_at = time.time()
        digest = hashlib.sha256()
        sent = 0
        with open(path, "rb") as fh:
            while True:
                active.check()
                chunk = fh.read(cfg.chunk_size)
                if not chunk:
                    break
                sent += len(chunk)
                if sent > info.size:
                    raise TransferError("source file grew while sending; aborted")
                digest.update(chunk)
                seq, ct = sealer.seal(chunk)
                send_frame(tls, MsgType.RECORD, seq.to_bytes(SEQ_BYTES, "big") + ct)
                self._progress(active, len(chunk))
        if sent != info.size:
            raise TransferError("source file shrank while sending; aborted")

        summary = encode_json({"size": sent, "records": sealer.next_seq, "sha256": digest.hexdigest()})
        seq, ct = sealer.seal(summary, final=True)
        send_frame(tls, MsgType.FINAL, seq.to_bytes(SEQ_BYTES, "big") + ct)
        mtype, payload = expect(tls, (MsgType.RESULT,))
        result = decode_json(payload)
        if result.get("ok") is not True:
            raise TransferError("receiver did not confirm the transfer")
        saved = result.get("saved_as")
        info.saved_as = saved if isinstance(saved, str) else None

    # ---------------------------------------------------------------- receiving

    def _accept_loop(self) -> None:
        assert self._listener is not None
        while not self._stop.is_set():
            try:
                conn, addr = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                log.exception("accept failed")
                time.sleep(0.2)
                continue
            if not self._slots.acquire(blocking=False):
                log.warning("connection from %s refused: concurrency limit reached", addr[0])
                conn.close()
                continue
            t = threading.Thread(target=self._serve, args=(conn, addr), name="cl-recv", daemon=True)
            with self._lock:
                self._threads.add(t)
            t.start()

    def _serve(self, conn: socket.socket, addr: tuple) -> None:
        try:
            self._handle_inbound(conn, f"{addr[0]}:{addr[1]}")
        except Exception:
            log.exception("inbound handler crashed")
        finally:
            conn.close()
            self._slots.release()
            with self._lock:
                self._threads.discard(threading.current_thread())

    def _handle_inbound(self, raw: socket.socket, address: str) -> None:
        cfg = self.config
        raw.settimeout(cfg.handshake_timeout)
        try:
            magic, version, cert_len = PREFACE.unpack(recv_exact(raw, PREFACE.size))
            if magic != MAGIC or version != PROTOCOL_VERSION or not 0 < cert_len <= MAX_CERT_BYTES:
                raise ProtocolError("bad preface")
            client_der = recv_exact(raw, cert_len)
        except (OSError, ProtocolError) as exc:
            log.info("dropped connection from %s before authentication: %s", address, exc)
            return

        fp = ce.fingerprint(client_der)
        peer = self.peers.find_by_fingerprint(fp)
        if peer is None:
            log.warning("rejected untrusted peer %s (fingerprint %s…)", address, fp[:16])
            try:
                self.events.on_unknown_peer(fp, address)
            except Exception:
                log.exception("on_unknown_peer handler failed")
            return

        try:
            tls = ce.server_tls_context(self.identity, client_der).wrap_socket(raw, server_side=True)
        except (OSError, ce.CryptoError) as exc:
            log.warning("TLS handshake with %s (%s) failed: %s", peer.name, address, exc)
            return
        with tls:
            presented = tls.getpeercert(binary_form=True)
            if not presented or not ce.fingerprints_match(ce.fingerprint(presented), fp):
                log.warning("peer %s presented a different certificate in TLS", address)
                return
            tls.settimeout(cfg.io_timeout)
            self._receive_transfer(tls, peer)

    def _receive_transfer(self, tls: ssl.SSLSocket, peer: Peer) -> None:
        cfg = self.config
        try:
            _, payload = expect(tls, (MsgType.OFFER,))
            offer = parse_offer(payload, cfg)
        except TransferRejected as exc:
            _try_send(tls, MsgType.REJECT, {"reason": str(exc)})
            log.info("rejected offer from %s: %s", peer.name, exc)
            return
        except (TransferError, OSError) as exc:
            _try_send(tls, MsgType.ERROR, {"reason": describe_error(exc)})
            log.warning("bad offer from %s: %s", peer.name, describe_error(exc))
            return

        tid_hex = offer.transfer_id.hex()
        with self._lock:
            duplicate = tid_hex in self._active
        if duplicate:
            _try_send(tls, MsgType.ERROR, {"reason": "duplicate transfer id"})
            return
        info = TransferInfo(tid_hex, "receive", peer.name, offer.name, offer.size, status="awaiting_consent")
        active = self._register(info)
        active.sock = tls
        self._emit("on_transfer_started", active)
        try:
            self._receive_body(active, tls, offer)
            self._finish(active, "completed")
        except BaseException as exc:  # noqa: BLE001
            self._fail(active, exc)
            if not isinstance(exc, (TransferRejected, ConnectionError)):
                _try_send(tls, MsgType.ERROR, {"reason": active.info.error or "transfer failed"})

    def _receive_body(self, active: _Active, tls: ssl.SSLSocket, offer: Offer) -> None:
        cfg = self.config
        info = active.info
        free = shutil.disk_usage(cfg.receive_dir).free
        if free < offer.size + 16 * 1024 * 1024:
            _try_send(tls, MsgType.REJECT, {"reason": "insufficient disk space on receiver"})
            raise TransferRejected("Insufficient disk space for incoming file")

        accepted = bool(self.events.on_incoming_offer(dataclasses.replace(info)))
        active.check()
        if not accepted:
            _try_send(tls, MsgType.REJECT, {"reason": "declined by user"})
            raise TransferRejected("Declined incoming transfer")
        send_frame(tls, MsgType.ACCEPT)

        _, wrapped = expect(tls, (MsgType.KEY,), MAX_KEY_BYTES)
        session_key = ce.unwrap_session_key(self.identity.key, wrapped, offer.transfer_id)
        opener = ce.RecordOpener(session_key, offer.transfer_id, offer.digest)
        del session_key

        info.status = "transferring"
        info.started_at = time.time()
        self._emit("on_progress", active)
        tmp = cfg.receive_dir / f".cipherlink-{offer.transfer_id.hex()}.part"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        try:
            digest = hashlib.sha256()
            received = 0
            max_record = SEQ_BYTES + offer.chunk_size + ce.TAG_BYTES
            with os.fdopen(fd, "wb") as out:
                while True:
                    active.check()
                    mtype, payload = expect(tls, (MsgType.RECORD, MsgType.FINAL), max_record)
                    if len(payload) < SEQ_BYTES + ce.TAG_BYTES:
                        raise ProtocolError("record too short")
                    seq = int.from_bytes(payload[:SEQ_BYTES], "big")
                    if mtype is MsgType.RECORD:
                        chunk = opener.open(seq, payload[SEQ_BYTES:])
                        if not chunk or len(chunk) > offer.chunk_size:
                            raise ProtocolError("record size outside the negotiated chunk size")
                        received += len(chunk)
                        if received > offer.size:
                            raise ProtocolError("peer sent more data than it offered")
                        try:
                            out.write(chunk)
                        except OSError as exc:
                            raise TransferError(f"Write failed on receiver: {exc.strerror}") from exc
                        digest.update(chunk)
                        self._progress(active, len(chunk))
                        continue
                    data_records = opener.next_seq
                    summary = decode_json(opener.open(seq, payload[SEQ_BYTES:], final=True))
                    expected = {"size": offer.size, "records": data_records, "sha256": digest.hexdigest()}
                    if received != offer.size or summary != expected:
                        raise ProtocolError("completion check failed: file is truncated or altered")
                    break
                out.flush()
                os.fsync(out.fileno())
            final = publish_unique(tmp, cfg.receive_dir, offer.name)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        info.saved_as = final.name
        send_frame(tls, MsgType.RESULT, encode_json({"ok": True, "saved_as": final.name}))


def _try_send(sock: socket.socket, mtype: MsgType, obj: dict) -> None:
    try:
        send_frame(sock, mtype, encode_json(obj))
    except OSError:
        pass


def publish_unique(tmp: Path, directory: Path, name: str) -> Path:
    """Move ``tmp`` to ``directory/name`` without overwriting anything.

    A placeholder is created with O_EXCL (fails if the name exists, including symlinks),
    then atomically replaced by the finished temp file. Clashing names get `` (n)``.
    """
    validate_filename(name)
    stem, dot, ext = name.rpartition(".")
    if not stem:
        stem, dot, ext = name, "", ""
    for n in range(1000):
        candidate = directory / (name if n == 0 else f"{stem} ({n}){dot}{ext}")
        if candidate.parent.resolve() != directory.resolve():
            raise ProtocolError("unsafe destination path")
        try:
            os.close(os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        except FileExistsError:
            continue
        try:
            os.replace(tmp, candidate)
        except BaseException:
            candidate.unlink(missing_ok=True)
            raise
        return candidate
    raise TransferError("could not find a free filename in the receive folder")

