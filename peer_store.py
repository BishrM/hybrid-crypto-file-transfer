"""Trusted-peer storage: display name, LAN address, and pinned certificate fingerprint.

Trust is only ever created by an explicit ``add`` or a confirmed ``replace_pin`` call.
A connecting peer is never added automatically. A storage file that cannot be validated
is moved aside and the store starts *empty*, so a storage error can only remove trust.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from crypto_engine import FingerprintError, normalize_fingerprint

log = logging.getLogger(__name__)

MAX_NAME_LEN = 64
MAX_HOST_LEN = 253


class PeerStoreError(ValueError):
    """Invalid peer data or a disallowed trust change."""


@dataclass(frozen=True)
class Peer:
    name: str
    host: str
    port: int
    fingerprint: str  # normalised 64-char upper-case hex

    @staticmethod
    def create(name: str, host: str, port: int, fingerprint: str) -> Peer:
        """Validate and normalise user or file input into a Peer."""
        if not isinstance(name, str) or not name.strip() or len(name.strip()) > MAX_NAME_LEN:
            raise PeerStoreError(f"peer name must be 1-{MAX_NAME_LEN} characters")
        if not name.strip().isprintable():
            raise PeerStoreError("peer name contains control characters")
        if (
            not isinstance(host, str)
            or not host.strip()
            or len(host.strip()) > MAX_HOST_LEN
            or any(c.isspace() or not c.isprintable() for c in host.strip())
        ):
            raise PeerStoreError("host must be an IP address or hostname without spaces")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise PeerStoreError("port must be between 1 and 65535")
        try:
            fp = normalize_fingerprint(fingerprint)
        except FingerprintError as exc:
            raise PeerStoreError(str(exc)) from exc
        return Peer(name.strip(), host.strip(), port, fp)


class PeerStore:
    """Thread-safe JSON-backed list of trusted peers."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._peers: dict[str, Peer] = {}
        self.load_warning: str | None = None
        self._load()

    # ---------------------------------------------------------------- queries

    def peers(self) -> list[Peer]:
        with self._lock:
            return sorted(self._peers.values(), key=lambda p: p.name.lower())

    def get(self, name: str) -> Peer | None:
        with self._lock:
            return self._peers.get(name)

    def find_by_fingerprint(self, fingerprint: str) -> Peer | None:
        try:
            fp = normalize_fingerprint(fingerprint)
        except FingerprintError:
            return None
        with self._lock:
            return next((p for p in self._peers.values() if p.fingerprint == fp), None)

    # ---------------------------------------------------------------- changes

    def add(self, peer: Peer) -> None:
        """Trust a new peer. Fails if the name or fingerprint is already pinned."""
        with self._lock:
            if peer.name in self._peers:
                raise PeerStoreError(f"a peer named '{peer.name}' already exists")
            if any(p.fingerprint == peer.fingerprint for p in self._peers.values()):
                raise PeerStoreError("that fingerprint is already pinned to another peer")
            self._peers[peer.name] = peer
            self._save()

    def update_address(self, name: str, new_name: str, host: str, port: int) -> Peer:
        """Change name/host/port. The pinned fingerprint is deliberately untouched."""
        with self._lock:
            old = self._require(name)
            peer = Peer.create(new_name, host, port, old.fingerprint)
            if peer.name != name and peer.name in self._peers:
                raise PeerStoreError(f"a peer named '{peer.name}' already exists")
            del self._peers[name]
            self._peers[peer.name] = peer
            self._save()
            return peer

    def replace_pin(self, name: str, fingerprint: str, confirmed: bool) -> Peer:
        """Replace a peer's pinned fingerprint. Requires explicit user confirmation."""
        if confirmed is not True:
            raise PeerStoreError("replacing a pinned fingerprint requires explicit confirmation")
        with self._lock:
            old = self._require(name)
            peer = Peer.create(old.name, old.host, old.port, fingerprint)
            if any(p.fingerprint == peer.fingerprint and p.name != name for p in self._peers.values()):
                raise PeerStoreError("that fingerprint is already pinned to another peer")
            self._peers[name] = peer
            self._save()
            log.warning("pinned fingerprint replaced for peer %r", name)
            return peer

    def remove(self, name: str) -> None:
        with self._lock:
            self._require(name)
            del self._peers[name]
            self._save()

    # ---------------------------------------------------------------- persistence

    def _require(self, name: str) -> Peer:
        peer = self._peers.get(name)
        if peer is None:
            raise PeerStoreError(f"no peer named '{name}'")
        return peer

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or not isinstance(data.get("peers"), list):
                raise PeerStoreError("expected an object with a 'peers' list")
            peers: dict[str, Peer] = {}
            for raw in data["peers"]:
                if not isinstance(raw, dict):
                    raise PeerStoreError("peer entry is not an object")
                peer = Peer.create(raw.get("name"), raw.get("host"), raw.get("port"), raw.get("fingerprint"))
                if peer.name in peers or any(p.fingerprint == peer.fingerprint for p in peers.values()):
                    raise PeerStoreError("duplicate peer name or fingerprint")
                peers[peer.name] = peer
        except (OSError, ValueError) as exc:  # JSONDecodeError and PeerStoreError are ValueErrors
            backup = self.path.with_name(f"{self.path.name}.corrupt-{int(time.time())}")
            try:
                os.replace(self.path, backup)
            except OSError:
                backup = self.path
            self.load_warning = (
                f"Trusted-peer file was invalid ({exc}). No peers are trusted; "
                f"the old file was kept as {backup.name}."
            )
            log.error("peer store invalid, starting with no trusted peers: %s", exc)
            return
        self._peers = peers

    def _save(self) -> None:
        payload = json.dumps({"peers": [asdict(p) for p in self._peers.values()]}, indent=2)
        atomic_write_text(self.path, payload)


def atomic_write_text(path: Path, text: str) -> None:
    """Write via a temp file in the same directory, fsync, then ``os.replace``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
