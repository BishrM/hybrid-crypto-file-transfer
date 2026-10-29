"""Persistent, local transfer history.

Only metadata is stored (name, peer, size, timing, status) - never keys, file contents,
or full local paths. The file is treated as untrusted input: malformed entries are
dropped, and an unreadable file is moved aside so the application still starts.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from network_p2p import TransferInfo
from peer_store import atomic_write_text

log = logging.getLogger(__name__)

MAX_ENTRIES = 1000
_STATUSES = {"completed", "failed", "rejected", "cancelled"}


@dataclass(frozen=True)
class HistoryEntry:
    transfer_id: str
    filename: str
    direction: str
    peer: str
    size: int
    bytes_transferred: int
    started_at: float
    finished_at: float
    status: str
    error: str = ""
    saved_as: str = ""

    @property
    def duration(self) -> float:
        return max(0.0, self.finished_at - self.started_at)

    @property
    def average_speed(self) -> float:
        """Bytes per second over the whole transfer (0 if instantaneous)."""
        return self.bytes_transferred / self.duration if self.duration > 0 else 0.0

    @staticmethod
    def from_info(info: TransferInfo) -> HistoryEntry:
        return HistoryEntry(
            transfer_id=info.transfer_id,
            filename=info.filename,
            direction=info.direction,
            peer=info.peer,
            size=info.size,
            bytes_transferred=info.bytes_done,
            started_at=info.started_at,
            finished_at=info.finished_at or time.time(),
            status=info.status,
            error=info.error or "",
            saved_as=info.saved_as or "",
        )

    @staticmethod
    def from_dict(raw: object) -> HistoryEntry:
        """Validate one stored entry; raises ValueError if anything is off."""
        if not isinstance(raw, dict):
            raise ValueError("entry is not an object")
        entry = HistoryEntry(**raw)  # TypeError on missing/unknown keys
        text = ("transfer_id", "filename", "peer", "error", "saved_as")
        if any(not isinstance(getattr(entry, k), str) for k in text):
            raise ValueError("text field has wrong type")
        for k in ("size", "bytes_transferred"):
            v = getattr(entry, k)
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                raise ValueError(f"{k} must be a non-negative integer")
        for k in ("started_at", "finished_at"):
            v = getattr(entry, k)
            if isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0:
                raise ValueError(f"{k} must be a timestamp")
        if entry.direction not in ("send", "receive") or entry.status not in _STATUSES:
            raise ValueError("unknown direction or status")
        return entry


class TransferHistory:
    """Thread-safe history list persisted as JSON with atomic replacement."""

    def __init__(self, path: Path, max_entries: int = MAX_ENTRIES) -> None:
        self.path = Path(path)
        self.max_entries = max_entries
        self._lock = threading.Lock()
        self._entries: list[HistoryEntry] = []
        self.load_warning: str | None = None
        self._load()

    def entries(self) -> list[HistoryEntry]:
        """Newest first."""
        with self._lock:
            return list(reversed(self._entries))

    def record(self, info: TransferInfo) -> HistoryEntry:
        entry = HistoryEntry.from_info(info)
        with self._lock:
            self._entries.append(entry)
            del self._entries[: -self.max_entries]
            try:
                self._save()
            except OSError as exc:  # history is best-effort; never break a transfer
                log.error("could not save transfer history: %s", exc)
        return entry

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._save()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                raise ValueError("history must be a JSON list")
        except (OSError, ValueError) as exc:
            backup = self.path.with_name(f"{self.path.name}.corrupt-{int(time.time())}")
            try:
                os.replace(self.path, backup)
            except OSError:
                backup = self.path
            self.load_warning = f"Transfer history was unreadable and has been reset (old file: {backup.name})."
            log.error("history unreadable, starting empty: %s", exc)
            return
        dropped = 0
        for raw in data:
            try:
                self._entries.append(HistoryEntry.from_dict(raw))
            except (TypeError, ValueError):
                dropped += 1
        if dropped:
            self.load_warning = f"Ignored {dropped} malformed history entr{'y' if dropped == 1 else 'ies'}."
            log.warning("dropped %d malformed history entries", dropped)
        del self._entries[: -self.max_entries]

    def _save(self) -> None:
        atomic_write_text(self.path, json.dumps([asdict(e) for e in self._entries], indent=1))
