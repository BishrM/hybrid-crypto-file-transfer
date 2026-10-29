"""Validated application configuration for CipherLink.

All local state lives under one data directory (``CIPHERLINK_HOME`` or the project
directory by default). An optional ``config.json`` in that directory overrides the
defaults; unknown keys and out-of-range values are rejected at startup.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, fields
from pathlib import Path

APP_NAME = "CipherLink"
APP_VERSION = "1.0.0"
PROTOCOL_VERSION = 1

KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB

DEFAULT_PORT = 52520
MAX_CHUNK_SIZE = 1 * MIB


class ConfigError(ValueError):
    """Raised when configuration is missing, malformed, or out of range."""


@dataclass(frozen=True)
class Config:
    """Runtime settings. Paths are derived from ``data_dir`` unless overridden."""

    data_dir: Path
    listen_host: str = "0.0.0.0"
    listen_port: int = DEFAULT_PORT
    receive_dir: Path | None = None
    max_concurrent_transfers: int = 4
    max_file_size: int = 10 * GIB
    connect_timeout: float = 10.0
    handshake_timeout: float = 10.0
    io_timeout: float = 30.0
    consent_timeout: float = 120.0
    chunk_size: int = 64 * KIB
    protocol_version: int = field(default=PROTOCOL_VERSION, init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "data_dir", Path(self.data_dir))
        if self.receive_dir is None:
            object.__setattr__(self, "receive_dir", self.data_dir / "received_files")
        else:
            object.__setattr__(self, "receive_dir", Path(self.receive_dir))

        if not isinstance(self.listen_host, str) or not self.listen_host.strip():
            raise ConfigError("listen_host must be a non-empty string")
        _check_int("listen_port", self.listen_port, 0, 65535)  # 0 = OS-assigned (tests)
        _check_int("max_concurrent_transfers", self.max_concurrent_transfers, 1, 64)
        _check_int("max_file_size", self.max_file_size, 0, 1024 * GIB)
        _check_int("chunk_size", self.chunk_size, KIB, MAX_CHUNK_SIZE)
        for name in ("connect_timeout", "handshake_timeout", "io_timeout", "consent_timeout"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0.1 <= value <= 3600:
                raise ConfigError(f"{name} must be a number between 0.1 and 3600 seconds")

    @property
    def identity_dir(self) -> Path:
        return self.data_dir / "identities"

    @property
    def peers_file(self) -> Path:
        return self.data_dir / "peers.json"

    @property
    def history_file(self) -> Path:
        return self.data_dir / "transfer_history.json"

    @property
    def log_file(self) -> Path:
        return self.data_dir / "cipherlink.log"


def _check_int(name: str, value: object, low: int, high: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ConfigError(f"{name} must be an integer between {low} and {high}")


def default_data_dir() -> Path:
    """``CIPHERLINK_HOME`` if set, otherwise the directory containing this file."""
    env = os.environ.get("CIPHERLINK_HOME")
    return Path(env).expanduser() if env else Path(__file__).resolve().parent


def load_config(data_dir: Path | None = None) -> Config:
    """Build a Config from defaults plus ``<data_dir>/config.json`` if present."""
    data_dir = Path(data_dir) if data_dir else default_data_dir()
    overrides: dict[str, object] = {}
    path = data_dir / "config.json"
    if path.exists():
        try:
            overrides = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"cannot read {path.name}: {exc}") from exc
        if not isinstance(overrides, dict):
            raise ConfigError(f"{path.name} must contain a JSON object")
        allowed = {f.name for f in fields(Config) if f.init} - {"data_dir"}
        unknown = set(overrides) - allowed
        if unknown:
            raise ConfigError(f"unknown settings in {path.name}: {', '.join(sorted(unknown))}")
    return Config(data_dir=data_dir, **overrides)  # type: ignore[arg-type]
