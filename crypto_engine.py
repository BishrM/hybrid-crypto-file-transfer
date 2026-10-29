"""Cryptographic building blocks for CipherLink.

* Identity: a persistent RSA-3072 key and a self-signed X.509 certificate per laptop.
* Fingerprint: SHA-256 over the exact DER certificate bytes, used for manual pinning.
* TLS 1.3 contexts for the pinned, mutually authenticated channel.
* RSA-OAEP (SHA-256, MGF1-SHA-256) wrapping of a fresh AES-256 key per transfer.
* AES-256-GCM transfer records with a counter nonce and authenticated header data.

All primitives come from the ``cryptography`` library and Python's ``ssl`` module.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import os
import secrets
import ssl
import struct
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

from config import PROTOCOL_VERSION

RSA_KEY_BITS = 3072
MIN_PEER_RSA_BITS = 3072
SESSION_KEY_BYTES = 32  # AES-256
NONCE_BYTES = 12  # 96-bit GCM nonce
TAG_BYTES = 16
TRANSFER_ID_BYTES = 16
# Records per key. Nonces are a counter so they never repeat, but we stay well inside
# NIST SP 800-38D's 2^32 invocation guidance; at 64 KiB chunks this is ~256 TiB.
MAX_RECORDS = 2**32 - 1
CERT_VALIDITY_DAYS = 3650
KEY_FILE = "identity_key.pem"
CERT_FILE = "identity_cert.pem"

_RECORD_DATA = 0
_RECORD_FINAL = 1
_AAD_HEADER = struct.Struct(">B16sBQ")  # version, transfer id, record kind, sequence


class CryptoError(Exception):
    """Base class for cryptographic failures. Messages never contain key material."""


class IdentityError(CryptoError):
    """The local identity is missing, inconsistent, expired, or unreadable."""


class FingerprintError(CryptoError):
    """A fingerprint is malformed."""


class RecordError(CryptoError):
    """A transfer record failed authentication or sequencing checks."""


# --------------------------------------------------------------------------- fingerprints


def fingerprint(cert_der: bytes) -> str:
    """SHA-256 of the DER-encoded certificate as 64 upper-case hex characters."""
    return hashlib.sha256(cert_der).hexdigest().upper()


def normalize_fingerprint(text: str) -> str:
    """Accept ``AB:CD..``, ``ab cd ..`` or plain hex; return 64 upper-case hex chars."""
    if not isinstance(text, str):
        raise FingerprintError("fingerprint must be text")
    cleaned = "".join(text.split()).replace(":", "").upper()
    if len(cleaned) != 64 or any(c not in "0123456789ABCDEF" for c in cleaned):
        raise FingerprintError("fingerprint must be 64 hexadecimal characters (SHA-256)")
    return cleaned


def format_fingerprint(fp: str) -> str:
    """Colon-separated pairs for display, e.g. ``AB:CD:...``."""
    fp = normalize_fingerprint(fp)
    return ":".join(fp[i : i + 2] for i in range(0, len(fp), 2))


def fingerprints_match(a: str, b: str) -> bool:
    """Constant-time comparison of two fingerprints; malformed input raises."""
    return hmac.compare_digest(normalize_fingerprint(a), normalize_fingerprint(b))


# --------------------------------------------------------------------------- identity


@dataclass(frozen=True)
class Identity:
    """This laptop's private key and matching self-signed certificate."""

    key: rsa.RSAPrivateKey
    cert: x509.Certificate
    key_path: Path
    cert_path: Path

    @property
    def cert_der(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.DER)

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.cert_der)


def generate_identity(directory: Path, common_name: str = "CipherLink peer") -> Identity:
    """Create a new key + certificate. Refuses to overwrite an existing identity."""
    directory = Path(directory)
    key_path, cert_path = directory / KEY_FILE, directory / CERT_FILE
    if key_path.exists() or cert_path.exists():
        raise IdentityError("an identity already exists; move it away before generating a new one")
    directory.mkdir(parents=True, exist_ok=True)
    _restrict_dir(directory)

    key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_BITS)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=CERT_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    _write_new_file(key_path, key_pem, mode=0o600)
    _write_new_file(cert_path, cert.public_bytes(serialization.Encoding.PEM), mode=0o644)
    return Identity(key, cert, key_path, cert_path)


def load_identity(directory: Path) -> Identity:
    """Load and validate an existing identity (key/cert pair, RSA size, validity window)."""
    directory = Path(directory)
    key_path, cert_path = directory / KEY_FILE, directory / CERT_FILE
    if not key_path.exists() or not cert_path.exists():
        raise IdentityError(
            f"incomplete identity in {directory.name}/: need both {KEY_FILE} and {CERT_FILE}"
        )
    try:
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise IdentityError(f"cannot read identity files: {type(exc).__name__}") from exc
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < RSA_KEY_BITS:
        raise IdentityError(f"identity key must be RSA with at least {RSA_KEY_BITS} bits")
    if cert.public_key().public_numbers() != key.public_key().public_numbers():
        raise IdentityError("certificate does not match the private key")
    now = dt.datetime.now(dt.UTC)
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        raise IdentityError("identity certificate is outside its validity period")
    return Identity(key, cert, key_path, cert_path)


def load_or_create_identity(directory: Path) -> tuple[Identity, bool]:
    """Return ``(identity, created)``. Only generates when *no* identity files exist."""
    directory = Path(directory)
    if not (directory / KEY_FILE).exists() and not (directory / CERT_FILE).exists():
        return generate_identity(directory), True
    return load_identity(directory), False


def _write_new_file(path: Path, data: bytes, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)  # mode ignored on Windows
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _restrict_dir(directory: Path) -> None:
    try:
        os.chmod(directory, 0o700)
    except OSError:  # e.g. filesystems without POSIX permissions
        pass


# --------------------------------------------------------------------------- TLS


def client_tls_context(identity: Identity) -> ssl.SSLContext:
    """TLS 1.3 client context presenting our certificate.

    Chain validation is disabled because peers use self-signed certificates; the caller
    MUST compare the server certificate's fingerprint with the pinned value before
    sending anything. TLS 1.3 CertificateVerify proves the server holds that key.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(identity.cert_path, identity.key_path)
    return ctx


def server_tls_context(identity: Identity, trusted_peer_der: bytes) -> ssl.SSLContext:
    """TLS 1.3 server context that *requires* a client certificate chaining only to
    ``trusted_peer_der`` (the already-pinned peer certificate)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(identity.cert_path, identity.key_path)
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        ctx.load_verify_locations(cadata=trusted_peer_der)
    except ssl.SSLError as exc:
        raise CryptoError("peer certificate is not valid DER") from exc
    return ctx


def public_key_from_cert_der(cert_der: bytes) -> rsa.RSAPublicKey:
    """Extract the RSA public key from a peer certificate, enforcing a minimum size."""
    try:
        key = x509.load_der_x509_certificate(cert_der).public_key()
    except ValueError as exc:
        raise CryptoError("peer certificate is malformed") from exc
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < MIN_PEER_RSA_BITS:
        raise CryptoError(f"peer key must be RSA with at least {MIN_PEER_RSA_BITS} bits")
    return key


# --------------------------------------------------------------------------- session keys


def new_session_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def new_transfer_id() -> bytes:
    return secrets.token_bytes(TRANSFER_ID_BYTES)


def _oaep(transfer_id: bytes) -> padding.OAEP:
    _check_len("transfer id", transfer_id, TRANSFER_ID_BYTES)
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=b"cipherlink-v%d-key:" % PROTOCOL_VERSION + transfer_id,
    )


def wrap_session_key(public_key: rsa.RSAPublicKey, session_key: bytes, transfer_id: bytes) -> bytes:
    """RSA-OAEP encrypt the session key; the transfer id is bound in as the OAEP label."""
    _check_len("session key", session_key, SESSION_KEY_BYTES)
    return public_key.encrypt(session_key, _oaep(transfer_id))


def unwrap_session_key(private_key: rsa.RSAPrivateKey, wrapped: bytes, transfer_id: bytes) -> bytes:
    try:
        key = private_key.decrypt(wrapped, _oaep(transfer_id))
    except ValueError as exc:
        raise CryptoError("session key could not be unwrapped") from exc
    _check_len("session key", key, SESSION_KEY_BYTES)
    return key


# --------------------------------------------------------------------------- records


def _check_len(what: str, value: bytes, expected: int) -> None:
    if not isinstance(value, bytes) or len(value) != expected:
        raise CryptoError(f"{what} must be {expected} bytes")


def record_nonce(seq: int) -> bytes:
    """96-bit nonce: 4 zero bytes + 64-bit big-endian sequence number. Unique per key
    because every transfer has a fresh key and the sequence strictly increases."""
    if not 0 <= seq <= MAX_RECORDS:
        raise RecordError("sequence number out of range")
    return b"\x00\x00\x00\x00" + seq.to_bytes(8, "big")


def _aad(transfer_id: bytes, kind: int, seq: int, context: bytes) -> bytes:
    return _AAD_HEADER.pack(PROTOCOL_VERSION, transfer_id, kind, seq) + context


class _RecordBase:
    def __init__(self, key: bytes, transfer_id: bytes, context: bytes, max_records: int) -> None:
        _check_len("session key", key, SESSION_KEY_BYTES)
        _check_len("transfer id", transfer_id, TRANSFER_ID_BYTES)
        _check_len("context digest", context, 32)
        self._aead = AESGCM(key)
        self._transfer_id = transfer_id
        self._context = context
        self._max_records = min(max_records, MAX_RECORDS)
        self.next_seq = 0
        self.closed = False


class RecordSealer(_RecordBase):
    """Encrypts the sender's records in order. One instance per transfer and key.

    ``context`` is the SHA-256 of the exact offer bytes, so every record is bound to the
    advertised filename and size as well as to the transfer id and its position.
    """

    def __init__(self, key: bytes, transfer_id: bytes, context: bytes, max_records: int = MAX_RECORDS):
        super().__init__(key, transfer_id, context, max_records)

    def seal(self, plaintext: bytes, final: bool = False) -> tuple[int, bytes]:
        if self.closed:
            raise RecordError("transfer already finalised")
        seq = self.next_seq
        if seq >= self._max_records:
            raise RecordError("record counter exhausted for this session key")
        kind = _RECORD_FINAL if final else _RECORD_DATA
        ct = self._aead.encrypt(record_nonce(seq), plaintext, _aad(self._transfer_id, kind, seq, self._context))
        self.next_seq = seq + 1
        self.closed = final
        return seq, ct


class RecordOpener(_RecordBase):
    """Decrypts records, accepting only the next expected sequence number.

    Duplicates, gaps, reordering, records from another transfer (different key, id or
    offer), and data records relabelled as final all fail here before any plaintext is
    returned.
    """

    def __init__(self, key: bytes, transfer_id: bytes, context: bytes, max_records: int = MAX_RECORDS):
        super().__init__(key, transfer_id, context, max_records)

    def open(self, seq: int, ciphertext: bytes, final: bool = False) -> bytes:
        if self.closed:
            raise RecordError("record received after the final record")
        if seq != self.next_seq:
            raise RecordError(f"unexpected sequence number {seq} (expected {self.next_seq})")
        if seq >= self._max_records:
            raise RecordError("record counter exhausted for this session key")
        if len(ciphertext) < TAG_BYTES:
            raise RecordError("record too short")
        kind = _RECORD_FINAL if final else _RECORD_DATA
        try:
            plaintext = self._aead.decrypt(
                record_nonce(seq), ciphertext, _aad(self._transfer_id, kind, seq, self._context)
            )
        except InvalidTag as exc:
            raise RecordError("record failed authentication (tampered or wrong key)") from exc
        self.next_seq = seq + 1
        self.closed = final
        return plaintext
