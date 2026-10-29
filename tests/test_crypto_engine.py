"""Unit tests for crypto_engine: identities, fingerprints, key wrapping, GCM records."""
from __future__ import annotations

import hashlib
import os
import stat
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import crypto_engine as ce

TID = bytes(range(16))
CTX = hashlib.sha256(b"offer").digest()


# ------------------------------------------------------------------ identity


def test_generated_identity_is_rsa3072_self_signed_sha256(identity_a: ce.Identity) -> None:
    cert = identity_a.cert
    assert identity_a.key.key_size == 3072
    assert cert.subject == cert.issuer
    assert cert.signature_hash_algorithm.name == "sha256"
    # signature verifies with its own public key (self-signed)
    cert.verify_directly_issued_by(cert)


def test_identity_persists_and_reloads(identity_a: ce.Identity) -> None:
    loaded = ce.load_identity(identity_a.key_path.parent)
    assert loaded.fingerprint == identity_a.fingerprint
    assert loaded.cert_der == identity_a.cert_der


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_private_key_file_is_owner_only(identity_a: ce.Identity) -> None:
    assert stat.S_IMODE(os.stat(identity_a.key_path).st_mode) == 0o600


def test_generate_refuses_to_overwrite(identity_a: ce.Identity) -> None:
    with pytest.raises(ce.IdentityError):
        ce.generate_identity(identity_a.key_path.parent)


def test_load_or_create_creates_once(tmp_path) -> None:
    first, created = ce.load_or_create_identity(tmp_path / "ids")
    second, created_again = ce.load_or_create_identity(tmp_path / "ids")
    assert created and not created_again
    assert first.fingerprint == second.fingerprint


def test_mismatched_key_and_cert_rejected(tmp_path, identity_a, identity_b) -> None:
    d = tmp_path / "mixed"
    d.mkdir()
    (d / ce.KEY_FILE).write_bytes(identity_a.key_path.read_bytes())
    (d / ce.CERT_FILE).write_bytes(identity_b.cert_path.read_bytes())
    with pytest.raises(ce.IdentityError, match="does not match"):
        ce.load_identity(d)


def test_partial_identity_is_not_silently_regenerated(tmp_path, identity_a) -> None:
    d = tmp_path / "partial"
    d.mkdir()
    (d / ce.KEY_FILE).write_bytes(identity_a.key_path.read_bytes())
    with pytest.raises(ce.IdentityError, match="incomplete"):
        ce.load_or_create_identity(d)
    assert not (d / ce.CERT_FILE).exists()


def test_corrupt_identity_rejected(tmp_path, identity_a) -> None:
    d = tmp_path / "corrupt"
    d.mkdir()
    (d / ce.KEY_FILE).write_bytes(b"not a key")
    (d / ce.CERT_FILE).write_bytes(identity_a.cert_path.read_bytes())
    with pytest.raises(ce.IdentityError):
        ce.load_identity(d)


# ------------------------------------------------------------------ fingerprints


def test_fingerprint_is_sha256_of_der(identity_a: ce.Identity) -> None:
    der = identity_a.cert.public_bytes(serialization.Encoding.DER)
    assert identity_a.fingerprint == hashlib.sha256(der).hexdigest().upper()
    assert len(identity_a.fingerprint) == 64


def test_fingerprint_normalization() -> None:
    fp = "ab" * 32
    assert ce.normalize_fingerprint(fp) == "AB" * 32
    assert ce.normalize_fingerprint(ce.format_fingerprint(fp)) == "AB" * 32
    assert ce.normalize_fingerprint(" ab:AB\nab " + "ab" * 29) == "AB" * 32


@pytest.mark.parametrize("bad", ["", "AB" * 31, "AB" * 33, "ZZ" * 32, "AB" * 31 + "A-", None, 123])
def test_malformed_fingerprints_rejected(bad) -> None:
    with pytest.raises(ce.FingerprintError):
        ce.normalize_fingerprint(bad)


def test_fingerprint_comparison(identity_a, identity_b) -> None:
    assert ce.fingerprints_match(identity_a.fingerprint, ce.format_fingerprint(identity_a.fingerprint).lower())
    assert not ce.fingerprints_match(identity_a.fingerprint, identity_b.fingerprint)
    with pytest.raises(ce.FingerprintError):
        ce.fingerprints_match(identity_a.fingerprint, "nope")


# ------------------------------------------------------------------ RSA-OAEP


def test_wrap_unwrap_roundtrip(identity_b: ce.Identity) -> None:
    key = ce.new_session_key()
    pub = ce.public_key_from_cert_der(identity_b.cert_der)
    wrapped = ce.wrap_session_key(pub, key, TID)
    assert len(wrapped) == 384 and key not in wrapped
    assert ce.unwrap_session_key(identity_b.key, wrapped, TID) == key


def test_unwrap_with_wrong_key_or_transfer_id_fails(identity_a, identity_b) -> None:
    key = ce.new_session_key()
    wrapped = ce.wrap_session_key(identity_b.key.public_key(), key, TID)
    with pytest.raises(ce.CryptoError):
        ce.unwrap_session_key(identity_a.key, wrapped, TID)
    with pytest.raises(ce.CryptoError):  # OAEP label binds the transfer id
        ce.unwrap_session_key(identity_b.key, wrapped, bytes(16))


def test_wrap_validates_key_length(identity_b) -> None:
    with pytest.raises(ce.CryptoError):
        ce.wrap_session_key(identity_b.key.public_key(), b"short", TID)


def test_small_peer_rsa_key_rejected() -> None:
    import datetime as dt

    from cryptography import x509 as _x
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = _x.Name([_x.NameAttribute(NameOID.COMMON_NAME, "weak")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        _x.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key())
        .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
        .sign(k, hashes.SHA256())
    )
    with pytest.raises(ce.CryptoError, match="3072"):
        ce.public_key_from_cert_der(cert.public_bytes(serialization.Encoding.DER))


def test_session_keys_and_transfer_ids_are_unique() -> None:
    keys = {ce.new_session_key() for _ in range(1000)}
    ids = {ce.new_transfer_id() for _ in range(1000)}
    assert len(keys) == 1000 and len(ids) == 1000
    assert all(len(k) == 32 for k in keys)


# ------------------------------------------------------------------ AES-GCM records


def _pair(**kw):
    key = ce.new_session_key()
    return ce.RecordSealer(key, TID, CTX, **kw), ce.RecordOpener(key, TID, CTX, **kw), key


@pytest.mark.parametrize("size", [0, 1, 65535, 65536])
def test_record_roundtrip_sizes(size: int) -> None:
    sealer, opener, _ = _pair()
    data = os.urandom(size)
    seq, ct = sealer.seal(data)
    assert seq == 0 and len(ct) == size + ce.TAG_BYTES
    assert opener.open(seq, ct) == data


def test_record_matches_independent_aesgcm_with_documented_nonce_and_aad() -> None:
    """Known-answer style check: decrypt with a separately-built AESGCM using the
    documented nonce (4 zero bytes + seq) and AAD layout."""
    sealer, _, key = _pair()
    sealer.seal(b"first")
    seq, ct = sealer.seal(b"second")
    nonce = b"\x00" * 4 + (1).to_bytes(8, "big")
    aad = bytes([1]) + TID + bytes([0]) + (1).to_bytes(8, "big") + CTX
    assert AESGCM(key).decrypt(nonce, ct, aad) == b"second"


def test_tampered_ciphertext_and_tag_rejected() -> None:
    sealer, opener, key = _pair()
    _, ct = sealer.seal(b"hello world")
    for i in (0, len(ct) - 1):  # flip a ciphertext byte, then a tag byte
        bad = bytearray(ct)
        bad[i] ^= 1
        with pytest.raises(ce.RecordError, match="authentication"):
            opener.open(0, bytes(bad))
    assert opener.next_seq == 0  # failed records do not advance the counter
    with pytest.raises(ce.RecordError):
        opener.open(0, b"x" * 5)  # shorter than a tag
    assert opener.open(0, ct) == b"hello world"


def test_wrong_transfer_id_or_context_rejected() -> None:
    key = ce.new_session_key()
    _, ct = ce.RecordSealer(key, TID, CTX).seal(b"data")
    with pytest.raises(ce.RecordError):
        ce.RecordOpener(key, bytes(16), CTX).open(0, ct)
    with pytest.raises(ce.RecordError):
        ce.RecordOpener(key, TID, hashlib.sha256(b"other offer").digest()).open(0, ct)


def test_duplicate_reordered_and_missing_sequence_rejected() -> None:
    sealer, opener, _ = _pair()
    records = [sealer.seal(bytes([i])) for i in range(3)]
    assert opener.open(*records[0]) == b"\x00"
    with pytest.raises(ce.RecordError, match="unexpected sequence"):
        opener.open(*records[0])  # duplicate / replay
    with pytest.raises(ce.RecordError, match="unexpected sequence"):
        opener.open(*records[2])  # gap / reorder
    # relabelling ciphertext with a different sequence number fails authentication
    with pytest.raises(ce.RecordError, match="authentication"):
        opener.open(1, records[2][1])
    assert opener.open(*records[1]) == b"\x01"


def test_data_record_cannot_be_passed_off_as_final() -> None:
    sealer, opener, _ = _pair()
    seq, ct = sealer.seal(b"data")
    with pytest.raises(ce.RecordError, match="authentication"):
        opener.open(seq, ct, final=True)


def test_nothing_accepted_after_final() -> None:
    sealer, opener, _ = _pair()
    seq, ct = sealer.seal(b"{}", final=True)
    opener.open(seq, ct, final=True)
    with pytest.raises(ce.RecordError):
        sealer.seal(b"more")
    with pytest.raises(ce.RecordError):
        opener.open(1, ct)


def test_sequence_counter_exhaustion() -> None:
    sealer, opener, _ = _pair(max_records=2)
    r = [sealer.seal(b"a"), sealer.seal(b"b")]
    with pytest.raises(ce.RecordError, match="exhausted"):
        sealer.seal(b"c")
    opener.open(*r[0])
    opener.open(*r[1])
    with pytest.raises(ce.RecordError, match="exhausted"):
        opener.open(2, r[1][1])


def test_nonce_layout_and_range() -> None:
    assert ce.record_nonce(0) == bytes(12)
    assert len(ce.record_nonce(ce.MAX_RECORDS)) == ce.NONCE_BYTES
    with pytest.raises(ce.RecordError):
        ce.record_nonce(-1)
    with pytest.raises(ce.RecordError):
        ce.record_nonce(ce.MAX_RECORDS + 1)


@pytest.mark.parametrize(
    "key,tid,ctx",
    [(b"k" * 16, TID, CTX), (b"k" * 32, b"t" * 8, CTX), (b"k" * 32, TID, b"c" * 10)],
)
def test_record_input_lengths_validated(key, tid, ctx) -> None:
    with pytest.raises(ce.CryptoError):
        ce.RecordSealer(key, tid, ctx)


def test_certificate_der_parses(identity_a) -> None:
    assert x509.load_der_x509_certificate(identity_a.cert_der).serial_number == identity_a.cert.serial_number
