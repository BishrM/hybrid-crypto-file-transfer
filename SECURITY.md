# CipherLink security design

This document describes what CipherLink protects against, how, and where the protection
stops. It is an academic project. No independent audit or penetration test has been done.
The automated tests listed at the end check specific properties. They do not prove the
system secure.

## 1. Assets and assumptions

- **Assets:** file contents and metadata in transit, the integrity of received files, each
  laptop's private identity key, and the receiving laptop's file system.
- **Deployment:** two laptops on the same LAN, each run by a user who controls it. The
  app is not meant to be reachable from the internet.
- **Trust root:** the users compare SHA-256 certificate fingerprints over a channel they
  trust (in person, or by voice). **Everything below depends on this step.**
- **Out of scope:** malware or another administrator on either laptop, physical theft of
  an unlocked laptop, side channels, and denial of service by someone with a network
  position.

## 2. Primitives (all from `cryptography` 50.0.2 or OpenSSL via Python's `ssl`)

| Purpose | Primitive |
|---|---|
| Identity | RSA-3072 key, self-signed X.509 v3 certificate signed with SHA-256, valid 10 years |
| Fingerprint | SHA-256 over the exact DER certificate bytes (64 hex digits), compared in constant time |
| Channel | TLS 1.3 only (`minimum_version = TLSv1_3`), ECDHE key exchange (forward secrecy) |
| Session-key wrapping | RSA-OAEP, SHA-256, MGF1-SHA-256, label `cipherlink-v1-key:` + transfer ID |
| File records | AES-256-GCM, 96-bit nonce, 128-bit tag |
| File digest | SHA-256 over the plaintext, carried in the authenticated completion record |
| Randomness | `os.urandom` through `AESGCM.generate_key` and `secrets.token_bytes` |

No cryptographic algorithm is implemented by hand.

## 3. Authentication: pinning on both sides

Python's `ssl` module can't verify a client certificate that isn't already in its trust
store. So CipherLink authenticates the client like this:

1. The client (sender) sends a short cleartext **preface**: magic, version, and its
   certificate in DER. A certificate is public, so this reveals no secret.
2. The server (receiver) computes the certificate's fingerprint and looks it up in its
   pinned peers. **If it is unknown, the connection is closed** and the user is notified.
   Nothing else is read.
3. The server builds a TLS context that **requires** a client certificate and trusts only
   that pinned certificate. During TLS 1.3 the client must sign the handshake transcript
   (CertificateVerify) with the matching private key. Someone who replays the public
   certificate without the key fails here. After the handshake the server checks again
   that the certificate presented in TLS is the one from the preface.
4. The client turns off chain validation (self-signed certificates have no CA). Instead,
   it **compares the server certificate's fingerprint with its pin** and closes the
   connection before sending the offer if they differ. The TLS 1.3 CertificateVerify
   proves the server holds that certificate's key.

Unknown, malformed, missing or changed certificates fail closed. A new fingerprint is
**never** trusted automatically. Changing a pin requires
`PeerStore.replace_pin(..., confirmed=True)`, which the GUI calls only after a
confirmation dialog showing the old and new fingerprints.

## 4. Confidentiality and integrity: three layers

| Layer | What it gives you |
|---|---|
| TLS 1.3 | Encryption and integrity for everything after the preface, forward secrecy through ECDHE, and proof of key possession. On its own it does **not** say who the peer is, because the certificates are self-signed. |
| Fingerprint pinning | Decides *which* certificate is acceptable. This is what makes TLS authenticate a specific person's laptop. |
| RSA-OAEP key wrapping | A fresh AES-256 key per transfer, encrypted to the pinned receiver's public key, so only that private key can unwrap it. The OAEP label binds it to the transfer ID. |
| AES-256-GCM records | Each 64 KiB chunk is encrypted and authenticated with the per-transfer key. This is defence in depth inside TLS, and it gives end-to-end record-level integrity and ordering checks independent of TLS. |

The RSA wrapping is **not** a replacement for TLS. The connection is still authenticated
by TLS plus pinning, and the wrapped key is sent only after the server's fingerprint has
been checked.

## 5. Key and nonce lifecycle

- **Identity key:** generated once, stored as unencrypted PKCS#8 PEM with mode 0600 (the
  `identities/` directory is 0700). It is never transmitted, logged or shown. On Windows
  the POSIX modes don't apply (see README).
- **Session key:** 32 random bytes for each transfer. The sender drops its reference right
  after creating the record sealer, and the receiver right after unwrapping. Session keys
  are never logged or persisted. (Python can't guarantee the memory is wiped.)
- **Nonce:** `0x00000000 || seq` (64-bit big-endian). The key is unique to each transfer
  and the sequence number strictly increases within it, so a key/nonce pair is never
  reused. Each key is limited to 2^32 − 1 records, about 256 TiB at 64 KiB. The sealer and
  opener refuse to go past that, and offers that would need more records are rejected.
- **AAD** for every record: `version || transfer_id || kind(data/final) || seq ||
  SHA-256(exact offer bytes)`.

## 6. Protocol protections

| Attack | How it is handled |
|---|---|
| Tampering | A GCM tag failure aborts the transfer before the record's plaintext is used. |
| Replay or duplicate record | The opener accepts only `seq == expected` (the next number). Anything else aborts. |
| Reordering or missing record | Same rule, plus the sequence number is in the nonce and AAD, so relabelling fails authentication. |
| Record from another transfer | Different key, and a different transfer ID and offer hash in the AAD: authentication fails. |
| Changed filename or size | The offer hash is in every record's AAD and the completion record must match the offer. |
| Truncation | Data must end with an authenticated FINAL record whose `{size, records, sha256}` exactly match what was received and offered. Without it, the file is not published. |
| Extra data | More bytes than offered, records larger than the negotiated chunk size, or anything after FINAL all abort. |
| A data record passed off as FINAL | The record kind is in the AAD. |
| Replaying a whole earlier session | Recorded bytes can't be injected into a new TLS session, and every transfer needs the user's consent. |
| Unexpected or malformed messages | Explicit state checks (`expect`), version checks, strict JSON field validation, and size limits per message type (4 KiB for control messages, chunk + 24 bytes for records, 8 KiB for the preface certificate). |

## 7. File-system protections

- The offered filename must be a single safe path component. Separators of every
  platform, `..`, leading dots, control and reserved characters, Windows device names and
  names over 255 bytes are **rejected**, not sanitised.
- Plaintext goes to `received_files/.cipherlink-<transfer id>.part`, created with
  `O_EXCL` and mode 0600. It is fsynced and published only after the completion check
  passes. On any error, cancel or disconnect it is deleted.
- Publishing creates the final name with `O_EXCL` (fails on existing files, including
  symlinks) and then `os.replace`s the temp file onto it. Existing files are never
  overwritten. Clashes become `name (n).ext`.
- The receiver checks free disk space before accepting, rejects offers over
  `max_file_size`, and turns write errors into a failed transfer plus cleanup.

## 8. Threat model summary

| Threat | Status |
|---|---|
| Passive eavesdropper on the LAN | **Mitigated:** TLS 1.3 plus GCM. They do learn that a connection happened, the **client certificate** (it is in the cleartext preface, which links connections to the same sender laptop), and the approximate file size. |
| Active man-in-the-middle | **Mitigated if** fingerprints were verified out of band. The certificate check on either side fails otherwise. |
| Spoofed or untrusted peer | **Mitigated:** dropped before TLS. The user is told, and nothing is trusted automatically. |
| Peer whose identity changed (reinstall, or compromise) | **Rejected** until the user knowingly replaces the pin. Users must verify the new fingerprint, because the app can't tell a legitimate reinstall from an attacker. |
| Malicious but trusted peer | Partly. It cannot write outside the receive folder, overwrite files, or send without consent. It **can** send unwanted content to a user who accepts, and can tie up receiver slots. |
| Malformed frames or fuzzing | Validated and bounded. Covered by the protocol tests, but no fuzzing campaign has been run. |
| Interrupted or truncated transfer | Detected. Never marked successful, and the temp file is removed. |
| Connection exhaustion | **Partly mitigated:** a bounded number of inbound slots and a 10 s handshake timeout. A LAN attacker can still keep the slots busy by reconnecting repeatedly. There is no per-IP rate limiting. |
| Stolen private key | **Not mitigated:** the attacker can impersonate that laptop until peers remove or replace the pin. The key is not passphrase-protected. Past TLS sessions stay protected by ECDHE forward secrecy, but the inner RSA-wrapped session keys have no forward secrecy of their own. |
| Unauthorized local access to received files or history | Relies on OS account security. Temp files and published received files are 0600 (owner-only), and history stores filenames. |

## 9. Logging

The log (`cipherlink.log`) records connection events, state changes, errors, peer
names, filenames and short prefixes of transfer IDs or fingerprints. It **never** records
private keys, session keys, wrapped keys, plaintext, ciphertext or full local paths of
sent files.

## 10. Known risks and non-goals

- One RSA key serves both TLS signatures and OAEP decryption. This is acceptable for the
  project, but separate keys would be better practice.
- The cleartext preface reveals the sender's certificate to passive observers (a privacy
  leak, not a confidentiality one).
- No passphrase on the identity key, no hardware-backed key storage, no revocation lists.
- No protection against a compromised endpoint.
- Not tested against an active attacker on a real network. Testing has been on one
  machine.
- Internet exposure, NAT traversal and peer discovery are deliberately out of scope.

## 11. What the tests check

These are the security properties exercised by `pytest`, against real sockets and real
TLS:

- GCM round-trips. Tampered ciphertext or tag, wrong transfer ID, wrong offer hash,
  duplicate, reordered or relabelled records, a data record presented as final, counter
  exhaustion, and nonce or key length checks.
- RSA-OAEP wrapping is bound to the transfer ID. Weak (RSA-2048) peer keys are rejected.
  The sender wraps to the authenticated receiver's key.
- A wrong server pin aborts before an offer is sent. An unknown client is dropped and not
  trusted. A client replaying someone else's certificate without the key fails TLS. A
  changed identity is rejected until the pin is replaced.
- Truncation, wrong completion data, extra data, oversized frames, malformed JSON or
  offers, unsafe filenames, and symlinks at the destination.
- Disconnects, cancellations and write failures leave no partial file.

See README "Running the tests" for the commands.
