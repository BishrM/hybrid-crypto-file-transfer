# CipherLink viva reference

Short answers to likely questions. The details are in [SECURITY.md](SECURITY.md) and in
the docstring at the top of `network_p2p.py`.

**1. Why use RSA-OAEP to wrap the session key?**
RSA can only encrypt small inputs, and it is slow, so it encrypts a 32-byte AES key rather
than the file itself. OAEP is randomised padding with a security proof. The older PKCS#1
v1.5 encryption padding is vulnerable to padding-oracle attacks (Bleichenbacher), and
"textbook" RSA with no padding is deterministic and malleable. We use SHA-256 with
MGF1-SHA-256, and we set the OAEP *label* to the transfer ID, so a wrapped key can't be
reused for a different transfer (`crypto_engine.wrap_session_key`).

**2. Why use AES-GCM for the file?**
AES is fast, and hardware-accelerated on modern CPUs. GCM mode gives confidentiality and
integrity in one operation, and it can also authenticate unencrypted "associated data".
We use that to bind each chunk to its position and to its transfer.

**3. What does authenticated encryption mean?**
Decryption checks a tag, a keyed checksum, before returning any plaintext. If even one bit
of the ciphertext, the tag or the associated data has changed, decryption fails, so the
receiver never acts on forged or altered data. Our opener raises `RecordError` and the
transfer is aborted before anything is written.

**4. How does fingerprint pinning work?**
Each laptop has a self-signed certificate. Its fingerprint is SHA-256 of the
certificate's exact bytes. Users exchange fingerprints in person. On every connection,
each side hashes the certificate the other side presented and compares it with the stored
pin. A match means "this is the laptop my friend showed me". TLS 1.3 then proves the peer
actually holds the private key behind that certificate.

**5. If we already pin keys and encrypt with AES-GCM, why do we still need TLS?**
TLS gives a well-analysed handshake that proves both sides hold their private keys, and it
provides forward secrecy through ephemeral Diffie-Hellman. It also encrypts *all*
messages, including the offer metadata and the protocol messages. Building our own
handshake would be the most error-prone part of the project. TLS alone, on the other hand,
does not identify a self-signed peer, which is why pinning is added on top. AES-GCM inside
TLS adds a record layer we control and can test: per-record ordering, binding to the
offer, and an end-to-end completion check.

**6. How do you handle replay and reordering?**
Every record carries a 64-bit sequence number. The receiver accepts only the next
expected number, so duplicates, gaps and reordered records are rejected. The sequence
number is also part of the GCM nonce and the associated data, so an attacker can't change
it without breaking the tag. Records from another transfer use a different key and a
different transfer ID in the associated data. A recorded old session can't be replayed,
because TLS sessions have fresh keys.

**7. How is truncation detected?**
The sender finishes with an authenticated FINAL record containing the total size, the
number of records and the SHA-256 of the file. The receiver compares that with what it
actually received and with what was offered. If the stream stops early, or FINAL doesn't
match, the temp file is deleted and the transfer is marked failed.

**8. Why does chunking reduce memory use?**
The sender reads 64 KiB, encrypts it, sends it, and repeats. The receiver decrypts and
writes 64 KiB at a time. Memory stays at roughly a few chunks no matter how big the file
is. A test sends a 48 MiB file and asserts that peak traced memory stays under 8 MiB for
the sender and receiver combined. The original prototype read the whole file with
`f.read()` and buffered the whole ciphertext.

**9. How do threads keep the GUI responsive?**
All networking runs on worker threads: a listener thread, one thread per inbound
connection (capped by a semaphore), and a bounded `ThreadPoolExecutor` for outbound
sends. Workers never touch widgets. They call `Bridge` methods, which emit `pyqtSignal`s.
Because `Bridge` lives in the GUI thread, Qt queues those signals and runs the slots on
the GUI thread. The consent question is the one place a worker waits. It blocks on a
`threading.Event`, and the GUI thread sets it when the user clicks Accept or Decline.

**10. How do simultaneous peer-to-peer transfers work?**
Each laptop is both a server (its listener) and a client (its send pool). Every transfer
is its own TCP+TLS connection, with its own transfer ID, AES key, sequence counter,
cancel flag and progress. Nothing is shared between transfers except the read-only
identity and the thread-safe peer store. A test runs A→B and B→A at the same time and
checks the files byte for byte.

**11. What happens to corrupted or interrupted files?**
Data goes into a private `.part` file. Any authentication failure, sequence error,
disconnect, cancellation, timeout or write error deletes it and records the transfer as
failed or cancelled. Only after FINAL verifies is the file renamed into place, and even
then it never overwrites an existing file.

**12. What has been tested, and what hasn't?**
- *Tested (automated, 191 tests):* the crypto primitives, protocol parsing and state,
  authentication failures, real localhost transfers (empty, small, multi-chunk, 48 MiB
  streaming, duplicates, cancellation, disconnects, tampering, bidirectional, concurrent),
  storage corruption, and the GUI widgets on the offscreen platform.
- *Tested manually:* two separate OS processes on one Mac, transferring in both
  directions at once over loopback and over the Mac's own LAN address, with matching
  SHA-256 hashes.
- *Not yet verified:* two physical laptops, Windows and Linux, the native file dialog and
  real drag-and-drop on a desktop, and behaviour on congested or lossy Wi-Fi. There has
  been no security audit or fuzzing.
