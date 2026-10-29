# CipherLink: secure peer-to-peer file transfer on a LAN

CipherLink is a desktop app for sending files directly between two laptops on the same
local network. Each laptop has its own cryptographic identity. Peers trust each other only
after their users have compared certificate fingerprints by hand. Each file is encrypted
with a fresh AES-256-GCM key, that key is wrapped with the receiver's RSA key (RSA-OAEP),
and everything travels inside a TLS 1.3 connection.

It is a college project. It grew out of a command-line RSA/AES file-transfer prototype,
which is kept in this repository (see [Legacy prototype](#legacy-prototype)).

> **Status:** an academic project, not a security product. It has not been independently
> audited or penetration-tested. See [SECURITY.md](SECURITY.md) for the threat model and
> its limits.

## Features

- Persistent RSA-3072 identity per laptop, with a self-signed X.509 certificate (SHA-256).
- Manual **certificate fingerprint pinning** in both directions. Unknown or changed
  identities are rejected, never trusted automatically.
- **Mutually authenticated TLS 1.3** channel.
- A fresh **AES-256 key for every transfer**, wrapped with **RSA-OAEP (SHA-256)** for the
  authenticated receiver.
- **AES-256-GCM** records. Every record is bound to its sequence number, the transfer ID
  and the exact offered filename and size, so replay, reordering, truncation and records
  from another transfer are all detected.
- An authenticated **completion record** (size, record count, SHA-256). The file is
  published only after it verifies.
- **Receiver consent** dialog before any file content is accepted.
- Streaming in 64 KiB chunks, so large files never sit in memory in full.
- **Bidirectional and concurrent:** both laptops listen and send at the same time, with a
  configurable limit on concurrent transfers.
- Live progress, speed, elapsed time and ETA, plus cancellation and a persistent history.
- Safe file handling: a private temp file, publication without ever overwriting
  (`name (1).ext`), and strict filename validation.

## Architecture

```text
 ┌────────────────────────── one laptop ──────────────────────────┐
 │  main.py ── loads ──> config.py   crypto_engine.Identity        │
 │     │                 peer_store.PeerStore  transfer_history     │
 │     ▼                                                            │
 │  gui_app.MainWindow  <── Qt signals (queued) ──  gui_app.Bridge  │
 │     │ send_file / cancel                         ▲ callbacks     │
 │     ▼                                            │ (worker thr.) │
 │  network_p2p.PeerNode ── listener thread + bounded worker pools  │
 │     │  uses crypto_engine: TLS contexts, RSA-OAEP, AES-GCM       │
 └─────┼────────────────────────────────────────────────────────────┘
       │ TCP 52520 · preface(cert) · TLS 1.3 (pinned both ways)
       ▼
   other laptop's PeerNode ── OFFER → ACCEPT → KEY → RECORD… → FINAL → RESULT
```

| Module | Responsibility |
|---|---|
| `main.py` | Startup: config, logging, identity, stores, listener, window, shutdown. |
| `config.py` | Validated settings and defaults, plus an optional `config.json` override. |
| `crypto_engine.py` | Identity generation and loading, fingerprints, TLS contexts, RSA-OAEP wrapping, AES-GCM record sealer and opener. |
| `network_p2p.py` | Wire protocol, listener, outbound transfers, pinning checks, streaming, temp-file publishing, cancellation. No Qt code. |
| `peer_store.py` | Trusted peers (name, address, pinned fingerprint), stored as validated JSON written atomically. |
| `transfer_history.py` | Transfer metadata history, bounded to 1000 entries, safe against corrupt input. |
| `gui_app.py` | PyQt6 interface and the thread-safe `Bridge` from network callbacks to Qt signals. |
| `tests/` | 191 automated tests: crypto, protocol, authentication, transfers, validation and GUI. |

The protocol is specified in the docstring at the top of `network_p2p.py`. The security
reasoning is in [SECURITY.md](SECURITY.md), and a viva Q&A is in [VIVA.md](VIVA.md).

## Requirements

- **Python 3.12 or newer.** Developed and tested with Python 3.12.0.
- **Operating systems:** macOS (tested on macOS 26, Apple Silicon). Windows and Linux
  should work, since the code includes platform guards, but are **not yet tested**.
- Both laptops on the same LAN, with TCP port **52520** reachable (see
  [Firewall](#firewall-and-ports)).

## Installation

Do this on each laptop:

```bash
git clone https://github.com/soundaryakl/hybrid-crypto-file-transfer.git
cd hybrid-crypto-file-transfer
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt      # or requirements-dev.txt to run the tests
python main.py
```

### Quick start (macOS / Linux)

```bash
./run.sh                 # or: ./run.sh --home ~/cipherlink-b
```

`run.sh` works from any directory. It finds Python 3.12+ (or uses `PYTHON=/path/to/python`),
creates `.venv` if it is missing, installs `requirements.txt` only when that file has changed,
and starts `main.py` with any arguments you pass. It respects `CIPHERLINK_HOME` and never
touches your identity, peers, history or received files. On Windows use the manual steps above.

**Two instances on one computer** (for example, to test locally) need separate data
directories *and* different ports, or the second one shows "Not listening". Give each data
directory its own `config.json` with its own `listen_port`:

```bash
mkdir -p ~/cl-a ~/cl-b
echo '{"listen_port": 52520}' > ~/cl-a/config.json
echo '{"listen_port": 52521}' > ~/cl-b/config.json
./run.sh --home ~/cl-a &      # first instance
./run.sh --home ~/cl-b        # second instance
```

When adding each as a trusted peer of the other, use `127.0.0.1` and the other's port.

Run from source as shown. `pip install .` also works, but it installs generic top-level
module names (`config`, `main`) into the environment, so only use it inside a dedicated
virtualenv.

## First run: your identity

On first launch CipherLink creates `identities/identity_key.pem` (private key, mode 0600)
and `identities/identity_cert.pem` (certificate), then shows your **fingerprint** in the
"Your identity" card.

- **Never copy the identity folder to the other laptop.** Each laptop needs its own.
- **Backup:** copy the `identities/` folder somewhere private. Restoring it restores the
  same fingerprint.
- **Replacement:** quit, move `identities/` away and restart, and a new identity is
  created. Your peer must then replace your pin (Edit → new fingerprint → confirm).
- If only one of the two files exists, CipherLink refuses to start rather than silently
  creating a new identity.
- **Windows:** POSIX file modes do not apply. Keep the app folder inside your user profile
  and restrict the key file, for example:
  `icacls identities\identity_key.pem /inheritance:r /grant:r "%USERNAME%:F"`.

## Trusting each other (fingerprint exchange)

1. On both laptops, start CipherLink and read out or show the fingerprint in "Your
   identity" (**Copy fingerprint** puts it on the clipboard).
2. Exchange fingerprints **over a channel you trust**: in person, or by reading them aloud
   on a call. Do not trust a fingerprint that arrived in an unverified message.
3. On each laptop, go to **Trusted peers → Add…** and enter a name, the other laptop's LAN
   IP, the port (default 52520) and its fingerprint. Confirm the trust prompt.

From then on each side checks the other's certificate against the pin on every connection.
If the fingerprint doesn't match, the connection is refused and an error appears in red in
the peers card.

## Finding the LAN address

| OS | Command |
|---|---|
| macOS | `ipconfig getifaddr en0` (Wi-Fi), or System Settings → Wi-Fi → Details |
| Windows | `ipconfig` → "IPv4 Address" of the active adapter |
| Linux | `hostname -I` or `ip -4 addr` |

## Firewall and ports

- CipherLink listens on **TCP 52520** on all interfaces (`0.0.0.0`) by default. Connections
  from unpinned certificates are dropped before any file data is read.
- **macOS:** allow incoming connections for Python when prompted (System Settings → Network
  → Firewall).
- **Windows:** allow Python on **Private** networks only when Windows Defender Firewall
  asks.
- Guest or campus Wi-Fi often blocks traffic between devices ("client isolation"). If the
  peer is unreachable on such a network, use a phone hotspot or a home router.
- CipherLink is meant for the LAN only. Do not forward the port on your router.

## Sending and receiving

1. Both laptops: `python main.py`. The header pill should say **Listening on port 52520**.
2. Sender: drop files on the drop zone (or use **Browse…**), pick the peer under **To:**,
   and click **Send securely**.
3. Receiver: an **Incoming file** dialog shows the sender, name and size. Click **Accept**
   or **Decline**. Unanswered requests expire after `consent_timeout` (120 s) and are
   declined.
4. The **Active transfers** tab shows progress, speed, elapsed time, remaining time and a
   **Cancel** button. Finished transfers go into **History**.

Both laptops can send at the same time. Each transfer has its own connection, key,
counters and progress.

### Receive folder behaviour

- Files are saved to `received_files/` (or `receive_dir` in `config.json`). Use **Open
  receive folder** in the header to open it.
- Data is written first to a hidden `.cipherlink-<id>.part` file (mode 0600). It is
  renamed to the real name only after every record and the completion record have
  verified. On any failure, cancellation or disconnect, the partial file is deleted.
- Existing files are **never overwritten**. A clash is saved as `name (1).ext`,
  `name (2).ext` and so on, and the GUI tells you.
- Filenames containing path separators, `..`, control characters, a leading dot or
  Windows device names are rejected, not "fixed".

## Configuration

Copy `config.example.json` to `config.json` (in the data directory) and edit it. Unknown
keys or out-of-range values stop the app at startup with a clear error.

| Key | Default | Meaning |
|---|---|---|
| `listen_host` | `0.0.0.0` | Interface to listen on |
| `listen_port` | `52520` | TCP port |
| `receive_dir` | `<data dir>/received_files` | Where accepted files go |
| `max_concurrent_transfers` | `4` | Inbound connection limit, and size of the outbound worker pool |
| `max_file_size` | 10 GiB | Larger offers are rejected |
| `connect_timeout`, `handshake_timeout`, `io_timeout` | 10, 10, 30 s | Socket timeouts |
| `consent_timeout` | 120 s | How long a request waits for the receiving user |
| `chunk_size` | 65536 | Plaintext bytes per record (1 KiB to 1 MiB) |

**Data directory:** the app folder by default. Use `--home DIR` or the `CIPHERLINK_HOME`
environment variable to change it, for example to run two instances on one machine:
`python main.py --home ~/cl-a` and `python main.py --home ~/cl-b`, each with a different
`listen_port` in its `config.json`.

Local-only files (all git-ignored): `identities/`, `received_files/`, `peers.json`,
`transfer_history.json`, `cipherlink.log`, `config.json`.

## Running the tests

```bash
pip install -r requirements-dev.txt
python -m pytest                       # whole suite (about 35 s)
python -m pytest tests/test_protocol.py -k duplicate   # a single test
ruff check .                           # lint
```

GUI tests run on Qt's `offscreen` platform (set automatically). They exercise the widgets,
signals and real localhost transfers, but they **do not** prove that the native file
picker or OS drag-and-drop works on a particular desktop.

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| "Not listening" in the header | Port busy: another CipherLink or app is using 52520. Set a different `listen_port`. |
| "Peer not reachable: connection refused" | The peer app isn't running, the IP or port is wrong, or a firewall is blocking it. |
| "Connection timed out" | Wrong IP, different network, or Wi-Fi client isolation. |
| "…does not match its pinned fingerprint" | The peer's identity changed, or something is intercepting. Re-verify the fingerprint with the peer in person before replacing the pin. |
| "TLS handshake failed" or "Connection lost" when sending | The receiver hasn't added **your** fingerprint yet, or pinned an old one. |
| Receiver shows "Rejected a connection … untrusted fingerprint" | Someone not in your trusted list tried to connect. Add them only after verifying. |
| "Insufficient disk space" | Free up space on the receiver. |
| Warning banner about the peer or history file | The file was corrupt. It was moved aside as `*.corrupt-<time>` and the app started with no trusted peers, or with empty history. |

Logs: `cipherlink.log` in the data directory. Logs never contain keys or file contents.

## Known limitations

- Transfers are tested only between processes on one Mac (loopback and its own LAN
  address). A transfer between two physical laptops has **not** been tested yet.
- Windows and Linux have not been tested.
- The private key is stored unencrypted, protected only by file permissions. There is no
  passphrase.
- The RSA identity key is used both for TLS authentication and for unwrapping session keys
  (see SECURITY.md).
- Individual files only, no folders. Interrupted transfers cannot be resumed.
- Cancelling the receiver closes the connection, so the sender reports a failure rather
  than "cancelled by peer".
- Identity certificates are valid for 10 years. There is no revocation beyond removing or
  replacing a pin.

## Security considerations

Read [SECURITY.md](SECURITY.md). In short: the protection is only as good as the
fingerprint exchange. If you pin a fingerprint you did not verify with its owner, an
attacker on your network can impersonate that peer.

## Legacy prototype

The original command-line prototype (RSA-2048 + AES-128-EAX, one-way, hardcoded to
`127.0.0.1:8080`, no peer authentication) is preserved unchanged in
`project1_sender/`, `project1_receiver/` and `project1_keyutils/`, apart from a one-line
Python 3.12 fix (`receiver.join()`). `project1_settingsParser/`, the XML configs and
`project1_receiver/keyUtils.py` belong to an even earlier version and are no longer used.
CipherLink does not import any of this code. To run the prototype: `pip install
pycryptodome==4.2.0`, then from the repository root run `python -m project1_receiver.receiver`
and `python -m project1_sender.sender`.

## License

Open for any use, as stated in the original project ("fully open"). `setup.py` declares MIT.
