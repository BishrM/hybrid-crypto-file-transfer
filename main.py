"""CipherLink entry point: config -> identity -> peers/history -> listener -> GUI.

Usage:  python main.py [--home DIR]

``--home`` (or the CIPHERLINK_HOME environment variable) selects the data directory, which
holds the identity, trusted peers, history, log and (by default) received files. Two
instances on one machine need two different homes and ports.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from config import APP_NAME, ConfigError, load_config
from crypto_engine import CryptoError, load_or_create_identity
from network_p2p import PeerNode
from peer_store import PeerStore
from transfer_history import TransferHistory

log = logging.getLogger("cipherlink")


def setup_logging(log_file: Path) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        handlers=[logging.FileHandler(log_file, encoding="utf-8"), logging.StreamHandler()],
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=f"{APP_NAME} secure LAN file transfer")
    parser.add_argument("--home", type=Path, help="data directory (default: CIPHERLINK_HOME or the app folder)")
    args = parser.parse_args(argv)

    from PyQt6.QtWidgets import QApplication, QMessageBox

    app = QApplication(sys.argv[:1])
    app.setApplicationName(APP_NAME)

    def fatal(title: str, message: str) -> int:
        log.error("%s: %s", title, message)
        QMessageBox.critical(None, title, message)
        return 1

    try:
        config = load_config(args.home)
    except ConfigError as exc:
        return fatal("Invalid configuration", str(exc))
    setup_logging(config.log_file)

    warnings: list[str] = []
    try:
        identity, created = load_or_create_identity(config.identity_dir)
    except CryptoError as exc:
        return fatal(
            "Identity problem",
            f"{exc}\n\nFix or move the files in '{config.identity_dir}' (see README, 'Identity backup and replacement').",
        )
    if created:
        warnings.append(
            "A new identity was created for this computer. Share your fingerprint with your peer, "
            "and back up the 'identities' folder if you want to keep this identity."
        )
        log.info("created new identity %s…", identity.fingerprint[:16])

    peers = PeerStore(config.peers_file)
    history = TransferHistory(config.history_file)
    warnings += [w for w in (peers.load_warning, history.load_warning) if w]

    from gui_app import Bridge, MainWindow

    bridge = Bridge(config.consent_timeout)
    node = PeerNode(identity, peers, config, bridge)
    listen_error = None
    try:
        node.start()
    except OSError as exc:
        listen_error = f"Could not listen on {config.listen_host}:{config.listen_port}: {exc.strerror or exc}"
        warnings.append(listen_error + ". You can still send files; set another 'listen_port' in config.json to receive.")
        log.error(listen_error)

    window = MainWindow(node, bridge, identity, peers, history, config, listen_error, warnings)
    app.aboutToQuit.connect(window.shutdown)
    window.show()
    code = app.exec()
    window.shutdown()
    return code


if __name__ == "__main__":
    os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")
    sys.exit(main())
