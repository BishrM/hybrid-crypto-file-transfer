"""Validation of untrusted or user-supplied input: filenames, config, peers, history."""
from __future__ import annotations

import json
import threading
import time

import pytest

import network_p2p as net
from config import Config, ConfigError, load_config
from peer_store import Peer, PeerStore, PeerStoreError
from transfer_history import TransferHistory

FP1, FP2 = "AA" * 32, "BB" * 32

# ------------------------------------------------------------------ filenames


@pytest.mark.parametrize("name", ["report.pdf", "a", "My File (2).tar.gz", "ünïcødé.txt", "x" * 200])
def test_valid_filenames(name) -> None:
    assert net.validate_filename(name) == name


@pytest.mark.parametrize(
    "name",
    ["", ".", "..", "../etc/passwd", "a/b", "a\\b", "/abs", "C:evil", ".hidden", "trail.", "trail ",
     "nul\x00byte", "tab\tname", "CON", "con.txt", "LPT1.log", "x" * 256, "é" * 128, None, 5],
)
def test_unsafe_filenames_rejected(name) -> None:
    with pytest.raises(net.ProtocolError):
        net.validate_filename(name)


def test_publish_unique_never_overwrites_or_follows_symlink(tmp_path) -> None:
    d = tmp_path / "recv"
    d.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    (d / "a.txt").symlink_to(outside)  # an attacker-planted or pre-existing symlink
    tmp = d / ".part"
    tmp.write_text("new")
    final = net.publish_unique(tmp, d, "a.txt")
    assert final.name == "a (1).txt" and final.read_text() == "new"
    assert outside.read_text() == "secret"
    assert not tmp.exists()


def test_publish_unique_without_extension(tmp_path) -> None:
    (tmp_path / "README").write_text("old")
    tmp = tmp_path / ".p"
    tmp.write_text("new")
    assert net.publish_unique(tmp, tmp_path, "README").name == "README (1)"


# ------------------------------------------------------------------ config


def test_config_defaults(tmp_path) -> None:
    c = load_config(tmp_path)
    assert c.listen_port == 52520 and c.chunk_size == 64 * 1024
    assert c.receive_dir == tmp_path / "received_files"
    assert c.identity_dir == tmp_path / "identities"


@pytest.mark.parametrize(
    "over",
    [{"listen_port": 70000}, {"listen_port": "80"}, {"chunk_size": 10}, {"chunk_size": 2**21},
     {"max_concurrent_transfers": 0}, {"io_timeout": 0}, {"io_timeout": True}, {"listen_host": ""},
     {"max_file_size": -1}],
)
def test_invalid_config_rejected(tmp_path, over) -> None:
    with pytest.raises(ConfigError):
        Config(data_dir=tmp_path, **over)


def test_config_file_overrides_and_rejects_unknown(tmp_path) -> None:
    (tmp_path / "config.json").write_text(json.dumps({"listen_port": 6000, "receive_dir": str(tmp_path / "in")}))
    c = load_config(tmp_path)
    assert c.listen_port == 6000 and c.receive_dir == tmp_path / "in"
    (tmp_path / "config.json").write_text(json.dumps({"listen_prot": 1}))
    with pytest.raises(ConfigError, match="unknown"):
        load_config(tmp_path)
    (tmp_path / "config.json").write_text("{broken")
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_config_env_home(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("CIPHERLINK_HOME", str(tmp_path))
    assert load_config().data_dir == tmp_path


# ------------------------------------------------------------------ peer store


def test_peer_store_roundtrip_and_management(tmp_path) -> None:
    path = tmp_path / "peers.json"
    s = PeerStore(path)
    s.add(Peer.create("Laptop B", "192.168.1.20", 52520, FP1.lower()))
    s2 = PeerStore(path)
    (p,) = s2.peers()
    assert p == Peer("Laptop B", "192.168.1.20", 52520, FP1)
    s2.update_address("Laptop B", "Lab PC", "10.0.0.5", 6000)
    assert PeerStore(path).get("Lab PC").fingerprint == FP1  # rename keeps the pin
    s2.remove("Lab PC")
    assert PeerStore(path).peers() == []


def test_duplicate_name_or_fingerprint_rejected(tmp_path) -> None:
    s = PeerStore(tmp_path / "p.json")
    s.add(Peer.create("A", "h", 1, FP1))
    with pytest.raises(PeerStoreError):
        s.add(Peer.create("A", "h", 1, FP2))
    with pytest.raises(PeerStoreError):
        s.add(Peer.create("B", "h", 1, FP1))


def test_pin_replacement_requires_confirmation(tmp_path) -> None:
    s = PeerStore(tmp_path / "p.json")
    s.add(Peer.create("A", "h", 1, FP1))
    for bad in (False, None, "yes", 1):
        with pytest.raises(PeerStoreError, match="confirmation"):
            s.replace_pin("A", FP2, confirmed=bad)
    assert s.get("A").fingerprint == FP1
    s.replace_pin("A", FP2, confirmed=True)
    assert s.find_by_fingerprint(FP2).name == "A" and s.find_by_fingerprint(FP1) is None


@pytest.mark.parametrize(
    "args",
    [("", "h", 1, FP1), ("x" * 65, "h", 1, FP1), ("n\x00", "h", 1, FP1), ("n", "", 1, FP1), ("n", "a b", 1, FP1),
     ("n", "h", 0, FP1), ("n", "h", 65536, FP1), ("n", "h", True, FP1), ("n", "h", 1, "abc")],
)
def test_invalid_peer_fields(args) -> None:
    with pytest.raises(PeerStoreError):
        Peer.create(*args)


@pytest.mark.parametrize(
    "content",
    ["{broken", "[]", '{"peers": [{"name": "A"}]}',
     json.dumps({"peers": [{"name": "A", "host": "h", "port": 1, "fingerprint": "zz"}]}),
     json.dumps({"peers": [{"name": "A", "host": "h", "port": 1, "fingerprint": FP1},
                           {"name": "B", "host": "h", "port": 1, "fingerprint": FP1}]})],
)
def test_corrupt_peer_store_trusts_nobody(tmp_path, content) -> None:
    path = tmp_path / "peers.json"
    path.write_text(content)
    s = PeerStore(path)
    assert s.peers() == [] and s.find_by_fingerprint(FP1) is None
    assert s.load_warning
    assert list(tmp_path.glob("peers.json.corrupt-*")), "original kept for inspection"


# ------------------------------------------------------------------ history


def _info(i=0, status="completed", direction="send"):
    info = net.TransferInfo(f"{i:032x}", direction, "Peer", f"file{i}.txt", 100, 100, status)
    info.started_at, info.finished_at = 1000.0, 1002.0
    return info


def test_history_persists_metrics(tmp_path) -> None:
    h = TransferHistory(tmp_path / "h.json")
    h.record(_info(1))
    (e,) = TransferHistory(tmp_path / "h.json").entries()
    assert e.filename == "file1.txt" and e.duration == 2.0 and e.average_speed == 50.0


def test_history_never_stores_secrets(tmp_path) -> None:
    h = TransferHistory(tmp_path / "h.json")
    h.record(_info())
    keys = set(json.loads((tmp_path / "h.json").read_text())[0])
    assert keys == {"transfer_id", "filename", "direction", "peer", "size", "bytes_transferred",
                    "started_at", "finished_at", "status", "error", "saved_as"}


def test_history_drops_malformed_entries(tmp_path) -> None:
    h = TransferHistory(tmp_path / "h.json")
    h.record(_info(1))
    good = json.loads((tmp_path / "h.json").read_text())[0]
    bad = [dict(good, size=-5), dict(good, status="hacked"), dict(good, extra=1), "str", dict(good, filename=3)]
    (tmp_path / "h.json").write_text(json.dumps([good, *bad]))
    h2 = TransferHistory(tmp_path / "h.json")
    assert len(h2.entries()) == 1 and "5 malformed" in h2.load_warning


@pytest.mark.parametrize("content", ["{nope", '{"a": 1}', "\x00\x01"])
def test_corrupt_history_resets_safely(tmp_path, content) -> None:
    (tmp_path / "h.json").write_text(content)
    h = TransferHistory(tmp_path / "h.json")
    assert h.entries() == [] and h.load_warning
    h.record(_info())
    assert len(TransferHistory(tmp_path / "h.json").entries()) == 1


def test_history_is_bounded_and_newest_first(tmp_path) -> None:
    h = TransferHistory(tmp_path / "h.json", max_entries=3)
    for i in range(5):
        h.record(_info(i))
    assert [e.filename for e in h.entries()] == ["file4.txt", "file3.txt", "file2.txt"]


def test_concurrent_history_writes(tmp_path) -> None:
    h = TransferHistory(tmp_path / "h.json")
    threads = [threading.Thread(target=lambda i=i: h.record(_info(i))) for i in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    stored = json.loads((tmp_path / "h.json").read_text())
    assert len(stored) == 40 and len({e["transfer_id"] for e in stored}) == 40
    assert not list(tmp_path.glob(".h.json.*")), "no temp files left behind"


def test_history_entry_for_unfinished_info_gets_timestamp(tmp_path) -> None:
    info = _info()
    info.finished_at = None
    before = time.time()
    e = TransferHistory(tmp_path / "h.json").record(info)
    assert e.finished_at >= before
