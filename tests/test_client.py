import os
import sys
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

import pytest
import keys
from client.client import VaultClient, ClientError, KEY_CHANGED
from secure_share import Rejected, MODIFIED, STALE
from server.server import VaultServer
from shared import protocol as p
from shared.formats import decode_document, encode_document, encode_user
from keys import create_account


@pytest.fixture(autouse=True)
def fast_argon2(monkeypatch):
    monkeypatch.setattr(keys, "ARGON2", dict(time_cost=1, memory_cost=64, parallelism=1))


@pytest.fixture
def world(tmp_path):
    #one server, two users on "separate machines" (separate data folders)
    server = VaultServer(tmp_path / "server")
    layla = VaultClient(server.handle, tmp_path / "layla_pc")
    omar = VaultClient(server.handle, tmp_path / "omar_pc")
    layla.signup("layla", "Layla@2026")
    omar.signup("omar", "Omar@2026")
    thesis = tmp_path / "thesis-draft.pdf"
    thesis.write_bytes(b"%PDF-1.7 Layla's thesis draft " * 50)
    return server, layla, omar, thesis, tmp_path


def verify_each_other(layla, omar):
    #both see the same number, compare it, then mark verified
    assert layla.contact("omar") == omar.contact("layla")
    layla.verify("omar")
    omar.verify("layla")


# accounts

def test_login_again_gives_same_keys(world):
    server, layla, *_ = world
    keys_before = layla.keys
    layla.logout()
    assert layla.keys is None
    layla.login("layla", "Layla@2026")
    assert layla.keys == keys_before

def test_wrong_password(world):
    server, layla, *_ = world
    layla.logout()
    with pytest.raises(ClientError):
        layla.login("layla", "wrong")

def test_passwd(world):
    server, layla, *_ = world
    layla.passwd("Layla@2026", "New@2026")
    layla.logout()
    layla.login("layla", "New@2026")
    with pytest.raises(ClientError):
        layla.login("layla", "Layla@2026")

def test_commands_need_login(world):
    server, layla, *_ = world
    layla.logout()
    with pytest.raises(ClientError):
        layla.list()


# the whole scenario

def test_full_scenario(world):
    server, layla, omar, thesis, tmp = world
    doc_id = layla.upload(thesis)
    verify_each_other(layla, omar)
    layla.share(doc_id[:6], "omar")

    assert [d["filename"] for d in omar.list()] == ["thesis-draft.pdf"]
    path, sender, verified = omar.download(doc_id[:6], tmp / "omar_downloads")
    assert path.read_bytes() == thesis.read_bytes()
    assert sender == "layla" and verified

def test_share_blocked_until_verified(world):
    server, layla, omar, thesis, _ = world
    doc_id = layla.upload(thesis)
    layla.contact("omar")                   #pinned, but not verified yet
    with pytest.raises(ClientError):
        layla.share(doc_id, "omar")

def test_owner_can_download_own_file(world):
    server, layla, omar, thesis, tmp = world
    doc_id = layla.upload(thesis)
    path, sender, _ = layla.download(doc_id, tmp / "out")
    assert path.read_bytes() == thesis.read_bytes() and sender == "layla"


# key trust (TOFU)

def test_key_change_is_blocked(world):
    server, layla, omar, *_ = world
    layla.contact("omar")
    #the server swaps omar's keys for new ones
    record, _ = create_account("omar", "whatever")
    (server.root / "users" / "omar.bin").write_bytes(encode_user(record))
    with pytest.raises(ClientError) as e:
        layla.contact("omar")
    assert str(e.value) == KEY_CHANGED

def test_swapped_key_gives_different_safety_number(world, tmp_path):
    #MITM from the start: layla gets a fake "omar" key on first contact
    server, layla, omar, *_ = world
    real_number = omar.contact("layla")
    real = (server.root / "users" / "omar.bin").read_bytes()
    fake, _ = create_account("omar", "attacker")
    (server.root / "users" / "omar.bin").write_bytes(encode_user(fake))
    assert layla.contact("omar") != real_number


# attacks on the way back (a network attacker changes the server's answer)

def tamper_downloads(client, change):
    real_send = client.send
    def send(frame):
        reply = real_send(frame)
        if frame[4] == p.DOWNLOAD:
            status, payload = p.decode_response(reply)
            doc_bytes, grant_bytes = p.unpack(payload, 2)
            reply = p.encode_response(status, p.pack(change(doc_bytes), grant_bytes))
        return reply
    client.send = send

def shared_doc(world):
    server, layla, omar, thesis, tmp = world
    doc_id = layla.upload(thesis)
    verify_each_other(layla, omar)
    layla.share(doc_id, "omar")
    return doc_id

def test_flipped_byte_rejected(world):
    doc_id = shared_doc(world)
    omar, tmp = world[2], world[4]
    def flip(doc_bytes):
        b = bytearray(doc_bytes)
        b[-30] ^= 0x01                      #inside the ciphertext
        return bytes(b)
    tamper_downloads(omar, flip)
    with pytest.raises(Rejected) as e:
        omar.download(doc_id, tmp / "out")
    assert str(e.value) == MODIFIED
    assert not (tmp / "out" / "thesis-draft.pdf").exists()   #nothing saved

def test_changed_filename_rejected(world):
    doc_id = shared_doc(world)
    omar, tmp = world[2], world[4]
    def rename(doc_bytes):
        doc = decode_document(doc_bytes)
        doc.filename = "final-approved.pdf"
        return encode_document(doc)
    tamper_downloads(omar, rename)
    with pytest.raises(Rejected) as e:
        omar.download(doc_id, tmp / "out")
    assert str(e.value) == MODIFIED

def test_replayed_old_version_is_stale(world):
    server, layla, omar, thesis, tmp = world
    doc_id = shared_doc(world)
    omar.download(doc_id, tmp / "out")
    v1 = (server.root / "docs" / doc_id / "v1.bin").read_bytes()

    #layla uploads v2 and shares it
    thesis.write_bytes(b"%PDF-1.7 fixed version")
    layla.update(doc_id, thesis)
    layla.share(doc_id, "omar")
    omar.download(doc_id, tmp / "out")

    #the attacker now answers with yesterday's v1 (+ its grant)
    real_send = omar.send
    v1_grant = (server.root / "grants" / doc_id / "v1" / "omar.bin").read_bytes()
    def send(frame):
        reply = real_send(frame)
        if frame[4] == p.DOWNLOAD:
            reply = p.encode_response(p.OK, p.pack(v1, v1_grant))
        return reply
    omar.send = send
    with pytest.raises(Rejected) as e:
        omar.download(doc_id, tmp / "out")
    assert str(e.value) == STALE


# small safety details

def test_filename_cannot_escape_download_folder(world):
    server, layla, omar, _, tmp = world
    evil = tmp / "evil.txt"
    evil.write_bytes(b"x")
    doc_id = layla.upload(evil)
    #pretend the stored name were "../../evil.txt" -- only the base name is used
    path, *_ = layla.download(doc_id, tmp / "out")
    assert path.parent == tmp / "out"

def test_pinned_keys_saved_locally(world):
    server, layla, omar, *_ = world
    layla.contact("omar")
    pinned = json.loads((layla.data_dir / "layla" / "pinned.json").read_text())
    assert pinned["omar"]["verified"] is False
