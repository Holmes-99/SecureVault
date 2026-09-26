import os
import sys
import socket
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

import pytest
import keys
from keys import create_account, derive_keys, open_account, change_password
from secure_share import encrypt_document, make_grant, open_document
from shared.formats import (Request, encode_request, request_signed_part, encode_user,
                            encode_document, encode_grant, decode_document, decode_grant, lv, u32)
from shared import protocol as p
from server.server import VaultServer, TCPServer, LOGIN_FAILED, REJECTED
from crypto import ed25519


@pytest.fixture(autouse=True)
def fast_argon2(monkeypatch):
    monkeypatch.setattr(keys, "ARGON2", dict(time_cost=1, memory_cost=64, parallelism=1))


@pytest.fixture
def server(tmp_path):
    return VaultServer(tmp_path / "data")


class Account:
    def __init__(self, server, name, password="pass-" + "x" * 8):
        self.name, self.password = name, password
        self.record, self.keys = create_account(name, password)
        status, _ = call(server, p.make_request(p.REGISTER, name, encode_user(self.record),
                                                self.keys.ed25519_sk))
        assert status == p.OK

    def request(self, server, msg_type, body=b""):
        return call(server, p.make_request(msg_type, self.name, body, self.keys.ed25519_sk))


def call(server, frame):
    return p.decode_response(server.handle(frame))


def upload(server, owner, data=b"thesis text", version=1, doc_id=None):
    doc, dek = encrypt_document(owner.name, "thesis-draft.pdf", "application/pdf", data,
                                version=version, doc_id=doc_id)
    self_grant = make_grant(doc, dek, data, owner.name, owner.keys.ed25519_sk,
                            owner.name, owner.record.x25519_pk)
    status, _ = owner.request(server, p.UPLOAD, p.pack(encode_document(doc), encode_grant(self_grant)))
    return status, doc, dek


# --- sign-up ---

def test_register_and_duplicate(server):
    Account(server, "layla")
    record, k = create_account("layla", "other")
    status, msg = call(server, p.make_request(p.REGISTER, "layla", encode_user(record), k.ed25519_sk))
    assert status == p.ERROR

def test_register_needs_matching_signature(server):
    record, _ = create_account("layla", "pw")
    other_key = ed25519.generate_private_key()
    status, _ = call(server, p.make_request(p.REGISTER, "layla", encode_user(record), other_key))
    assert status == p.ERROR

def test_bad_usernames_rejected(server):
    for name in ["../evil", "Layla", "a b", ""]:
        record, k = create_account(name, "pw")
        status, _ = call(server, p.make_request(p.REGISTER, name, encode_user(record), k.ed25519_sk))
        assert status == p.ERROR

def test_stored_record_has_no_password(server):
    Account(server, "layla", password="Layla@BirZeit2026")
    stored = (server.root / "users" / "layla.bin").read_bytes()
    assert b"Layla@BirZeit2026" not in stored


# --- login ---

def login(server, name, password):
    _, salt = call(server, p.make_request(p.GET_SALT, name))
    auth_key, _ = derive_keys(password, salt)
    _, challenge = call(server, p.make_request(p.LOGIN_START, name))
    return call(server, p.make_request(p.LOGIN_PROOF, name, keys.login_proof(auth_key, challenge)))

def test_login_returns_keys_that_unlock(server):
    acc = Account(server, "layla")
    status, payload = login(server, "layla", acc.password)
    assert status == p.OK
    salt, blob, x_pk, ed_pk = p.unpack(payload, 4)
    assert open_account("layla", acc.password, salt, blob) == acc.keys

def test_wrong_password_and_unknown_user_look_the_same(server):
    Account(server, "layla")
    assert login(server, "layla", "wrong") == (p.ERROR, LOGIN_FAILED.encode())
    assert login(server, "nobody", "wrong") == (p.ERROR, LOGIN_FAILED.encode())

def test_fake_salt_is_stable(server):
    _, s1 = call(server, p.make_request(p.GET_SALT, "nobody"))
    _, s2 = call(server, p.make_request(p.GET_SALT, "nobody"))
    assert s1 == s2 and len(s1) == 16

def test_login_proof_cannot_be_replayed(server):
    acc = Account(server, "layla")
    _, salt = call(server, p.make_request(p.GET_SALT, "layla"))
    auth_key, _ = derive_keys(acc.password, salt)
    _, challenge = call(server, p.make_request(p.LOGIN_START, "layla"))
    proof = keys.login_proof(auth_key, challenge)
    assert call(server, p.make_request(p.LOGIN_PROOF, "layla", proof))[0] == p.OK
    #the challenge is used up -- the same proof again fails
    assert call(server, p.make_request(p.LOGIN_PROOF, "layla", proof))[0] == p.ERROR


# --- signed requests: freshness and forgery ---

def test_replayed_request_rejected(server):
    acc = Account(server, "layla")
    frame = p.make_request(p.LIST, "layla", b"", acc.keys.ed25519_sk)
    assert call(server, frame)[0] == p.OK
    assert call(server, frame) == (p.ERROR, REJECTED.encode())

def test_old_request_rejected(server):
    acc = Account(server, "layla")
    req = Request(p.LIST, "layla", 1_000_000, os.urandom(16), b"", b"")
    req.signature = ed25519.sign(acc.keys.ed25519_sk, request_signed_part(req))
    assert call(server, encode_request(req))[0] == p.ERROR

def test_request_signed_by_someone_else_rejected(server):
    Account(server, "layla")
    mallory_key = ed25519.generate_private_key()
    assert call(server, p.make_request(p.LIST, "layla", b"", mallory_key))[0] == p.ERROR

def test_garbage_rejected(server):
    assert call(server, b"\x00\x00\x00\x03abc")[0] == p.ERROR


# --- upload, share, list, download ---

def test_full_flow_layla_to_omar(server):
    layla, omar = Account(server, "layla"), Account(server, "omar")
    data = b"%PDF Layla's thesis draft"
    status, doc, dek = upload(server, layla, data)
    assert status == p.OK

    #layla gets omar's keys and shares
    status, ks = layla.request(server, p.GET_KEYS, lv("omar"))
    omar_x_pk = ks[32:]
    grant = make_grant(doc, dek, data, "layla", layla.keys.ed25519_sk, "omar", omar_x_pk)
    assert layla.request(server, p.SHARE, encode_grant(grant))[0] == p.OK

    #omar lists and downloads
    status, listing = omar.request(server, p.LIST)
    assert int.from_bytes(listing[:4], 'big') == 1 and doc.doc_id in listing
    status, payload = omar.request(server, p.DOWNLOAD, doc.doc_id + u32(1))
    doc_bytes, grant_bytes = p.unpack(payload, 2)
    plaintext, _ = open_document(decode_document(doc_bytes), decode_grant(grant_bytes),
                                 "omar", omar.keys.x25519_sk, layla.record.ed25519_pk)
    assert plaintext == data

def test_server_copy_is_unreadable(server):
    layla = Account(server, "layla")
    status, doc, _ = upload(server, layla, b"SECRET THESIS CONTENT")
    stored = server.doc_path(doc.doc_id, 1).read_bytes()
    assert b"SECRET THESIS CONTENT" not in stored

def test_cannot_upload_as_someone_else(server):
    layla, mallory = Account(server, "layla"), Account(server, "mallory")
    doc, dek = encrypt_document("layla", "x.pdf", "application/pdf", b"fake")
    grant = make_grant(doc, dek, b"fake", "layla", mallory.keys.ed25519_sk, "layla", layla.record.x25519_pk)
    status, _ = mallory.request(server, p.UPLOAD, p.pack(encode_document(doc), encode_grant(grant)))
    assert status == p.ERROR

def test_only_owner_can_share(server):
    layla, omar, mallory = Account(server, "layla"), Account(server, "omar"), Account(server, "mallory")
    _, doc, dek = upload(server, layla)
    grant = make_grant(doc, dek, b"thesis text", "mallory", mallory.keys.ed25519_sk, "omar", omar.record.x25519_pk)
    assert mallory.request(server, p.SHARE, encode_grant(grant))[0] == p.ERROR

def test_versions_must_go_up(server):
    layla = Account(server, "layla")
    _, doc, _ = upload(server, layla, version=1)
    assert upload(server, layla, version=2, doc_id=doc.doc_id)[0] == p.OK
    assert upload(server, layla, version=2, doc_id=doc.doc_id)[0] == p.ERROR
    assert upload(server, layla, version=5, doc_id=doc.doc_id)[0] == p.ERROR

def test_no_download_without_grant(server):
    layla, mallory = Account(server, "layla"), Account(server, "mallory")
    _, doc, _ = upload(server, layla)
    assert mallory.request(server, p.DOWNLOAD, doc.doc_id + u32(1))[0] == p.ERROR


# --- password change ---

def test_change_password(server):
    acc = Account(server, "layla", password="old-pass")
    new_record = change_password(acc.record, "old-pass", "new-pass")
    assert acc.request(server, p.CHANGE_PASSWORD, encode_user(new_record))[0] == p.OK
    assert login(server, "layla", "new-pass")[0] == p.OK
    assert login(server, "layla", "old-pass")[0] == p.ERROR

def test_change_password_cannot_swap_keys(server):
    acc = Account(server, "layla", password="old-pass")
    other, _ = create_account("layla", "whatever")
    assert acc.request(server, p.CHANGE_PASSWORD, encode_user(other))[0] == p.ERROR


# --- over a real socket ---

def test_real_socket(tmp_path):
    tcp = TCPServer(("127.0.0.1", 0), VaultServer(tmp_path / "data"))
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    try:
        with socket.create_connection(tcp.server_address) as s:
            s.sendall(p.make_request(p.GET_SALT, "layla"))
            status, salt = p.decode_response(p.recv_frame(s))
            assert status == p.OK and len(salt) == 16
    finally:
        tcp.shutdown()
        tcp.server_close()
