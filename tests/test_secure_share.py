import os
import sys
from dataclasses import replace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

import pytest
from secure_share import (encrypt_document, make_grant, open_document, verify_authorship,
                       fingerprint, Rejected, MODIFIED, BAD_SENDER, STALE)
from crypto import x25519, ed25519
from shared.formats import encode_document, decode_document


class User:
    def __init__(self, name):
        self.name = name
        self.x_sk = x25519.generate_private_key()
        self.x_pk = x25519.public_key(self.x_sk)
        self.ed_sk = ed25519.generate_private_key()
        self.ed_pk = ed25519.public_key(self.ed_sk)


THESIS = b"%PDF-1.7 Layla's thesis draft ... " * 20


@pytest.fixture
def layla():
    return User("layla")

@pytest.fixture
def omar():
    return User("omar")


def upload_and_share(sender, recipient, data=THESIS, version=1, doc_id=None):
    doc, dek = encrypt_document(sender.name, "thesis-draft.pdf", "application/pdf",
                                data, version=version, doc_id=doc_id)
    grant = make_grant(doc, dek, data, sender.name, sender.ed_sk, recipient.name, recipient.x_pk)
    return doc, grant


def open_as(user, doc, grant, sender, last_seen=None):
    return open_document(doc, grant, user.name, user.x_sk, sender.ed_pk, last_seen)


def rejected_with(message, fn, *args):
    with pytest.raises(Rejected) as e:
        fn(*args)
    assert str(e.value) == message


# honest path

def test_omar_opens_what_layla_shared(layla, omar):
    doc, grant = upload_and_share(layla, omar)
    plaintext, _ = open_as(omar, doc, grant, layla)
    assert plaintext == THESIS

def test_owner_opens_own_document(layla):
    doc, grant = upload_and_share(layla, layla)
    assert open_as(layla, doc, grant, layla)[0] == THESIS

def test_server_copy_is_unreadable(layla, omar):
    doc, grant = upload_and_share(layla, omar)
    stored = encode_document(doc)
    assert THESIS[:32] not in stored
    assert b"Layla's thesis" not in stored

def test_works_after_storage_roundtrip(layla, omar):
    doc, grant = upload_and_share(layla, omar)
    assert open_as(omar, decode_document(encode_document(doc)), grant, layla)[0] == THESIS

def test_empty_file(layla, omar):
    doc, grant = upload_and_share(layla, omar, data=b"")
    assert open_as(omar, doc, grant, layla)[0] == b""

def test_new_key_and_nonce_every_time(layla, omar):
    a, _ = encrypt_document("layla", "f", "t", THESIS)
    b, _ = encrypt_document("layla", "f", "t", THESIS)
    assert a.nonce != b.nonce and a.ciphertext != b.ciphertext


# demo 6: one byte of ciphertext flipped

def test_flipped_ciphertext_byte_rejected(layla, omar):
    doc, grant = upload_and_share(layla, omar)
    bad = bytearray(doc.ciphertext)
    bad[10] ^= 0x01
    rejected_with(MODIFIED, open_as, omar, replace(doc, ciphertext=bytes(bad)), grant, layla)

def test_flipped_tag_rejected(layla, omar):
    doc, grant = upload_and_share(layla, omar)
    bad = bytearray(doc.tag)
    bad[0] ^= 0x01
    rejected_with(MODIFIED, open_as, omar, replace(doc, tag=bytes(bad)), grant, layla)


# demo 7: metadata changed

@pytest.mark.parametrize("field,value", [
    ("filename", "final-approved.pdf"), ("mime", "text/plain"),
    ("size", 1), ("timestamp", 0),
])
def test_changed_metadata_rejected(layla, omar, field, value):
    doc, grant = upload_and_share(layla, omar)
    rejected_with(MODIFIED, open_as, omar, replace(doc, **{field: value}), grant, layla)

def test_changed_owner_rejected(layla, omar):
    doc, grant = upload_and_share(layla, omar)
    rejected_with(MODIFIED, open_as, omar, replace(doc, owner="mallory"), grant,layla)

def test_changed_grant_sender_rejected(layla, omar):
    doc, grant = upload_and_share(layla, omar)
    rejected_with(MODIFIED, open_as, omar, doc, replace(grant, sender="mallory"), layla)


# metadata binding: pieces can't be moved between documents

def test_grant_moved_to_other_document_rejected(layla, omar):
    doc_a, grant_a = upload_and_share(layla, omar)
    doc_b, _ = upload_and_share(layla, omar, data=b"another file")
    rejected_with(MODIFIED, open_as, omar, doc_b, grant_a, layla)

def test_header_of_one_doc_on_another_rejected(layla, omar):
    doc_a, grant_a = upload_and_share(layla, omar)
    doc_b, _ = upload_and_share(layla, omar, data=b"another file")
    mixed = replace(doc_a, ciphertext=doc_b.ciphertext, tag=doc_b.tag, nonce=doc_b.nonce)
    rejected_with(MODIFIED, open_as, omar, mixed, grant_a, layla)

def test_grant_for_someone_else_cannot_be_opened(layla, omar):
    mallory = User("mallory")
    doc, grant = upload_and_share(layla, omar)
    rejected_with(MODIFIED, open_as, mallory, doc, grant, layla)
    #even if mallory renames the grant to herself, the AAD / key won't match
    rejected_with(MODIFIED, open_as, mallory, doc, replace(grant, recipient="mallory"), layla)


# origin: a forged sender

def test_forger_signing_as_layla_rejected(layla, omar):
    #mallory builds a whole document claiming to be layla, signed with her own key
    mallory = User("mallory")
    doc, dek = encrypt_document("layla", "thesis-draft.pdf", "application/pdf", b"fake")
    grant = make_grant(doc, dek, b"fake", "layla", mallory.ed_sk, "omar", omar.x_pk)
    #omar checks with layla's pinned key -> fails
    rejected_with(BAD_SENDER, open_as, omar, doc, grant, layla)


# demo 8: replay of an old version

def test_old_version_rejected_as_stale(layla, omar):
    doc_id = os.urandom(16)
    v1, g1 = upload_and_share(layla, omar, data=b"version 1", version=1, doc_id=doc_id)
    v2, g2 = upload_and_share(layla, omar, data=b"version 2", version=2, doc_id=doc_id)

    open_as(omar, v2, g2, layla)
    seen = (v2.version, fingerprint(v2))
    #the attacker replays yesterday's genuine v1
    rejected_with(STALE, open_as, omar, v1, g1, layla, seen)

def test_opening_same_copy_again_is_fine(layla, omar):
    doc, grant = upload_and_share(layla, omar)
    seen = (doc.version, fingerprint(doc))
    assert open_as(omar, doc, grant, layla, seen)[0] == THESIS

def test_newer_version_accepted(layla, omar):
    doc_id = os.urandom(16)
    v1, _ = upload_and_share(layla, omar, version=1, doc_id=doc_id)
    v2, g2 = upload_and_share(layla, omar, data=b"version 2", version=2, doc_id=doc_id)
    assert open_as(omar, v2, g2, layla, (1, fingerprint(v1)))[0] == b"version 2"


# demo 5: proof to a third party

def test_third_party_can_verify_authorship(layla, omar):
    doc, grant = upload_and_share(layla, omar)
    plaintext, signature = open_as(omar, doc, grant, layla)
    assert verify_authorship(plaintext, doc, "omar", signature, layla.ed_pk) is True

def test_proof_fails_for_changed_file(layla, omar):
    doc, grant = upload_and_share(layla, omar)
    plaintext, signature = open_as(omar, doc, grant, layla)
    assert verify_authorship(plaintext + b"x", doc, "omar", signature, layla.ed_pk) is False

def test_omar_cannot_forward_as_if_sent_to_someone_else(layla, omar):
    #the recipient's name is inside the signature
    doc, grant = upload_and_share(layla, omar)
    plaintext, signature = open_as(omar, doc, grant, layla)
    assert verify_authorship(plaintext, doc, "mallory", signature, layla.ed_pk) is False
