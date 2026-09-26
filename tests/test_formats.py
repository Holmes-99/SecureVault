import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from shared.formats import (
    FormatError, Document, KeyGrant, UserRecord, Request,
    encode_document, decode_document, document_header,
    encode_grant, decode_grant, grant_header,
    encode_user, decode_user, encode_request, decode_request,
    request_signed_part, signed_statement, lv,
)


def sample_document():
    return Document(doc_id=os.urandom(16), owner="layla", filename="thesis-draft.pdf",
                    mime="application/pdf", size=1024, timestamp=1790000000, version=2,
                    nonce=os.urandom(12), ciphertext=os.urandom(1024), tag=os.urandom(16))

def sample_grant():
    return KeyGrant(doc_id=os.urandom(16), version=2, sender="layla", recipient="omar",
                    ephemeral_pk=os.urandom(32), nonce=os.urandom(12),
                    sealed=os.urandom(96), tag=os.urandom(16))

def sample_user():
    return UserRecord(username="omar", salt=os.urandom(16), auth_key=os.urandom(32),
                      x25519_pk=os.urandom(32), ed25519_pk=os.urandom(32),
                      key_blob=os.urandom(92))

def sample_request():
    return Request(msg_type=3, username="layla", timestamp=1790000000,
                   nonce=os.urandom(16), body=b"some body bytes", signature=os.urandom(64))


# round trips: decode(encode(x)) gives x back

def test_document_roundtrip():
    doc = sample_document()
    assert decode_document(encode_document(doc)) == doc

def test_grant_roundtrip():
    grant = sample_grant()
    assert decode_grant(encode_grant(grant)) == grant

def test_user_roundtrip():
    user = sample_user()
    assert decode_user(encode_user(user)) == user

def test_request_roundtrip():
    req = sample_request()
    assert decode_request(encode_request(req)) == req

def test_request_with_empty_body():
    req = sample_request()
    req.body = b""
    assert decode_request(encode_request(req)) == req

def test_arabic_filename_roundtrip():
    doc = sample_document()
    doc.filename = "رسالة-الماجستير.pdf"
    assert decode_document(encode_document(doc)).filename == doc.filename


# exact layout checks against the table in DESIGN.md

def test_document_layout():
    doc = sample_document()
    data = encode_document(doc)
    assert data[:4] == b"SVD1"
    assert data[4:20] == doc.doc_id
    assert data.endswith(doc.tag)
    header = document_header(doc)
    assert data.startswith(header)
    assert data[len(header):len(header) + 12] == doc.nonce

def test_grant_is_fixed_size_apart_from_names():
    grant = sample_grant()
    data = encode_grant(grant)
    #4+16+4 + (2+5) + (2+4) + 32 + 12 + 96 + 16
    assert len(data) == 193

def test_user_record_size():
    #(2+4) + 16 + 32 + 32 + 32 + 92
    assert len(encode_user(sample_user())) == 210

def test_signed_statement_layout():
    doc_id = os.urandom(16)
    s = signed_statement(doc_id, 2, "layla", "omar", b"\x01" * 32, b"\x02" * 32)
    assert s[:4] == b"SVS1"
    assert s[4:20] == doc_id
    assert s.endswith(b"\x01" * 32 + b"\x02" * 32)


# the length prefix stops field-boundary tricks

def test_lv_prevents_ambiguity():
    assert lv("ab") + lv("c") != lv("a") + lv("bc")

def test_changing_any_metadata_changes_header():
    doc = sample_document()
    original = document_header(doc)
    for field, value in [("owner", "mallory"), ("filename", "final.pdf"),
                         ("mime", "text/plain"), ("size", 1), ("timestamp", 1), ("version", 1)]:
        changed = sample_document()
        changed.__dict__.update(doc.__dict__)
        setattr(changed, field, value)
        assert document_header(changed) != original

def test_recipient_is_in_grant_header():
    grant = sample_grant()
    other = KeyGrant(**{**grant.__dict__, "recipient": "mallory"})
    assert grant_header(grant) != grant_header(other)

def test_signature_not_in_signed_part():
    req = sample_request()
    assert req.signature not in request_signed_part(req)


# decoding rejects broken data

def test_truncated_document_rejected():
    data = encode_document(sample_document())
    with pytest.raises(FormatError):
        decode_document(data[:-1])

def test_extra_bytes_rejected():
    data = encode_grant(sample_grant())
    with pytest.raises(FormatError):
        decode_grant(data + b"\x00")

def test_wrong_magic_rejected():
    data = encode_grant(sample_grant())
    with pytest.raises(FormatError):
        decode_document(data)

def test_bad_request_length_rejected():
    data = bytearray(encode_request(sample_request()))
    data[3] ^= 0x01
    with pytest.raises(FormatError):
        decode_request(bytes(data))

def test_wrong_field_size_rejected_on_encode():
    doc = sample_document()
    doc.nonce = os.urandom(11)
    with pytest.raises(FormatError):
        encode_document(doc)

def test_empty_input_rejected():
    for decode in [decode_document, decode_grant, decode_user, decode_request]:
        with pytest.raises(FormatError):
            decode(b"")
