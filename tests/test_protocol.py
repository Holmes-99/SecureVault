import os
import sys
import socket

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

import pytest
from shared import protocol as p
from shared.formats import decode_request, request_signed_part, FormatError, u32
from crypto import ed25519


def test_signed_request_verifies():
    sk = ed25519.generate_private_key()
    req = decode_request(p.make_request(p.LIST, "layla", b"body", sk))
    assert ed25519.verify(ed25519.public_key(sk), request_signed_part(req), req.signature)

def test_unsigned_request_has_zero_signature():
    req = decode_request(p.make_request(p.GET_SALT, "layla"))
    assert req.signature == p.NO_SIGNATURE

def test_every_request_gets_a_fresh_nonce():
    a = decode_request(p.make_request(p.GET_SALT, "layla"))
    b = decode_request(p.make_request(p.GET_SALT, "layla"))
    assert a.nonce != b.nonce

def test_response_roundtrip():
    assert p.decode_response(p.encode_response(p.OK, b"data")) == (p.OK, b"data")
    assert p.decode_response(p.encode_response(p.ERROR, "Request rejected")) == (p.ERROR, b"Request rejected")

def test_pack_unpack():
    parts = [b"", b"a", os.urandom(1000)]
    assert p.unpack(p.pack(*parts), 3) == parts

def test_unpack_rejects_bad_data():
    data = p.pack(b"one", b"two")
    for bad, count in [(data[:-1], 2), (data + b"x", 2), (data, 3)]:
        with pytest.raises(FormatError):
            p.unpack(bad, count)

def test_recv_frame_refuses_huge_frames():
    a, b = socket.socketpair()
    with a, b:
        a.sendall(u32(p.MAX_FRAME + 1))
        with pytest.raises(FormatError):
            p.recv_frame(b)

def test_recv_frame_reads_whole_frame():
    a, b = socket.socketpair()
    with a, b:
        frame = p.encode_response(p.OK, os.urandom(5000))
        a.sendall(frame)
        assert p.recv_frame(b) == frame
