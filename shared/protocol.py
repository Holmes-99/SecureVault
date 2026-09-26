import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))            #project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))  #for crypto/

from crypto import ed25519
from shared.formats import Request, encode_request, request_signed_part, u8, u32, FormatError

# how client and server talk over the socket
#
# every message = 4-byte length + bytes
#   client -> server : a Request frame (shared/formats.py)
#   server -> client : status (1 byte) + payload

# message types
REGISTER = 1
GET_SALT = 2          #not signed (the user has no keys yet on a new machine)
LOGIN_START = 3       #not signed
LOGIN_PROOF = 4       #not signed
GET_KEYS = 10
UPLOAD = 11
SHARE = 12
LIST = 13
DOWNLOAD = 14
CHANGE_PASSWORD = 15

UNSIGNED = {GET_SALT, LOGIN_START, LOGIN_PROOF}
NO_SIGNATURE = b"\x00" * 64

OK = 0
ERROR = 1

MAX_FRAME = 64 * 1024 * 1024   #refuse anything bigger than 64 MiB


def make_request(msg_type, username, body=b"", ed25519_sk=None):
    #every request carries the time and a fresh random nonce (replay protection)
    req = Request(msg_type=msg_type, username=username, timestamp=int(time.time()),
                  nonce=os.urandom(16), body=body, signature=NO_SIGNATURE)
    if ed25519_sk is not None:
        req.signature = ed25519.sign(ed25519_sk, request_signed_part(req))
    return encode_request(req)


def encode_response(status, payload=b""):
    if isinstance(payload, str):
        payload = payload.encode('utf-8')
    return u32(1 + len(payload)) + u8(status) + payload


def decode_response(frame):
    if len(frame) < 5:
        raise FormatError("response is truncated")
    return frame[4], frame[5:]


# --- packing several big fields into one body (4-byte length each) ---

def pack(*parts):
    return b"".join(u32(len(p)) + p for p in parts)


def unpack(data, count):
    parts, pos = [], 0
    for _ in range(count):
        if pos + 4 > len(data):
            raise FormatError("data is truncated")
        n = int.from_bytes(data[pos:pos + 4], 'big')
        pos += 4
        if pos + n > len(data):
            raise FormatError("data is truncated")
        parts.append(data[pos:pos + n])
        pos += n
    if pos != len(data):
        raise FormatError("unexpected extra bytes")
    return parts


# --- socket helpers ---

def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    return data


def recv_frame(sock):
    #returns the whole frame, length included
    header = recv_exact(sock, 4)
    length = int.from_bytes(header, 'big')
    if length > MAX_FRAME:
        raise FormatError("frame too large")
    return header + recv_exact(sock, length)
