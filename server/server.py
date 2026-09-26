import os
import re
import sys
import time
import argparse
import threading
import socketserver
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client')) #crypto/

from crypto import ed25519
from crypto.hmac_sha256 import hmac_sha256
from keys import login_proof
from shared.formats import (FormatError, decode_request, request_signed_part,
                            decode_user, encode_user, decode_document, decode_grant,
                            lv, u32, u64, Reader)
from shared import protocol as p


# store + relay only, it never holds a key that opens anything
# it checks: login challenge --> signature --> timestamp --> nonce
#         users can only upload / share as themselves

FRESH_WINDOW   = 5 * 60 #5 minutes
CHALLENGE_LIFE = 60     #seconds

LOGIN_FAILED = "Invalid username or password"
REJECTED = "Request rejected"

USERNAME_RE = re.compile(r"^[a-z0-9_]{1,32}$") #also blocks "../"


class Denied(Exception):
    pass


def atomic_write(path, data):

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


class VaultServer:
    def __init__(self, data_dir):
        self.root = Path(data_dir)
        self.root.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.challenges  = {} #username
        self.seen_nonces = {} #nonce

        secret_file = self.root / "server_secret.bin"
        if not secret_file.exists():
            atomic_write(secret_file, os.urandom(32))
        self.secret = secret_file.read_bytes()


    def user_path(self, username):
        return self.root / "users" / f"{username}.bin"

    def doc_path(self, doc_id, version):
        return self.root / "docs" / doc_id.hex() / f"v{version}.bin"

    def grant_path(self, doc_id, version, recipient):
        return self.root / "grants" / doc_id.hex() / f"v{version}" / f"{recipient}.bin"

    def load_user(self, username):
        if not USERNAME_RE.match(username):
            return None
        path = self.user_path(username)
        return decode_user(path.read_bytes()) if path.exists() else None

    def latest_version(self, doc_id):
        folder = self.root / "docs" / doc_id.hex()
        versions = [int(f.stem[1:]) for f in folder.glob("v*.bin")] if folder.exists() else []
        return max(versions, default=0)

    # one frame in --> one frame out

    def handle(self, frame):
        with self.lock:
            try:
                req = decode_request(frame)
                handler = {
                    p.REGISTER: self.register,
                    p.GET_SALT: self.get_salt,
                    p.LOGIN_START: self.login_start,
                    p.LOGIN_PROOF: self.login_proof,
                    p.GET_KEYS: self.get_keys,
                    p.UPLOAD: self.upload,
                    p.SHARE: self.share,
                    p.LIST: self.list_documents,
                    p.DOWNLOAD: self.download,
                    p.CHANGE_PASSWORD: self.change_password,
                }.get(req.msg_type)
                if handler is None:
                    raise Denied(REJECTED)
                if req.msg_type not in p.UNSIGNED and req.msg_type != p.REGISTER:
                    self.check_signed(req, self.load_user(req.username))
                return p.encode_response(p.OK, handler(req))

            except Denied as e:
                return p.encode_response(p.ERROR, str(e))

            except (FormatError, ValueError):
                return p.encode_response(p.ERROR, REJECTED)


    def check_fresh(self, req):
        now = int(time.time())
        #drop old nonces, the timestamp check covers them
        self.seen_nonces = {n: t for n, t in self.seen_nonces.items() if now - t <= FRESH_WINDOW}
        if abs(now - req.timestamp) > FRESH_WINDOW or req.nonce in self.seen_nonces:
            raise Denied(REJECTED)

    def check_signed(self, req, user):
        if user is None:
            raise Denied(REJECTED)
        self.check_fresh(req)
        if not ed25519.verify(user.ed25519_pk, request_signed_part(req), req.signature):
            raise Denied(REJECTED)
        self.seen_nonces[req.nonce] = req.timestamp

    # sign-up

    def register(self, req):
        record = decode_user(req.body)
        if record.username != req.username or not USERNAME_RE.match(record.username):
            raise Denied(REJECTED)

        self.check_signed(req, record)
        if self.user_path(record.username).exists():
            raise Denied("Username not available")
        atomic_write(self.user_path(record.username), encode_user(record))
        return b""

    # login

    def fake_salt(self, username):
        #same name --> same fake salt,looks like a real account
        return hmac_sha256(self.secret, b"fake salt" + username.encode('utf-8'))[:16]

    def get_salt(self, req):
        user = self.load_user(req.username)
        return user.salt if user else self.fake_salt(req.username)

    def login_start(self, req):
        challenge = os.urandom(32)
        self.challenges[req.username] = (challenge, time.time() + CHALLENGE_LIFE)
        return challenge

    def login_proof(self, req):
        user = self.load_user(req.username)
        challenge, expires = self.challenges.pop(req.username, (os.urandom(32), 0)) #one use only

        #unknown user --> random key--> so same work and same time
        auth_key = user.auth_key if user else os.urandom(32)
        expected = login_proof(auth_key, challenge)
        diff = len(expected) ^ len(req.body)
        for a, b in zip(expected, req.body):
            diff |= a ^ b

        if user is None or diff != 0 or time.time() > expires:
            raise Denied(LOGIN_FAILED)
        return p.pack(user.salt, user.key_blob, user.x25519_pk, user.ed25519_pk)

    # keys

    def get_keys(self, req):
        target = self.load_user(Reader(req.body).text())
        if target is None:
            raise Denied(REJECTED)
        return target.ed25519_pk + target.x25519_pk

    def change_password(self, req):
        old = self.load_user(req.username)
        new = decode_user(req.body)
        #only the lock changes
        if (new.username != old.username or new.x25519_pk != old.x25519_pk or
                new.ed25519_pk != old.ed25519_pk):
            raise Denied(REJECTED)
        atomic_write(self.user_path(old.username), encode_user(new))
        return b""

    # documents

    def upload(self, req):
        doc_bytes, grant_bytes = p.unpack(req.body, 2)
        doc, grant = decode_document(doc_bytes), decode_grant(grant_bytes)

        #upload only as yourself
        if (doc.owner != req.username or grant.sender != req.username or
                grant.recipient != req.username or grant.doc_id != doc.doc_id or
                grant.version != doc.version):
            raise Denied(REJECTED)

        latest = self.latest_version(doc.doc_id)
        if latest:
            first = decode_document(self.doc_path(doc.doc_id, 1).read_bytes())
            if first.owner != req.username:
                raise Denied(REJECTED)
        if doc.version != latest + 1:
            raise Denied(REJECTED)

        atomic_write(self.doc_path(doc.doc_id, doc.version), doc_bytes)
        atomic_write(self.grant_path(doc.doc_id, doc.version, req.username), grant_bytes)
        return b""

    def share(self, req):
        grant = decode_grant(req.body)
        path = self.doc_path(grant.doc_id, grant.version)
        if not path.exists() or self.load_user(grant.recipient) is None:
            raise Denied(REJECTED)
        doc = decode_document(path.read_bytes())
        if doc.owner != req.username or grant.sender != req.username:
            raise Denied(REJECTED)
        atomic_write(self.grant_path(grant.doc_id, grant.version, grant.recipient), req.body)
        return b""

    def list_documents(self, req):
        latest = {}
        for grant_file in (self.root / "grants").glob(f"*/v*/{req.username}.bin"):
            doc_id = bytes.fromhex(grant_file.parent.parent.name)
            version = int(grant_file.parent.name[1:])
            latest[doc_id] = max(version, latest.get(doc_id, 0))

        out = u32(len(latest))
        for doc_id, version in sorted(latest.items()):
            doc = decode_document(self.doc_path(doc_id, version).read_bytes())
            out += (doc_id + u32(version) + lv(doc.owner) + lv(doc.filename) +
                    u64(doc.size) + u64(doc.timestamp))
        return out

    def download(self, req):
        r = Reader(req.body)
        doc_id, version = r.take(16), r.u32()
        r.done()
        grant_path = self.grant_path(doc_id, version, req.username)
        if not grant_path.exists():
            raise Denied(REJECTED)
        return p.pack(self.doc_path(doc_id, version).read_bytes(), grant_path.read_bytes())


# network

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while True:
                frame = p.recv_frame(self.request)
                self.request.sendall(self.server.vault.handle(frame))
        except (ConnectionError, FormatError, OSError):
            pass #client left or sent garbage, just close


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, vault):
        super().__init__(address, Handler)
        self.vault = vault


def main():
    parser = argparse.ArgumentParser(description="SecureVault server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5050)
    parser.add_argument("--data", default="server_data")
    args = parser.parse_args()

    with TCPServer((args.host, args.port), VaultServer(args.data)) as server:
        print(f"SecureVault server on {args.host}:{args.port}, data in {args.data}/")
        server.serve_forever()


if __name__ == "__main__":
    main()
