import os
import sys
import socket
import getpass
import argparse
import mimetypes
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__)) #client/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from keys import (create_account, derive_keys, unlock_private_keys, change_password,
                  login_proof)
from secure_share import (encrypt_document, make_grant, open_document, unwrap_grant,
                          fingerprint, Rejected, STALE)
from crypto import x25519, ed25519
from crypto.safety_number import safety_number
from shared.formats import (UserRecord, encode_user, encode_document, encode_grant,
                            decode_document, decode_grant, lv, u32, Reader, FormatError)
from shared import protocol as p
from server.storage.json_store import save_json, load_json

# flow
# signup / login --> keys unlocked in memory only
# contact --> pin their keys (TOFU) --> compare safety number --> verify
# upload --> encrypt + grant for me   share --> grant for a VERIFIED user only
# download --> open_document checks everything --> save file + say who sent it

KEY_CHANGED = "Blocked: key changed"


class ClientError(Exception):
    pass


class Connection:
    #one TCP connection to the server
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port))

    def send(self, frame):
        self.sock.sendall(frame)
        return p.recv_frame(self.sock)


class VaultClient:
    def __init__(self, send, data_dir="client_data"):
        self.send = send               #frame in --> frame out (socket or, in tests, the server)
        self.data_dir = Path(data_dir)
        self.logout()

    # talking to the server

    def call(self, msg_type, body=b"", signed=True, username=None):
        key = self.keys.ed25519_sk if signed else None
        frame = p.make_request(msg_type, username or self.username, body, key)
        status, payload = p.decode_response(self.send(frame))
        if status != p.OK:
            raise ClientError(payload.decode('utf-8', 'replace'))
        return payload

    def need_login(self):
        if self.keys is None:
            raise ClientError("log in first")

    # local files (per user): pinned keys + last version seen of each doc

    def local(self, name):
        return self.data_dir / self.username / f"{name}.json"

    def pinned(self):
        return load_json(self.local("pinned"), default={})

    def seen(self):
        return load_json(self.local("seen"), default={})

    # account

    def signup(self, username, password):
        record, keys = create_account(username, password)
        self.username, self.keys = username, keys
        try:
            self.call(p.REGISTER, encode_user(record))
        except ClientError:
            self.logout()
            raise
        self.record = record

    def login(self, username, password):
        salt = self.call(p.GET_SALT, signed=False, username=username)
        auth_key, enc_key = derive_keys(password, salt)
        challenge = self.call(p.LOGIN_START, signed=False, username=username)
        payload = self.call(p.LOGIN_PROOF, login_proof(auth_key, challenge),
                            signed=False, username=username)

        salt, blob, x_pk, ed_pk = p.unpack(payload, 4)
        try:
            keys = unlock_private_keys(username, enc_key, blob)
        except ValueError:
            raise ClientError("Invalid username or password")
        self.username, self.keys = username, keys
        self.record = UserRecord(username=username, salt=salt, auth_key=auth_key,
                                 x25519_pk=x_pk, ed25519_pk=ed_pk, key_blob=blob)

    def logout(self):
        #the "session" is just the unlocked keys, so logging out drops them
        self.username = None
        self.keys = None
        self.record = None

    def passwd(self, old_password, new_password):
        self.need_login()
        try:
            new = change_password(self.record, old_password, new_password)
        except ValueError:
            raise ClientError("wrong password")
        self.call(p.CHANGE_PASSWORD, encode_user(new))
        self.record = new

    # contacts: TOFU + safety number

    def contact(self, name):
        #returns the safety number to compare with `name` by phone / in person
        self.need_login()
        keys = self.call(p.GET_KEYS, lv(name))
        ed_pk, x_pk = keys[:32], keys[32:]

        pinned = self.pinned()
        if name in pinned:
            old = pinned[name]
            if old["ed25519"] != ed_pk.hex() or old["x25519"] != x_pk.hex():
                raise ClientError(KEY_CHANGED)
        else:
            pinned[name] = {"ed25519": ed_pk.hex(), "x25519": x_pk.hex(), "verified": False}
            save_json(self.local("pinned"), pinned)

        return safety_number((self.username, self.record.ed25519_pk, self.record.x25519_pk),
                             (name, ed_pk, x_pk))

    def verify(self, name):
        #call only after both sides compared the safety number
        pinned = self.pinned()
        if name not in pinned:
            raise ClientError(f"run contact {name} first")
        pinned[name]["verified"] = True
        save_json(self.local("pinned"), pinned)

    def their_keys(self, name):
        #pinned keys of `name`; pins them on first use
        if name == self.username:
            return self.record.ed25519_pk, self.record.x25519_pk, True
        if name not in self.pinned():
            self.contact(name)
        entry = self.pinned()[name]
        return bytes.fromhex(entry["ed25519"]), bytes.fromhex(entry["x25519"]), entry["verified"]

    # documents

    def upload(self, path, doc_id=None, version=1):
        self.need_login()
        path = Path(path)
        data = path.read_bytes()
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"

        doc, dek = encrypt_document(self.username, path.name, mime, data, version, doc_id)
        grant = make_grant(doc, dek, data, self.username, self.keys.ed25519_sk,
                           self.username, self.record.x25519_pk)
        self.call(p.UPLOAD, p.pack(encode_document(doc), encode_grant(grant)))
        return doc.doc_id.hex()

    def update(self, doc_id_hex, path):
        #new version of a document I own
        doc_id = self.resolve(doc_id_hex)
        return self.upload(path, doc_id=doc_id, version=self.latest(doc_id) + 1)

    def list(self):
        self.need_login()
        r = Reader(self.call(p.LIST))
        items = []
        for _ in range(r.u32()):
            items.append({"doc_id": r.take(16).hex(), "version": r.u32(), "owner": r.text(),
                          "filename": r.text(), "size": r.u64(), "timestamp": r.u64()})
        r.done()
        return items

    def resolve(self, prefix):
        #lets the user type the first few characters of a doc id
        matches = [d["doc_id"] for d in self.list() if d["doc_id"].startswith(prefix.lower())]
        if len(matches) != 1:
            raise ClientError("unknown document")
        return bytes.fromhex(matches[0])

    def latest(self, doc_id):
        return max(d["version"] for d in self.list() if d["doc_id"] == doc_id.hex())

    def fetch(self, doc_id, version):
        payload = self.call(p.DOWNLOAD, doc_id + u32(version))
        try:
            doc_bytes, grant_bytes = p.unpack(payload, 2)
            return decode_document(doc_bytes), decode_grant(grant_bytes)
        except FormatError:
            raise Rejected("document was modified")

    def share(self, doc_id_hex, recipient):
        self.need_login()
        doc_id = self.resolve(doc_id_hex)
        _, x_pk, verified = self.their_keys(recipient)
        if not verified:
            raise ClientError(f"verify {recipient} first (compare the safety number)")

        #open my own copy to get the file and its DEK back
        doc, my_grant = self.fetch(doc_id, self.latest(doc_id))
        plaintext, _ = open_document(doc, my_grant, self.username, self.keys.x25519_sk,
                                     self.record.ed25519_pk)
        dek, _ = unwrap_grant(my_grant, self.keys.x25519_sk)

        grant = make_grant(doc, dek, plaintext, self.username, self.keys.ed25519_sk,
                           recipient, x_pk)
        self.call(p.SHARE, encode_grant(grant))

    def download(self, doc_id_hex, out_dir="downloads"):
        #returns (saved path, sender, sender verified?) or raises Rejected
        self.need_login()
        doc_id = self.resolve(doc_id_hex)
        wanted = self.latest(doc_id)
        doc, grant = self.fetch(doc_id, wanted)

        sender_ed_pk, _, verified = self.their_keys(doc.owner)
        seen = self.seen()
        last = seen.get(doc_id.hex())
        last_seen = (last[0], bytes.fromhex(last[1])) if last else None

        plaintext, _ = open_document(doc, grant, self.username, self.keys.x25519_sk,
                                     sender_ed_pk, last_seen)
        #the server said there is a newer one than what we got
        if doc.version < wanted:
            raise Rejected(STALE)

        seen[doc_id.hex()] = [doc.version, fingerprint(doc).hex()]
        save_json(self.local("seen"), seen)

        #only the base name -- a file called "../../x" can't escape the folder
        out = Path(out_dir) / Path(doc.filename).name
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(plaintext)
        return out, doc.owner, verified


# command line

HELP = """commands:
  signup <user>            login <user>           logout
  contact <user>           verify <user>
  upload <file>            update <doc> <file>
  list                     share <doc> <user>     download <doc>
  passwd                   help                   quit
(<doc> = the first few characters of the id shown by list)"""


def shell(client):
    print("SecureVault client -- type help")
    while True:
        try:
            line = input(f"{client.username or 'guest'}> ").split()
        except EOFError:
            break
        if not line:
            continue
        cmd, args = line[0], line[1:]
        try:
            if cmd == "quit":
                break
            elif cmd == "help":
                print(HELP)
            elif cmd == "signup":
                pw = getpass.getpass("new password: ")
                if pw != getpass.getpass("again: "):
                    print("passwords don't match")
                    continue
                client.signup(args[0], pw)
                print(f"account created, logged in as {args[0]}")
            elif cmd == "login":
                client.login(args[0], getpass.getpass("password: "))
                print(f"logged in as {args[0]}")
            elif cmd == "logout":
                client.logout()
                print("logged out, keys wiped from memory")
            elif cmd == "passwd":
                client.passwd(getpass.getpass("old password: "), getpass.getpass("new password: "))
                print("password changed")
            elif cmd == "contact":
                number = client.contact(args[0])
                print(f"safety number with {args[0]}:  {number}")
                print(f"compare it with {args[0]} by phone / in person, then: verify {args[0]}")
            elif cmd == "verify":
                client.verify(args[0])
                print(f"{args[0]} marked as verified")
            elif cmd == "upload":
                print(f"uploaded, id {client.upload(args[0])}")
            elif cmd == "update":
                client.update(args[0], args[1])
                print("new version uploaded")
            elif cmd == "list":
                for d in client.list():
                    print(f"  {d['doc_id'][:8]}  v{d['version']}  {d['filename']}  "
                          f"({d['size']} bytes, from {d['owner']})")
            elif cmd == "share":
                client.share(args[0], args[1])
                print(f"shared with {args[1]}")
            elif cmd == "download":
                path, sender, verified = client.download(args[0])
                print(f"OK: file is intact and was signed by {sender}"
                      f"{'' if verified else ' (NOT verified -- compare safety numbers)'}")
                print(f"saved to {path}")
            else:
                print("unknown command, type help")
        except Rejected as e:
            print(f"Rejected: {e}")
        except (ClientError, ConnectionError) as e:
            print(e)
        except IndexError:
            print("missing argument, type help")
        except FileNotFoundError:
            print("file not found")


def main():
    parser = argparse.ArgumentParser(description="SecureVault client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5050)
    parser.add_argument("--data", default="client_data")
    args = parser.parse_args()

    conn = Connection(args.host, args.port)
    shell(VaultClient(conn.send, args.data))


if __name__ == "__main__":
    main()
