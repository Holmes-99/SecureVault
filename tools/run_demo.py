import os
import sys
import json
import shutil
import tempfile
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from client.client import VaultClient, Connection, ClientError
from secure_share import Rejected
from server.server import VaultServer, TCPServer
from attacks.attacker import Attacker, Proxy
from attacks import weakened_build as weak
from tools.verify_proof import check as check_proof
from tools.show_server_data import readable_ratio
from shared.formats import decode_user, decode_document, decode_grant, decode_request, Reader
from shared import protocol as p

# the whole spec scenario, end to end, over real sockets:
# layla --> attacker proxy --> server <-- attacker proxy <-- omar
# run: python tools/run_demo.py [--wire] [--pause]
#   --wire   show every message the attacker sees on the network
#   --pause  wait for Enter between steps (for presenting)

PINK, GREEN, GREY, RESET = "\033[38;5;218m", "\033[38;5;151m", "\033[38;5;245m", "\033[0m"
WIRE = "--wire" in sys.argv
PAUSE = "--pause" in sys.argv
results = []

NAMES = {p.REGISTER: "REGISTER", p.GET_SALT: "GET_SALT", p.LOGIN_START: "LOGIN_START",
         p.LOGIN_PROOF: "LOGIN_PROOF", p.GET_KEYS: "GET_KEYS", p.UPLOAD: "UPLOAD", p.SHARE: "SHARE",
         p.LIST: "LIST", p.DOWNLOAD: "DOWNLOAD", p.CHANGE_PASSWORD: "CHANGE_PASSWORD"}


def short(data, n=12):
    return data[:n].hex() + ("..." if len(data) > n else "")


class WireTap(Attacker):
    #same attacker, but it also writes down everything it sees
    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self.trace = []

    def on_request(self, frame):
        self.last_body = decode_request(frame).body
        return super().on_request(frame)

    def on_response(self, msg_type, username, frame):
        new = super().on_response(msg_type, username, frame)
        self.trace.append((msg_type, username, self.last_body, frame, new, self.mode))
        return new


def describe(msg_type, user, body, reply, sent, mode):
    status, payload = p.decode_response(sent)
    name = NAMES.get(msg_type, "?")
    lines = []
    if msg_type == p.REGISTER:
        lines.append("user record: salt + auth_key + 2 public keys + encrypted private keys (no password)")
    elif msg_type == p.LOGIN_PROOF:
        lines.append(f"sends HMAC(auth_key, challenge) {short(body)} (the password never travels)")
    elif msg_type == p.GET_KEYS and status == p.OK:
        lines.append(f"reply: public keys of {Reader(body).text()}  ed25519 {short(payload[:32], 6)}  x25519 {short(payload[32:], 6)}")
    elif msg_type == p.UPLOAD:
        doc_bytes, grant_bytes = p.unpack(body, 2)
        doc = decode_document(doc_bytes)
        lines.append(f"document '{doc.filename}' v{doc.version} owner {doc.owner} (metadata readable, can't be changed)")
        lines.append(f"ciphertext {len(doc.ciphertext)} B: {short(doc.ciphertext)}  tag {short(doc.tag, 6)}")
        lines.append("grant for the owner: DEK + signature, encrypted (96 B)")
    elif msg_type == p.SHARE:
        g = decode_grant(body)
        lines.append(f"grant {g.sender} -> {g.recipient}: temp X25519 key {short(g.ephemeral_pk, 6)}, "
                     f"sealed DEK + signature {short(g.sealed, 6)} (only {g.recipient} can open it)")
    elif msg_type == p.DOWNLOAD and status == p.OK:
        doc = decode_document(p.unpack(payload, 2)[0])
        lines.append(f"reply: '{doc.filename}' v{doc.version}, ciphertext {short(doc.ciphertext)} + grant for {user}")
    if status != p.OK:
        lines.append(f"reply: error '{payload.decode()}'")
    if reply != sent:
        lines.append(f"{PINK}!! attacker changed this reply ({mode}){RESET}")
    return name, lines


def flush(tap):
    if not WIRE or tap is None:
        return
    for msg_type, user, body, reply, sent, mode in tap.trace:
        if msg_type == p.LIST:
            continue   #just id lookups
        name, lines = describe(msg_type, user, body, reply, sent, mode)
        print(f"    {GREY}[wire] {user:>6} --> {name}{RESET}")
        for line in lines:
            print(f"    {GREY}         {line}{RESET}")
    tap.trace.clear()


TAP = None


def step(title):
    flush(TAP)
    if PAUSE:
        input(f"\n{GREY}press Enter for the next step...{RESET}")
    print(f"\n{PINK}{title}{RESET}")


def ok(text, passed=True):
    results.append(passed)
    mark = f"{GREEN}✓{RESET}" if passed else f"{PINK}✗ FAILED{RESET}"
    print(f"  {mark} {text}")


def info(text):
    print(f"    {GREY}{text}{RESET}")


def expect_reject(action, expected):
    try:
        action()
    except (Rejected, ClientError) as e:
        return str(e) == expected, str(e)
    return False, "accepted (!)"


def main():
    global TAP
    os.system("")
    work = tempfile.mkdtemp(prefix="securevault_demo_")
    server = TCPServer(("127.0.0.1", 0), VaultServer(os.path.join(work, "server")))
    attacker = TAP = WireTap(server.server_address, quiet=True)
    proxy = Proxy(("127.0.0.1", 0), attacker)
    for s in (server, proxy):
        threading.Thread(target=s.serve_forever, daemon=True).start()

    def client(name):
        return VaultClient(Connection(*proxy.server_address).send, os.path.join(work, f"{name}_pc"))

    thesis = os.path.join(work, "thesis-draft.pdf")
    with open(thesis, "wb") as f:
        f.write(b"%PDF-1.7 CHAPTER ONE: Layla's thesis draft ...")
    out = os.path.join(work, "downloads")

    try:
        step("1. two users sign up and log in (real Argon2id, 384 MiB)")
        layla, omar = client("layla"), client("omar")
        layla.signup("layla", "Layla@BirZeit2026")
        omar.signup("omar", "Omar@2026")
        layla.logout()
        layla.login("layla", "Layla@BirZeit2026")
        ok("layla and omar registered, layla logged back in")
        same, msg = expect_reject(lambda: client("x").login("layla", "wrong"), "Invalid username or password")
        same2, msg2 = expect_reject(lambda: client("x").login("nobody", "wrong"), "Invalid username or password")
        ok("wrong password and unknown user get the same answer", same and same2)

        step("2. the stored credential record reveals nothing")
        record = open(os.path.join(work, "server", "users", "layla.bin"), "rb").read()
        user = decode_user(record)
        info(f"salt     {user.salt.hex()}")
        info(f"auth_key {user.auth_key.hex()}")
        ok("no password in the record", b"Layla@BirZeit2026" not in record)

        step("3. upload: the server's copy is unreadable")
        doc_id = layla.upload(thesis)
        stored = open(os.path.join(work, "server", "docs", doc_id, "v1.bin"), "rb").read()
        doc = decode_document(stored)
        info(f"ciphertext {doc.ciphertext[:24].hex()} ...")
        ok(f"file text not in the stored copy ({readable_ratio(doc.ciphertext):.0%} of bytes look like text)",
           b"CHAPTER ONE" not in stored)

        step("4. share with omar, omar downloads")
        n1, n2 = layla.contact("omar"), omar.contact("layla")
        info(f"safety number  layla: {n1}   omar: {n2}")
        ok("both see the same safety number", n1 == n2)
        blocked, msg = expect_reject(lambda: layla.share(doc_id, "omar"), "")
        ok("sharing refused before verifying", "verify omar first" in msg)
        layla.verify("omar"), omar.verify("layla")
        layla.share(doc_id, "omar")
        path, sender, verified = omar.download(doc_id, out)
        ok("omar opened the file, content identical", open(path, "rb").read() == open(thesis, "rb").read())

        step("5. who sent it, provable to a third party")
        ok(f"client reports: signed by {sender} (verified contact: {verified})", sender == "layla" and verified)
        proof_path = omar.prove(doc_id, out)
        proof = json.load(open(proof_path, encoding="utf-8"))
        ok("third party checks the proof: valid", check_proof(proof, open(path, "rb").read()))
        ok("same proof with a changed file: invalid", not check_proof(proof, b"changed"))

        step("6. attacker flips one ciphertext byte")
        attacker.mode = "flip"
        good, msg = expect_reject(lambda: omar.download(doc_id, out), "document was modified")
        ok(f"rejected: {msg}", good)

        step("7. attacker changes the file name in the metadata")
        attacker.mode = "rename"
        good, msg = expect_reject(lambda: omar.download(doc_id, out), "document was modified")
        ok(f"rejected: {msg}", good)

        step("8. attacker replays yesterday's copy")
        attacker.mode = "pass"
        with open(thesis, "wb") as f:
            f.write(b"%PDF-1.7 fixed version")
        layla.update(doc_id, thesis)
        layla.share(doc_id, "omar")
        omar.download(doc_id, out)
        info("omar now has v2; the attacker recorded v1 earlier")
        attacker.mode = "replay"
        good, msg = expect_reject(lambda: omar.download(doc_id, out), "stale version")
        ok(f"rejected: {msg}", good)

        step("+ man-in-the-middle on public keys")
        attacker.mode = "swapkey"
        sara = client("sara")
        sara.signup("sara", "Sara@2026")
        fake = sara.contact("omar")
        attacker.mode = "pass"
        real = omar.contact("sara")
        ok("swapped key --> the two safety numbers differ", fake != real)
        attacker.mode = "swapkey"
        good, msg = expect_reject(lambda: layla.contact("omar"), "Blocked: key changed")
        ok(f"swapped after pinning --> {msg}", good)

        step("+ attacker replays a captured request to the server")
        attacker.mode = "pass"
        layla.list()
        answer = attacker.resend()
        ok(f"server says: {answer}", answer == "Request rejected")

        step("+ weakened build (bonus)")
        key = os.urandom(32)
        known, secret = b"known file known file known file", b"SECRET exam answers Q1=B Q2=D !!"
        c1, _ = weak.weak_encrypt_reused_nonce(key, known)
        c2, _ = weak.weak_encrypt_reused_nonce(key, secret)
        ok("reused nonce: attacker recovers the secret file", weak.attack_keystream_reuse(c1, known, c2) == secret)
        r1, _ = weak.real_encrypt(known)
        r2, _ = weak.real_encrypt(secret)
        ok("our build: same attack gets nothing", weak.attack_keystream_reuse(r1, known, r2) != secret)
    finally:
        for s in (server, proxy):
            s.shutdown()
            s.server_close()
        shutil.rmtree(work, ignore_errors=True)

    flush(TAP)
    passed = sum(results)
    color = GREEN if passed == len(results) else PINK
    print(f"\n{color}{passed}/{len(results)} checks passed{RESET}")
    print(f"{GREY}9. the primitives: python -m pytest tests{RESET}\n")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
