import os
import sys
import socket
import argparse
import threading
import socketserver

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client')) #crypto/

from crypto import x25519, ed25519
from shared.formats import decode_request, decode_document, encode_document, FormatError
from shared import protocol as p

# ============================================================
#   ATTACKER -- FOR THE DEMO ONLY
#   a network attacker that sits between our client and OUR
#   OWN local server. never point it at anything else.
# ============================================================
#
# flow
# client --> attacker (:5051) --> server (:5050)
#        <-- attacker changes the answer here <--
#
# modes
#   pass     forward everything untouched
#   flip     flip one byte of the downloaded ciphertext     (demo 6)
#   rename   change the file name in the metadata           (demo 7)
#   replay   answer with an older copy it recorded before   (demo 8)
#   swapkey  hand out the attacker's keys instead (MITM)    (key trust)
# command
#   resend   send the last captured signed request again    (server freshness)

MODES = ["pass", "flip", "rename", "replay", "swapkey"]


class Attacker:
    def __init__(self, target, quiet=False):
        self.target = target
        self.mode = "pass"
        self.quiet = quiet
        self.lock = threading.Lock()
        self.recorded = {}        #(user, doc_id) -> {version: download answer}
        self.last_signed = None   #last signed request seen on the wire

        #the attacker's own keys, used for the swap
        self.fake_ed_pk = ed25519.public_key(ed25519.generate_private_key())
        self.fake_x_pk = x25519.public_key(x25519.generate_private_key())

    def log(self, text):
        if not self.quiet:
            print(f"[attacker] {text}")

    # look at the request on its way to the server

    def on_request(self, frame):
        try:
            req = decode_request(frame)
        except FormatError:
            return None, None
        if req.msg_type not in p.UNSIGNED:
            with self.lock:
                self.last_signed = frame   #captured, can be replayed later
        return req.msg_type, req.username

    # change the answer on its way back

    def on_response(self, msg_type, username, frame):
        status, payload = p.decode_response(frame)
        if status != p.OK:
            return frame

        with self.lock:
            mode = self.mode
            if msg_type == p.DOWNLOAD:
                payload = self.attack_download(mode, username, payload)
            elif msg_type == p.GET_KEYS and mode == "swapkey":
                self.log("swapped the public keys for the attacker's own")
                payload = self.fake_ed_pk + self.fake_x_pk

        return p.encode_response(status, payload)

    def attack_download(self, mode, username, payload):
        doc_bytes, grant_bytes = p.unpack(payload, 2)
        doc = decode_document(doc_bytes)

        #always record what passes by (each user's copy has their own grant)
        copies = self.recorded.setdefault((username, doc.doc_id), {})
        copies.setdefault(doc.version, payload)

        if mode == "flip":
            b = bytearray(doc.ciphertext or doc.tag)
            b[0] ^= 0x01
            if doc.ciphertext:
                doc.ciphertext = bytes(b)
            else:
                doc.tag = bytes(b)
            self.log(f"flipped one byte of '{doc.filename}'")
            return p.pack(encode_document(doc), grant_bytes)

        if mode == "rename":
            old = doc.filename
            doc.filename = "final-approved.pdf"
            self.log(f"renamed '{old}' --> '{doc.filename}'")
            return p.pack(encode_document(doc), grant_bytes)

        if mode == "replay":
            oldest = min(copies)
            if oldest < doc.version:
                self.log(f"replayed old v{oldest} instead of v{doc.version}")
                return copies[oldest]

        return payload

    # replay a captured request straight to the server

    def resend(self):
        with self.lock:
            frame = self.last_signed
        if frame is None:
            return "nothing captured yet"
        with socket.create_connection(self.target) as s:
            s.sendall(frame)
            status, payload = p.decode_response(p.recv_frame(s))
        answer = "accepted" if status == p.OK else payload.decode('utf-8', 'replace')
        self.log(f"resent a captured request --> server says: {answer}")
        return answer


# network: one upstream connection per client connection

class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        attacker = self.server.attacker
        try:
            with socket.create_connection(attacker.target) as upstream:
                while True:
                    frame = p.recv_frame(self.request)
                    msg_type, username = attacker.on_request(frame)
                    upstream.sendall(frame)
                    answer = p.recv_frame(upstream)
                    self.request.sendall(attacker.on_response(msg_type, username, answer))
        except (ConnectionError, FormatError, OSError):
            pass


class Proxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, attacker):
        super().__init__(address, ProxyHandler)
        self.attacker = attacker


def main():
    parser = argparse.ArgumentParser(description="SecureVault ATTACKER (demo only)")
    parser.add_argument("--listen", type=int, default=5051)
    parser.add_argument("--server-port", type=int, default=5050)
    args = parser.parse_args()

    attacker = Attacker(("127.0.0.1", args.server_port))
    proxy = Proxy(("127.0.0.1", args.listen), attacker)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()

    print(f"ATTACKER listening on :{args.listen} --> server :{args.server_port}")
    print(f"modes: {', '.join(MODES)}   commands: mode <m>, resend, quit")
    while True:
        try:
            line = input(f"attacker[{attacker.mode}]> ").split()
        except EOFError:
            break
        if not line:
            continue
        if line[0] == "quit":
            break
        elif line[0] == "mode" and len(line) == 2 and line[1] in MODES:
            attacker.mode = line[1]
        elif line[0] == "resend":
            attacker.resend()
        else:
            print(f"modes: {', '.join(MODES)}   commands: mode <m>, resend, quit")
    proxy.shutdown()


if __name__ == "__main__":
    main()
