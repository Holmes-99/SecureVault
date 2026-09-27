import os
import sys
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

from secure_share import verify_authorship
from shared.formats import decode_document, FormatError
from crypto.sha256 import sha256

# third party checks "the sender signed THIS file for THIS recipient" (non-repudiation)
# needs no account, no server, no secret -- only the proof, the file and the sender's public key
# run: python tools/verify_proof.py <file.proof.json> <file>


def check(proof, plaintext):
    try:
        doc = decode_document(bytes.fromhex(proof["document"]))
        return verify_authorship(plaintext, doc, proof["recipient"],
                                 bytes.fromhex(proof["signature"]),
                                 bytes.fromhex(proof["sender_ed25519"]))
    except (KeyError, ValueError, FormatError):
        return False


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: python tools/verify_proof.py <file.proof.json> <file>")
    proof = json.load(open(sys.argv[1], encoding="utf-8"))
    plaintext = open(sys.argv[2], "rb").read()

    if check(proof, plaintext):
        print(f"VALID: {proof['sender']} signed this exact file for {proof['recipient']}")
        #the key must really be the sender's -- confirm it with them, not with the server
        print(f"sender key fingerprint: {sha256(bytes.fromhex(proof['sender_ed25519'])).hex()[:20]}")
    else:
        print("INVALID: the file, metadata or signature does not match")
        sys.exit(1)
