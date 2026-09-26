import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__)) #client/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from crypto.gcm import gcm_encrypt, gcm_decrypt
from crypto.sha256 import sha256
from crypto.hkdf import hkdf
from crypto import x25519, ed25519
from shared.formats import (Document, KeyGrant, document_header, grant_header,
                            signed_statement, encode_document)

# flow 
# upload: plaintext --> AES-GCM --> Document
# share:  sign --> X25519 + HKDF --> wrap key --> KeyGrant
# open:   unwrap grant --> decrypt --> verify --> check version
#         return only if all checks pass

GRANT_INFO = b"SecureVault key grant v1"

#the only three messages a user ever sees
MODIFIED = "document was modified"
BAD_SENDER = "sender could not be verified"
STALE      = "stale version"


class Rejected(Exception):
    pass


# sender's side

def encrypt_document(owner, filename, mime, plaintext, version=1, doc_id=None):
    #a brand-new random DEK for every document version
    dek = os.urandom(32)
    doc = Document(doc_id=doc_id or os.urandom(16), owner=owner, filename=filename,
                   mime=mime, size=len(plaintext), timestamp=int(time.time()),
                   version=version)
    doc.nonce = os.urandom(12)
    #metadata goes in as AAD
    doc.ciphertext, doc.tag = gcm_encrypt(dek, doc.nonce, plaintext, document_header(doc))
    return doc, dek


def _wrap_key(shared, ephemeral_pk, recipient_pk):
    #HKDF cleans X25519 output into a proper AES key
    return hkdf(shared, ephemeral_pk + recipient_pk, GRANT_INFO, 32)


def make_grant(doc, dek, plaintext, sender, sender_ed25519_sk, recipient, recipient_x25519_pk):
    # sign: hash of the file + hash of the metadata + who it is for
    statement = signed_statement(doc.doc_id, doc.version, sender, recipient,
                                 sha256(document_header(doc)), sha256(plaintext))
    signature = ed25519.sign(sender_ed25519_sk, statement)

    # diffie-hellman with a temporary key -> a secret only the recipient can rebuild
    ephemeral_sk = x25519.generate_private_key()
    ephemeral_pk = x25519.public_key(ephemeral_sk)
    shared = x25519.shared_secret(ephemeral_sk, recipient_x25519_pk)
    wrap_key = _wrap_key(shared, ephemeral_pk, recipient_x25519_pk)

    # lock the DEK and the signature together (so the server never sees the signature)
    grant = KeyGrant(doc_id=doc.doc_id, version=doc.version, sender=sender,
                     recipient=recipient, ephemeral_pk=ephemeral_pk)
    grant.nonce = os.urandom(12)
    grant.sealed, grant.tag = gcm_encrypt(wrap_key, grant.nonce, dek + signature, grant_header(grant))
    return grant


# recipient's side

def open_document(doc, grant, my_username, my_x25519_sk, sender_ed25519_pk, last_seen=None):
    #returns (plaintext, signature) or raises a rejection with a message
    #last_seen = (version, fingerprint) of the newest copy this client already accepted

    #the grant must belong to all of these
    if (grant.doc_id != doc.doc_id or grant.version != doc.version or
            grant.sender != doc.owner or grant.recipient != my_username):
        raise Rejected(MODIFIED)

    #unwrap the DEK +signature
    try:
        shared = x25519.shared_secret(my_x25519_sk, grant.ephemeral_pk)
        my_pk = x25519.public_key(my_x25519_sk)
        wrap_key = _wrap_key(shared, grant.ephemeral_pk, my_pk)
        sealed = gcm_decrypt(wrap_key, grant.nonce, grant.sealed, grant.tag, grant_header(grant))
    except ValueError:
        raise Rejected(MODIFIED)
    dek, signature = sealed[:32], sealed[32:]

    #decrypt 
    try:
        plaintext = gcm_decrypt(dek, doc.nonce, doc.ciphertext, doc.tag, document_header(doc))
    except ValueError:
        raise Rejected(MODIFIED)

    #who really wrote it? checked with the sender's pinned public key
    statement = signed_statement(doc.doc_id, doc.version, grant.sender, my_username,
                                 sha256(document_header(doc)), sha256(plaintext))
    if not ed25519.verify(sender_ed25519_pk, statement, signature):
        raise Rejected(BAD_SENDER)

    #genuine -- but is it older than what we already have?
    check_fresh(doc, last_seen)

    return plaintext, signature


def fingerprint(doc):
    #identifies one exact stored object
    return sha256(encode_document(doc))


def check_fresh(doc, last_seen):
    #older version -> stale; same version is fine only if it is the very same object
    if last_seen is None:
        return
    last_version, last_fingerprint = last_seen
    if doc.version < last_version:
        raise Rejected(STALE)
    if doc.version == last_version and fingerprint(doc) != last_fingerprint:
        raise Rejected(STALE)


# --- proof for a third party (non-repudiation) ---

def verify_authorship(plaintext, doc, recipient, signature, sender_ed25519_pk):
    #anyone holding the plaintext, the metadata and the signature can check
    #that the sender signed THIS file for THIS recipient
    statement = signed_statement(doc.doc_id, doc.version, doc.owner, recipient,
                                 sha256(document_header(doc)), sha256(plaintext))
    return ed25519.verify(sender_ed25519_pk, statement, signature)
