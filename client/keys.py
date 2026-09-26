import os
import sys
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(__file__))                        #client/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))   #project root

from crypto.password_hash import hash_password, new_salt
from crypto.hkdf import hkdf
from crypto.hmac_sha256 import hmac_sha256
from crypto.gcm import gcm_encrypt, gcm_decrypt
from crypto import x25519, ed25519
from shared.formats import UserRecord, lv

ARGON2 = {}

AUTH_INFO = b"SecureVault auth key v1"
ENC_INFO = b"SecureVault enc key v1"
LOGIN_LABEL = b"SecureVault login v1"
BLOB_LABEL = b"SVU1"


@dataclass
class PrivateKeys:
    x25519_sk: bytes     #32, for receiving documents
    ed25519_sk: bytes    #32, for signing


def derive_keys(password, salt):
    #one slow Argon2id, then HKDF splits it into two unrelated keys
    if isinstance(password, str):
        password = password.encode('utf-8')
    master = hash_password(password, salt, **ARGON2)
    auth_key = hkdf(master, b"", AUTH_INFO, 32)
    enc_key = hkdf(master, b"", ENC_INFO, 32)
    return auth_key, enc_key


def _blob_aad(username):
    #binds the locked keys to this user: a blob moved to another account won't open
    return BLOB_LABEL + lv(username)


def lock_private_keys(username, enc_key, keys):
    nonce = os.urandom(12)
    ct, tag = gcm_encrypt(enc_key, nonce, keys.x25519_sk + keys.ed25519_sk, _blob_aad(username))
    return nonce + ct + tag


def unlock_private_keys(username, enc_key, blob):
    #raises ValueError on a wrong password or a changed blob
    if len(blob) != 12 + 64 + 16:
        raise ValueError("bad key blob")
    nonce, ct, tag = blob[:12], blob[12:76], blob[76:]
    plain = gcm_decrypt(enc_key, nonce, ct, tag, _blob_aad(username))
    return PrivateKeys(x25519_sk=plain[:32], ed25519_sk=plain[32:])


def create_account(username, password):
    #sign-up: make the user's keys and the record the server will store
    keys = PrivateKeys(x25519_sk=x25519.generate_private_key(),
                       ed25519_sk=ed25519.generate_private_key())
    salt = new_salt()
    auth_key, enc_key = derive_keys(password, salt)

    record = UserRecord(username=username, salt=salt, auth_key=auth_key,
                        x25519_pk=x25519.public_key(keys.x25519_sk),
                        ed25519_pk=ed25519.public_key(keys.ed25519_sk),
                        key_blob=lock_private_keys(username, enc_key, keys))
    return record, keys


def open_account(username, password, salt, blob):
    #login on any machine: the password alone gets the private keys back
    _, enc_key = derive_keys(password, salt)
    return unlock_private_keys(username, enc_key, blob)


def change_password(record, old_password, new_password):
    #only the outer lock changes: same private keys, new salt / auth_key / blob
    keys = open_account(record.username, old_password, record.salt, record.key_blob)

    salt = new_salt()
    auth_key, enc_key = derive_keys(new_password, salt)

    return UserRecord(username=record.username, salt=salt, auth_key=auth_key,
                      x25519_pk=record.x25519_pk, ed25519_pk=record.ed25519_pk,
                      key_blob=lock_private_keys(record.username, enc_key, keys))


def login_proof(auth_key, challenge):
    #answer to the server's random challenge -- a new challenge means a new answer
    return hmac_sha256(auth_key, LOGIN_LABEL + challenge)
