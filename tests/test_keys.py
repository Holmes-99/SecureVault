import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

import pytest
import keys
from keys import (derive_keys, create_account, open_account, change_password,
                  unlock_private_keys, login_proof)
from crypto import x25519, ed25519


@pytest.fixture(autouse=True)
def fast_argon2(monkeypatch):
    #small costs so tests run fast -- they check behaviour, not strength
    monkeypatch.setattr(keys, "ARGON2", dict(time_cost=1, memory_cost=64, parallelism=1))


# derive_keys

def test_auth_and_enc_keys_differ():
    auth_key, enc_key = derive_keys("Layla@2026", os.urandom(16))
    assert auth_key != enc_key
    assert len(auth_key) == len(enc_key) == 32

def test_same_password_same_salt_same_keys():
    salt = os.urandom(16)
    assert derive_keys("Layla@2026", salt) == derive_keys("Layla@2026", salt)

def test_same_password_different_salt_different_keys():
    assert derive_keys("Layla@2026", os.urandom(16)) != derive_keys("Layla@2026", os.urandom(16))


# sign-up

def test_record_holds_matching_public_keys():
    record, priv = create_account("layla", "Layla@2026")
    assert record.x25519_pk == x25519.public_key(priv.x25519_sk)
    assert record.ed25519_pk == ed25519.public_key(priv.ed25519_sk)

def test_record_reveals_no_private_key_or_password():
    record, priv = create_account("layla", "Layla@2026")
    everything = record.salt + record.auth_key + record.key_blob
    assert priv.x25519_sk not in everything
    assert priv.ed25519_sk not in everything
    assert b"Layla@2026" not in everything

def test_two_users_same_password_look_different():
    a, _ = create_account("layla", "samepass")
    b, _ = create_account("omar", "samepass")
    assert a.salt != b.salt and a.auth_key != b.auth_key


# login / unlocking

def test_right_password_unlocks_keys():
    record, priv = create_account("layla", "Layla@2026")
    assert open_account("layla", "Layla@2026", record.salt, record.key_blob) == priv

def test_wrong_password_fails():
    record, _ = create_account("layla", "Layla@2026")
    with pytest.raises(ValueError):
        open_account("layla", "wrong", record.salt, record.key_blob)

def test_tampered_blob_fails():
    record, _ = create_account("layla", "Layla@2026")
    blob = bytearray(record.key_blob)
    blob[20] ^= 0x01
    with pytest.raises(ValueError):
        open_account("layla", "Layla@2026", record.salt, bytes(blob))

def test_blob_moved_to_other_user_fails():
    #the blob is bound to the username through the AAD
    record, _ = create_account("layla", "Layla@2026")
    _, enc_key = derive_keys("Layla@2026", record.salt)
    with pytest.raises(ValueError):
        unlock_private_keys("omar", enc_key, record.key_blob)

def test_auth_key_cannot_unlock_blob():
    #the server holds auth_key -- it must not open the private keys
    record, _ = create_account("layla", "Layla@2026")
    with pytest.raises(ValueError):
        unlock_private_keys("layla", record.auth_key, record.key_blob)


# password change

def test_change_password():
    record, priv = create_account("layla", "old-pass")
    new = change_password(record, "old-pass", "new-pass")

    #same identity, new lock
    assert new.x25519_pk == record.x25519_pk and new.ed25519_pk == record.ed25519_pk
    assert new.salt != record.salt and new.auth_key != record.auth_key

    assert open_account("layla", "new-pass", new.salt, new.key_blob) == priv
    with pytest.raises(ValueError):
        open_account("layla", "old-pass", new.salt, new.key_blob)

def test_change_password_needs_old_password():
    record, _ = create_account("layla", "old-pass")
    with pytest.raises(ValueError):
        change_password(record, "not-the-old-pass", "new-pass")


# login challenge

def test_login_proof_changes_with_challenge():
    auth_key, _ = derive_keys("Layla@2026", os.urandom(16))
    assert login_proof(auth_key, os.urandom(32)) != login_proof(auth_key, os.urandom(32))

def test_login_proof_depends_on_password():
    salt, challenge = os.urandom(16), os.urandom(32)
    right, _ = derive_keys("Layla@2026", salt)
    wrong, _ = derive_keys("wrong", salt)
    assert login_proof(right, challenge) != login_proof(wrong, challenge)
