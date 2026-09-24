import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

import pytest
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from crypto.password_hash import hash_password, verify_password, new_salt

#small costs so the tests run fast -- they check behaviour, not strength
FAST = dict(time_cost=1, memory_cost=64, parallelism=1)


def test_rfc9106_vector_on_reference():
    #RFC 9106 section 5.3 -- proves the reference we compare against is real Argon2id
    kdf = Argon2id(salt=b'\x02' * 16, length=32, iterations=3, lanes=4,
                   memory_cost=32, ad=b'\x04' * 12, secret=b'\x03' * 8)
    tag = kdf.derive(b'\x01' * 32)
    assert tag.hex() == "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"


def test_matches_reference_implementation():
    salt = b'fixedsalt1234567'
    for pw in [b'', b'password', b'x' * 100]:
        ref = Argon2id(salt=salt, length=32, iterations=2, lanes=2, memory_cost=128).derive(pw)
        ours = hash_password(pw, salt, time_cost=2, memory_cost=128, parallelism=2)
        assert ours == ref


def test_output_is_32_bytes():
    assert len(hash_password(b'password', new_salt(), **FAST)) == 32

def test_same_inputs_same_output():
    salt = new_salt()
    assert hash_password(b'password', salt, **FAST) == hash_password(b'password', salt, **FAST)

def test_same_password_different_salts():
    #two users with the same password must not look identical
    assert hash_password(b'password', new_salt(), **FAST) != hash_password(b'password', new_salt(), **FAST)

def test_salts_are_random_and_16_bytes():
    a, b = new_salt(), new_salt()
    assert len(a) == 16 and a != b

def test_verify_correct_and_wrong_password():
    salt = new_salt()
    stored = hash_password(b'mypassword', salt, **FAST)
    assert verify_password(b'mypassword', salt, stored, **FAST) is True
    assert verify_password(b'wrongpassword', salt, stored, **FAST) is False

def test_short_salt_rejected():
    with pytest.raises(ValueError):
        hash_password(b'password', b'short', **FAST)

def test_password_must_be_bytes():
    with pytest.raises(TypeError):
        hash_password('password', new_salt(), **FAST)
