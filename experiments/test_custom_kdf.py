import os
import sys
sys.path.insert(0, os.path.dirname(__file__))

import pytest
import custom_kdf as _argon2
from custom_kdf import argon2id_verify

#the pure-python implementation takes ~30s per hash at default params,
#so tests use minimal costs -- they check behaviour, not strength
FAST = dict(time_cost=1, memory_cost=8)

def argon2id(password, salt, **kw):
    return _argon2.argon2id(password, salt, **{**FAST, **kw})

def argon2id_encode(password, **kw):
    return _argon2.argon2id_encode(password, **{**FAST, **kw})


def test_output_is_32_bytes():
    h = argon2id(b'password', b'saltsaltsalt1234')
    assert len(h) == 32

def test_custom_hash_len():
    h = argon2id(b'password', b'saltsaltsalt1234', hash_len=64)
    assert len(h) == 64

def test_same_inputs_same_output():
    salt = b'fixedsalt1234567'
    h1 = argon2id(b'password', salt)
    h2 = argon2id(b'password', salt)
    assert h1 == h2

def test_different_passwords_different_output():
    salt = b'fixedsalt1234567'
    h1 = argon2id(b'password1', salt)
    h2 = argon2id(b'password2', salt)
    assert h1 != h2

def test_different_salts_different_output():
    h1 = argon2id(b'password', b'saltsaltsalt1111')
    h2 = argon2id(b'password', b'saltsaltsalt2222')
    assert h1 != h2

def test_output_is_bytes():
    h = argon2id(b'password', b'saltsaltsalt1234')
    assert isinstance(h, bytes)

def test_encode_returns_string():
    encoded = argon2id_encode(b'password')
    assert isinstance(encoded, str)

def test_encode_starts_with_prefix():
    encoded = argon2id_encode(b'password')
    assert encoded.startswith('$sv-kdf$')

def test_verify_correct_password():
    encoded = argon2id_encode(b'mypassword')
    assert argon2id_verify(b'mypassword', encoded) is True

def test_verify_wrong_password():
    encoded = argon2id_encode(b'mypassword')
    assert argon2id_verify(b'wrongpassword', encoded) is False

def test_verify_empty_password():
    encoded = argon2id_encode(b'')
    assert argon2id_verify(b'', encoded) is True
    assert argon2id_verify(b'notempty', encoded) is False

def test_two_encodes_same_password_different_salts():
    #each call generates a fresh random salt
    h1 = argon2id_encode(b'password')
    h2 = argon2id_encode(b'password')
    assert h1 != h2
    #but both verify correctly
    assert argon2id_verify(b'password', h1) is True
    assert argon2id_verify(b'password', h2) is True

def test_encode_with_fixed_salt():
    salt = b'fixedsalt1234567'
    h1 = argon2id_encode(b'password', salt=salt)
    h2 =  argon2id_encode(b'password', salt=salt)
    assert h1 == h2

def test_different_time_cost_different_output():
    salt = b'fixedsalt1234567'
    h1 = argon2id(b'password', salt, time_cost=1)
    h2 = argon2id(b'password', salt, time_cost=2)
    assert h1 != h2

def test_different_memory_cost_different_output():
    salt = b'fixedsalt1234567'
    h1 = argon2id(b'password', salt, memory_cost=8)
    h2 = argon2id(b'password', salt, memory_cost=16)
    assert h1 != h2

def test_encoded_params_roundtrip():
    #verify that params encoded correctly
    encoded = argon2id_encode(b'pass', time_cost=2, memory_cost=8)
    assert 't=2' in encoded
    assert 'm=8' in encoded
    assert argon2id_verify(b'pass', encoded) is True

def test_wrong_password_returns_false_not_raises():
    encoded = argon2id_encode(b'realpassword')
    result = argon2id_verify(b'fakepassword', encoded)
    assert result is False

def test_salt_too_short_raises():
    with pytest.raises(AssertionError):
        argon2id(b'password', b'short')

def test_password_must_be_bytes():
    with pytest.raises(AssertionError):
        argon2id('password', b'saltsaltsalt1234')  # str not bytes