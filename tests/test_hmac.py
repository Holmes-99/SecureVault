# test_hmac.py
# hmac module allowed ONLY here for verification, never in production code

import hmac
import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

from crypto.hmac_sha256 import hmac_sha256, hmac_sha256_hex


def ref(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()


#official test vectors

def test_vector_1():
    # key shorter than block size
    key = b'\x0b' * 20
    msg = b"Hi There"
    assert hmac_sha256(key, msg) == ref(key, msg)

def test_vector_2():
    key = b"Jefe"
    msg = b"what do ya want for nothing?"
    assert hmac_sha256(key, msg) == ref(key, msg)

def test_vector_3():
    key = b'\xaa' * 20
    msg = b'\xdd' * 50
    assert hmac_sha256(key, msg) == ref(key, msg)

def test_vector_4():
    key = bytes(range(1, 26))  # 0x01 to 0x19
    msg = b'\xcd' * 50
    assert hmac_sha256(key, msg) == ref(key, msg)


#key size edge cases 

def test_key_longer_than_block_size():
    # key > 64 bytes gets hashed first
    key = os.urandom(100)
    msg = b"test message"
    assert hmac_sha256(key, msg) == ref(key, msg)

def test_key_exactly_block_size():
    key = os.urandom(64)
    msg = b"test message"
    assert hmac_sha256(key, msg) == ref(key, msg)

def test_key_shorter_than_block_size():
    key = os.urandom(16)
    msg = b"test message"
    assert hmac_sha256(key, msg) == ref(key, msg)

def test_empty_message():
    key = os.urandom(32)
    assert hmac_sha256(key, b"") == ref(key, b"")

def test_empty_key():
    msg = b"test message"
    assert hmac_sha256(b"", msg) == ref(b"", msg)




def test_output_is_32_bytes():
    assert len(hmac_sha256(b"key", b"msg")) == 32

def test_output_is_bytes():
    assert isinstance(hmac_sha256(b"key", b"msg"), bytes)

def test_different_keys_give_different_tags():
    msg = b"same message"
    tag1 = hmac_sha256(b"key1", msg)
    tag2 = hmac_sha256(b"key2", msg)
    assert tag1 != tag2

def test_different_messages_give_different_tags():
    key = b"same key"
    tag1 = hmac_sha256(key, b"message1")
    tag2 = hmac_sha256(key, b"message2")
    assert tag1 != tag2

def test_deterministic():
    key = b"mykey"
    msg = b"mymessage"
    assert hmac_sha256(key, msg) == hmac_sha256(key, msg)


# check 100 random inputs 

def test_random_inputs_match_stdlib():
    for _ in range(100):
        key = os.urandom(int.from_bytes(os.urandom(1), 'big') % 100 + 1)
        msg = os.urandom(int.from_bytes(os.urandom(2), 'big') % 500)
        assert hmac_sha256(key, msg) == ref(key, msg)



def test_hkdf_extract_use_case():
    salt = os.urandom(32)
    shared_secret = os.urandom(32)
    prk = hmac_sha256(salt, shared_secret)  
    assert len(prk) == 32
    assert prk == ref(salt, shared_secret)

def test_argon2_mixing_use_case():
    key = os.urandom(32)
    block_data = os.urandom(1024)
    tag = hmac_sha256(key, block_data)
    assert len(tag) == 32
    assert tag == ref(key, block_data)