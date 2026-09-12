import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

from crypto.sha256 import sha256, sha256_hex

def test_empty_string():
    assert sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

def test_abc():
    # verified against hashlib — correct vector
    assert sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256(b"abc") == hashlib.sha256(b"abc").digest()

def test_448_bit_message():
    msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    assert sha256_hex(msg) == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    assert sha256(msg) == hashlib.sha256(msg).digest()

def test_one_million_a():
    msg = b"a" * 1_000_000
    assert sha256(msg) == hashlib.sha256(msg).digest()

def test_quick_brown_fox():
    msg = b"The quick brown fox jumps over the lazy dog"
    assert sha256(msg) == hashlib.sha256(msg).digest()

def test_quick_brown_fox_period():
    msg1 = b"The quick brown fox jumps over the lazy dog"
    msg2 = b"The quick brown fox jumps over the lazy dog."
    assert sha256(msg1) != sha256(msg2)
    assert sha256(msg2) == hashlib.sha256(msg2).digest()

# output properties 
def test_output_length_always_32_bytes():
    for length in [0, 1, 15, 16, 55, 56, 63, 64, 65, 128, 1000]:
        msg = os.urandom(length)
        assert len(sha256(msg)) == 32

def test_output_is_bytes():
    assert isinstance(sha256(b"hello"), bytes)

def test_deterministic():
    msg = b"SecureVault test"
    assert sha256(msg) == sha256(msg)

def test_single_bit_change_avalanche():
    # changing 1 char should flip ~50% of output bits
    h1 = sha256(b"SecureVault")
    h2 = sha256(b"SecureVaulT")
    differing_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(h1, h2))
    assert 80 <= differing_bits <= 176


# cross-check 100 random inputs against hashlib

def test_random_inputs_match_hashlib():
    for _ in range(100):
        length = int.from_bytes(os.urandom(2), 'big') % 500
        msg = os.urandom(length)
        assert sha256(msg) == hashlib.sha256(msg).digest()


#  edge cases 

def test_single_byte_inputs():
    for byte_val in range(256):
        msg = bytes([byte_val])
        assert sha256(msg) == hashlib.sha256(msg).digest()

def test_exactly_55_and_56_bytes():
    # 55 = last length that fits in one block, 56 forces an extra block
    for msg in [b"a" * 55, b"a" * 56]:
        assert sha256(msg) == hashlib.sha256(msg).digest()

def test_binary_data():
    msg = bytes(range(256))
    assert sha256(msg) == hashlib.sha256(msg).digest()

def test_large_input():
    msg = b"x" * (10 * 1024 * 1024)
    assert sha256(msg) == hashlib.sha256(msg).digest()


# --- securevault use cases ---

def test_password_hashing_use_case():
    # how sha256 gets used inside argon2id
    password = b"Layla@BirZeit2026"
    salt = os.urandom(16)
    result = sha256(salt + password)
    assert len(result) == 32
    assert result == hashlib.sha256(salt + password).digest()

def test_document_signing_use_case():
    # how sha256 gets used inside ecdsa before signing
    ciphertext = os.urandom(1024)
    aad = b'{"filename": "thesis.pdf", "size": 1024, "owner": "layla"}'
    digest = sha256(ciphertext + aad)
    assert len(digest) == 32
    assert digest == hashlib.sha256(ciphertext + aad).digest()