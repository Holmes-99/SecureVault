import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

from crypto.sha512 import sha512, sha512_hex

# NIST vectors 

def test_empty_string():
    assert sha512_hex(b"") == (
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")

def test_abc():
    assert sha512_hex(b"abc") == (
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")

def test_896_bit_message():
    msg = (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
           b"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
    assert sha512_hex(msg) == (
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
        "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909")

def test_one_million_a():
    msg = b"a" * 1_000_000
    assert sha512(msg) == hashlib.sha512(msg).digest()

# output properties

def test_output_length_always_64_bytes():
    for length in [0, 1, 111, 112, 127, 128, 129, 1000]:
        assert len(sha512(os.urandom(length))) == 64

def test_single_bit_change_avalanche():
    # changing 1 char should flip ~50% of the 512 output bits
    h1 = sha512(b"SecureVault")
    h2 = sha512(b"SecureVaulT")
    differing_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(h1, h2))
    assert 192 <= differing_bits <= 320

# cross-check random inputs against hashlib

def test_random_inputs_match_hashlib():
    for _ in range(100):
        length = int.from_bytes(os.urandom(2), 'big') % 600
        msg = os.urandom(length)
        assert sha512(msg) == hashlib.sha512(msg).digest()

# edge cases

def test_single_byte_inputs():
    for byte_val in range(256):
        msg = bytes([byte_val])
        assert sha512(msg) == hashlib.sha512(msg).digest()

def test_exactly_111_and_112_bytes():
    # 111 = last length that fits in one block, 112 forces an extra block
    for msg in [b"a" * 111, b"a" * 112]:
        assert sha512(msg) == hashlib.sha512(msg).digest()

def test_binary_data():
    msg = bytes(range(256))
    assert sha512(msg) == hashlib.sha512(msg).digest()
