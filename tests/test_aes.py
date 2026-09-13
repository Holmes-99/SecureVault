
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

from crypto.aes import aes_encrypt_block, aes_decrypt_block
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def ref_encrypt(key, block):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(block) + enc.finalize()

def ref_decrypt(key, block):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    dec = cipher.decryptor()
    return dec.update(block) + dec.finalize()


#official test vectors

def test_nist_encrypt():
    key= bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected  = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    assert aes_encrypt_block(key, plaintext) == expected

def test_nist_decrypt():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    ciphertext = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    expected   = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert aes_decrypt_block(key, ciphertext) == expected


def test_encrypt_decrypt_roundtrip():
    key = os.urandom(32)
    block = os.urandom(16)
    assert aes_decrypt_block(key, aes_encrypt_block(key, block)) == block

def test_roundtrip_zero_block():
    key = os.urandom(32)
    block = b'\x00' * 16
    assert aes_decrypt_block(key, aes_encrypt_block(key, block)) == block

def test_roundtrip_zero_key():
    key = b'\x00' * 32
    block = os.urandom(16)
    assert aes_decrypt_block(key, aes_encrypt_block(key, block)) == block



def test_output_is_16_bytes():
    key = os.urandom(32)
    block = os.urandom(16)
    assert len(aes_encrypt_block(key, block)) == 16
    assert len(aes_decrypt_block(key, block)) == 16

def test_output_is_bytes():
    key = os.urandom(32)
    block = os.urandom(16)
    assert isinstance(aes_encrypt_block(key, block), bytes)

def test_different_keys_give_different_output():
    block = os.urandom(16)
    c1 = aes_encrypt_block(os.urandom(32), block)
    c2 = aes_encrypt_block(os.urandom(32), block)
    assert c1 != c2

def test_different_blocks_give_different_output():
    key = os.urandom(32)
    c1 = aes_encrypt_block(key, os.urandom(16))
    c2 = aes_encrypt_block(key, os.urandom(16))
    assert c1 != c2


def test_random_encrypt_matches_reference():
    for _ in range(100):
        key= os.urandom(32)
        block = os.urandom(16)
        assert aes_encrypt_block(key, block) == ref_encrypt(key, block)

def test_random_decrypt_matches_reference():
    for _ in range(100):
        key   = os.urandom(32)
        block = os.urandom(16)
        assert aes_decrypt_block(key, block) == ref_decrypt(key, block)


def test_single_bit_change_avalanche():
    # changing 1 byte in plaintext should change ~50% of output bits
    key = os.urandom(32)
    block1 = b'\x00' * 16
    block2 = b'\x01' + b'\x00'*15
    c1 = aes_encrypt_block(key, block1)
    c2 = aes_encrypt_block(key, block2)
    differing_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(c1, c2))
    assert 40 <= differing_bits <= 88 