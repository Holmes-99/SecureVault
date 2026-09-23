import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from aes import aes_encrypt_block


def gf_mul_128(X, Y):
    # multiply two nums in GF(2^128)
    # reduction polynomial
    R = 0xE1000000000000000000000000000000
    Z = 0
    V = X
    for i in range(128):
        if (Y >> (127 - i)) & 1:
            Z ^= V
        if V & 1:
            V = (V >> 1) ^ R
        else:
            V >>= 1
    return Z


def _bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')

def _int_to_bytes(n, length=16):
    return n.to_bytes(length, byteorder='big')


def ghash(H, aad, ciphertext):
    # H = AES_K(0^128), the hash subkey
    # pads aad and ciphertext to multiples of 16 bytes then feeds blocks into GHASH
    H_int = _bytes_to_int(H)

    def pad_to_16(data):
        remainder = len(data) % 16
        if remainder:
            data += b'\x00' * (16 - remainder)
        return data

    aad_padded = pad_to_16(aad)
    ct_padded = pad_to_16(ciphertext)

    len_block = (len(aad) * 8).to_bytes(8, 'big') + (len(ciphertext) * 8).to_bytes(8, 'big')

    data = aad_padded + ct_padded + len_block

    X = 0
    for i in range(0, len(data), 16):
        block = _bytes_to_int(data[i:i+16])
        X = gf_mul_128(X ^ block, H_int)

    return _int_to_bytes(X)


def _inc32(counter_block):
    prefix = counter_block[:12]
    ctr = int.from_bytes(counter_block[12:], 'big')
    ctr = (ctr + 1) & 0xFFFFFFFF
    return prefix + ctr.to_bytes(4, 'big')


def ctr_encrypt(key, initial_counter, data):
    result = bytearray()
    counter = initial_counter

    for i in range(0, len(data), 16):
        keystream = aes_encrypt_block(key, counter)
        block = data[i:i+16]
        for j in range(len(block)):
            result.append(block[j] ^ keystream[j])
        counter = _inc32(counter)

    return bytes(result)


def make_j0(nonce):
    assert len(nonce) == 12, "nonce must be 12 bytes"
    return nonce + b'\x00\x00\x00\x01'


def gcm_encrypt(key, nonce, plaintext, aad):
    assert len(key) == 32, "AES-256 key must be 32 bytes"
    assert len(nonce) == 12, "GCM nonce must be 12 bytes"

    # hash subkey H = AES_K(0^128)
    H = aes_encrypt_block(key, b'\x00' * 16)

    J0 = make_j0(nonce)  # counter block for tag generation

    J1 = _inc32(J0)
    ciphertext = ctr_encrypt(key, J1, plaintext)

    S = ghash(H, aad, ciphertext)
    tag = ctr_encrypt(key, J0, S)

    return ciphertext, tag


def gcm_decrypt(key, nonce, ciphertext, tag, aad):
    assert len(key) == 32, "AES-256 key must be 32 bytes"
    assert len(nonce) == 12, "GCM nonce must be 12 bytes"
    assert len(tag) == 16, "GCM tag must be 16 bytes"

    H = aes_encrypt_block(key, b'\x00' * 16)
    J0 = make_j0(nonce)

    S = ghash(H, aad, ciphertext)
    expected_tag = ctr_encrypt(key, J0, S)

    diff = 0
    for a, b in zip(expected_tag, tag):
        diff |= a ^ b
    if diff != 0:
        raise ValueError("GCM authentication failed")

    J1 = _inc32(J0)
    plaintext = ctr_encrypt(key, J1, ciphertext)

    return plaintext