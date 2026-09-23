import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

import pytest
from crypto.gcm import gcm_encrypt, gcm_decrypt


# NIST test vectors 

def test_nist_ciphertext():
    key = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
    nonce = bytes.fromhex("000000000000000000000000")
    plaintext = bytes.fromhex("00000000000000000000000000000000")
    aad = b""
    expected_ct = bytes.fromhex("cea7403d4d606b6e074ec5d3baf39d18")
    ct, _ = gcm_encrypt(key, nonce, plaintext, aad)
    assert ct == expected_ct

def test_nist_tag():
    key = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
    nonce = bytes.fromhex("000000000000000000000000")
    plaintext = bytes.fromhex("00000000000000000000000000000000")
    aad = b""
    expected_tag = bytes.fromhex("d0d1c8a799996bf0265b98b5d48ab919")
    _, tag = gcm_encrypt(key, nonce, plaintext, aad)
    assert tag == expected_tag

def test_nist_decrypt():
    key = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
    nonce = bytes.fromhex("000000000000000000000000")
    plaintext = bytes.fromhex("00000000000000000000000000000000")
    aad = b""
    ct, tag = gcm_encrypt(key, nonce, plaintext, aad)
    recovered = gcm_decrypt(key, nonce, ct, tag, aad)
    assert recovered == plaintext


#round-trip tests
def test_roundtrip_short():
    key = os.urandom(32)
    nonce = os.urandom(12)
    plaintext = b"hello"
    aad = b""
    ct, tag = gcm_encrypt(key, nonce, plaintext, aad)
    assert gcm_decrypt(key, nonce, ct, tag, aad) == plaintext

def test_roundtrip_empty_plaintext():
    key = os.urandom(32)
    nonce = os.urandom(12)
    plaintext = b""
    aad = b"metadata only"
    ct, tag = gcm_encrypt(key, nonce, plaintext, aad)
    assert gcm_decrypt(key, nonce, ct, tag, aad) == plaintext

def test_roundtrip_with_aad():
    key = bytes(range(32))
    nonce = os.urandom(12)
    plaintext = b"Hello, SecureVault!"
    aad = b"sender=alice;recipient=bob"
    ct, tag = gcm_encrypt(key, nonce, plaintext, aad)
    assert gcm_decrypt(key, nonce, ct, tag, aad) == plaintext

def test_roundtrip_exactly_one_block():
    key = os.urandom(32)
    nonce = os.urandom(12)
    plaintext = b"A" * 16
    aad = b""
    ct, tag = gcm_encrypt(key, nonce, plaintext, aad)
    assert gcm_decrypt(key, nonce, ct, tag, aad) == plaintext

def test_roundtrip_multi_block():
    key = os.urandom(32)
    nonce = os.urandom(12)
    plaintext = b"B" * 100
    aad = b"some header"
    ct, tag = gcm_encrypt(key, nonce, plaintext, aad)
    assert gcm_decrypt(key, nonce, ct, tag, aad) == plaintext

def test_ciphertext_length_matches_plaintext():
    key = os.urandom(32)
    nonce = os.urandom(12)
    plaintext = b"test message 123"
    ct, _ = gcm_encrypt(key, nonce, plaintext, b"")
    assert len(ct) == len(plaintext)

def test_tag_is_16_bytes():
    key = os.urandom(32)
    nonce = os.urandom(12)
    _, tag = gcm_encrypt(key, nonce, b"anything", b"")
    assert len(tag) == 16


#authentication failure tests

def test_tampered_ciphertext_raises():
    key = os.urandom(32)
    nonce = os.urandom(12)
    ct, tag = gcm_encrypt(key, nonce, b"secret", b"")
    bad_ct = bytearray(ct)
    bad_ct[0] ^= 0xFF
    with pytest.raises(ValueError, match="GCM authentication failed"):
        gcm_decrypt(key, nonce, bytes(bad_ct), tag, b"")

def test_tampered_tag_raises():
    key = os.urandom(32)
    nonce = os.urandom(12)
    ct, tag = gcm_encrypt(key, nonce, b"secret", b"")
    bad_tag = bytearray(tag)
    bad_tag[0] ^= 0x01
    with pytest.raises(ValueError, match="GCM authentication failed"):
        gcm_decrypt(key, nonce, ct, bytes(bad_tag), b"")

def test_tampered_aad_raises():
    key = os.urandom(32)
    nonce = os.urandom(12)
    plaintext = b"secret document"
    aad = b"sender=alice;recipient=bob"
    ct, tag = gcm_encrypt(key, nonce, plaintext, aad)
    with pytest.raises(ValueError, match="GCM authentication failed"):
        gcm_decrypt(key, nonce, ct, tag, b"sender=eve;recipient=bob")

def test_wrong_key_raises():
    nonce = os.urandom(12)
    ct, tag = gcm_encrypt(os.urandom(32), nonce, b"secret", b"")
    with pytest.raises(ValueError, match="GCM authentication failed"):
        gcm_decrypt(os.urandom(32), nonce, ct, tag, b"")

def test_wrong_nonce_raises():
    key = os.urandom(32)
    ct, tag = gcm_encrypt(key, os.urandom(12), b"secret", b"")
    with pytest.raises(ValueError, match="GCM authentication failed"):
        gcm_decrypt(key, os.urandom(12), ct, tag, b"")

def test_no_plaintext_returned_on_auth_failure():
    #make sure decrypt raises and never silently returns data
    key = os.urandom(32)
    nonce = os.urandom(12)
    ct, tag = gcm_encrypt(key, nonce, b"top secret", b"")
    bad_ct = bytearray(ct)
    bad_ct[0] ^= 0xFF
    result = None
    try:
        result = gcm_decrypt(key, nonce, bytes(bad_ct), tag, b"")
    except ValueError:
        pass
    assert result is None



def test_cross_check_encrypt():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = bytes(range(32))
    nonce = bytes(range(12))
    plaintext = b"cross-check me"
    aad = b"header"

    our_ct, our_tag = gcm_encrypt(key, nonce, plaintext, aad)

    ref = AESGCM(key)
    ref_output = ref.encrypt(nonce, plaintext, aad)  # ct + tag concatenated
    ref_ct = ref_output[:-16]
    ref_tag = ref_output[-16:]

    assert our_ct == ref_ct
    assert our_tag == ref_tag

def test_cross_check_decrypt():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = bytes(range(32))
    nonce = bytes(range(12))
    plaintext = b"cross-check decrypt"
    aad = b"some aad"

    ref = AESGCM(key)
    ref_output = ref.encrypt(nonce, plaintext, aad)
    ref_ct = ref_output[:-16]
    ref_tag = ref_output[-16:]

    recovered = gcm_decrypt(key, nonce, ref_ct, ref_tag, aad)
    assert recovered == plaintext
