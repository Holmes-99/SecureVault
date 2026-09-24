import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from crypto.hkdf import hkdf, hkdf_extract, hkdf_expand

# RFC 5869 appendix A test vectors (SHA-256)

def test_rfc5869_case1_basic():
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    prk = hkdf_extract(salt, ikm)
    assert prk.hex() == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    assert hkdf_expand(prk, info, 42).hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865")

def test_rfc5869_case2_long_inputs():
    ikm = bytes(range(0x00, 0x50))
    salt = bytes(range(0x60, 0xb0))
    info = bytes(range(0xb0, 0x100))
    prk = hkdf_extract(salt, ikm)
    assert prk.hex() == "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
    assert hkdf_expand(prk, info, 82).hex() == (
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f1d87")

def test_rfc5869_case3_no_salt_no_info():
    ikm = bytes.fromhex("0b" * 22)
    prk = hkdf_extract(b"", ikm)
    assert prk.hex() == "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
    assert hkdf_expand(prk, b"", 42).hex() == (
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8")

# cross-check against the cryptography library

def test_random_inputs_match_library():
    for length in [1, 16, 32, 33, 64, 100, 255]:
        ikm, salt, info = os.urandom(32), os.urandom(16), os.urandom(10)
        ref = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)
        assert hkdf(ikm, salt, info, length) == ref

# properties we rely on in SecureVault

def test_different_info_gives_unrelated_keys():
    # auth_key and enc_key come from the same master with different labels
    master = os.urandom(32)
    auth_key = hkdf(master, b"", b"auth", 32)
    enc_key = hkdf(master, b"", b"enc", 32)
    assert auth_key != enc_key

def test_output_length():
    for length in [0, 1, 31, 32, 33, 8160]:
        assert len(hkdf(b"secret", b"salt", b"info", length)) == length

def test_too_long_rejected():
    with pytest.raises(ValueError):
        hkdf(b"secret", b"salt", b"info", 8161)
