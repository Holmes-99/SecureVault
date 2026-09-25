import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from crypto.x25519 import x25519, public_key, shared_secret, generate_private_key

# RFC 7748 section 5.2 test vectors

def test_rfc7748_vector1():
    k = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    assert x25519(k, u).hex() == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"

def test_rfc7748_vector2():
    k = bytes.fromhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
    u = bytes.fromhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
    assert x25519(k, u).hex() == "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"

def test_rfc7748_iterated():
    #k = u = 9, then repeatedly k, u = x25519(k, u), k
    k = u = (9).to_bytes(32, 'little')
    k, u = x25519(k, u), k
    assert k.hex() == "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
    for _ in range(999):
        k, u = x25519(k, u), k
    assert k.hex() == "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"

# RFC 7748 section 6.1: Alice and Bob Diffie-Hellman

def test_rfc7748_diffie_hellman():
    alice_priv = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    bob_priv = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    alice_pub = public_key(alice_priv)
    bob_pub = public_key(bob_priv)
    assert alice_pub.hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    assert bob_pub.hex() == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    #both sides compute the same secret
    assert shared_secret(alice_priv, bob_pub) == shared_secret(bob_priv, alice_pub)

# cross-check against the cryptography library

def _raw(pub):
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def test_random_keys_match_library():
    for _ in range(20):
        a, b = generate_private_key(), generate_private_key()
        ref_a = X25519PrivateKey.from_private_bytes(a)
        ref_b = X25519PrivateKey.from_private_bytes(b)
        assert public_key(a) == _raw(ref_a.public_key())
        ref_secret = ref_a.exchange(X25519PublicKey.from_public_bytes(public_key(b)))
        assert shared_secret(a, public_key(b)) == ref_secret

# properties we rely on

def test_layla_and_omar_get_same_secret():
    layla_temp, omar = generate_private_key(), generate_private_key()
    assert shared_secret(layla_temp, public_key(omar)) == shared_secret(omar, public_key(layla_temp))

def test_different_partner_different_secret():
    me, a, b = generate_private_key(), generate_private_key(), generate_private_key()
    assert shared_secret(me, public_key(a)) != shared_secret(me, public_key(b))

def test_zero_public_key_rejected():
    #a small-order point makes the secret all zeros
    with pytest.raises(ValueError):
        shared_secret(generate_private_key(), b'\x00' * 32)

def test_wrong_length_rejected():
    with pytest.raises(AssertionError):
        x25519(b'\x01' * 31, b'\x09' + b'\x00' * 31)
