import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from crypto.ed25519 import public_key, sign, verify, generate_private_key, L

#rfc 8032 section 7.1 test vectors
RFC_VECTORS = [
    (  #empty message
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (  #one byte
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (  #two bytes
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]

def test_rfc8032_vectors():
    for sk, pk, msg, sig in RFC_VECTORS:
        sk, pk, msg, sig = map(bytes.fromhex, (sk, pk, msg, sig))
        assert public_key(sk) == pk
        assert sign(sk, msg) == sig
        assert verify(pk, msg, sig) is True

def _raw(pub):
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def test_random_keys_match_library():
    for length in [0, 1, 32, 100, 1000]:
        sk = generate_private_key()
        msg = os.urandom(length)
        ref = Ed25519PrivateKey.from_private_bytes(sk)
        assert public_key(sk) == _raw(ref.public_key())
        assert sign(sk, msg) == ref.sign(msg)

def test_library_signature_verifies_with_ours():
    ref = Ed25519PrivateKey.generate()
    msg = b"thesis-draft.pdf v2"
    assert verify(_raw(ref.public_key()), msg, ref.sign(msg)) is True

def test_our_signature_verifies_with_library():
    sk = generate_private_key()
    msg = b"thesis-draft.pdf v2"
    Ed25519PublicKey.from_public_bytes(public_key(sk)).verify(sign(sk, msg), msg)

def setup():
    sk = generate_private_key()
    msg = b"Layla shares thesis-draft.pdf with Omar"
    return sk, public_key(sk), msg, sign(sk, msg)

def test_changed_message_rejected():
    sk, pk, msg, sig = setup()
    assert verify(pk, msg + b"!", sig) is False

def test_flipped_signature_byte_rejected():
    sk, pk, msg, sig = setup()
    for i in [0, 31, 32, 63]:
        bad = bytearray(sig)
        bad[i] ^= 0x01
        assert verify(pk, msg, bytes(bad)) is False

def test_wrong_public_key_rejected():
    sk, pk, msg, sig = setup()
    assert verify(public_key(generate_private_key()), msg, sig) is False

def test_non_canonical_s_rejected():
    #S + L is same mod L but rfc 8032 says reject it
    sk, pk, msg, sig = setup()
    S = int.from_bytes(sig[32:], 'little') + L
    if S < 2**256:
        assert verify(pk, msg, sig[:32] + S.to_bytes(32, 'little')) is False

def test_bad_lengths_rejected():
    sk, pk, msg, sig = setup()
    assert verify(pk, msg, sig[:63]) is False
    assert verify(pk[:31], msg, sig) is False

def test_same_message_same_signature():
    #deterministic: no random r so same inputs always give same output
    sk, pk, msg, sig = setup()
    assert sign(sk, msg) == sig