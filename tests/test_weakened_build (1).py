import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

import pytest
from attacks.weakened_build import (weak_encrypt_reused_nonce, real_encrypt, attack_keystream_reuse,
                                    weak_decrypt_no_tag_check, attack_bitflip)
from crypto.gcm import gcm_encrypt, gcm_decrypt

KNOWN = b"Grade report: every student passed the course."
SECRET = b"Exam answers: Q1=B, Q2=D, Q3=A, Q4=C, Q5=B !!!"


def test_nonce_reuse_attack_works_on_weak_build():
    key = os.urandom(32)
    c1, _ = weak_encrypt_reused_nonce(key, KNOWN)
    c2, _ = weak_encrypt_reused_nonce(key, SECRET)
    assert attack_keystream_reuse(c1, KNOWN, c2) == SECRET

def test_nonce_reuse_attack_fails_on_real_build():
    c1, _ = real_encrypt(KNOWN)
    c2, _ = real_encrypt(SECRET)
    assert attack_keystream_reuse(c1, KNOWN, c2) != SECRET

def test_bitflip_works_without_tag_check():
    key, nonce = os.urandom(32), os.urandom(12)
    order = b"Transfer 100 JOD to Omar"
    ct, _ = gcm_encrypt(key, nonce, order, b"")
    forged = attack_bitflip(ct, b"100", b"900", order.index(b"100"))
    assert weak_decrypt_no_tag_check(key, nonce, forged) == b"Transfer 900 JOD to Omar"

def test_bitflip_rejected_with_tag_check():
    key, nonce = os.urandom(32), os.urandom(12)
    order = b"Transfer 100 JOD to Omar"
    ct, tag = gcm_encrypt(key, nonce, order, b"")
    forged = attack_bitflip(ct, b"100", b"900", order.index(b"100"))
    with pytest.raises(ValueError):
        gcm_decrypt(key, nonce, forged, tag, b"")
