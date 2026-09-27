import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client')) #crypto/

from crypto.gcm import gcm_encrypt, gcm_decrypt, ctr_encrypt, make_j0, _inc32


#   two broken versions of our document encryption, each with

# weak 1: one key + one FIXED nonce for every document
#         --> same keystream --> c1 ^ c2 = p1^ p2

# weak 2:decrypt without checking the GCM tag
#        --> CTR is malleable --> flip bits, change the text

FIXED_NONCE = b"\x00" * 12


#  weak 1

def weak_encrypt_reused_nonce(key, plaintext):
    #the same (key, nonce) for every document
    return gcm_encrypt(key, FIXED_NONCE, plaintext, b"")


def real_encrypt(plaintext):
    dek, nonce = os.urandom(32), os.urandom(12)
    ct, tag = gcm_encrypt(dek, nonce, plaintext, b"")
    return ct, tag


def attack_keystream_reuse(ct_known, known_plain, ct_secret):
    #c1 ^ c2 = p1 ^ p2(Known plaintext attack)
    n = min(len(ct_known), len(known_plain), len(ct_secret))
    return bytes(ct_known[i] ^ known_plain[i] ^ ct_secret[i] for i in range(n))


#   weak 2

def weak_decrypt_no_tag_check(key, nonce, ciphertext):
    #skips the tag and decrypts whatever arrives
    return ctr_encrypt(key, _inc32(make_j0(nonce)), ciphertext)


def attack_bitflip(ciphertext, old_text, new_text, position):
    #xor (old ^ new)
    ct = bytearray(ciphertext)
    for i, (a, b) in enumerate(zip(old_text, new_text)):
        ct[position + i] ^= a ^ b
    return bytes(ct)


def demo():
    key = os.urandom(32)

    print("weak 1: fixed nonce")
    known = b"Grade report: every student passed the course."
    secret = b"Exam answers: Q1=B, Q2=D, Q3=A, Q4=C, Q5=B !!!"
    c1, _ = weak_encrypt_reused_nonce(key, known)
    c2, _ = weak_encrypt_reused_nonce(key, secret)
    print(f"  weak build --> attacker recovers: {attack_keystream_reuse(c1, known, c2)!r}")
    r1, _ = real_encrypt(known)
    r2, _ = real_encrypt(secret)
    print(f"  real build --> attacker gets:{attack_keystream_reuse(r1, known, r2)[:24]!r}...")

    print("\nweak 2: no tag check(no authentication)")
    nonce = os.urandom(12)
    order = b"Transfer 100 JOD to Omar"
    ct, tag = gcm_encrypt(key, nonce, order, b"")
    forged = attack_bitflip(ct, b"100", b"900", order.index(b"100"))
    print(f"  weak build --> decrypts to:{weak_decrypt_no_tag_check(key, nonce, forged)!r}")
    try:
        gcm_decrypt(key, nonce, forged, tag, b"")
        print("  REAL build --> accepted (BAD)")
    except ValueError:
        print("  REAL build --> rejected: GCM tag check failed")


if __name__ == "__main__":
    demo()
