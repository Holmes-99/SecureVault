import os
import sys
import time
import statistics

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

from crypto import x25519, ed25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import x25519 as lib_x25519, ed25519 as lib_ed25519

# we measure ECC vs RSA at the SAME security level (128-bit):
# curve25519 (256-bit)  <-->  RSA-3072   


RUNS = 20
MSG = b"thesis-draft.pdf signed statement" * 4


def measure(fn, runs=RUNS):
    #median time ms
    times = []
    for _ in range(runs):
        start = time.perf_counter()
        fn()
        times.append(time.perf_counter() - start)
    return statistics.median(times) * 1000


def sizes():
    return [
        ("public key","32 B (X25519 / Ed25519)", "384 B (RSA-3072 modulus)"),
        ("signature","64 B (Ed25519)", "384 B (RSA-3072)"),
        ("wrapped DEK","32 B ephemeral key","384 B (RSA-OAEP ciphertext)"),
        ("private key","32 B", "~1.7 KB (n, d, p, q, ...)"),
    ]


def same_engine():
    #rsa private operation = m^d mod n
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    nums = key.private_numbers()
    n, d, e = nums.public_numbers.n, nums.d, nums.public_numbers.e
    m = int.from_bytes(os.urandom(300), 'big')

    x_sk, e_sk = x25519.generate_private_key(), ed25519.generate_private_key()
    x_pk, e_pk = x25519.public_key(x_sk), ed25519.public_key(e_sk)
    sig = ed25519.sign(e_sk, MSG)
    peer = x25519.public_key(x25519.generate_private_key())

    return [
        ("key agreement / transport", measure(lambda: x25519.shared_secret(x_sk, peer)),
                                      measure(lambda: pow(m, d, n))),
        ("sign",measure(lambda: ed25519.sign(e_sk, MSG)),
                                      measure(lambda: pow(m, d, n))),
        ("verify",measure(lambda: ed25519.verify(e_pk, MSG, sig)),
                                      measure(lambda: pow(m, e, n))),
    ]


def same_library():
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    rsa_pub = rsa_key.public_key()
    rsa_sig = rsa_key.sign(MSG, pss, hashes.SHA256())
    wrapped = rsa_pub.encrypt(os.urandom(32), oaep)

    x_key = lib_x25519.X25519PrivateKey.generate()
    peer = lib_x25519.X25519PrivateKey.generate().public_key()
    e_key = lib_ed25519.Ed25519PrivateKey.generate()
    e_pub = e_key.public_key()
    e_sig = e_key.sign(MSG)

    return [
        ("key generation",measure(lib_ed25519.Ed25519PrivateKey.generate),
                           measure(lambda: rsa.generate_private_key(65537, 3072), runs=5)),
        ("key agreement / transport", measure(lambda: x_key.exchange(peer)),
                                      measure(lambda: rsa_key.decrypt(wrapped, oaep))),
        ("sign",measure(lambda: e_key.sign(MSG)),
                   measure(lambda: rsa_key.sign(MSG, pss, hashes.SHA256()))),
        ("verify",measure(lambda: e_pub.verify(e_sig, MSG)),
                   measure(lambda: rsa_pub.verify(rsa_sig, MSG, pss, hashes.SHA256()))),
    ]


def print_table(title, rows):
    print(f"\n{title}")
    print(f"{'operation':<27}{'Curve25519':>12}{'RSA-3072':>12}{'RSA / ECC':>11}")
    for name, ecc, rsa_ms in rows:
        print(f"  {name:<27}{ecc:>10.3f}ms{rsa_ms:>10.3f}ms{rsa_ms / ecc:>10.1f}x")


if __name__ == "__main__":
    print("ECC vs RSA at 128-bit security (the median of runs)")
    print("\nsizes")
    for name, ecc, rsa_size in sizes():
        print(f"  {name:<16}{ecc:<28}{rsa_size}")
    print_table("1) same engine (python big ints)", same_engine())
    print_table("2) same library (OpenSSL)"  , same_library())