import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from hmac_sha256 import hmac_sha256

# HKDF with HMAC-SHA256 (RFC 5869)
# turns one secret into as many independent keys as we need,
# each one separated by a different "info" label

HASH_LEN = 32  #sha256 output


#step 1: extract: squeeze the input secret into a strong fixed-size key (PRK)
def hkdf_extract(salt, ikm):
    if not salt:
        salt = b'\x00' * HASH_LEN  #rfc: no salt = string of zeros
    return hmac_sha256(salt, ikm)


#step 2: expand: stretch the PRK into `length` bytes tied to `info`
#T(1) = HMAC(PRK, info | 0x01), T(i) = HMAC(PRK, T(i-1) | info | i)
def hkdf_expand(prk, info, length):
    if length > 255 * HASH_LEN:
        raise ValueError("HKDF can output at most 255 * 32 = 8160 bytes")

    output = b""
    t = b""
    counter = 1
    while len(output) < length:
        t = hmac_sha256(prk, t + info + bytes([counter]))
        output += t
        counter += 1

    return output[:length]


def hkdf(ikm, salt, info, length):
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)
