import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from sha256 import sha256

# both users compute the same short number from BOTH their public keys
# and compare it,  a swapped key gives a different number
# to protect from Man/woman in the middle attacks
DIGITS = 20 #5 groups of 4
LABEL = b"SecureVault safety number v1"


def _identity(username, ed25519_pk, x25519_pk):
    #we use prefix so "ab"+"c" != "a"+"bc"
    name = username.encode('utf-8')
    return len(name).to_bytes(2, 'big') + name + ed25519_pk + x25519_pk


def safety_number(user_a, user_b):
    #sort so Layla and Omar get the same number no matter who computes it
    ids = sorted([_identity(*user_a), _identity(*user_b)])
    digest = sha256(LABEL + ids[0] + ids[1])

    number = int.from_bytes(digest[:16], 'big') % (10 ** DIGITS)
    text = str(number).zfill(DIGITS)
    return " ".join(text[i:i+4] for i in range(0, DIGITS, 4))
