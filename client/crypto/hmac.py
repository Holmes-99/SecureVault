import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from sha256 import sha256
BLOCK_SIZE = 64 #sha256

#hmac standards
IPAD = 0x36  # inner padding
OPAD = 0x5C  # outer padding


def hmac_sha256(key, message):
    #we use hash to shorten it
    if len(key) > BLOCK_SIZE:
        key = sha256(key)

    if len(key) < BLOCK_SIZE:
        key = key + b'\x00' * (BLOCK_SIZE - len(key))

    inner_key = bytes(b ^ IPAD for b in key)
    outer_key = bytes(b ^ OPAD for b in key)
    
    # two nested hashes  kill the length extension attack
    inner_hash = sha256(inner_key + message)

    result = sha256(outer_key + inner_hash)

    return result #256 bits

def hmac_sha256_hex(key, message):
    return hmac_sha256(key, message).hex()