import os
import sys
import struct
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from hmac_sha256 import hmac_sha256


#Argon2id parameters (RFC 9106)
TIME_COST = 3       #number of passes over memory
MEMORY_COST = 64    #number of 1KB blocks (use 65536 in prod)
PARALLELISM = 1     #single lane
HASH_LEN = 32       #output length in bytes
SALT_LEN = 16       #salt length in bytes
BLOCK_SIZE = 1024   #each block is 1024 bytes


def _h(data):
    #variable-length hash via HMAC-SHA256 (replaces Blake2b in standard Argon2)
    return hmac_sha256(b'argon2-sv', data)


def _h_prime(out_len, data):
    #variable-length output (RFC 9106 section 3.2)
    #chains HMAC-SHA256 blocks to produce out_len bytes
    if out_len <= 32:
        return _h(out_len.to_bytes(4, 'little') + data)[:out_len]

    result = bytearray()
    a = _h(out_len.to_bytes(4, 'little') + data)
    result += a
    produced = 32

    counter = 1
    while produced < out_len:
        a = _h(counter.to_bytes(4, 'little') + a)
        need = min(32, out_len - produced)
        result += a[:need]
        produced += need
        counter += 1

    return bytes(result)


def _le64(x):
    return struct.pack('<Q', x & 0xFFFFFFFFFFFFFFFF)

def _le32(x):
    return struct.pack('<I', x & 0xFFFFFFFF)


def _mix_block(block_a, block_b):
    #mix two 1024-byte blocks using HMAC-SHA256 as compression function
    #replaces the G function (Blake2b) from the RFC
    combined = bytes(a ^ b for a, b in zip(block_a, block_b))

    result = bytearray()
    for i in range(0, BLOCK_SIZE, 32):
        chunk = combined[i:i+32]
        mixed = hmac_sha256(chunk, combined) #each chunk mixed with full state
        result += mixed

    return bytes(x ^ y for x, y in zip(result, block_a)) #XOR with block_a (Argon2 feedback)


def _index_alpha(pass_num, slice_num, block_idx, pseudo_rand, memory_cost):
    #compute reference block index (RFC 9106 section 3.3)
    #Argon2id: first two slices of pass 0 -> data-independent, rest -> data-dependent
    if pass_num == 0 and slice_num < 2:
        reference_area_size = block_idx - 1 if block_idx > 0 else 0
    else:
        reference_area_size = memory_cost - 1

    x = (pseudo_rand & 0xFFFFFFFF)
    y = (x * x) >> 32
    z = (reference_area_size * y) >> 32
    return int(reference_area_size - 1 - z) % max(1, memory_cost)


def argon2id(password, salt, time_cost=TIME_COST, memory_cost=MEMORY_COST,
             parallelism=PARALLELISM, hash_len=HASH_LEN):
    assert isinstance(password, bytes), "password must be bytes"
    assert isinstance(salt, bytes) and len(salt) >= 8, "salt must be at least 8 bytes"

    #stage 1: produce H0 (64 bytes) -- binds all parameters to the output
    h0_input = (
        _le32(parallelism) +
        _le32(hash_len) +
        _le32(memory_cost) +
        _le32(time_cost) +
        _le32(0x13) +           #version 1.3
        _le32(2) +              #type: Argon2id
        _le32(len(password)) + password +
        _le32(len(salt))     + salt +
        _le32(0) +              #no secret
        _le32(0)                #no associated data
    )
    H0 = _h_prime(64, h0_input)

    #stage 2: initialize memory matrix
    B = [None] * memory_cost

    B[0] = _h_prime(BLOCK_SIZE, H0 + _le32(0) + _le32(0))
    if memory_cost > 1:
        B[1] = _h_prime(BLOCK_SIZE, H0 + _le32(1) + _le32(0))

    for i in range(2, memory_cost):
        B[i] = _h_prime(BLOCK_SIZE, B[i-1] + B[0])

    #stage 3: time_cost passes -- mix blocks
    for t in range(time_cost):
        for i in range(memory_cost):
            pseudo_rand = int.from_bytes(B[i][:8], 'little')
            slice_num = i // (memory_cost // 4 + 1)
            j = _index_alpha(t, slice_num, i, pseudo_rand, memory_cost)

            prev = B[(i - 1) % memory_cost]
            ref = B[j]
            B[i] = _mix_block(prev, ref)

    #stage 4: finalize -- XOR all blocks then hash
    final_block = B[0]
    for i in range(1, memory_cost):
        final_block = bytes(a ^ b for a, b in zip(final_block, B[i]))

    return _h_prime(hash_len, final_block)


def argon2id_encode(password, salt=None, time_cost=TIME_COST,
                    memory_cost=MEMORY_COST, parallelism=PARALLELISM, hash_len=HASH_LEN):
    #returns PHC-style string for DB storage
    #format: $argon2id$v=19$m=<mem>,t=<time>,p=<par>$<salt_b64>$<hash_b64>
    import base64
    if salt is None:
        salt = os.urandom(SALT_LEN)

    h = argon2id(password, salt, time_cost, memory_cost, parallelism, hash_len)

    salt_b64 = base64.b64encode(salt).decode().rstrip('=')
    hash_b64 = base64.b64encode(h).decode().rstrip('=')

    return f"$argon2id$v=19$m={memory_cost},t={time_cost},p={parallelism}${salt_b64}${hash_b64}"


def argon2id_verify(password, encoded):
    #parse encoded string and check password
    import base64

    parts = encoded.split('$')
    # ['', 'argon2id', 'v=19', 'm=64,t=3,p=1', '<salt>', '<hash>']
    assert parts[1] == 'argon2id', "not an argon2id hash"

    params = {}
    for kv in parts[3].split(','):
        k, v = kv.split('=')
        params[k] = int(v)

    def pad(s):
        return s + '=' * (-len(s) % 4)

    salt = base64.b64decode(pad(parts[4]))
    expected_hash = base64.b64decode(pad(parts[5]))
    hash_len = len(expected_hash)

    computed = argon2id(password, salt,
                        time_cost=params['t'],
                        memory_cost=params['m'],
                        parallelism=params['p'],
                        hash_len=hash_len)

    #constant-time comparison
    diff = 0
    for a, b in zip(computed, expected_hash):
        diff |= a ^ b
    return diff == 0