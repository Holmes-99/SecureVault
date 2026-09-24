import os
from argon2.low_level import hash_secret_raw, Type

#Argon2id (RFC 9106) from the argon2-cffi library -- part of our 30%
#pure python was too slow to reach a real memory cost (see experiments/custom_kdf.py)

TIME_COST = 3        #passes over memory
MEMORY_COST = 393216 #in KiB -> 384 MiB, ~0.46s per hash (tools/bench_password_hash.py)
PARALLELISM = 4      #lanes
HASH_LEN = 32        #output bytes
SALT_LEN = 16        #random salt per user, stored in the clear


def new_salt():
    return os.urandom(SALT_LEN)


def hash_password(password, salt, time_cost=TIME_COST, memory_cost=MEMORY_COST,
                  parallelism=PARALLELISM, hash_len=HASH_LEN):
    if not isinstance(password, bytes):
        raise TypeError("password must be bytes")
    if not isinstance(salt, bytes) or len(salt) < 16:
        raise ValueError("salt must be at least 16 bytes")

    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=hash_len,
        type=Type.ID,
    )


def verify_password(password, salt, expected, **params):
    computed = hash_password(password, salt, hash_len=len(expected), **params)

    #constant-time comparison
    diff = 0
    for a, b in zip(computed, expected):
        diff |= a ^ b
    return diff == 0
