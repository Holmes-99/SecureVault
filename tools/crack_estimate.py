import os
import sys
import time
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

from crypto.password_hash import hash_password, new_salt, MEMORY_COST, TIME_COST, PARALLELISM

# how long would an offline attack on a stolen credential store take?
# the attacker has the salt + auth_key of an account and guesses passwords.
# every guess = one full Argon2id with our parameters (then a cheap HKDF).
#
# measured here: our Argon2id time, SHA-256 speed on this CPU
# assumed: one high-end GPU (numbers below, check them before the report)
# run: python tools/crack_estimate.py

# --- assumptions about the attacker's GPU (RTX 4090 class) ---
GPU_MEMORY = 24 * 2**30          #24 GiB of memory
GPU_BANDWIDTH = 1.0e12           #~1 TB/s memory bandwidth
GPU_SHA256 = 2.2e10              #~22 billion SHA-256/s (public hashcat benchmark, approx)

# Argon2id touches its memory about 3 times per pass (read 2 blocks, write 1)
ARGON2_TRAFFIC = 3 * MEMORY_COST * 1024 * TIME_COST   #bytes moved per guess


# password spaces the attacker has to search
SPACES = [
    ("8 lowercase + digits",  36 ** 8),
    ("8 letters + digits",    62 ** 8),
    ("10 letters + digits",   62 ** 10),
    ("top 1,000,000 common",  10 ** 6),
]


def measured_argon2():
    #seconds for one real hash on this machine
    start = time.perf_counter()
    hash_password(b"guess", new_salt())
    return time.perf_counter() - start


def measured_sha256():
    #SHA-256 per second on one CPU core (hashlib, C code)
    n = 200_000
    start = time.perf_counter()
    for i in range(n):
        hashlib.sha256(b"salt1234salt1234" + i.to_bytes(8, 'big')).digest()
    return n / (time.perf_counter() - start)


def gpu_argon2_rate():
    #upper bound: limited by memory bandwidth, and by how many guesses fit in memory
    by_bandwidth = GPU_BANDWIDTH / ARGON2_TRAFFIC
    fits_in_memory = GPU_MEMORY // (MEMORY_COST * 1024)
    return by_bandwidth, fits_in_memory


def human(seconds):
    for name, size in [("years", 365 * 86400), ("days", 86400), ("hours", 3600),
                       ("minutes", 60), ("seconds", 1)]:
        if seconds >= size:
            return f"{seconds / size:,.1f} {name}"
    if seconds >= 0.001:
        return f"{seconds * 1000:.1f} ms"
    return "under 1 ms"


def print_table(title, rate):
    print(f"\n{title}  ({rate:,.0f} guesses/s)")
    for name, size in SPACES:
        #on average the password is found after searching half the space
        print(f"  {name:<24} {human(size / 2 / rate):>22}")


if __name__ == "__main__":
    argon2_time = measured_argon2()
    sha_rate = measured_sha256()
    gpu_rate, parallel = gpu_argon2_rate()

    print("offline attack on ONE stolen account (average time to find the password)")
    print(f"\nour Argon2id: m = {MEMORY_COST // 1024} MiB, t = {TIME_COST}, p = {PARALLELISM}")
    print(f"  measured here: {argon2_time:.2f} s per guess")
    print(f"  GPU bound: {ARGON2_TRAFFIC / 2**30:.1f} GiB moved per guess, "
          f"only {parallel} guesses fit in {GPU_MEMORY // 2**30} GiB at once")

    print_table("A) Argon2id, our parameters, one GPU", gpu_rate)
    print_table("B) bare SHA-256 (no password hashing), one GPU", GPU_SHA256)
    print_table("C) bare SHA-256, one CPU core (measured here)", sha_rate)

    print("\nnotes")
    print("  - every account has its own salt, so the attacker pays this again per account")
    print("  - a password from a common list still falls quickly (last row)")
