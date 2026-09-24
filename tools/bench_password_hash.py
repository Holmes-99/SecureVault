import os
import sys
import time
import statistics
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

from crypto.password_hash import hash_password, new_salt

#measures Argon2id at a few memory costs so we can pick the one closest
#to our target of ~0.5s per verification on the machine we run on
#run: python tools/bench_password_hash.py

TARGET = 0.5
RUNS = 5
MEMORY_OPTIONS_MIB = [64, 128, 256, 384]


def measure(memory_mib, time_cost=3, parallelism=4):
    salt = new_salt()
    times = []
    for _ in range(RUNS):
        start = time.perf_counter()
        hash_password(b'benchmark password', salt, time_cost=time_cost,
                      memory_cost=memory_mib * 1024, parallelism=parallelism)
        times.append(time.perf_counter() - start)
    return statistics.median(times)


if __name__ == "__main__":
    print(f"Argon2id, t=3, p=4, median of {RUNS} runs (target ~{TARGET}s)\n")
    for mib in MEMORY_OPTIONS_MIB:
        print(f"  m = {mib:>3} MiB : {measure(mib):.3f} s")
