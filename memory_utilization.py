import argparse
import os
import random
import statistics
import tracemalloc
import gc

import std_aes as std
import mod_aes as mod


def randbytes(n: int) -> bytes:
    return os.urandom(n)


def measure_peak_alloc(callable_fn, *args, return_result=False):
    """
    Measures peak Python memory allocations (bytes) during callable_fn(*args)
    using tracemalloc. Returns (result, peak_bytes) if return_result else peak_bytes.
    """
    gc.collect()
    tracemalloc.start()
    try:
        result = callable_fn(*args)
        current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        gc.collect()
    return (result, peak) if return_result else peak


def verify_cbc_correctness(trials: int, key_size: int, msg_bytes: int):
    for _ in range(trials):
        key = randbytes(key_size)
        iv = randbytes(16)
        msg = randbytes(msg_bytes)
        a_std = std.AES(key)
        a_mod = mod.AES(key)

        ct_std = a_std.encrypt_cbc(msg, iv)
        pt_std = a_std.decrypt_cbc(ct_std, iv)
        assert pt_std == msg, "Standard AES CBC decrypt mismatch"

        ct_mod = a_mod.encrypt_cbc(msg, iv)
        pt_mod = a_mod.decrypt_cbc(ct_mod, iv)
        assert pt_mod == msg, "Modified AES CBC decrypt mismatch"


def memory_benchmark(trials: int, key_size: int, msg_bytes: int, seed: int):
    random.seed(seed)
    enc_peaks_std = []
    dec_peaks_std = []
    enc_peaks_mod = []
    dec_peaks_mod = []

    for _ in range(trials):
        key = randbytes(key_size)
        iv = randbytes(16)
        msg = randbytes(msg_bytes)

        aes_std = std.AES(key)
        aes_mod = mod.AES(key)

        # Encryption memory peaks (measure only the method call)
        ct_std, enc_peak_std = measure_peak_alloc(aes_std.encrypt_cbc, msg, iv, return_result=True)
        ct_mod, enc_peak_mod = measure_peak_alloc(aes_mod.encrypt_cbc, msg, iv, return_result=True)
        enc_peaks_std.append(enc_peak_std)
        enc_peaks_mod.append(enc_peak_mod)

        # Decryption memory peaks (use ciphertexts from above)
        pt_std, dec_peak_std = measure_peak_alloc(aes_std.decrypt_cbc, ct_std, iv, return_result=True)
        pt_mod, dec_peak_mod = measure_peak_alloc(aes_mod.decrypt_cbc, ct_mod, iv, return_result=True)
        assert pt_std == msg and pt_mod == msg, "CBC decrypt mismatch after timing"
        dec_peaks_std.append(dec_peak_std)
        dec_peaks_mod.append(dec_peak_mod)

    def stats(xs):
        return statistics.mean(xs), statistics.pstdev(xs)

    return {
        "enc_std": stats(enc_peaks_std),
        "enc_mod": stats(enc_peaks_mod),
        "dec_std": stats(dec_peaks_std),
        "dec_mod": stats(dec_peaks_mod),
    }


def declare_winner(metric_name: str, std_score: float, mod_score: float) -> str:
    # Lower peak bytes is better
    if mod_score < std_score:
        return f"Winner ({metric_name}): Modified AES"
    elif mod_score > std_score:
        return f"Winner ({metric_name}): Standard AES"
    else:
        return f"Winner ({metric_name}): Tie"


def to_kib(b: float) -> float:
    return b / 1024.0


def main():
    ap = argparse.ArgumentParser(description="Memory Utilization comparison (CBC): std_aes vs mod_aes.")
    ap.add_argument("--key-size", type=int, choices=[16, 24, 32], default=16, help="AES key size in bytes")
    ap.add_argument("--message-bytes", type=int, default=65536, help="Plaintext size per trial in bytes")
    ap.add_argument("--trials", type=int, default=50, help="Number of trials")
    ap.add_argument("--seed", type=int, default=1337, help="PRNG seed")
    ap.add_argument("--correctness-trials", type=int, default=5, help="CBC sanity trials")
    args = ap.parse_args()

    if args.message_bytes <= 0:
        raise ValueError("message-bytes must be > 0")

    print("Configuration:")
    print(f"  Key size: {args.key_size} bytes")
    print(f"  Message size per trial: {args.message_bytes} bytes")
    print(f"  Trials: {args.trials}, Seed: {args.seed}")
    print()

    print("Verifying high-level CBC encryption/decryption correctness...")
    verify_cbc_correctness(args.correctness_trials, args.key_size, args.message_bytes)
    print("Correctness: OK\n")

    print("Measuring peak Python memory allocations (tracemalloc) during CBC calls...")
    res = memory_benchmark(args.trials, args.key_size, args.message_bytes, args.seed)

    enc_std_mean, enc_std_sd = res["enc_std"]
    enc_mod_mean, enc_mod_sd = res["enc_mod"]
    dec_std_mean, dec_std_sd = res["dec_std"]
    dec_mod_mean, dec_mod_sd = res["dec_mod"]

    # Report in KiB
    print("=== Metrics: Memory Utilization (lower is better) ===")
    print("Metric: Memory Utilization (peak allocations during call)")
    print("Purpose: Implementation efficiency")
    print("Expected: Standard often uses less; Modified may use more due to whitening/permutation")
    print()

    print("Encryption (CBC) peak allocations:")
    print(f"  Standard AES: mean={to_kib(enc_std_mean):.2f} KiB  sd={to_kib(enc_std_sd):.2f} KiB")
    print(f"  Modified  AES: mean={to_kib(enc_mod_mean):.2f} KiB  sd={to_kib(enc_mod_sd):.2f} KiB")
    print(declare_winner("Memory (Encryption)", enc_std_mean, enc_mod_mean))
    print()

    print("Decryption (CBC) peak allocations:")
    print(f"  Standard AES: mean={to_kib(dec_std_mean):.2f} KiB  sd={to_kib(dec_std_sd):.2f} KiB")
    print(f"  Modified  AES: mean={to_kib(dec_mod_mean):.2f} KiB  sd={to_kib(dec_mod_sd):.2f} KiB")
    print(declare_winner("Memory (Decryption)", dec_std_mean, dec_mod_mean))
    print()

    std_overall = (enc_std_mean + dec_std_mean) / 2.0
    mod_overall = (enc_mod_mean + dec_mod_mean) / 2.0
    print("Overall (average of enc/dec peaks):")
    print(f"  Standard AES overall: {to_kib(std_overall):.2f} KiB")
    print(f"  Modified  AES overall: {to_kib(mod_overall):.2f} KiB")
    print(declare_winner("Memory (Overall)", std_overall, mod_overall))
    print()
    print("Notes:")
    print("  - Uses tracemalloc: Python-level allocations only (native/RSS not included).")
    print("  - Same (key, IV, message) are used per trial for fairness.")
    print("  - Increase message size and trials for more stable statistics.")
    print("  - Lower peak indicates better memory efficiency.")


if __name__ == "__main__":
    main()