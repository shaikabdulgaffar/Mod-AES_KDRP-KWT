import os
import math
import argparse
import random
import statistics
from typing import List, Tuple

import std_aes as std
import mod_aes as mod


def randbytes(n: int) -> bytes:
    return os.urandom(n)


def shannon_entropy_bits(data: bytes) -> float:
    """
    Shannon entropy (bits per byte) based on byte histogram.
    Max is 8.0 bits when distribution is uniform over 256 symbols.
    """
    n = len(data)
    if n == 0:
        return float("nan")
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    H = 0.0
    for c in counts:
        if c:
            p = c / n
            H -= p * math.log2(p)
    return H


def verify_cbc_correctness(trials: int, key_size: int, msg_bytes: int) -> None:
    for _ in range(trials):
        key = randbytes(key_size)
        iv = randbytes(16)
        msg = randbytes(msg_bytes)

        aes_std = std.AES(key)
        aes_mod = mod.AES(key)

        c_std = aes_std.encrypt_cbc(msg, iv)
        p_std = aes_std.decrypt_cbc(c_std, iv)
        assert p_std == msg, "Standard AES CBC decrypt mismatch"

        c_mod = aes_mod.encrypt_cbc(msg, iv)
        p_mod = aes_mod.decrypt_cbc(c_mod, iv)
        assert p_mod == msg, "Modified AES CBC decrypt mismatch"


def measure_entropy(
    trials: int,
    key_size: int,
    msg_bytes: int,
    seed: int,
) -> Tuple[List[float], List[float]]:
    """
    Runs 'trials' CBC encryptions with random key/iv/message.
    Returns two lists: per-trial ciphertext entropy (bits/byte) for std and mod.
    """
    random.seed(seed)
    ent_std: List[float] = []
    ent_mod: List[float] = []

    for _ in range(trials):
        key = randbytes(key_size)
        iv = randbytes(16)
        msg = randbytes(msg_bytes)

        aes_std = std.AES(key)
        aes_mod = mod.AES(key)

        c_std = aes_std.encrypt_cbc(msg, iv)
        c_mod = aes_mod.encrypt_cbc(msg, iv)

        ent_std.append(shannon_entropy_bits(c_std))
        ent_mod.append(shannon_entropy_bits(c_mod))

    return ent_std, ent_mod


def safe_mean(xs: List[float]) -> float:
    xs2 = [x for x in xs if x == x]
    return statistics.mean(xs2) if xs2 else float("nan")


def safe_stdev(xs: List[float]) -> float:
    xs2 = [x for x in xs if x == x]
    return statistics.pstdev(xs2) if xs2 else float("nan")


def declare_winner_entropy(mean_std: float, mean_mod: float) -> str:
    # Winner is closer to 8.0 bits
    d_std = abs(8.0 - mean_std)
    d_mod = abs(8.0 - mean_mod)
    if d_mod < d_std:
        return "Winner (Entropy): Modified AES"
    elif d_mod > d_std:
        return "Winner (Entropy): Standard AES"
    else:
        return "Winner (Entropy): Tie"


def main():
    ap = argparse.ArgumentParser(description="Entropy comparison (CBC): Standard AES vs Modified AES.")
    ap.add_argument("--key-size", type=int, choices=[16, 24, 32], default=16, help="AES key size in bytes")
    ap.add_argument("--message-bytes", type=int, default=4096, help="Plaintext size per trial in bytes")
    ap.add_argument("--trials", type=int, default=200, help="Number of random trials")
    ap.add_argument("--seed", type=int, default=1337, help="PRNG seed")
    ap.add_argument("--correctness-trials", type=int, default=10, help="CBC encrypt/decrypt sanity trials")
    args = ap.parse_args()

    if args.message_bytes <= 0:
        raise ValueError("message-bytes must be > 0")

    print("Configuration:")
    print(f"  Key size: {args.key_size} bytes")
    print(f"  Message size per trial: {args.message_bytes} bytes")
    print(f"  Trials: {args.trials}")
    print(f"  Seed: {args.seed}")
    print()

    print("Verifying high-level CBC encryption/decryption correctness...")
    verify_cbc_correctness(args.correctness_trials, args.key_size, args.message_bytes)
    print("Correctness: OK\n")

    print("Measuring ciphertext entropy (bits/byte) on CBC outputs...")
    ent_std, ent_mod = measure_entropy(
        trials=args.trials,
        key_size=args.key_size,
        msg_bytes=args.message_bytes,
        seed=args.seed,
    )

    mean_std = safe_mean(ent_std)
    sd_std = safe_stdev(ent_std)
    mean_mod = safe_mean(ent_mod)
    sd_mod = safe_stdev(ent_mod)

    dist_std = abs(8.0 - mean_std)
    dist_mod = abs(8.0 - mean_mod)
    improvement = dist_std - dist_mod  # positive => Modified closer to 8

    print("=== Metrics: Entropy ===")
    print("Metric: Entropy (bits per byte)")
    print("Purpose: Randomness measure")
    print("Expected Improvement (Modified AES): Closer to 8 bits")
    print("Reason: Uniform byte distribution (via added diffusion/whitening)")
    print()
    print(f"  Standard AES: mean={mean_std:.5f}  sd={sd_std:.5f}  distance_to_8={dist_std:.5f}")
    print(f"  Modified  AES: mean={mean_mod:.5f}  sd={sd_mod:.5f}  distance_to_8={dist_mod:.5f}")
    print(f"  Improvement (distance_to_8: Std - Mod): {improvement:+.5f}")
    print(declare_winner_entropy(mean_std, mean_mod))
    print()
    print("Notes:")
    print("  - Higher mean entropy and smaller distance_to_8 indicate more uniform ciphertext bytes.")
    print("  - CBC encryption used for both ciphers; identical trial conditions (key/IV/message) ensure fairness.")
    print("  - Increase --message-bytes and --trials for stronger statistical power in publication.")


if __name__ == "__main__":
    main()