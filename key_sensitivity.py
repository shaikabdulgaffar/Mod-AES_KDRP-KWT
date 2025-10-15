import os
import random
import statistics
import argparse
from typing import Tuple, Optional

import std_aes as std
import mod_aes as mod


def randbytes(n: int) -> bytes:
    return os.urandom(n)


def flip_bit(b: bytes, bit_index: int) -> bytes:
    # bit_index in [0, len(b)*8); MSB-first inside each byte
    byte_i = bit_index // 8
    bit_in_byte = bit_index % 8
    mask = 1 << (7 - bit_in_byte)
    ba = bytearray(b)
    ba[byte_i] ^= mask
    return bytes(ba)


def hamming_distance_bits(a: bytes, b: bytes) -> int:
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def pct(bits_changed: int, total_bits: int) -> float:
    return 100.0 * bits_changed / total_bits if total_bits else 0.0


def verify_high_level_correctness(
    trials: int = 10,
    key_size: int = 16,
    message_bytes: Optional[int] = None,
) -> None:
    # CBC correctness for both implementations
    for _ in range(trials):
        key = randbytes(key_size)
        iv = randbytes(16)

        if message_bytes is not None and message_bytes >= 0:
            msg = randbytes(message_bytes)
        else:
            # Random 1..8 blocks, possibly not block-aligned to exercise padding
            blocks = random.randint(1, 8)
            msg = randbytes(blocks * 16 - random.randint(0, 15))

        aes_std = std.AES(key)
        aes_mod = mod.AES(key)

        c_std = aes_std.encrypt_cbc(msg, iv)
        p_std = aes_std.decrypt_cbc(c_std, iv)
        assert p_std == msg, "Standard AES CBC decrypt mismatch."

        c_mod = aes_mod.encrypt_cbc(msg, iv)
        p_mod = aes_mod.decrypt_cbc(c_mod, iv)
        assert p_mod == msg, "Modified AES CBC decrypt mismatch."


def key_sensitivity_cbc(
    trials: int = 400,
    key_size: int = 16,
    message_bytes: Optional[int] = None,
    blocks_range: Tuple[int, int] = (2, 6),
) -> Tuple[float, float, float, float]:
    """
    Key Sensitivity (CBC, high-level):
    - Draw random key K and flip 1 random bit -> K'
    - Use same msg and IV, compute c = E_K(msg, iv), c' = E_{K'}(msg, iv)
    - Measure % of ciphertext bits changed
    Returns (mean_std, stddev_std, mean_mod, stddev_mod)
    """
    results_std = []
    results_mod = []

    for _ in range(trials):
        key = randbytes(key_size)
        bit_i = random.randrange(key_size * 8)
        key_flip = flip_bit(key, bit_i)
        iv = randbytes(16)

        if message_bytes is not None and message_bytes >= 0:
            msg = randbytes(message_bytes)
        else:
            n_blocks = random.randint(blocks_range[0], blocks_range[1])
            msg = randbytes(n_blocks * 16 - random.randint(0, 15))

        # Standard AES
        aes_std = std.AES(key)
        aes_std_flip = std.AES(key_flip)
        c1_std = aes_std.encrypt_cbc(msg, iv)
        c2_std = aes_std_flip.encrypt_cbc(msg, iv)
        d_std = hamming_distance_bits(c1_std, c2_std)
        results_std.append(pct(d_std, len(c1_std) * 8))

        # Modified AES
        aes_mod = mod.AES(key)
        aes_mod_flip = mod.AES(key_flip)
        c1_mod = aes_mod.encrypt_cbc(msg, iv)
        c2_mod = aes_mod_flip.encrypt_cbc(msg, iv)
        d_mod = hamming_distance_bits(c1_mod, c2_mod)
        results_mod.append(pct(d_mod, len(c1_mod) * 8))

    return (
        statistics.mean(results_std),
        statistics.pstdev(results_std),
        statistics.mean(results_mod),
        statistics.pstdev(results_mod),
    )


def declare_winner(metric_name: str, mean_std: float, mean_mod: float) -> str:
    if mean_mod > mean_std:
        return f"Winner ({metric_name}): Modified AES"
    elif mean_mod < mean_std:
        return f"Winner ({metric_name}): Standard AES"
    else:
        return f"Winner ({metric_name}): Tie"


def parse_blocks_range(s: str) -> Tuple[int, int]:
    if "-" in s:
        a, b = s.split("-", 1)
        lo, hi = int(a), int(b)
    else:
        lo = hi = int(s)
    if lo < 1 or hi < lo:
        raise ValueError("Invalid blocks range")
    return lo, hi


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Compare Key Sensitivity: Standard AES vs Modified AES (CBC).")
    p.add_argument("--seed", type=int, default=1337, help="PRNG seed")
    p.add_argument("--key-size", type=int, choices=[16, 24, 32], default=16, help="AES key size in bytes (16/24/32)")

    # Message size control (applies to correctness and metric)
    p.add_argument("--message-bytes", type=int, default=None, help="Exact message size in bytes (CBC tests)")
    p.add_argument("--cbc-blocks-range", type=str, default="2-6", help="Blocks range when --message-bytes not set, e.g. 2-6")

    # Trials
    p.add_argument("--trials-correctness", type=int, default=20, help="Correctness trials (CBC)")
    p.add_argument("--trials", type=int, default=400, help="Key Sensitivity trials (CBC)")
    return p.parse_args()


def main():
    args = parse_args()
    random.seed(args.seed)
    blocks_range = parse_blocks_range(args.cbc_blocks_range)

    print("Configuration:")
    print(f"  Key size: {args.key_size} bytes")
    if args.message_bytes is not None:
        print(f"  Message size (CBC): {args.message_bytes} bytes")
    else:
        print(f"  Message blocks range (CBC): {blocks_range[0]}–{blocks_range[1]} blocks (random length, with padding)")
    print(f"  Trials: correctness={args.trials_correctness}, key-sensitivity={args.trials}\n")

    print("Verifying high-level CBC encryption/decryption correctness...")
    verify_high_level_correctness(
        trials=args.trials_correctness,
        key_size=args.key_size,
        message_bytes=args.message_bytes,
    )
    print("Correctness: OK\n")

    print("Measuring Key Sensitivity (CBC, high-level)...")
    ks_mean_std, ks_sd_std, ks_mean_mod, ks_sd_mod = key_sensitivity_cbc(
        trials=args.trials,
        key_size=args.key_size,
        message_bytes=args.message_bytes,
        blocks_range=blocks_range,
    )
    ks_improve = ks_mean_mod - ks_mean_std

    # Report
    print("=== Metrics Summary ===")
    print("Metric: Key Sensitivity (percent ciphertext bits changed when flipping 1 key bit)")
    print("Purpose: Key dependence")
    print("Expected Improvement (Modified AES): Higher bit difference")
    print("Reason: Key-derived permutation (KDRP)")
    print(f"  Standard AES: mean={ks_mean_std:.2f}%  sd={ks_sd_std:.2f}%")
    print(f"  Modified  AES: mean={ks_mean_mod:.2f}%  sd={ks_sd_mod:.2f}%")
    print(f"  Improvement (Modified - Standard): {ks_improve:+.2f}%")
    print(declare_winner("Key Sensitivity (CBC)", ks_mean_std, ks_mean_mod))


if __name__ == "__main__":
    main()