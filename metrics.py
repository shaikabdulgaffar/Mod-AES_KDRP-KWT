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
    # bit_index in [0, len(b)*8)
    byte_i = bit_index // 8
    bit_in_byte = bit_index % 8
    mask = 1 << (7 - bit_in_byte)  # MSB-first bit numbering
    ba = bytearray(b)
    ba[byte_i] ^= mask
    return bytes(ba)


def hamming_distance_bits(a: bytes, b: bytes) -> int:
    # Sum popcount over XOR of each byte
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def pct(bits_changed: int, total_bits: int) -> float:
    return 100.0 * bits_changed / total_bits


def verify_high_level_correctness(
    trials: int = 10,
    key_size: int = 16,
    message_bytes: Optional[int] = None,
) -> None:
    # CBC correctness for both implementations
    for _ in range(trials):
        key = randbytes(key_size)
        iv = randbytes(16)

        if message_bytes is not None and message_bytes > 0:
            msg = randbytes(message_bytes)
        else:
            # Random message length across 1..8 blocks (with padding inside CBC)
            plen = random.randint(1, 8) * 16 - random.randint(0, 15)
            msg = randbytes(plen)

        aes_std = std.AES(key)
        aes_mod = mod.AES(key)

        c_std = aes_std.encrypt_cbc(msg, iv)
        p_std = aes_std.decrypt_cbc(c_std, iv)
        assert p_std == msg, "Standard AES CBC decrypt mismatch."

        c_mod = aes_mod.encrypt_cbc(msg, iv)
        p_mod = aes_mod.decrypt_cbc(c_mod, iv)
        assert p_mod == msg, "Modified AES CBC decrypt mismatch."


def avalanche_block(trials: int = 1000, key_size: int = 16) -> Tuple[float, float, float, float]:
    """
    Measure Avalanche Effect at block level:
    - Random key
    - Random 16-byte plaintext
    - Flip one random bit in plaintext
    - Measure % of ciphertext bits changed
    Returns (mean_std, stddev_std, mean_mod, stddev_mod)
    """
    results_std = []
    results_mod = []
    total_bits = 16 * 8

    for _ in range(trials):
        key = randbytes(key_size)
        p = randbytes(16)
        bit_i = random.randrange(total_bits)
        p_flip = flip_bit(p, bit_i)

        aes_std = std.AES(key)
        c1_std = aes_std.encrypt_block(p)
        c2_std = aes_std.encrypt_block(p_flip)
        d_std = hamming_distance_bits(c1_std, c2_std)
        results_std.append(pct(d_std, total_bits))

        aes_mod = mod.AES(key)
        # For fairness, use default tweak (block_index=0, tweak_iv=None)
        c1_mod = aes_mod.encrypt_block(p)
        c2_mod = aes_mod.encrypt_block(p_flip)
        d_mod = hamming_distance_bits(c1_mod, c2_mod)
        results_mod.append(pct(d_mod, total_bits))

    return (
        statistics.mean(results_std),
        statistics.pstdev(results_std),
        statistics.mean(results_mod),
        statistics.pstdev(results_mod),
    )


def avalanche_cbc(
    trials: int = 300,
    key_size: int = 16,
    message_bytes: Optional[int] = None,
    blocks_range: Tuple[int, int] = (2, 6),
) -> Tuple[float, float, float, float]:
    """
    Measure Avalanche Effect at high-level CBC:
    - Random key and IV
    - Either exact message_bytes or random message of N blocks (uniform in blocks_range)
    - Flip one random bit in the first block of the plaintext
    - Measure % of ciphertext bits changed
    Returns (mean_std, stddev_std, mean_mod, stddev_mod)
    """
    results_std = []
    results_mod = []
    for _ in range(trials):
        key = randbytes(key_size)
        iv = randbytes(16)

        if message_bytes is not None and message_bytes > 0:
            msg = randbytes(message_bytes)
        else:
            n_blocks = random.randint(blocks_range[0], blocks_range[1])
            msg = randbytes(n_blocks * 16)

        # Flip one bit in first block to localize the difference origin
        bit_i = random.randrange(min(16, max(1, len(msg))) * 8)
        msg_flip = flip_bit(msg, bit_i)

        aes_std = std.AES(key)
        c1_std = aes_std.encrypt_cbc(msg, iv)
        c2_std = aes_std.encrypt_cbc(msg_flip, iv)
        d_std = hamming_distance_bits(c1_std, c2_std)
        results_std.append(pct(d_std, len(c1_std) * 8))

        aes_mod = mod.AES(key)
        c1_mod = aes_mod.encrypt_cbc(msg, iv)
        c2_mod = aes_mod.encrypt_cbc(msg_flip, iv)
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


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Compare Standard AES vs Modified AES on Avalanche metrics.")
    p.add_argument("--seed", type=int, default=1337, help="PRNG seed")
    p.add_argument("--key-size", type=int, choices=[16, 24, 32], default=16, help="AES key size in bytes (16/24/32)")

    # Message size control (applies to correctness and CBC avalanche)
    p.add_argument("--message-bytes", type=int, default=None, help="Exact message size in bytes for CBC tests")
    p.add_argument("--cbc-blocks-range", type=str, default="2-6", help="Blocks range when --message-bytes not set, e.g. 2-6")

    # Trials
    p.add_argument("--trials-correctness", type=int, default=20, help="Correctness trials (CBC)")
    p.add_argument("--trials-block", type=int, default=1000, help="Avalanche trials (block-level)")
    p.add_argument("--trials-cbc", type=int, default=400, help="Avalanche trials (CBC-level)")
    return p.parse_args()


def parse_blocks_range(s: str) -> Tuple[int, int]:
    if "-" in s:
        a, b = s.split("-", 1)
        lo, hi = int(a), int(b)
    else:
        lo = hi = int(s)
    if lo < 1 or hi < lo:
        raise ValueError("Invalid blocks range")
    return lo, hi


def main():
    args = parse_args()
    random.seed(args.seed)

    blocks_range = parse_blocks_range(args.cbc_blocks_range)

    print("Configuration:")
    print(f"  Key size: {args.key_size} bytes")
    if args.message_bytes:
        print(f"  Message size (CBC tests): {args.message_bytes} bytes")
    else:
        print(f"  Message blocks range (CBC tests): {blocks_range[0]}–{blocks_range[1]} blocks")
    print(f"  Trials: correctness={args.trials_correctness}, block-avalanche={args.trials_block}, cbc-avalanche={args.trials_cbc}\n")

    print("Verifying high-level CBC encryption/decryption correctness...")
    verify_high_level_correctness(
        trials=args.trials_correctness,
        key_size=args.key_size,
        message_bytes=args.message_bytes,
    )
    print("Correctness: OK\n")

    print("Measuring Avalanche Effect (block-level, encrypt_block)...")
    b_mean_std, b_sd_std, b_mean_mod, b_sd_mod = avalanche_block(
        trials=args.trials_block,
        key_size=args.key_size,
    )
    b_improve = b_mean_mod - b_mean_std

    print("Measuring Avalanche Effect (high-level CBC, fixed IV)...")
    c_mean_std, c_sd_std, c_mean_mod, c_sd_mod = avalanche_cbc(
        trials=args.trials_cbc,
        key_size=args.key_size,
        message_bytes=args.message_bytes,
        blocks_range=blocks_range,
    )
    c_improve = c_mean_mod - c_mean_std

    # Report
    print("=== Metrics Summary ===")
    print("Metric: Avalanche Effect (Block)")
    print(f"  Standard AES: mean={b_mean_std:.2f}%  sd={b_sd_std:.2f}%")
    print(f"  Modified  AES: mean={b_mean_mod:.2f}%  sd={b_sd_mod:.2f}%")
    print(f"  Improvement (Modified - Standard): {b_improve:+.2f}%")
    print("  Expected Improvement (KDRP + KW-Tweak): +3–6%")
    print(declare_winner("Avalanche Effect (Block)", b_mean_std, b_mean_mod))
    print()

    print("Metric: Avalanche Effect (CBC)")
    print(f"  Standard AES: mean={c_mean_std:.2f}%  sd={c_sd_std:.2f}%")
    print(f"  Modified  AES: mean={c_mean_mod:.2f}%  sd={c_sd_mod:.2f}%")
    print(f"  Improvement (Modified - Standard): {c_improve:+.2f}%")
    print("  Expected Improvement (KDRP + KW-Tweak): +3–6%")
    print(declare_winner("Avalanche Effect (CBC)", c_mean_std, c_mean_mod))
    print()

    # Overall winner by averaging both avalanche means
    std_overall = (b_mean_std + c_mean_std) / 2.0
    mod_overall = (b_mean_mod + c_mean_mod) / 2.0
    print("Overall Comparison (Average of two avalanche metrics):")
    print(f"  Standard AES overall: {std_overall:.2f}%")
    print(f"  Modified  AES overall: {mod_overall:.2f}%")
    print(declare_winner("Overall Avalanche", std_overall, mod_overall))


if __name__ == "__main__":
    main()