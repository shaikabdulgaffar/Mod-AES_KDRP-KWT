import os
import argparse
import random
import statistics
from typing import List, Tuple

import std_aes as std
import mod_aes as mod


def randbytes(n: int) -> bytes:
    return os.urandom(n)


def bytes_to_bits(data: bytes) -> List[int]:
    out = []
    for b in data:
        for i in range(7, -1, -1):
            out.append((b >> i) & 1)
    return out


def pearson_abs(x: List[float], y: List[float]) -> float:
    # Return absolute Pearson correlation |r|; lower is better (closer to 0).
    n = len(x)
    if n == 0 or n != len(y):
        return float("nan")
    mx = sum(x) / n
    my = sum(y) / n
    num = 0.0
    dx2 = 0.0
    dy2 = 0.0
    for i in range(n):
        dx = x[i] - mx
        dy = y[i] - my
        num += dx * dy
        dx2 += dx * dx
        dy2 += dy * dy
    denom = (dx2 * dy2) ** 0.5
    if denom == 0.0:
        return 0.0
    return abs(num / denom)


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


def correlation_trials(
    trials: int,
    key_size: int,
    msg_bytes: int,
    seed: int,
) -> Tuple[Tuple[List[float], List[float]], Tuple[List[float], List[float]]]:
    """
    Returns:
      (byte_abs_r_std, bit_abs_r_std), (byte_abs_r_mod, bit_abs_r_mod)
      Each is a list of |r| values across trials.
    """
    random.seed(seed)

    byte_rs_std: List[float] = []
    bit_rs_std: List[float] = []
    byte_rs_mod: List[float] = []
    bit_rs_mod: List[float] = []

    for _ in range(trials):
        key = randbytes(key_size)
        iv = randbytes(16)
        msg = randbytes(msg_bytes)

        aes_std = std.AES(key)
        aes_mod = mod.AES(key)

        c_std = aes_std.encrypt_cbc(msg, iv)
        c_mod = aes_mod.encrypt_cbc(msg, iv)

        # Align lengths to original plaintext length (ignore padding-only tail)
        c_std_slice = c_std[:len(msg)]
        c_mod_slice = c_mod[:len(msg)]

        # Byte-level |r|
        x_b = list(msg)  # 0..255
        y_b_std = list(c_std_slice)
        y_b_mod = list(c_mod_slice)
        byte_rs_std.append(pearson_abs(x_b, y_b_std))
        byte_rs_mod.append(pearson_abs(x_b, y_b_mod))

        # Bit-level |r|
        x_bits = bytes_to_bits(msg)
        y_bits_std = bytes_to_bits(c_std_slice)
        y_bits_mod = bytes_to_bits(c_mod_slice)
        bit_rs_std.append(pearson_abs(x_bits, y_bits_std))
        bit_rs_mod.append(pearson_abs(x_bits, y_bits_mod))

    return (byte_rs_std, bit_rs_std), (byte_rs_mod, bit_rs_mod)


def declare_winner(metric: str, score_std: float, score_mod: float) -> str:
    # Lower absolute correlation is better (closer to 0)
    if score_mod < score_std:
        return f"Winner ({metric}): Modified AES"
    elif score_mod > score_std:
        return f"Winner ({metric}): Standard AES"
    else:
        return f"Winner ({metric}): Tie"


def safe_mean(xs: List[float]) -> float:
    xs2 = [x for x in xs if x == x]
    return statistics.mean(xs2) if xs2 else float("nan")


def safe_stdev(xs: List[float]) -> float:
    xs2 = [x for x in xs if x == x]
    return statistics.pstdev(xs2) if xs2 else float("nan")


def main():
    ap = argparse.ArgumentParser(description="Correlation Coefficient comparison: Standard AES vs Modified AES (CBC).")
    ap.add_argument("--key-size", type=int, choices=[16, 24, 32], default=16, help="AES key size in bytes")
    ap.add_argument("--message-bytes", type=int, default=4096, help="Plaintext size per trial in bytes")
    ap.add_argument("--trials", type=int, default=200, help="Number of random trials")
    ap.add_argument("--seed", type=int, default=1337, help="PRNG seed")
    ap.add_argument("--correctness-trials", type=int, default=10, help="CBC encrypt/decrypt sanity trials")
    args = ap.parse_args()

    print("Configuration:")
    print(f"  Key size: {args.key_size} bytes")
    print(f"  Message size per trial: {args.message_bytes} bytes")
    print(f"  Trials: {args.trials}")
    print(f"  Seed: {args.seed}")
    print()

    print("Verifying high-level CBC encryption/decryption correctness...")
    verify_cbc_correctness(args.correctness_trials, args.key_size, args.message_bytes)
    print("Correctness: OK\n")

    print("Measuring plaintext–ciphertext correlation (byte-level and bit-level)...")
    (byte_std, bit_std), (byte_mod, bit_mod) = correlation_trials(
        trials=args.trials,
        key_size=args.key_size,
        msg_bytes=args.message_bytes,
        seed=args.seed,
    )

    byte_mean_std = safe_mean(byte_std)
    byte_mean_mod = safe_mean(byte_mod)
    byte_sd_std = safe_stdev(byte_std)
    byte_sd_mod = safe_stdev(byte_mod)

    bit_mean_std = safe_mean(bit_std)
    bit_mean_mod = safe_mean(bit_mod)
    bit_sd_std = safe_stdev(bit_std)
    bit_sd_mod = safe_stdev(bit_mod)

    byte_improve = byte_mean_std - byte_mean_mod  # positive => closer to 0 for Modified
    bit_improve = bit_mean_std - bit_mean_mod

    print("=== Metrics: Correlation Coefficient ===")
    print("Metric: Correlation Coefficient (|r| between plaintext and ciphertext)")
    print("Purpose: Plain–cipher independence")
    print("Expected Improvement (Modified AES): Closer to 0")
    print("Reason: Row-level permutation (KDRP)")
    print()

    print("Byte-level correlation (|r|):")
    print(f"  Standard AES: mean={byte_mean_std:.5f}  sd={byte_sd_std:.5f}")
    print(f"  Modified  AES: mean={byte_mean_mod:.5f}  sd={byte_sd_mod:.5f}")
    print(f"  Improvement (lower is better): {byte_improve:+.5f}")
    print(declare_winner("Correlation (byte-level)", byte_mean_std, byte_mean_mod))
    print()

    print("Bit-level correlation (|r|):")
    print(f"  Standard AES: mean={bit_mean_std:.5f}  sd={bit_sd_std:.5f}")
    print(f"  Modified  AES: mean={bit_mean_mod:.5f}  sd={bit_sd_mod:.5f}")
    print(f"  Improvement (lower is better): {bit_improve:+.5f}")
    print(declare_winner("Correlation (bit-level)", bit_mean_std, bit_mean_mod))
    print()

    # Overall winner by averaging the two |r| means
    std_overall = (byte_mean_std + bit_mean_std) / 2.0
    mod_overall = (byte_mean_mod + bit_mean_mod) / 2.0
    print("Overall Comparison (average of byte- and bit-level |r|):")
    print(f"  Standard AES overall |r|: {std_overall:.5f}")
    print(f"  Modified  AES overall |r|: {mod_overall:.5f}")
    print(declare_winner("Correlation (overall)", std_overall, mod_overall))
    print()

    print("Notes:")
    print("  - Lower |r| means ciphertext is less linearly related to plaintext (closer to 0 is better).")
    print("  - Computed on high-level CBC encryption; ciphertext was truncated to the original plaintext length for pairing.")
    print("  - Increase --message-bytes and --trials for stronger statistical power in publication.")


if __name__ == "__main__":
    main()