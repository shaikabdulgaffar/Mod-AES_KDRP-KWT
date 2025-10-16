import os
import math
import argparse
import random
from typing import List, Tuple

import std_aes as std
import mod_aes as mod


def randbytes(n: int) -> bytes:
    return os.urandom(n)


def flip_one_bit_first_block(msg: bytes) -> bytes:
    if not msg:
        return msg
    limit_bits = min(16, len(msg)) * 8
    bit_i = random.randrange(limit_bits)
    byte_i = bit_i // 8
    bit_in_byte = bit_i % 8
    mask = 1 << (7 - bit_in_byte)  # MSB-first
    ba = bytearray(msg)
    ba[byte_i] ^= mask
    return bytes(ba)


def flip_one_byte_first_block(msg: bytes) -> bytes:
    if not msg:
        return msg
    limit = min(16, len(msg))
    idx = random.randrange(limit)
    delta = random.randrange(1, 256)  # non-zero XOR delta
    ba = bytearray(msg)
    ba[idx] ^= delta
    return bytes(ba)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def chi2_sf_wilson(chi2: float, df: int) -> float:
    # Wilson–Hilferty normal approximation for chi-square survival function
    if df <= 0:
        return float("nan")
    if chi2 <= 0:
        return 1.0
    k = df
    c = 2.0 / (9.0 * k)
    z = ((chi2 / k) ** (1.0 / 3.0) - (1.0 - 2.0 / (9.0 * k))) / math.sqrt(c)
    # Survival function 1 - Phi(z)
    return 0.5 * math.erfc(z / math.sqrt(2.0))


def uniformity_p_from_hist(counts: List[int]) -> Tuple[float, float, float]:
    """
    Given 256-bin counts of byte values, compute:
      - p_uni: chi-square p-value vs uniform
      - zero_abs_err: |freq(0x00) - 1/256|
      - max_rel_dev: max_i |count_i - expected| / expected
    """
    k = sum(counts)
    if k == 0:
        return float("nan"), float("nan"), float("nan")
    expected = k / 256.0
    chi2 = 0.0
    max_rel_dev = 0.0
    for i, c in enumerate(counts):
        diff = c - expected
        chi2 += (diff * diff) / expected
        max_rel_dev = max(max_rel_dev, abs(diff) / expected)
    p_uni = chi2_sf_wilson(chi2, df=255)
    zero_abs_err = abs((counts[0] / k) - (1.0 / 256.0))
    return p_uni, zero_abs_err, max_rel_dev


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


def differential_experiment(
    trials: int,
    key_size: int,
    msg_bytes: int,
    seed: int,
    diff_mode: str,
) -> Tuple[List[int], List[int]]:
    """
    Runs trials with same (K, IV) and messages M, M' that differ in first block by:
      - diff_mode == 'bit': one random bit flip
      - diff_mode == 'byte': one random byte XOR with non-zero delta
    Collects histogram of ciphertext XOR differences over all positions for:
      - Standard AES CBC
      - Modified AES CBC
    Returns two 256-length hist arrays (std_hist, mod_hist).
    """
    random.seed(seed)
    hist_std = [0] * 256
    hist_mod = [0] * 256

    for _ in range(trials):
        key = randbytes(key_size)
        iv = randbytes(16)
        msg = randbytes(msg_bytes)
        msg_prime = flip_one_bit_first_block(msg) if diff_mode == "bit" else flip_one_byte_first_block(msg)

        aes_std = std.AES(key)
        aes_mod = mod.AES(key)

        c_std = aes_std.encrypt_cbc(msg, iv)
        c_std_p = aes_std.encrypt_cbc(msg_prime, iv)
        dc_std = xor_bytes(c_std, c_std_p)
        for b in dc_std:
            hist_std[b] += 1

        c_mod = aes_mod.encrypt_cbc(msg, iv)
        c_mod_p = aes_mod.encrypt_cbc(msg_prime, iv)
        dc_mod = xor_bytes(c_mod, c_mod_p)
        for b in dc_mod:
            hist_mod[b] += 1

    return hist_std, hist_mod


def declare_winner(metric: str, score_std: float, score_mod: float, higher_is_better: bool = True) -> str:
    if score_std != score_std or score_mod != score_mod:  # NaN checks
        return f"Winner ({metric}): Undetermined"
    if higher_is_better:
        if score_mod > score_std:
            return f"Winner ({metric}): Modified AES"
        elif score_mod < score_std:
            return f"Winner ({metric}): Standard AES"
        else:
            return f"Winner ({metric}): Tie"
    else:
        if score_mod < score_std:
            return f"Winner ({metric}): Modified AES"
        elif score_mod > score_std:
            return f"Winner ({metric}): Standard AES"
        else:
            return f"Winner ({metric}): Tie"


def main():
    ap = argparse.ArgumentParser(description="Differential Resistance comparison: Standard AES vs Modified AES (CBC).")
    ap.add_argument("--key-size", type=int, choices=[16, 24, 32], default=16, help="AES key size in bytes")
    ap.add_argument("--message-bytes", type=int, default=4096, help="Plaintext size per trial in bytes")
    ap.add_argument("--trials", type=int, default=400, help="Number of differential trials")
    ap.add_argument("--seed", type=int, default=1337, help="PRNG seed")
    ap.add_argument("--correctness-trials", type=int, default=10, help="CBC encrypt/decrypt sanity trials")
    ap.add_argument("--diff-mode", choices=["bit", "byte"], default="bit", help="Type of input differential in first block")
    args = ap.parse_args()

    if args.message_bytes <= 0:
        raise ValueError("message-bytes must be > 0")

    print("Configuration:")
    print(f"  Key size: {args.key_size} bytes")
    print(f"  Message size per trial: {args.message_bytes} bytes")
    print(f"  Trials: {args.trials}")
    print(f"  Seed: {args.seed}")
    print(f"  Differential mode: {args.diff_mode} (in first block)")
    print()

    print("Verifying high-level CBC encryption/decryption correctness...")
    verify_cbc_correctness(args.correctness_trials, args.key_size, args.message_bytes)
    print("Correctness: OK\n")

    print("Running differential experiment and aggregating ciphertext XOR histograms...")
    hist_std, hist_mod = differential_experiment(
        trials=args.trials,
        key_size=args.key_size,
        msg_bytes=args.message_bytes,
        seed=args.seed,
        diff_mode=args.diff_mode,
    )

    p_uni_std, zero_err_std, max_dev_std = uniformity_p_from_hist(hist_std)
    p_uni_mod, zero_err_mod, max_dev_mod = uniformity_p_from_hist(hist_mod)

    print("=== Metrics: Differential Resistance ===")
    print("Metric: Differential Resistance (ciphertext XOR distribution under chosen-input difference)")
    print("Purpose: Cryptanalytic robustness")
    print("Expected Improvement (Modified AES): Higher resistance")
    print("Reason: Extra confusion via KDRP")
    print()

    # Primary score: uniformity of byte-wise XOR deltas
    print("Primary score — Uniformity of delta-cipher bytes (chi-square p-value):")
    print(f"  Standard AES: p_uniform={p_uni_std:.4f}")
    print(f"  Modified  AES: p_uniform={p_uni_mod:.4f}")
    print(declare_winner("Differential Resistance (uniformity p-value)", p_uni_std, p_uni_mod, higher_is_better=True))
    print()

    # Secondary indicators
    print("Secondary indicators:")
    print(f"  Zero-delta bias |P(delta=0) - 1/256|  -> lower is better")
    print(f"    Standard AES: {zero_err_std:.6f}")
    print(f"    Modified  AES: {zero_err_mod:.6f}")
    print(declare_winner("Zero-delta bias", zero_err_std, zero_err_mod, higher_is_better=False))
    print()
    print(f"  Max-bin relative deviation (max_i |count_i - exp| / exp) -> lower is better")
    print(f"    Standard AES: {max_dev_std:.6f}")
    print(f"    Modified  AES: {max_dev_mod:.6f}")
    print(declare_winner("Max-bin relative deviation", max_dev_std, max_dev_mod, higher_is_better=False))
    print()

    # Overall winner: prioritize uniformity p-value, then tie-breakers
    overall_msg = declare_winner("Differential Resistance (overall)", p_uni_std, p_uni_mod, higher_is_better=True)
    if "Tie" in overall_msg:
        # tie-break 1: lower zero bias
        zb = declare_winner("Tie-break (zero bias)", zero_err_std, zero_err_mod, higher_is_better=False)
        if "Modified" in zb:
            overall_msg = "Winner (Differential Resistance — overall): Modified AES"
        elif "Standard" in zb:
            overall_msg = "Winner (Differential Resistance — overall): Standard AES"
        else:
            # tie-break 2: lower max deviation
            md = declare_winner("Tie-break (max deviation)", max_dev_std, max_dev_mod, higher_is_better=False)
            if "Modified" in md:
                overall_msg = "Winner (Differential Resistance — overall): Modified AES"
            elif "Standard" in md:
                overall_msg = "Winner (Differential Resistance — overall): Standard AES"
            else:
                overall_msg = "Winner (Differential Resistance — overall): Tie"

    print(overall_msg)
    print()
    print("Notes:")
    print("  - We flip 1 bit (or 1 byte) in the first block of the plaintext and compare CBC ciphertext pairs under identical K and IV.")
    print("  - A more uniform XOR(delta-cipher) distribution (higher p-value) indicates stronger differential resistance.")
    print("  - Increase --message-bytes and --trials for higher statistical power in your paper.")


if __name__ == "__main__":
    main()