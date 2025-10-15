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


def bit_stats(data: bytes) -> Tuple[int, int, int]:
    """
    Single pass over bytes to compute:
      n_bits, ones_count, runs_count
    Bits are processed MSB first per NIST convention.
    """
    n = 0
    ones = 0
    runs = 0
    prev = None
    for b in data:
        for i in range(7, -1, -1):
            bit = (b >> i) & 1
            ones += bit
            if prev is None:
                runs = 1
            elif bit != prev:
                runs += 1
            prev = bit
            n += 1
    return n, ones, runs


def erfc(x: float) -> float:
    # Thin wrapper for clarity
    return math.erfc(x)


def normal_sf(z: float) -> float:
    # Survival function 1 - Phi(z)
    return 0.5 * math.erfc(z / math.sqrt(2.0))


def chi2_sf_wilson(chi2: float, df: int) -> float:
    """
    Chi-square survival function using Wilson–Hilferty normal approximation.
    Works well for moderate/large df and is dependency-free.

    p ≈ 1 - Phi( [(X/df)^{1/3} - (1 - 2/(9df))] / sqrt(2/(9df)) )
    """
    if df <= 0:
        return float("nan")
    if chi2 <= 0:
        return 1.0
    k = df
    c = 2.0 / (9.0 * k)
    z = ((chi2 / k) ** (1.0 / 3.0) - (1.0 - 2.0 / (9.0 * k))) / math.sqrt(c)
    return normal_sf(z)


def monobit_frequency_p(ciphertext: bytes) -> float:
    """
    NIST SP 800-22 Frequency (Monobit) Test p-value on a single sequence.
    """
    n, ones, _ = bit_stats(ciphertext)
    if n == 0:
        return float("nan")
    s_obs = abs(2 * ones - n) / math.sqrt(n)
    return erfc(s_obs / math.sqrt(2.0))


def runs_test_p(ciphertext: bytes) -> float:
    """
    NIST SP 800-22 Runs Test p-value on a single sequence.
    Requires the Frequency test to be not too far from 0.5.
    """
    n, ones, runs = bit_stats(ciphertext)
    if n == 0:
        return float("nan")
    pi = ones / n
    tau = 2.0 / math.sqrt(n)
    if abs(pi - 0.5) >= tau:
        # Per NIST, if frequency deviates too much, runs test p-value is 0
        return 0.0
    denom = 2.0 * math.sqrt(2.0 * n) * pi * (1.0 - pi)
    if denom == 0:
        return 0.0
    p = erfc(abs(runs - 2.0 * n * pi * (1.0 - pi)) / denom)
    return p


def byte_chi_square_p(ciphertext: bytes) -> float:
    """
    Chi-square test for byte histogram uniformity (256 categories).
    p-value via Wilson–Hilferty approximation (df=255).
    For short messages (few bytes), this test has low power.
    """
    n = len(ciphertext)
    if n == 0:
        return float("nan")
    expected = n / 256.0
    # If expected is very small, chi-square is noisy; we still compute.
    counts = [0] * 256
    for b in ciphertext:
        counts[b] += 1
    chi2 = 0.0
    if expected == 0:
        return float("nan")
    for c in counts:
        diff = c - expected
        chi2 += (diff * diff) / expected
    return chi2_sf_wilson(chi2, df=255)


def uniformity_p_value(pvals: List[float], bins: int = 10) -> Tuple[float, List[int]]:
    """
    NIST-style uniformity of p-values check:
      - Bin p-values into 'bins' equal-width intervals in [0,1].
      - Compute chi-square against uniform target, df=bins-1.
      - Return p-value (higher ~= more uniform) and bin counts.
    """
    finite = [p for p in pvals if p == p and 0.0 <= p <= 1.0]  # filter nan and bounds
    k = len(finite)
    if k == 0:
        return float("nan"), [0] * bins
    counts = [0] * bins
    for p in finite:
        idx = min(bins - 1, int(p * bins))
        counts[idx] += 1
    expected = k / bins
    chi2 = sum((c - expected) ** 2 / expected for c in counts)
    p_uni = chi2_sf_wilson(chi2, df=bins - 1)
    return p_uni, counts


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


def measure_pvalues(
    trials: int,
    key_size: int,
    msg_bytes: int,
    seed: int,
):
    random.seed(seed)

    freq_p_std, runs_p_std, chi_p_std = [], [], []
    freq_p_mod, runs_p_mod, chi_p_mod = [], [], []

    for _ in range(trials):
        key = randbytes(key_size)
        iv = randbytes(16)
        msg = randbytes(msg_bytes)

        aes_std = std.AES(key)
        aes_mod = mod.AES(key)

        c_std = aes_std.encrypt_cbc(msg, iv)
        c_mod = aes_mod.encrypt_cbc(msg, iv)

        # Per-sequence p-values
        freq_p_std.append(monobit_frequency_p(c_std))
        runs_p_std.append(runs_test_p(c_std))
        chi_p_std.append(byte_chi_square_p(c_std))

        freq_p_mod.append(monobit_frequency_p(c_mod))
        runs_p_mod.append(runs_test_p(c_mod))
        chi_p_mod.append(byte_chi_square_p(c_mod))

    return (freq_p_std, runs_p_std, chi_p_std), (freq_p_mod, runs_p_mod, chi_p_mod)


def declare_winner(metric: str, score_std: float, score_mod: float) -> str:
    if score_mod > score_std:
        return f"Winner ({metric}): Modified AES"
    elif score_mod < score_std:
        return f"Winner ({metric}): Standard AES"
    else:
        return f"Winner ({metric}): Tie"


def main():
    ap = argparse.ArgumentParser(description="Ciphertext Randomness comparison: Standard AES vs Modified AES (CBC).")
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

    print("Measuring per-sequence p-values (Monobit Frequency, Runs, Byte Chi-Square)...")
    (freq_std, runs_std, chi_std), (freq_mod, runs_mod, chi_mod) = measure_pvalues(
        trials=args.trials,
        key_size=args.key_size,
        msg_bytes=args.message_bytes,
        seed=args.seed,
    )

    # Uniformity-of-p-values per test
    freq_uni_std, freq_bins_std = uniformity_p_value(freq_std)
    freq_uni_mod, freq_bins_mod = uniformity_p_value(freq_mod)

    runs_uni_std, runs_bins_std = uniformity_p_value(runs_std)
    runs_uni_mod, runs_bins_mod = uniformity_p_value(runs_mod)

    chi_uni_std, chi_bins_std = uniformity_p_value(chi_std)
    chi_uni_mod, chi_bins_mod = uniformity_p_value(chi_mod)

    # Summaries (means shown for sanity; decision uses uniformity p-values)
    def safe_mean(xs): 
        xs2 = [x for x in xs if x == x]  # drop NaN
        return statistics.mean(xs2) if xs2 else float("nan")

    print("=== Metrics: Ciphertext Randomness ===")
    print("Metric: Ciphertext Randomness")
    print("Purpose: Randomness quality")
    print("Expected Improvement (Modified AES): More uniform p-values")
    print("Reason: Added whitening (KW-Tweak)")
    print()

    print("Monobit Frequency Test:")
    print(f"  Standard AES: mean p={safe_mean(freq_std):.3f}, uniformity p={freq_uni_std:.3f}")
    print(f"  Modified  AES: mean p={safe_mean(freq_mod):.3f}, uniformity p={freq_uni_mod:.3f}")
    print(declare_winner("Monobit Frequency (uniformity of p-values)", freq_uni_std, freq_uni_mod))
    print()

    print("Runs Test:")
    print(f"  Standard AES: mean p={safe_mean(runs_std):.3f}, uniformity p={runs_uni_std:.3f}")
    print(f"  Modified  AES: mean p={safe_mean(runs_mod):.3f}, uniformity p={runs_uni_mod:.3f}")
    print(declare_winner("Runs (uniformity of p-values)", runs_uni_std, runs_uni_mod))
    print()

    print("Byte Chi-Square (256-bin uniformity):")
    print(f"  Standard AES: mean p={safe_mean(chi_std):.3f}, uniformity p={chi_uni_std:.3f}")
    print(f"  Modified  AES: mean p={safe_mean(chi_mod):.3f}, uniformity p={chi_uni_mod:.3f}")
    print(declare_winner("Byte Chi-Square (uniformity of p-values)", chi_uni_std, chi_uni_mod))
    print()

    # Overall winner by averaging uniformity p-values across tests
    std_overall = (freq_uni_std + runs_uni_std + chi_uni_std) / 3.0
    mod_overall = (freq_uni_mod + runs_uni_mod + chi_uni_mod) / 3.0

    print("Overall Comparison (average uniformity-of-p-values across tests):")
    print(f"  Standard AES overall uniformity score: {std_overall:.3f}")
    print(f"  Modified  AES overall uniformity score: {mod_overall:.3f}")
    print(declare_winner("Ciphertext Randomness (overall)", std_overall, mod_overall))
    print()

    # Notes for publication clarity
    print("Notes:")
    print("  - Higher 'uniformity p' indicates the set of p-values is closer to Uniform(0,1).")
    print("  - Tests run on high-level CBC encryption with identical keys/IVs/messages per trial for fairness.")
    print("  - Byte chi-square has more power with larger message sizes; consider --message-bytes >= 8192 and --trials >= 300.")


if __name__ == "__main__":
    main()