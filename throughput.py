import argparse
import os
import random
import statistics
import time

import std_aes as std
import mod_aes as mod


def randbytes(n: int) -> bytes:
    return os.urandom(n)


def time_op(func, *args, iterations=1):
    # small wrapper using perf_counter
    start = time.perf_counter()
    for _ in range(iterations):
        func(*args)
    end = time.perf_counter()
    return max(end - start, 1e-12)


def bench_single_round(aes_cls, key, iv, msg, iterations_encrypt=10, iterations_decrypt=10):
    aes = aes_cls(key)
    # encrypt once to obtain ciphertext for decrypt timing
    ct = aes.encrypt_cbc(msg, iv)

    # verify correctness (decrypt result equals original)
    pt = aes.decrypt_cbc(ct, iv)
    assert pt == msg, "Sanity decrypt mismatch"

    # encrypt timing (measure plaintext bytes processed)
    enc_time = time_op(aes.encrypt_cbc, msg, iv, iterations=iterations_encrypt)
    enc_bytes = len(msg) * iterations_encrypt
    enc_bps = enc_bytes / enc_time

    # decrypt timing (measure ciphertext bytes processed)
    dec_time = time_op(aes.decrypt_cbc, ct, iv, iterations=iterations_decrypt)
    dec_bytes = len(ct) * iterations_decrypt
    dec_bps = dec_bytes / dec_time

    return enc_bps, dec_bps, len(msg), len(ct)


def run_benchmark(
    key_size: int,
    message_bytes: int,
    trials: int,
    iterations_encrypt: int,
    iterations_decrypt: int,
    warmup: int,
    seed: int,
):
    random.seed(seed)
    std_encs, std_decs = [], []
    mod_encs, mod_decs = [], []
    msg_sizes = []
    ct_sizes = []

    # warmup
    for _ in range(warmup):
        key = randbytes(key_size)
        iv = randbytes(16)
        msg = randbytes(message_bytes)
        std.AES(key).encrypt_cbc(msg, iv)
        mod.AES(key).encrypt_cbc(msg, iv)

    for t in range(trials):
        key = randbytes(key_size)
        iv = randbytes(16)
        msg = randbytes(message_bytes)

        # Standard AES
        se, sd, mlen, ctlen = bench_single_round(
            std.AES, key, iv, msg, iterations_encrypt, iterations_decrypt
        )
        std_encs.append(se)
        std_decs.append(sd)

        # Modified AES
        me, md, _, _ = bench_single_round(
            mod.AES, key, iv, msg, iterations_encrypt, iterations_decrypt
        )
        mod_encs.append(me)
        mod_decs.append(md)

        msg_sizes.append(mlen)
        ct_sizes.append(ctlen)

    # statistics
    def stats(xs):
        return statistics.mean(xs), statistics.pstdev(xs)

    se_mean, se_sd = stats(std_encs)
    sd_mean, sd_sd = stats(std_decs)
    me_mean, me_sd = stats(mod_encs)
    md_mean, md_sd = stats(mod_decs)

    return {
        "std_enc_mean": se_mean, "std_enc_sd": se_sd,
        "std_dec_mean": sd_mean, "std_dec_sd": sd_sd,
        "mod_enc_mean": me_mean, "mod_enc_sd": me_sd,
        "mod_dec_mean": md_mean, "mod_dec_sd": md_sd,
        "avg_plain_bytes": statistics.mean(msg_sizes),
        "avg_ct_bytes": statistics.mean(ct_sizes),
    }


def declare_winner(metric_name: str, std_score: float, mod_score: float) -> str:
    if mod_score > std_score:
        return f"Winner ({metric_name}): Modified AES"
    elif mod_score < std_score:
        return f"Winner ({metric_name}): Standard AES"
    else:
        return f"Winner ({metric_name}): Tie"


def parse_args():
    p = argparse.ArgumentParser(description="Throughput comparison: std_aes vs mod_aes (CBC high-level).")
    p.add_argument("--key-size", type=int, choices=[16,24,32], default=16, help="Key size in bytes")
    p.add_argument("--message-bytes", type=int, default=16384, help="Plaintext size per trial (bytes)")
    p.add_argument("--trials", type=int, default=20, help="Number of independent trials")
    p.add_argument("--iters-enc", type=int, default=8, help="Inner encryption iterations per timing sample")
    p.add_argument("--iters-dec", type=int, default=8, help="Inner decryption iterations per timing sample")
    p.add_argument("--warmup", type=int, default=2, help="Warmup rounds (not measured)")
    p.add_argument("--seed", type=int, default=1337, help="PRNG seed")
    return p.parse_args()


def main():
    args = parse_args()
    print("Configuration:")
    print(f"  Key size: {args.key_size} bytes")
    print(f"  Message size: {args.message_bytes} bytes")
    print(f"  Trials: {args.trials}, inner iters enc/dec: {args.iters_enc}/{args.iters_dec}, warmup: {args.warmup}")
    print()

    results = run_benchmark(
        key_size=args.key_size,
        message_bytes=args.message_bytes,
        trials=args.trials,
        iterations_encrypt=args.iters_enc,
        iterations_decrypt=args.iters_dec,
        warmup=args.warmup,
        seed=args.seed,
    )

    print("=== Throughput Results (bytes/sec) ===")
    print(f"Encryption (plaintext bytes/sec):")
    print(f"  Standard AES: mean={results['std_enc_mean']:.2f}  sd={results['std_enc_sd']:.2f}")
    print(f"  Modified  AES: mean={results['mod_enc_mean']:.2f}  sd={results['mod_enc_sd']:.2f}")
    print(declare_winner("Encryption throughput", results['std_enc_mean'], results['mod_enc_mean']))
    print()

    print(f"Decryption (ciphertext bytes/sec):")
    print(f"  Standard AES: mean={results['std_dec_mean']:.2f}  sd={results['std_dec_sd']:.2f}")
    print(f"  Modified  AES: mean={results['mod_dec_mean']:.2f}  sd={results['mod_dec_sd']:.2f}")
    print(declare_winner("Decryption throughput", results['std_dec_mean'], results['mod_dec_mean']))
    print()

    overall_std = (results['std_enc_mean'] + results['std_dec_mean']) / 2.0
    overall_mod = (results['mod_enc_mean'] + results['mod_dec_mean']) / 2.0
    print("Overall (average of enc+dec throughput):")
    print(f"  Standard AES overall: {overall_std:.2f} bytes/sec")
    print(f"  Modified  AES overall: {overall_mod:.2f} bytes/sec")
    print(declare_winner("Overall throughput", overall_std, overall_mod))


if __name__ == "__main__":
    main()