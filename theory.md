
# KW‑Tweak + KDRP: A Tweakable, Key‑Dependent AES Variant with Hash‑Based Whitening and Dynamic Row Rotation

### Abstract
- We propose a tweakable and key‑dependent variant of AES‑128 that augments the round function with (i) a KW‑Tweak whitening mask W(T,K) derived from SHA‑256 over a per‑block tweak T and the master key K, and (ii) a Key‑Derived Row Permutation (KDRP) replacing the fixed ShiftRows with a key‑dependent left rotation applied to each state row. The tweak T encodes the IV and block index to ensure per‑block uniqueness across standard block modes. We analyze correctness/invertibility, discuss the construction as a family of tweakable permutations, and evaluate diffusion and avalanche. We provide an authenticated encryption wrapper using PBKDF2‑HMAC‑SHA256 for key derivation and HMAC‑SHA256 for integrity, and demonstrate applicability to CBC/PCBC/CFB/OFB/CTR. Our experiments show strong empirical diffusion with minimal structural overhead, at the cost of one SHA‑256 per block.

## 1) Background: standard AES (very brief)
- AES state: 4×4 byte matrix in column major order.
- Each round (AES‑128 has 10 rounds): SubBytes, ShiftRows, MixColumns; AddRoundKey before first round and after each round.
- ShiftRows (fixed): row 0 left shift 0, row 1 left shift 1, row 2 left shift 2, row 3 left shift 3.

## 2) Your modifications: design and exact algorithms
### 2.1) KW‑Tweak whitening (hash‑based pre‑whitening)
- Goal: Make the block cipher tweakable (per‑block variability) and reduce structural regularity by XOR’ing a per‑block mask into the state before AES rounds.
- Tweak T for a block i:
  - If an IV is provided by the mode, T = IV || i8 (i encoded as 8‑byte big‑endian).
  - If no IV (e.g., direct block call), T = i8 only.
- Whitening mask:
  - W(T, K) = Trunc16(SHA‑256(T || K)).
  - Pre‑whitening on encryption: X = P ⊕ W(T,K), then run AES core rounds on X.
  - Post step on decryption: after inverse AES rounds produce X, recover P = X ⊕ W(T,K).
- Properties:
  - For each fixed T, E′(T, ·) = E_K(· ⊕ W(T,K)) is a permutation of 128‑bit blocks, hence a tweakable block cipher (TBC).
  - If AES is a PRP and SHA‑256 used in this “XOF‑style” truncation acts as a PRF keyed by concatenating K, then T ↦ W(T,K) behaves pseudorandom. (For stronger conservatism you can replace SHA‑256 with HMAC‑SHA‑256(K, T) or KMAC; see Security notes.)

### 2.2) KDRP: Key‑Derived Row Permutation (replaces ShiftRows)
- Goal: Make the byte‑wise row rotation depend on the key to remove fixed linear structure and potentially hinder some structural distinguishers, while preserving linearity/invertibility and AES’s diffusion qualities.
- Derivation:
  - Take the first 4 key bytes K[0..3] as integers v0..v3.
  - Compute a permutation perm of {0,1,2,3} by stable‑sorting row indices by the corresponding byte value: perm = argsort([v0,v1,v2,v3]).
  - Example: if the first 4 key bytes are [0x2b,0x7e,0x15,0x16] = [43,126,21,22], ascending values are at indices [2,3,0,1], so perm = [2,3,0,1].
- Application to the state (row‑major view of each row):
  - For each row r ∈ {0,1,2,3}, rotate row r left by k = perm[r] mod 4 bytes. This is your _shift_rows_kdrp.
  - Inverse operation rotates row r right by perm[r] (your _inv_shift_rows_kdrp).
- Notes:
  - Standard AES uses fixed rotation amounts [0,1,2,3] for rows 0..3; you replace them with [perm[0],perm[1],perm[2],perm[3]] derived from the key. There are 24 possible patterns.

### 2.3) Unchanged parts
- S‑box, InvS‑box, MixColumns/InvMixColumns, key expansion (Rcon/S‑box schedule), AddRoundKey are standard.
- Round structure: You apply AddRoundKey at round 0, then for rounds 1..(Nr−1): SubBytes → KDRP → MixColumns → AddRoundKey, and at the final round: SubBytes → KDRP → AddRoundKey. This mirrors AES, just swapping ShiftRows for KDRP and adding pre‑whitening on input.

## 3) Block modes and where the tweak comes from
- CBC/PCBC:
  - Per block i: compute CBC chaining as usual to get X_i (X_i = P_i ⊕ C_{i−1} for CBC; X_i = P_i ⊕ C_{i−1} ⊕ P_{i−1} for PCBC).
  - Call encrypt_block(X_i, block_index=i, tweak_iv=IV). Inside, T = IV || i8.
- CFB/OFB/CTR:
  - You also pass (i, IV) as tweak, so the keystream is produced from a tweakable primitive. For CTR, the “input block” you give to AES is the nonce/IV (incremented), and whitening uses T = IV || i8, so keystream = AEScore((nonce_i) ⊕ W(IV||i8, K)).
- Consequence:
  - Each block sees a fresh whitening mask bound to the (IV, i). With random IVs (you derive a fresh IV from PBKDF2 each message), masks won’t repeat across messages/key instances.

## 4) Outer construction: PBKDF2 + HMAC (Encrypt‑then‑MAC)
- Key derivation per message:
  - salt ← 16 random bytes.
  - PBKDF2‑HMAC‑SHA256(key, salt, iters=100k) → 16 bytes AES key || 16 bytes IV || 16 bytes HMAC key.
- Encryption (CBC with PKCS#7 by default):
  - C_body = CBC_AEStweaked(P, IV). Then tag = HMAC‑SHA256(HK, salt || C_body).
  - Output = tag || salt || C_body.
- Decryption:
  - Split tag || salt || C_body, re‑derive keys, recompute tag over salt || C_body, compare in constant‑time, then decrypt CBC.
- Security:
  - Encrypt‑then‑MAC with strong MAC (HMAC‑SHA256) gives IND‑CCA security for the channel, assuming AES is a PRP and HMAC is a PRF. PBKDF2 mitigates weak passwords.

## 5) Why this helps: intuition and benefits
- Tweakability:
  - E′(T, P) = E_K(P ⊕ W(T,K)) is a tweakable block cipher (TBC). Each T yields a distinct permutation; changing T changes ciphertext even with identical P and K. This is valuable in disk/database page encryption, format‑preserving variants, and nonce‑based AE modes.
- Extra unpredictability around the core:
  - Pre‑whitening with a per‑block, per‑message mask disrupts structural regularities across blocks and messages, especially in ECB‑like cores (relevant for OFB/CFB/CTR where you build keystream). It is somewhat analogous to the “XEX” family of TBCs (though XEX applies masks both pre and post); your design applies pre‑XOR and reverses on decryption.
- Key‑dependent row rotation:
  - KDRP randomizes the linear layer’s pattern via the key. It retains linearity and invertibility while reducing “known structure” an adversary might exploit.
  - It does not reduce diffusion; it just permutes which rows get which rotation amount.
- Minimal footprint:
  - Only one SHA‑256 per block and a simple permutation lookup per round. Everything else remains AES‑like and proven invertible.


## 6) Performance implications
- Cost per block increases by one SHA‑256 (to compute W) plus trivial row rotations.
- The AES core operations remain the same complexity.
- In Python, SHA‑256 is implemented in C and is quite fast; still, expect a noticeable slowdown vs stock AES‑Python.

## 7) Applications
- Disk and database page encryption:
  - Tweakable design suits sector/page encryption, where per‑block tweaks avoid ECB‑type pattern leaks and provide context‑binding like XTS/LRW (yours is not XTS but is tweakable).
- Record‑oriented storage and backups:
  - Per‑record IV + block index tweak deters block reordering/duplication creating ciphertext collisions.
- Protocols needing per‑block diversification:
  - OFB/CFB/CTR keystreams benefit from per‑block tweak binding to the session IV, reducing cross‑session structure if IV reuse accidentally occurs (still avoid IV reuse).
- Educational/research:
  - Clean separation of a key‑randomized linear layer (KDRP) and a hash‑based whitening layer allows controlled experiments on diffusion/avalanche and structural distinguishers.

## 8) Limitations and cautions
- Not standard/FIPS compatible; interoperability with hardware AES is lost.
- KDRP uses only 24 patterns (permutation of [0,1,2,3]); treat it as structural diversity, not added brute‑force strength.
- Use HMAC(K, T) instead of raw SHA‑256(T || K) if you want conservative, standard PRF claims for W.
- Side‑channel leakage in Python; do not deploy in hostile environments without hardened implementations.