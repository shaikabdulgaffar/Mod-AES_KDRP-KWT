# Avalanche Effect Results & Analysis

### Syntax to run:
python block_avalanche.py --key-size 32 --message-bytes 10240 --trials-correctness 10 --trials-block 100 --trials-cbc 100

---

### **Summary of Experiments**

Evaluated both Standard AES and your Modified AES (using KDRP + KW-Tweak) for the avalanche effect, across three key sizes (16, 24, 32 bytes) and two message sizes (1024 bytes and 10240 bytes). For each configuration, you measured both block-level and CBC-level avalanche effect.

### **Key Observations**

#### **1. Correctness:**
- In all configurations, "Correctness: OK" was observed, indicating that encryption and decryption are functioning correctly.

#### **2. Avalanche Effect (Block Level)**
- **Block-level avalanche effect** for Standard AES: mean ~49.3% – 50.3%
- For Modified AES: mean ~49.5% – 50.5%
- **Expected improvement (theoretical):** +3% to +6%
- **Observed improvement (Modified - Standard):**
  - **16 bytes key, 1024 message:** +0.85%
  - **16 bytes key, 10240 message:** –0.84% (here Standard AES performed slightly better)
  - **24 bytes key, 1024 message:** +0.23%
  - **24 bytes key, 10240 message:** +0.35%
  - **32 bytes key, 1024 message:** +0.91%
  - **32 bytes key, 10240 message:** +0.70%
- **Conclusion:** In most cases, Modified AES showed a slight improvement at the block level, but in some cases, the improvement was negligible or even negative.

#### **3. Avalanche Effect (CBC Level)**
- **CBC avalanche effect** for both versions: ~49.9% – 50.0%
- **Observed improvement (Modified - Standard):**
  - All configurations: +0.01% to +0.06%
- **Conclusion:** At the CBC level, improvement is very marginal.

#### **4. Overall Winner**
- **Block-level:** Modified AES is the winner in most configurations, but not all.
- **CBC-level:** Modified AES consistently shows a very slight improvement.
- **Overall (average):** Modified AES performs better in most cases, but the improvement is modest (maximum ~0.9%), much less than the theoretical expectation.

### **Detailed Analysis**

- **Standard AES** already provides a near-ideal avalanche effect (~50%). Thus, any modification that aims to increase diffusion/randomness has limited room for improvement.
- **KDRP + KW-Tweak** shows some impact at the block level but has almost no effect at the CBC level.  
- **With larger messages (10240 bytes),** the improvement sometimes drops or becomes negative—likely because, in CBC mode, diffusion is already maximized, or the effect of modifications gets diluted.
- **Measurement method or trial size** might also influence the results, but with 100 trials, your sampling seems reasonable.

### **Possible Reasons for Lower-than-Expected Improvement**

1. **Standard AES is already highly diffusive:** There’s little room to improve further.
2. **The modifications may not be strong enough,** or their effect is diluted in CBC chaining.
3. **Real-world measurement** might not capture subtle theoretical improvements.


> **Avalanche Effect Evaluation:**  
> We evaluated the avalanche effect for both standard AES and our modified AES (incorporating KDRP and KW-Tweak), across key sizes of 128, 192, and 256 bits and message sizes of 1024 and 10240 bytes. The block-level avalanche effect for standard AES averaged approximately 49.3–50.3%, while the modified AES achieved 49.5–50.5%. The observed improvement at the block level ranged from –0.84% to +0.91%, which is substantially lower than the theoretically expected improvement of 3–6%. At the CBC level, both ciphers performed nearly identically (~50%), with the modified AES showing only a marginal improvement (up to +0.06%). Overall, the modified AES outperformed standard AES in most cases, but the improvement was modest (maximum ~0.9%). This suggests that standard AES already achieves near-ideal diffusion, and further improvements via KDRP and KW-Tweak have limited impact, especially at the CBC level.

#### **Sample Table:**

| Key Size (bytes) | Msg Size (bytes) | Block Avalanche Improvement | CBC Avalanche Improvement | Overall Winner |
|------------------|------------------|----------------------------|--------------------------|----------------|
| 16               | 1024 (1MB)             | +0.85%                     | +0.06%                   | Modified AES   |
| 16               | 10240 (10MB)            | –0.84%                     | +0.02%                   | Standard AES   |
| 24               | 1024 (1MB)              | +0.23%                     | +0.03%                   | Modified AES   |
| 24               | 10240 (10MB)            | +0.35%                     | +0.04%                   | Modified AES   |
| 32               | 1024 (1MB)              | +0.91%                     | +0.02%                   | Modified AES   |
| 32               | 10240 (10MB)            | +0.70%                     | +0.01%                   | Modified AES   |

---

### **Conclusion**

- **Modified AES (KDRP + KW-Tweak)** shows slightly better performance at the block level and marginal improvement at the CBC level.
- **Standard AES** already provides optimal diffusion, so the effect of further modifications is limited.
