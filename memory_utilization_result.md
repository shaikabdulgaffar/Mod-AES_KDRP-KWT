# Memory Utilization Results & Analysis (KDRP + KW-Tweak AES vs. Standard AES)

### **Summary of Experiments**

You measured the peak Python memory allocations (using tracemalloc) during CBC encryption and decryption operations for both Standard AES and Modified AES (KDRP + KW-Tweak), across all AES key sizes (128, 192, 256 bits) and two message sizes (1024 and 10240 bytes).

### **Why Memory Utilization Matters**

- **Objective:** Efficient cryptographic implementations use minimal memory resources, which is important for performance, especially on resource-constrained systems.
- **Metric:** Peak memory allocation during encryption/decryption (lower is better).

### **Key Results**

| Key Size (bits) | Msg Size | Enc Peak (Std/Mod) | Dec Peak (Std/Mod) | Overall (Std/Mod) | Winner      |
|-----------------|----------|--------------------|--------------------|-------------------|-------------|
| 128             | 1024     | 15.64 / 15.67 KiB  | 14.59 / 14.62 KiB  | 15.11 / 15.15 KiB | Standard    |
| 128             | 10240    | 110.86 / 110.92 KiB| 100.81 / 100.87 KiB| 105.83 / 105.89 KiB| Standard    |
| 192             | 1024     | 15.64 / 15.67 KiB  | 14.59 / 14.62 KiB  | 15.11 / 15.15 KiB | Standard    |
| 192             | 10240    | 110.86 / 110.92 KiB| 100.81 / 100.87 KiB| 105.83 / 105.89 KiB| Standard    |
| 256             | 1024     | 15.64 / 15.67 KiB  | 14.59 / 14.62 KiB  | 15.11 / 15.15 KiB | Standard    |
| 256             | 10240    | 110.86 / 110.92 KiB| 100.81 / 100.87 KiB| 105.83 / 105.89 KiB| Standard    |

- **Correctness:** Encryption/decryption was correct in all cases.
- **Interpretation:**
  - **Standard AES uses slightly less memory** than Modified AES in every configuration.
  - The difference is **very small** (0.03–0.06 KiB for 1 KB messages, and 0.06 KiB for 10 KB messages).
  - Modified AES’s extra memory usage is expected due to key whitening and permutation steps.

### **Discussion**

- **Efficiency tradeoff:**  
  The added whitening and permutation in Modified AES introduce a minor memory overhead compared to Standard AES.
- **Practical impact:**  
  The overhead is **minimal** and unlikely to affect most real-world applications, but should be considered for low-resource environments.
- **Experimental fairness:**  
  Both ciphers were tested under identical conditions (key, IV, message) for an unbiased comparison.

> **Memory Utilization Evaluation:**  
> We compared the peak Python memory allocations of Standard AES and our Modified AES (KDRP + KW-Tweak) during CBC encryption and decryption. In all key sizes and message configurations, Standard AES consistently used slightly less memory than Modified AES—the difference was less than 0.06 KiB even for large message sizes. This small overhead in Modified AES is attributable to additional whitening and permutation operations. Overall, both ciphers are highly memory-efficient, with only negligible differences in resource requirements.


### **Conclusion**

- **Standard AES is slightly more memory-efficient** than Modified AES, but the difference is minimal.
- The additional operations in Modified AES (KDRP + KW-Tweak) do not significantly impact memory usage, making it suitable for practical deployment.

If you need this formatted for a specific section or want to combine with other results in your paper, let me know!