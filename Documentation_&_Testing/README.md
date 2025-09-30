# MCES Documentation & Testing

This folder contains all formal documentation, technical reports, empirical test results, and validation logs for the MCES Cantor-Immune Stream Cipher.

---

## Contents

- **Technical Papers**  
  Cryptographic design notes, whitepapers, and algorithm documentation describing the core theory, cryptographic architecture, and implementation details behind MCES.

- **Empirical Results**  
  - **Dieharder, NIST, PractRand outputs:**  
    Detailed results from industry-standard statistical tests, including frequency, block frequency, runs, non-overlapping templates, cumulative sums, serial, and linear complexity.  
    These validate the pseudorandomness and statistical quality of the MCES keystreams.
  - **Bias and Sensitivity Analyses:**  
    Reports on key and IV sensitivity, bit bias, avalanche effect, tag forgery resistance, weak-key scans, and head-collision checks.
  - **Full-System Logs:**  
    System logs from AEAD malleability testing, known-plaintext recovery attempts, and tag forgery experiments across a wide range of keys, IVs, and configurations.

- **Performance & Implementation Reports**  
  Benchmark logs, multi-threading validation, and hardware-specific performance (AVX2, NEON, etc.) summaries.

---

## Organization

- **PDF and TXT files:**  
  Each report or log is typically named after the test (e.g., `finalAnalysisReport_200.txt`, `mces_v7.log`, etc).
- **Source code snippets and auxiliary files** may also appear for reproducibility.

---

## How to Use

- **To review the security claims:**  
  Start with the technical paper or design notes, then review empirical test results for statistical strength and AEAD security.
- **To replicate or audit:**  
  Use the included logs and reports as reference baselines when running your own tests (dieharder, NIST, PractRand, etc.) on MCES outputs.

---

## Disclaimer

MCES is research-grade software and these documents are provided for transparency, peer review, and reproducibility.  
No formal security proof is included; results reflect the current empirical/statistical validation status.

---

For implementation, CLI usage, and build instructions, see the main project [README](../README.md).
