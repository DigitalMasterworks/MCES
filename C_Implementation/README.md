# MCES C Implementation

This folder contains the cross-platform C implementation of MCES.

## Features

- High-performance stream cipher written in portable C
- Supports both x86_64 and ARM64 (with hardware optimizations)
- Integrates Argon2id and BLAKE3 for password/key derivation
- Passes NIST, Dieharder, Practrand to 1TB and Big Crush.

## Build Instructions

```sh
make
```

### Dependencies

- `clang` or `gcc`
- `make`
- `libssl-dev`
- `libargon2-dev`
- (Optional) `libblake3-dev` or built-in sources

## Output Binaries

This will build the following tools:
- `mces_encrypt`
- `mces_decrypt`
- `mces_bench_stream`
- `mces_stream_dieharder`
- `mces_make_nist_bins`
- `mces_test_harness`

## Usage

### **Encryption**
```sh
# Option 1: Let MCES generate a random strong password (recommended, prints to console)
./mces_encrypt input_file

# Option 2: Supply your own password (30-100 Unicode codepoints required)
./mces_encrypt pw "your_password_here" input_file
```

### **Decryption**
```sh
# Option 1: Interactive prompt (default)
./mces_decrypt vault_file

# Option 2: Supply password non-interactively
./mces_decrypt pw "your_password_here" vault_file
```

### **Benchmarks & Randomness Testing**
```sh
./mces_bench_stream     # Throughput benchmark
./mces_stream_dieharder # Pipe output to dieharder/practrand
./mces_make_nist_bins   # Generate NIST test binaries
./mces_test_harness     # Full crypto validation suite
```

# MCES.py and sigilbook.py

These scripts provide a graphical user interface and a secure password vault for MCES users.

---

## MCES.py — MCES GUI

- **Purpose:**  
  A PyQt6-based graphical user interface for encrypting and decrypting files with MCES.
- **Features:**  
  - Drag and drop file selection  
  - Password entry and management  
  - Real-time progress display and error reporting  
  - Option to auto-generate and save passwords to the Sigilbook vault  
  - Supports launching decryption, encryption, and viewing MCES vault files directly from the UI

**To run the GUI:**  
```sh
python3 MCES.py
```
- Requires: Python 3.8+ and PyQt6  
- All encryption/decryption actions use the MCES engine in the background.

---

## sigilbook.py — Secure Password Vault

- **Purpose:**  
  Provides a simple, encrypted, persistent password vault for MCES.
- **Features:**  
  - Save, retrieve, and manage MCES vault passwords securely  
  - Data is encrypted at rest and only decrypted in memory during use  
  - Designed to work seamlessly with MCES.py GUI, but can be run stand-alone for password management tasks

**To use as a standalone password vault:**  
```sh
python3 sigilbook.py
```
- Requires: Python 3.8+ (no additional dependencies for core vault functionality)

**Typical workflow:**  
1. Use MCES.py to generate or open a vault.
2. Store the randomly generated or user-created password in sigilbook.py.
3. Retrieve passwords from sigilbook.py when decrypting files.

---

**Security Notice:**  
- All vault data is encrypted; never store plaintext passwords outside of sigilbook.py.
- For best security, use long, random Unicode passphrases as required by MCES.

---

See the main project README for more information.


## Security

This is research software; do not use for critical secrets until independently audited.

