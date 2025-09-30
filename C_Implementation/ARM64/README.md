# MCES ARM64 Implementation

This folder provides an MCES build specifically optimized for ARM64 platforms (e.g. Raspberry Pi 3b+).

## Features

- Fully native C code for ARM64
- NEON instructions support for accelerated performance
- Integrates Argon2id and BLAKE3
- Tests Ran: Passes NIST, Dieharder, Practrand to 128GB. No weaks, fails or unusuals for Dieharder and Practrand.
## Build Instructions

```sh
make
```

### Required packages (Ubuntu/Debian):

```sh
sudo apt install build-essential clang libssl-dev libargon2-dev
```

## Output Binaries

This will build only the core tools for ARM64:
- `mces_encrypt`
- `mces_decrypt`
- `mces_bench_stream`
- `mces_stream_dieharder`

## Usage

### **Encryption**
```sh
./mces_encrypt input_file
# or
./mces_encrypt pw "your_password_here" input_file
```

### **Decryption**
```sh
./mces_decrypt vault_file
# or
./mces_decrypt pw "your_password_here" vault_file
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
