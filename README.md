# SARX

**SARX** is a 256-bit ARX stream cipher and password-based authenticated
encryption scheme (SARX-Vault) implemented in Rust.

- **SARX-256**: 4×64-bit ARX core, 8 rounds, counter mode keystream.
- **SARX-Vault**: password-based AEAD using Argon2id + keyed BLAKE3 in an
  Encrypt-then-MAC construction, plus an optional KDF hardening layer.

This repository contains the reference implementation used for the SARX
design paper, including the core cipher, the vault format, benchmarking,
randomness testing hooks, and thermodynamic KDF-hardening experiments.

> **Status:** research-grade, not yet recommended for production use.

---

## Features

- **New ARX stream cipher (SARX-256)**  
  - 256-bit key, 64-bit counter, 32-byte blocks  
  - 4×64-bit state, 8 rounds (column + diagonal ARX structure)  
  - Rotation constants chosen via automated ARX parameter search  
  - Designed for high throughput on 64-bit CPUs

- **Password-based AEAD (SARX-Vault)**  
  - Argon2id KDF with 256-bit salt and fixed parameters  
  - BLAKE3-derived keystream key for SARX-256  
  - Keyed BLAKE3 MAC (Encrypt-then-MAC over header + ciphertext)  
  - Vault header encodes salt, nonce, timestamp, KDF parameters, and KDF mode

- **Thermo hardening (optional)**  
  - Deterministic post-processing on Argon2id output  
  - ARX-based random walk over a large scratch buffer  
  - Raises per-guess cost for offline brute-force attacks  
  - Benchmarked in terms of both time and approximate J/bit

- **Tooling & experiments**  
  - CLI dispatcher: `sarx` (encrypt / decrypt / verify / benchmark / watch)  
  - Benchmark binaries for keystream and AEAD throughput  
  - RNG test harness for NIST SP800-22, Dieharder, PractRand, BigCrush  
  - Bit-energy and thermo-hardening experiment binaries

---

## Building

### Requirements

- Rust (stable, 1.7x+ recommended)
- Cargo
- A 64-bit Linux / macOS / Windows system

### Build locally

```sh
# From the repo root:
cargo build --release
