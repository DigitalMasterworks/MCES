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
````

This produces release binaries under `target/release/`, e.g.:

* `sarx`              – word-first CLI dispatcher
* `sarx_bench_stream` – keystream throughput benchmark
* `sarx_encrypt`      – low-level file encryptor
* `sarx_decrypt`      – low-level file decryptor
* `sarx_stream_dieharder`, `sarx_test_harness`, … – RNG and AEAD tests

### Install the CLI globally

```sh
# Install the crate and binaries into ~/.cargo/bin
cargo install --path . --force
```

After installation, make sure `~/.cargo/bin` is in your `PATH`, then:

```sh
sarx --help
```

---

## Basic Usage

### Encrypt a file into a vault

Interactive password (prompted on TTY):

```sh
sarx encrypt <input_file>
# Produces <input_file>.vault and deletes the plaintext on success
```

Specify a password on the command line (for scripting):

```sh
sarx encrypt --password 'your password here' <input_file>
```

### Decrypt a vault

```sh
sarx decrypt <input_file>.vault
# Restores the original file and removes the .vault on success
```

### Verify a vault’s MAC (no decryption)

```sh
sarx verify <input_file>.vault
```

This prompts for the password and only checks the keyed BLAKE3 MAC over
the header + ciphertext.

### Benchmarks

Keystream / AEAD benchmarks via the dispatcher:

```sh
# Keystream benchmark (SARX-256 core)
sarx benchmark speed

# AEAD stress test (stream+MAC)
sarx benchmark aead

# Raw keystream to stdout (pipe to Dieharder / PractRand)
sarx benchmark keystream | dieharder -g 200 -a
```

Or directly:

```sh
sarx_bench_stream        # throughput table
sarx_stream_dieharder    # RNG stream for testing
sarx_test_harness        # AEAD stress harness
```

---

## Project Layout

Key files and directories:

* `src/lib.rs`
  Core library: SARX-256, vault header encoding/decoding, KDF/MAC helpers.

* `src/sarx.rs`
  SARX-256 keystream implementation (ARX core + stream generator).

* `src/headers.rs`
  Vault header and tag structures (salt, nonce, timestamp, KDF params, etc.).

* `src/bin/sarx.rs`
  Word-first CLI dispatcher:

  * `sarx encrypt ...`
  * `sarx decrypt ...`
  * `sarx verify ...`
  * `sarx benchmark speed|aead|keystream`
  * `sarx watch ...`

* `src/bin/sarx_encrypt.rs`, `src/bin/sarx_decrypt.rs`
  Low-level binaries used by the dispatcher.

* `src/bin/sarx_bench_stream.rs`
  Keystream throughput benchmark.

* `src/bin/sarx_stream_dieharder.rs`, `src/bin/sarx_test_harness.rs`
  RNG and AEAD test harnesses.

* `Substrate_Crypto_Experiments/bit_energy_bench/*`
  Bit-energy and thermo-hardening experiment binaries:

  * `bit_energy_bench` – J/bit measurements for memory workloads
  * `thermo_bruteforce` – Argon2 vs Argon2+thermo cost comparison

* `Documentation/`
  LaTeX sources and PDFs for the SARX design paper.

---

## Security Notes

* SARX-256 is a new ARX stream cipher. Its security is analysed under a
  PRF assumption, with preliminary statistical and reduced-round
  tests. Further cryptanalysis is encouraged.
* SARX-Vault’s symmetric security is proven in a standard derived-key
  model under PRF (cipher) + SUF-CMA (MAC) assumptions.
* Password security depends on:

  * password entropy, and
  * Argon2id (and optional thermo hardening) parameters.
* The implementation uses only ARX operations (add, rotate, xor) for the
  core cipher and avoids table lookups, making constant-time
  implementations straightforward. We do not provide a full
  microarchitectural side-channel analysis.

---

## License

The crate is dual-licensed under **MIT** or **Apache 2.0**. See
`LICENSE-MIT` and `LICENSE-APACHE` (or the `license` field in
`Cargo.toml`) for details.
