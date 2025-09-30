# MCES (Miller’s Cantor-Immune Encryption Standard)

MCES is a high-performance research-grade stream cipher designed for secure file and stream encryption.  
It supports both C (x86_64, ARM64) and Rust implementations, with optional extras (GUI, automation, benchmarking).

---

## Features

- AES-level speed, quantum-attack resistance, and codepoint-aware passwords (UTF-8, 30–100+ chars)
- Robust file, folder, and stream encryption
- Multi-threaded and offline operation
- Secure password management and vaulting
- Extensive test harnesses, benchmarking, and support for dieharder/practrand/bigcrush randomness testing
- CLI, automation tools, folder watchers, and a modern GUI (Rust only)
- Designed for reproducibility and security research

---

## Quickstart Installation

### Rust (Linux, Windows, MacOS, ARM64)

```sh
cargo build --release
# Or to install globally:
cargo install --path .
