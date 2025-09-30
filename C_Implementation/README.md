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

### Dependencies

- `clang` or `gcc`
- `make`
- `libssl-dev`
- `libargon2-dev`
- (Optional) `libblake3-dev` or built-in sources

## Output Binaries

This will build the following tools:
- `mces_encrypt`          (File/stream encryption CLI)
- `mces_decrypt`          (File/stream decryption CLI)
- `mces_bench_stream`     (Performance benchmarking)
- `mces_stream_dieharder` (Randomness tester for dieharder/practrand)
- `mces_make_nist_bins`   (NIST test binary output generator)
- `mces_test_harness`     (Comprehensive cryptanalysis/test harness)

## Usage

Basic encryption:
```sh
./mces_encrypt --in input.txt --out encrypted.mces
```
Decryption:
```sh
./mces_decrypt --in encrypted.mces --out output.txt
```
For help:
```sh
./mces_encrypt --help
```

## GUI and Sigilbook

- To use the graphical interface, run `MCES.py` (requires Python + PyQt6).
- Passwords are stored/managed in `sigilbook.py` (secure password vault).

## Security

This is research software; do not use for critical secrets until independently audited.
