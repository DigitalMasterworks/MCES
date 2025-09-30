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
