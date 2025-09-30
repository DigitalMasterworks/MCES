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

## Note

For all password input, 30–100 Unicode codepoints are required.

For GUI, extended features, or full C toolchain, see the parent folder README.
