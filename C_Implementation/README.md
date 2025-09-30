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

## **Password Requirements**
- All passwords must be **30–100 Unicode codepoints** (not bytes), and non-surrogate.

## Security

This is research software; do not use for critical secrets until independently audited.

