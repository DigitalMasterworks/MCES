# Makefile for MCES-2DU (encrypt/decrypt/benchmark/stream) with BLAKE3 SIMD backends (non-ARM)

CC      := gcc
CFLAGS  := -std=c99 -O3 -march=native -D_POSIX_C_SOURCE=200809L -DBLAKE3_NO_AVX512 -DUSE_ARGON2 -pthread
CPPFLAGS:=
LDFLAGS :=
LDLIBS  := -lcrypto -largon2 -lrt -pthread -lm

# Always build x86-style backends (portable + SSE/AVX).
B3_SRCS := blake3.c blake3_dispatch.c blake3_portable.c blake3_sse2.c blake3_sse41.c blake3_avx2.c
B3_OBJS := $(B3_SRCS:.c=.o)
COMMON_OBJS := mces.o $(B3_OBJS)

.PHONY: all clean

all: mces_encrypt mces_decrypt mces_benchmark mces_bench_stream mces_stream_dieharder mces_make_nist_bins mces_test_harness

mces_encrypt: mces_encrypt.o $(COMMON_OBJS) mces.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ mces_encrypt.o $(COMMON_OBJS) $(LDLIBS)

mces_decrypt: mces_decrypt.o $(COMMON_OBJS) mces.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ mces_decrypt.o $(COMMON_OBJS) $(LDLIBS)

mces_benchmark: mces_benchmark.o $(COMMON_OBJS) mces.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ mces_benchmark.o $(COMMON_OBJS) $(LDLIBS)

mces_bench_stream: mces_bench_stream.o $(COMMON_OBJS) mces.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ mces_bench_stream.o $(COMMON_OBJS) $(LDLIBS)

mces_stream_dieharder: mces_stream_dieharder.o $(COMMON_OBJS) mces.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ mces_stream_dieharder.o $(COMMON_OBJS) $(LDLIBS)

mces_make_nist_bins: mces_make_nist_bins.o $(COMMON_OBJS) mces.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ mces_make_nist_bins.o $(COMMON_OBJS) $(LDLIBS)

mces_test_harness: mces_test_harness.o $(COMMON_OBJS) mces.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ mces_test_harness.o $(COMMON_OBJS) $(LDLIBS)

mces_ers_tester: mces_ers_tester.o $(COMMON_OBJS) mces.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ mces_ers_tester.o $(COMMON_OBJS) $(LDLIBS)

%.o: %.c mces.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	rm -f mces_encrypt mces_decrypt mces_benchmark mces_bench_stream mces_stream_dieharder \
	      mces_make_nist_bins mces_test_harness mces_ers_tester \
	      *.o MCES_Unicode_Benchmark_Full.txt