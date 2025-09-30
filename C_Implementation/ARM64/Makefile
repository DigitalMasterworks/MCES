# ARM64 Makefile — builds encrypt, decrypt, bench_stream, stream_dieharder

# Hard-stop if not on arm64
ARCH := $(shell uname -m)
ifneq ($(ARCH),aarch64)
  $(error This Makefile builds only on arm64 (aarch64). Detected $(ARCH))
endif

# Prefer clang on Android/Termux, else use system default (gcc if set)
UNAME_A := $(shell uname -a)
ifneq (,$(findstring Android,$(UNAME_A)))
  CC := clang
else
  CC ?= gcc
endif

# BLAKE3 (NEON path for arm64)
B3_SRCS := blake3.c blake3_dispatch.c blake3_portable.c blake3_neon.c
B3_OBJS := $(B3_SRCS:.c=.o)

# Flags
CFLAGS   := -std=c99 -O3 -pipe -march=armv8-a+crypto -mtune=native -D_POSIX_C_SOURCE=200809L -DUSE_ARGON2 -pthread
CPPFLAGS :=
LDFLAGS  := -pthread
LDLIBS   := -lcrypto -largon2 -lm

# Common objects
COMMON_OBJS := mces.o $(B3_OBJS)

# Binaries to build
BINS := mces_encrypt mces_decrypt mces_bench_stream mces_stream_dieharder

.PHONY: all clean
all: $(BINS)

mces_encrypt: mces_encrypt.o $(COMMON_OBJS) mces.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ mces_encrypt.o $(COMMON_OBJS) $(LDLIBS)

mces_decrypt: mces_decrypt.o $(COMMON_OBJS) mces.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ mces_decrypt.o $(COMMON_OBJS) $(LDLIBS)

mces_bench_stream: mces_bench_stream.o $(COMMON_OBJS) mces.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ mces_bench_stream.o $(COMMON_OBJS) $(LDLIBS)

mces_stream_dieharder: mces_stream_dieharder.o $(COMMON_OBJS) mces.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ mces_stream_dieharder.o $(COMMON_OBJS) $(LDLIBS)

# Pattern rules
mces.o: mces.c mces.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

%.o: %.c mces.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	rm -f $(BINS) *.o