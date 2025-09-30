// strict_cantorian_mces_ers_tester.c — Bitwise Cantorian Prefix ERT for MCES-2DU
#define _POSIX_C_SOURCE 200809L
#include "mces.h"
#include "blake3.h"
#ifdef USE_ARGON2
#include <argon2.h>
#else
#error "Compile with -DUSE_ARGON2 and link -largon2"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>

static inline void u64_to_be(uint64_t x, uint8_t out[8]) {
    for (int i=0;i<8;++i) out[i] = (uint8_t)((x >> (56 - 8*i)) & 0xFF);
}
static void secure_zero(void *v, size_t n) {
#if defined(__STDC_LIB_EXT1__)
    memset_s(v, n, 0, n);
#else
    volatile unsigned char *p = (volatile unsigned char*)v;
    while (n--) *p++ = 0;
#endif
}
static uint32_t urand32(void) {
    uint32_t r=0;
    FILE *u = fopen("/dev/urandom", "rb");
    if (!u) { fprintf(stderr,"urandom open failed\n"); exit(1); }
    if (fread(&r, 1, sizeof(r), u) != sizeof(r)) { fprintf(stderr,"urandom read failed\n"); fclose(u); exit(1); }
    fclose(u);
    return r;
}
static size_t utf8_codepoints(const char *s, uint32_t *indices) {
    size_t count = 0;
    for (size_t i = 0; s[i]; ++i)
        if ((s[i] & 0xC0) != 0x80) indices[count++] = (uint32_t)i;
    return count;
}
static void make_deterministic_nonce(const char *base_pw, int row, uint8_t out12[12]) {
    blake3_hasher h; blake3_hasher_init(&h);
    blake3_hasher_update(&h, (const uint8_t*)base_pw, strlen(base_pw));
    uint8_t row_be[4] = {(uint8_t)(row>>24),(uint8_t)(row>>16),(uint8_t)(row>>8),(uint8_t)row};
    blake3_hasher_update(&h, row_be, 4);
    uint8_t tmp[32]; blake3_hasher_finalize(&h, tmp, 32);
    memcpy(out12, tmp, 12);
    secure_zero(tmp, 32);
}
static int derive_okm_argon2id(const char *password, size_t pass_bytes,
                               const uint8_t salt32[32],
                               size_t k_stream_len, uint8_t *okm /* k_stream||k_mac */) {
    // t=3, m=2^17 KiB, lanes=1, like mces_encrypt.c
    return argon2id_hash_raw(3, (1u<<17), 1,
                             password, pass_bytes, salt32, 32,
                             okm, k_stream_len + 32);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr,
            "Usage: %s <window_bits> <num_windows>\n"
            "Outputs: bits.csv (strict Cantorian bitwise MCES)\n", argv[0]);
        return 1;
    }
    int N = atoi(argv[1]);         // window size in bits (e.g., 50)
    int WINDOWS = atoi(argv[2]);   // number of windows (e.g., 100)
    int total_rows = N + WINDOWS - 1;

    // --- Random Unicode password generator (from mces_encrypt.c) ---
    int pw_len = 30 + (urand32() % 71);
    char *base_pw = (char*)malloc((size_t)pw_len * 4 + 1);
    if (!base_pw) { fprintf(stderr,"OOM: base_pw\n"); return 1; }
    memset(base_pw, 0, (size_t)pw_len*4+1);
    size_t pass_bytes=0, cp_count=0;
    while ((int)cp_count < pw_len) {
        uint32_t cp;
        do {
            uint32_t r1=urand32(), r2=urand32();
            cp=(r1^(r2<<1))%0x110000u;
        } while ((cp>=0xD800&&cp<=0xDFFF)||cp<0x20);
        if (cp<=0x7F) base_pw[pass_bytes++]=(char)cp;
        else if (cp<=0x7FF){
            base_pw[pass_bytes++]=(char)(0xC0|(cp>>6));
            base_pw[pass_bytes++]=(char)(0x80|(cp&0x3F));
        } else if (cp<=0xFFFF){
            base_pw[pass_bytes++]=(char)(0xE0|(cp>>12));
            base_pw[pass_bytes++]=(char)(0x80|((cp>>6)&0x3F));
            base_pw[pass_bytes++]=(char)(0x80|(cp&0x3F));
        } else {
            base_pw[pass_bytes++]=(char)(0xF0|(cp>>18));
            base_pw[pass_bytes++]=(char)(0x80|((cp>>12)&0x3F));
            base_pw[pass_bytes++]=(char)(0x80|((cp>>6)&0x3F));
            base_pw[pass_bytes++]=(char)(0x80|(cp&0x3F));
        }
        cp_count++;
    }
    base_pw[pass_bytes]='\0';
    printf("[ERS] Using random Unicode password (%d codepoints):\n%s\n", pw_len, base_pw);

    // --- Track codepoints ---
    uint32_t *cp_indices = (uint32_t*)malloc((pass_bytes + 1) * sizeof(uint32_t));
    if (!cp_indices) { fprintf(stderr,"OOM: cp_indices\n"); return 1; }
    size_t codepoints = utf8_codepoints(base_pw, cp_indices);
    cp_indices[codepoints] = (uint32_t)pass_bytes;

    // --- MCES config/nonce setup (shared for all rows) ---
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t timestamp_ns = (uint64_t)ts.tv_sec*1000000000ull + (uint64_t)ts.tv_nsec;

    MCES_Config cfg = (MCES_Config){0};
    if (generate_config_with_timestamp(base_pw, NULL, 0, timestamp_ns, &cfg) != 0) {
        fprintf(stderr,"generate_config failed\n");
        return 1;
    }
    uint8_t nonce12[12]; make_deterministic_nonce(base_pw, 0, nonce12);
    uint8_t salt32[32];
    uint8_t salt_input[8+12];
    u64_to_be(timestamp_ns, salt_input);
    memcpy(salt_input+8, nonce12, 12);
    blake3_hasher h; blake3_hasher_init(&h);
    blake3_hasher_update(&h, salt_input, sizeof(salt_input));
    blake3_hasher_finalize(&h, salt32, 32);

    size_t mut_bytes = strlen(base_pw);
    size_t k_stream_len = ((mut_bytes + 31u) & ~((size_t)31u));
    if (k_stream_len == 0) k_stream_len = 32;
    size_t okm_len = k_stream_len + 32;
    uint8_t *okm = (uint8_t*)malloc(okm_len);
    if (!okm) { fprintf(stderr,"OOM: okm\n"); return 1; }
    if (derive_okm_argon2id(base_pw, mut_bytes, salt32, k_stream_len, okm) != ARGON2_OK) {
        fprintf(stderr,"Argon2id failed\n");
        free(okm); return 1;
    }
    uint8_t *k_stream = okm;
    size_t postmix_len = 16 + k_stream_len + 12 + 8;
    uint8_t *postmix = (uint8_t*)malloc(postmix_len);
    if (!postmix) { fprintf(stderr,"OOM: postmix\n"); free(okm); return 1; }
    memset(postmix, 0, postmix_len);
    memcpy(postmix, "MCES2DU-POST\x00\x00\x00\x00", 16);
    memcpy(postmix+16, k_stream, k_stream_len);
    memcpy(postmix+16+k_stream_len, nonce12, 12);
    u64_to_be(timestamp_ns, postmix+16+k_stream_len+12);

    // --- Cantorian bits.csv output ---
    FILE *fb = fopen("bits.csv","w");
    if (!fb) { fprintf(stderr,"cannot open bits.csv\n"); return 1; }

    for (int row = 0; row < total_rows; ++row) {
        int bitcount = row + 1;
        int input_bytes = (bitcount + 7) / 8;
        uint8_t *input = calloc(input_bytes, 1);
        if (!input) { fprintf(stderr,"OOM: input\n"); fclose(fb); return 1; }

        // MCES: Encrypt the input
        uint8_t *ks = (uint8_t*)malloc(input_bytes);
        if (!ks) { fprintf(stderr,"OOM: ks\n"); free(input); fclose(fb); return 1; }
        if (mces_generate_stream(&cfg, postmix, postmix_len, 0, input_bytes, ks) != 0) {
            fprintf(stderr,"mces_generate_stream fail row %d\n", row);
            free(input); free(ks); fclose(fb); return 1;
        }

        int bitpos = 0;
        for (int b = 0; b < input_bytes && bitpos < bitcount; ++b) {
            for (int k = 7; k >= 0 && bitpos < bitcount; --k, ++bitpos) {
                fprintf(fb, "%d", (ks[b] >> k) & 1u);
                if (bitpos < bitcount - 1) fprintf(fb, ",");
            }
        }
        fprintf(fb, "\n");

        free(input);
        free(ks);
    }
    fclose(fb);

    secure_zero(postmix, postmix_len); free(postmix);
    secure_zero(okm, okm_len); free(okm);
    free_config(&cfg);
    free(base_pw);
    free(cp_indices);

    printf("[ERS] Strict Cantorian bits.csv complete (%d rows, 1..%d bits per row)\n", total_rows, total_rows);

    return 0;
}