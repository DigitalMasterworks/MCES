// ███╗   ███╗ ██████╗ ███████╗ ███████╗
// ████╗ ████║██╔════╝ ██╔════╝ ██╔════╝
// ██╔████╔██║██║      ███████  ███████╗
// ██║╚██╔╝██║██║      ██═══╝   ╚════██║
// ██║ ╚═╝ ██║╚██████╗ ███████╗ ███████║
// ╚═╝     ╚═╝ ╚═════╝ ╚══════╝ ╚══════╝
// MCES v1 — Cantor-Immune Stream Cipher
// mces_bench_stream.c
#define _POSIX_C_SOURCE 200809L
#include "mces.h"
#include "blake3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <locale.h>
#include <pthread.h>
#include <unistd.h>

#ifdef USE_ARGON2
#include <argon2.h>
#else
#error "Argon2id is required for uncapped KDF. Compile with -DUSE_ARGON2 and link -largon2."
#endif


/* ===== Utilities ===== */
static inline void u64_to_be(uint64_t x, uint8_t out[8]) {
    for (int i = 0; i < 8; ++i) out[i] = (uint8_t)((x >> (56 - 8*i)) & 0xFF);
}
static void secure_zero(void *v, size_t n) {
#if defined(__STDC_LIB_EXT1__)
    memset_s(v, n, 0, n);
#else
    volatile unsigned char *p = (volatile unsigned char *)v;
    while (n--) *p++ = 0;
#endif
}
static uint32_t urand32(void){
    uint32_t r=0; FILE *u=fopen("/dev/urandom","rb");
    if(!u){fprintf(stderr,"urandom open failed\n"); exit(1);}
    if(fread(&r,1,sizeof(r),u)!=sizeof(r)){fprintf(stderr,"urandom read failed\n"); fclose(u); exit(1);}
    fclose(u); return r;
}
static inline size_t round_up_32(size_t x){ return (x + 31u) & ~((size_t)31u); }
static double diff_seconds(const struct timespec *start, const struct timespec *end) {
    return (end->tv_sec - start->tv_sec) + (end->tv_nsec - start->tv_nsec) * 1e-9;
}

static inline void xor_buf(uint8_t *dst, const uint8_t *src, const uint8_t *ks, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        dst[i] = src[i] ^ ks[i];
    }
}

/* ===== Uncapped password → salt/OKM → config + variable postmix ===== */
static int setup_config_and_postmix_from_password(
    const char *password,
    uint64_t timestamp_ns,
    uint8_t salt[32],
    uint8_t nonce[12],
    MCES_Config *cfg_out,
    uint8_t **postmix_out,
    size_t *postmix_len_out,
    uint8_t k_mac_out[32] 
){
    /* salt = BLAKE3(ts||nonce) */
    uint8_t salt_input[8 + 12];
    u64_to_be(timestamp_ns, salt_input);
    memcpy(salt_input + 8, nonce, 12);
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, salt_input, sizeof(salt_input));
    blake3_hasher_finalize(&h, salt, 32);

    const size_t pass_bytes = strlen(password);
    size_t k_stream_len     = round_up_32(pass_bytes);
    if (k_stream_len == 0) k_stream_len = 32;  /* never zero */
    size_t okm_len          = k_stream_len + 32; /* +32 spare (MAC space, not needed here) */

    uint8_t *okm = (uint8_t*)malloc(okm_len ? okm_len : 1);
    uint8_t *k_stream = okm;
    uint8_t *k_mac    = okm + k_stream_len; // 32-byte MAC key
    if (!okm) return -1;

    if (argon2id_hash_raw(3, (1u<<17), 1,
                          password, pass_bytes,
                          salt, 32,
                          okm, okm_len) != ARGON2_OK) {
        secure_zero(okm, okm_len); free(okm);
        return -1;
    }
    memcpy(k_mac_out, k_mac, 32);
    
    MCES_Config cfg = (MCES_Config){0};
    if (generate_config_with_timestamp(password, NULL, 0, timestamp_ns, &cfg) != 0) {
        secure_zero(okm, okm_len); free(okm);
        return -1;
    }

    size_t postmix_len = 16 + k_stream_len + 12 + 8;
    uint8_t *postmix = (uint8_t*)malloc(postmix_len ? postmix_len : 1);
    if (!postmix) {
        free_config(&cfg);
        secure_zero(okm, okm_len); free(okm);
        return -1;
    }
    memset(postmix, 0, postmix_len);
    memcpy(postmix, "MCES2DU-POST\x00\x00\x00\x00", 16);
    memcpy(postmix + 16, okm, k_stream_len);
    memcpy(postmix + 16 + k_stream_len, nonce, 12);
    u64_to_be(timestamp_ns, postmix + 16 + k_stream_len + 12);

    secure_zero(okm, okm_len); free(okm);
    *cfg_out = cfg;
    *postmix_out = postmix;
    *postmix_len_out = postmix_len;
    return 0;
}

/* ===== Parallel stream generation (chunked) ===== */
typedef struct {
    const MCES_Config *cfg;
    const uint8_t *postmix;
    size_t postmix_len;
    uint64_t offset;
    size_t length;
    uint8_t *out;
    int rc;
} gen_job_t;

static void *gen_worker(void *arg){
    gen_job_t *J = (gen_job_t*)arg;
    J->rc = mces_generate_stream(J->cfg, J->postmix, J->postmix_len,
                                 J->offset, J->length, J->out);
    return NULL;
}

/* Split [0..total_len) into T contiguous stripes & spawn T threads */
static int gen_stream_parallel(const MCES_Config *cfg,
                               const uint8_t *postmix, size_t postmix_len,
                               uint64_t start_offset, size_t total_len,
                               uint8_t *out,
                               int threads)
{
    if (threads < 1) threads = 1;
    pthread_t *th = (pthread_t*)calloc((size_t)threads, sizeof(pthread_t));
    gen_job_t *jobs = (gen_job_t*)calloc((size_t)threads, sizeof(gen_job_t));
    if (!th || !jobs) { free(th); free(jobs); return -1; }

    size_t base = total_len / (size_t)threads;
    size_t rem  = total_len % (size_t)threads;

    uint64_t off = start_offset;
    size_t   pos = 0;
    for (int i = 0; i < threads; ++i) {
        size_t len_i = base + (i < (int)rem ? 1 : 0);
        jobs[i] = (gen_job_t){
            .cfg = cfg,
            .postmix = postmix,
            .postmix_len = postmix_len,
            .offset = off,
            .length = len_i,
            .out    = out + pos,
            .rc     = -1
        };
        off += len_i;
        pos += len_i;
    }

    for (int i = 0; i < threads; ++i) pthread_create(&th[i], NULL, gen_worker, &jobs[i]);
    int rc = 0;
    for (int i = 0; i < threads; ++i) {
        pthread_join(th[i], NULL);
        if (jobs[i].rc != 0) rc = jobs[i].rc;
    }

    secure_zero(jobs, sizeof(gen_job_t) * (size_t)threads);
    free(jobs); free(th);
    return rc;
}

/* ===== Main: benchmark stream (XOR roundtrip) plus thread sweep ===== */
int main(void) {
    setlocale(LC_CTYPE, "");

    /* Data size: default 100 MB, override with MCES_MB=integer */
    const char *mb_env = getenv("MCES_MB");
    size_t MB = 1024 * 1024;
    size_t data_size = (size_t)((mb_env && *mb_env) ? strtoul(mb_env, NULL, 10) : 100) * MB;

    /* Password: random Unicode 30..101 codepoints */
    int pw_len = 30 + (urand32() % 72);
    char *password = (char*)malloc((size_t)pw_len * 4 + 1);
    if (!password) { fprintf(stderr,"OOM\n"); return 1; }
    memset(password, 0, (size_t)pw_len * 4 + 1);
    size_t pass_bytes = 0, cp_count = 0;
    while ((int)cp_count < pw_len) {
        uint32_t cp; do { uint32_t r1 = urand32(), r2 = urand32(); cp = (r1 ^ (r2 << 1)) % 0x110000u; } while ((cp>=0xD800&&cp<=0xDFFF)||cp<0x20);
        if (cp<=0x7F) password[pass_bytes++]=(char)cp;
        else if (cp<=0x7FF){ password[pass_bytes++]=(char)(0xC0|(cp>>6)); password[pass_bytes++]=(char)(0x80|(cp&0x3F)); }
        else if (cp<=0xFFFF){ password[pass_bytes++]=(char)(0xE0|(cp>>12)); password[pass_bytes++]=(char)(0x80|((cp>>6)&0x3F)); password[pass_bytes++]=(char)(0x80|(cp&0x3F)); }
        else { password[pass_bytes++]=(char)(0xF0|(cp>>18)); password[pass_bytes++]=(char)(0x80|((cp>>12)&0x3F)); password[pass_bytes++]=(char)(0x80|((cp>>6)&0x3F)); password[pass_bytes++]=(char)(0x80|(cp&0x3F)); }
        cp_count++;
    }
    password[pass_bytes] = '\0';

    /* Timestamp + Nonce */
    struct timespec ts_rt; clock_gettime(CLOCK_REALTIME, &ts_rt);
    uint64_t timestamp_ns = (uint64_t)ts_rt.tv_sec * 1000000000ull + (uint64_t)ts_rt.tv_nsec;
    uint8_t nonce[12]; FILE *nfd = fopen("/dev/urandom", "rb");
    if (!nfd || fread(nonce,1,12,nfd)!=12) { if(nfd) fclose(nfd); fprintf(stderr,"Nonce gen failed\n"); secure_zero(password,(size_t)pw_len*4+1); free(password); return 1; }
    fclose(nfd);

    /* Config + postmix (uncapped) */
    uint8_t salt[32];
    MCES_Config cfg = (MCES_Config){0};
    uint8_t *postmix = NULL; size_t postmix_len = 0;
    uint8_t header[61];
    uint8_t k_mac[32];
    memcpy(header, "MCES", 4);
    header[4] = VAULT_VERSION;
    memcpy(header+5,  salt, 32);
    u64_to_be(timestamp_ns, header+37);
    memcpy(header+45, nonce, 12);
    header[57] = 3;   // t_cost
    header[58] = 17;  // m_cost (2^17)
    header[59] = 1;   // lanes
    header[60] = 2;   // kdf_id = Argon2id v1.3
    if (setup_config_and_postmix_from_password(password, timestamp_ns,
            salt, nonce, &cfg, &postmix, &postmix_len, k_mac) != 0) {
        fprintf(stderr,"Config setup failed\n"); secure_zero(password,(size_t)pw_len*4+1); free(password); return 1;
    }

    /* Print the number of 256-bit “nodes” (for your walker intuition) */
    {
        size_t k_stream_bytes = postmix_len - (16 + 12 + 8);
        size_t blocks = (k_stream_bytes + 31) / 32; /* 32B per node */
        printf("[mces_bench_stream] Postmix nodes: %zu\n", blocks);
    }

    /* Hardware threads & sweep list */
    long hw = sysconf(_SC_NPROCESSORS_ONLN);
    if (hw < 1) hw = 1;
    int sweep[] = {1, 2, 4, 6, 8, 12};
    size_t sweep_n = sizeof(sweep)/sizeof(sweep[0]);

    /* Buffers */
    uint8_t *plain = (uint8_t*)malloc(data_size);
    uint8_t *ct    = (uint8_t*)malloc(data_size);
    uint8_t *pt2   = (uint8_t*)malloc(data_size);
    if (!plain || !ct || !pt2) { fprintf(stderr,"OOM\n"); free(plain); free(ct); free(pt2); free_config(&cfg); secure_zero(postmix, postmix_len); free(postmix); secure_zero(password,(size_t)pw_len*4+1); free(password); return 1; }

    /* Fill plaintext with randomness (so XOR has work to do) */
    FILE *ur = fopen("/dev/urandom", "rb");
    if (!ur || fread(plain,1,data_size,ur)!=data_size) { if (ur) fclose(ur); fprintf(stderr,"urandom read fail\n"); goto done; }
    fclose(ur);

    printf("[mces_bench_stream] Parallel stream: %ld HW threads available, data=%zu MB\n", hw, data_size/(1024*1024));
    printf("THREADS\tKS(MB/s)\tENC(MB/s)\tDEC(MB/s)\tRoundtrip(ms)\tOK\n");

    for (size_t i = 0; i < sweep_n; ++i) {
        int th = sweep[i];
        if (th > hw) th = (int)hw;
        
        /* KS: measure pure keystream generation speed (without XOR) */
        double ks_mbps = 0.0;
        {
            struct timespec k0, k1;
            uint8_t *ks_ks = (uint8_t*)malloc(data_size);
            if (!ks_ks) { fprintf(stderr,"OOM\n"); goto done; }
            clock_gettime(CLOCK_MONOTONIC, &k0);
            if (gen_stream_parallel(&cfg, postmix, postmix_len, 0, data_size, ks_ks, th) != 0) {
                fprintf(stderr,"gen_stream_parallel ks failed (threads=%d)\n", th);
                free(ks_ks); goto done;
            }
            clock_gettime(CLOCK_MONOTONIC, &k1);
            double t_ks = diff_seconds(&k0, &k1);
            double mb   = (double)data_size / (1024.0 * 1024.0);
            ks_mbps     = mb / t_ks;
            secure_zero(ks_ks, data_size);
            free(ks_ks);
        }
        
        /* ENC: generate keystream in parallel and XOR */
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        uint8_t *ks = (uint8_t*)malloc(data_size);
        if (!ks) { fprintf(stderr,"OOM\n"); goto done; }
        if (gen_stream_parallel(&cfg, postmix, postmix_len, 0, data_size, ks, th) != 0) {
            fprintf(stderr,"gen_stream_parallel enc failed (threads=%d)\n", th);
            free(ks); goto done;
        }
        xor_buf(ct, plain, ks, data_size);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double t_enc = diff_seconds(&t0, &t1);
        blake3_hasher mac_enc;
        blake3_hasher_init_keyed(&mac_enc, k_mac);
        blake3_hasher_update(&mac_enc, (const uint8_t*)"MCES2DU-MAC-v1", 14);
        blake3_hasher_update(&mac_enc, header, 61);

        uint8_t len_le[8];
        for (int i=0;i<8;++i) len_le[i] = (uint8_t)((data_size >> (8*i)) & 0xFF);
        blake3_hasher_update(&mac_enc, len_le, 8);
        blake3_hasher_update(&mac_enc, ct, data_size);

        uint8_t tag_enc[32];
        blake3_hasher_finalize(&mac_enc, tag_enc, 32);
        
        /* DEC: regenerate keystream (same offsets) and XOR back */
        clock_gettime(CLOCK_MONOTONIC, &t0);
        if (gen_stream_parallel(&cfg, postmix, postmix_len, 0, data_size, ks, th) != 0) {
            fprintf(stderr,"gen_stream_parallel dec failed (threads=%d)\n", th);
            free(ks); goto done;
        }
        xor_buf(pt2, ct, ks, data_size);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double t_dec = diff_seconds(&t0, &t1);
        blake3_hasher mac_dec;
        blake3_hasher_init_keyed(&mac_dec, k_mac);
        blake3_hasher_update(&mac_dec, (const uint8_t*)"MCES2DU-MAC-v1", 14);
        blake3_hasher_update(&mac_dec, header, 61);
        blake3_hasher_update(&mac_dec, len_le, 8);
        blake3_hasher_update(&mac_dec, ct, data_size);

        uint8_t tag_dec[32];
        blake3_hasher_finalize(&mac_dec, tag_dec, 32);

        if (memcmp(tag_enc, tag_dec, 32) != 0) {
            fprintf(stderr, "MAC mismatch\n");
        }
        
        free(ks);

        int ok = (memcmp(plain, pt2, data_size) == 0);
        double mb = (double)data_size / (1024.0 * 1024.0);
        double enc_mbps = mb / t_enc;
        double dec_mbps = mb / t_dec;
        double roundtrip_ms = (t_enc + t_dec) * 1000.0;

        printf("%d\t%.2f\t\t%.2f\t\t%.2f\t\t%.3f\t\t%s\n",
               th, ks_mbps, enc_mbps, dec_mbps, roundtrip_ms, ok ? "YES" : "NO");
    }

done:
    secure_zero(plain, data_size); free(plain);
    secure_zero(ct, data_size); free(ct);
    secure_zero(pt2, data_size); free(pt2);
    free_config(&cfg);
    secure_zero(postmix, postmix_len); free(postmix);
    secure_zero(password,(size_t)pw_len*4+1); free(password);
    return 0;
}