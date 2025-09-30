// MCES v1 — Cantor-Immune Stream Cipher
// mces_stream_dieharder.c
#define _POSIX_C_SOURCE 200809L
#include "mces.h"
#include "blake3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
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

/* ===== Uncapped password → config + variable postmix ===== */
static int setup_config_and_postmix_from_password(
    const char *password,
    uint64_t timestamp_ns,
    uint8_t salt[32],
    uint8_t nonce[12],
    MCES_Config *cfg_out,
    uint8_t **postmix_out,
    size_t *postmix_len_out
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
    size_t okm_len          = k_stream_len + 32;

    uint8_t *okm = (uint8_t*)malloc(okm_len ? okm_len : 1);
    if (!okm) return -1;

    if (argon2id_hash_raw(3, (1u<<17), 1,
                          password, pass_bytes,
                          salt, 32,
                          okm, okm_len) != ARGON2_OK) {
        secure_zero(okm, okm_len); free(okm);
        return -1;
    }

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

/* ===== Parallel stream generation (persistent pool) ===== */
typedef struct {
    const MCES_Config *cfg;
    const uint8_t *postmix;
    size_t postmix_len;
    uint64_t offset;   /* absolute offset for this lane's slice */
    size_t length;     /* bytes to produce for this lane */
    uint8_t *out;      /* destination pointer for this lane */
    int rc;
    int has_work;      /* 0=no work this round (e.g., length==0) */
} gen_job_t;

/* Pool state (persists across calls) */
static pthread_t        *g_threads        = NULL;
static gen_job_t        *g_jobs           = NULL;
static int               g_pool_threads   = 0;
static int               g_pool_inited    = 0;
static pthread_mutex_t   g_pool_mtx       = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t    g_pool_start_cv  = PTHREAD_COND_INITIALIZER;
static pthread_cond_t    g_pool_done_cv   = PTHREAD_COND_INITIALIZER;
static unsigned long     g_round_id       = 0;
static int               g_finished       = 0;
static int               g_stop           = 0;

static void *gen_pool_worker(void *arg)
{
    const int id = (int)(intptr_t)arg;
    unsigned long my_round = 0;

    for (;;) {
        pthread_mutex_lock(&g_pool_mtx);
        while (my_round == g_round_id && !g_stop) {
            pthread_cond_wait(&g_pool_start_cv, &g_pool_mtx);
        }
        if (g_stop) { pthread_mutex_unlock(&g_pool_mtx); break; }
        my_round = g_round_id;

        gen_job_t job = g_jobs[id]; /* snapshot my job */
        pthread_mutex_unlock(&g_pool_mtx);

        int rc = 0;
        if (job.has_work && job.length > 0) {
            rc = mces_generate_stream(job.cfg, job.postmix, job.postmix_len,
                                      job.offset, job.length, job.out);
        }

        pthread_mutex_lock(&g_pool_mtx);
        g_jobs[id].rc = rc;
        g_finished++;
        if (g_finished == g_pool_threads) {
            pthread_cond_signal(&g_pool_done_cv);
        }
        pthread_mutex_unlock(&g_pool_mtx);
    }
    return NULL;
}

/* Initialize pool once, clamping to (HW-2) and >=1. */
static int gen_pool_ensure(int requested_threads)
{
    if (g_pool_inited) return 0;

    long hw = sysconf(_SC_NPROCESSORS_ONLN);
    if (hw < 1) hw = 1;
    int max_allowed = (int)((hw >= 3) ? (hw - 2) : 1); /* reserve 2 cores */

    int desired = requested_threads > 0 ? requested_threads : (int)hw;
    if (desired > max_allowed) desired = max_allowed;
    if (desired < 1) desired = 1;

    g_threads = (pthread_t*)calloc((size_t)desired, sizeof(pthread_t));
    g_jobs    = (gen_job_t*)calloc((size_t)desired, sizeof(gen_job_t));
    if (!g_threads || !g_jobs) {
        free(g_threads); g_threads = NULL;
        free(g_jobs);    g_jobs    = NULL;
        return -1;
    }
    g_pool_threads = desired;

    for (int i = 0; i < g_pool_threads; ++i) {
        if (pthread_create(&g_threads[i], NULL, gen_pool_worker, (void*)(intptr_t)i) != 0) {
            /* best effort cleanup */
            g_stop = 1;
            pthread_cond_broadcast(&g_pool_start_cv);
            for (int j = 0; j < i; ++j) pthread_join(g_threads[j], NULL);
            free(g_threads); g_threads = NULL;
            free(g_jobs);    g_jobs    = NULL;
            return -1;
        }
    }
    g_pool_inited = 1;
    return 0;
}

/* Public entry: persistent, lane-stable parallel generation. */
static int gen_stream_parallel(const MCES_Config *cfg,
                               const uint8_t *postmix, size_t postmix_len,
                               uint64_t start_offset, size_t total_len,
                               uint8_t *out,
                               int threads_hint)
{
    if (gen_pool_ensure(threads_hint) != 0) return -1;

    const int T = g_pool_threads;
    size_t base = total_len / (size_t)T;
    size_t rem  = total_len % (size_t)T;

    uint64_t off = start_offset;
    size_t   pos = 0;

    pthread_mutex_lock(&g_pool_mtx);
    for (int i = 0; i < T; ++i) {
        size_t len_i = base + (i < (int)rem ? 1 : 0);

        g_jobs[i].cfg         = cfg;
        g_jobs[i].postmix     = postmix;
        g_jobs[i].postmix_len = postmix_len;
        g_jobs[i].offset      = off;
        g_jobs[i].length      = len_i;
        g_jobs[i].out         = out + pos;
        g_jobs[i].rc          = 0;
        g_jobs[i].has_work    = (len_i > 0) ? 1 : 0;

        off += len_i;
        pos += len_i;
    }

    g_finished = 0;
    g_round_id++;
    pthread_cond_broadcast(&g_pool_start_cv);

    while (g_finished < T) {
        pthread_cond_wait(&g_pool_done_cv, &g_pool_mtx);
    }
    pthread_mutex_unlock(&g_pool_mtx);

    int rc = 0;
    for (int i = 0; i < T; ++i) if (g_jobs[i].rc != 0) rc = g_jobs[i].rc;
    return rc;
}

static void gen_pool_shutdown(void)
{
    if (!g_pool_inited) return;
    pthread_mutex_lock(&g_pool_mtx);
    g_stop = 1;
    pthread_cond_broadcast(&g_pool_start_cv);
    pthread_mutex_unlock(&g_pool_mtx);

    for (int i = 0; i < g_pool_threads; ++i) pthread_join(g_threads[i], NULL);
    free(g_threads); g_threads = NULL;
    free(g_jobs);    g_jobs = NULL;
    g_pool_inited = 0;
}

/* ===== Main: emit infinite keystream to stdout (pipe to dieharder) =====
   Example: ./mces_stream_dieharder | dieharder -a -g 200
*/
int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0); /* unbuffered stdout */

    /* Password: random Unicode 30..101 codepoints (same generation style) */
    const char *password = NULL;
    char *dynamic_pw = NULL;
    size_t pw_len = 0;

    if (argc == 3 && strcmp(argv[1], "pw") == 0) {
        // User supplied password mode
        password = argv[2];
        pw_len = strlen(password);
    } else {
        // Generate random Unicode password
        int rand_pw_len = 30 + (urand32() % 72);
        dynamic_pw = (char*)malloc((size_t)rand_pw_len * 4 + 1);
        if (!dynamic_pw) { fprintf(stderr,"OOM\n"); return 1; }
        memset(dynamic_pw, 0, (size_t)rand_pw_len * 4 + 1);
        size_t pass_bytes = 0, cp_count = 0;
        while ((int)cp_count < rand_pw_len) {
            uint32_t cp; do { uint32_t r1 = urand32(), r2 = urand32(); cp = (r1 ^ (r2 << 1)) % 0x110000u; } while ((cp>=0xD800&&cp<=0xDFFF)||cp<0x20);
            if (cp<=0x7F) dynamic_pw[pass_bytes++]=(char)cp;
            else if (cp<=0x7FF){ dynamic_pw[pass_bytes++]=(char)(0xC0|(cp>>6)); dynamic_pw[pass_bytes++]=(char)(0x80|(cp&0x3F)); }
            else if (cp<=0xFFFF){ dynamic_pw[pass_bytes++]=(char)(0xE0|(cp>>12)); dynamic_pw[pass_bytes++]=(char)(0x80|((cp>>6)&0x3F)); dynamic_pw[pass_bytes++]=(char)(0x80|(cp&0x3F)); }
            else { dynamic_pw[pass_bytes++]=(char)(0xF0|(cp>>18)); dynamic_pw[pass_bytes++]=(char)(0x80|((cp>>12)&0x3F)); dynamic_pw[pass_bytes++]=(char)(0x80|((cp>>6)&0x3F)); dynamic_pw[pass_bytes++]=(char)(0x80|(cp&0x3F)); }
            cp_count++;
        }
        dynamic_pw[pass_bytes] = '\0';
        password = dynamic_pw;
        pw_len = pass_bytes;
    }

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
    if (setup_config_and_postmix_from_password(password, timestamp_ns, salt, nonce, &cfg, &postmix, &postmix_len) != 0) {
        fprintf(stderr,"Config setup failed\n"); secure_zero(password,(size_t)pw_len*4+1); free(password); return 1;
    }

    /* Threads: MCES_THREADS env or HW default, clamped to (HW-2) in pool */
    long hw = sysconf(_SC_NPROCESSORS_ONLN);
    if (hw < 1) hw = 1;
    int threads_hint = (int)hw;
    const char *env_t = getenv("MCES_THREADS");
    if (env_t && *env_t) { int t = atoi(env_t); if (t >= 1) threads_hint = t; }

    /* Chunk size per iteration: default 1 MiB, override via MCES_CHUNK_MB */
    const char *chunk_mb_env = getenv("MCES_CHUNK_MB");
    size_t MB = 1024 * 1024;
    size_t chunk = (size_t)((chunk_mb_env && *chunk_mb_env) ? strtoul(chunk_mb_env,NULL,10) : 1) * MB;
    if (chunk == 0) chunk = MB;

    /* Optional: clean shutdown at exit */
    atexit(gen_pool_shutdown);

    uint8_t *buf = (uint8_t*)malloc(chunk);
    if (!buf) { fprintf(stderr,"OOM\n"); goto bye; }

    uint64_t offset = 0;
    for (;;) {
        if (gen_stream_parallel(&cfg, postmix, postmix_len, offset, chunk, buf, threads_hint) != 0) {
            fprintf(stderr,"gen_stream_parallel failed\n");
            break;
        }
        size_t w = fwrite(buf, 1, chunk, stdout);
        if (w != chunk) { /* dieharder will close pipe and we’ll see short write/EPIPE */
            break;
        }
        offset += chunk;
    }

    secure_zero(buf, chunk); free(buf);
bye:
    free_config(&cfg);
    secure_zero(postmix, postmix_len); free(postmix);
    secure_zero(password,(size_t)pw_len*4+1); free(password);
    if (dynamic_pw) { secure_zero(dynamic_pw, pw_len); free(dynamic_pw); }
    return 0;
}