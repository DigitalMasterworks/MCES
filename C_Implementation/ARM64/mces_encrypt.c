// MCES v1 — Cantor-Immune Stream Cipher
/* mces_encrypt.c — streaming + per-chunk multithreading */
#if !defined(__aarch64__)
#  error "This binary is arm64-only."
#endif
#define _POSIX_C_SOURCE 200809L
#include "mces.h"
#include "blake3.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <locale.h>
#include <time.h>
#include <unistd.h>     /* isatty, sysconf */
#include <pthread.h>
#include <arm_neon.h>   /* NEON XOR */

#ifdef USE_ARGON2
#include <argon2.h>
#else
#error "Argon2id is required for uncapped KDF. Compile with -DUSE_ARGON2 and link -largon2."
#endif

/* ---------- config ---------- */
#define DEFAULT_CHUNK   (16u * 1024u * 1024u)  /* 16 MiB */
#define MAX_THREADS_CAP 1024

/* ---------- utilities ---------- */
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
static size_t pick_chunk_size(void){
    const char *s = getenv("MCES_IO_CHUNK");
    if (!s || !*s) return DEFAULT_CHUNK;
    long v = strtol(s,NULL,10);
    if (v < (1<<20)) v = (1<<20);
    if (v > (1<<28)) v = (1<<28);
    return (size_t)v;
}
static int pick_thread_count(void){
    const char *env = getenv("MCES_THREADS");
    if (env && *env) { int v = atoi(env); if (v > 0 && v <= MAX_THREADS_CAP) return v; }
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n < 1) n = 1; if (n > MAX_THREADS_CAP) n = MAX_THREADS_CAP;
    return (int)n;
}

/* ---------- NEON XOR helper ---------- */
static inline void xor_neon(uint8_t *dst, const uint8_t *src, const uint8_t *ks, size_t n){
    size_t i = 0;

    /* 64-byte blocks (4x 16B vectors) */
    for (; i + 64 <= n; i += 64) {
        uint8x16_t a0 = vld1q_u8(src + i +  0), b0 = vld1q_u8(ks + i +  0);
        uint8x16_t a1 = vld1q_u8(src + i + 16), b1 = vld1q_u8(ks + i + 16);
        uint8x16_t a2 = vld1q_u8(src + i + 32), b2 = vld1q_u8(ks + i + 32);
        uint8x16_t a3 = vld1q_u8(src + i + 48), b3 = vld1q_u8(ks + i + 48);
        vst1q_u8(dst + i +  0, veorq_u8(a0, b0));
        vst1q_u8(dst + i + 16, veorq_u8(a1, b1));
        vst1q_u8(dst + i + 32, veorq_u8(a2, b2));
        vst1q_u8(dst + i + 48, veorq_u8(a3, b3));
    }

    /* 16-byte chunks */
    for (; i + 16 <= n; i += 16) {
        uint8x16_t a = vld1q_u8(src + i);
        uint8x16_t b = vld1q_u8(ks  + i);
        vst1q_u8(dst + i, veorq_u8(a, b));
    }

    /* tail */
    for (; i < n; ++i) dst[i] = src[i] ^ ks[i];
}

/* ---------- per-chunk slice job ---------- */
typedef struct {
    const MCES_Config *cfg;
    const uint8_t *postmix;
    size_t postmix_len;

    const uint8_t *src;  /* plaintext slice */
    uint8_t *dst;        /* ciphertext slice */
    uint64_t offset;     /* absolute file offset of this slice */
    size_t   length;     /* slice length */

    int rc;              /* 0 ok, -1 fail */
} xor_job_t;

static void *xor_worker(void *arg) {
    xor_job_t *job = (xor_job_t*)arg;
    if (job->length == 0) { job->rc = 0; return NULL; }

    uint8_t *ks = (uint8_t*)malloc(job->length ? job->length : 1);
    if (!ks) { job->rc = -1; return NULL; }

    if (mces_generate_stream(job->cfg, job->postmix, job->postmix_len,
                             job->offset, job->length, ks) != 0) {
        secure_zero(ks, job->length); free(ks); job->rc = -1; return NULL;
    }

    /* NEON-accelerated XOR */
    xor_neon(job->dst, job->src, ks, job->length);

    secure_zero(ks, job->length); free(ks);
    job->rc = 0;
    return NULL;
}

/* split a chunk [0..total) into T slices */
static void build_jobs(xor_job_t *jobs, int T,
                       const MCES_Config *cfg,
                       const uint8_t *postmix, size_t postmix_len,
                       const uint8_t *src, uint8_t *dst,
                       uint64_t abs_offset, size_t total)
{
    size_t base = total / (size_t)T;
    size_t rem  = total % (size_t)T;
    size_t off_local = 0;
    for (int i=0;i<T;++i) {
        size_t len = base + (i < (int)rem ? 1u : 0u);
        jobs[i].cfg = cfg;
        jobs[i].postmix = postmix;
        jobs[i].postmix_len = postmix_len;
        jobs[i].src = src + off_local;
        jobs[i].dst = dst + off_local;
        jobs[i].offset = abs_offset + off_local;
        jobs[i].length = len;
        jobs[i].rc = 0;
        off_local += len;
    }
}

// Returns 0 on success, 1 on fail (same as x86 version)
static int try_save_to_sigilbook(const char *vault_path, const char *password) {
    int status = 1;
    pid_t pid = fork();
    if (pid == 0) {
        execlp("sigilbook", "sigilbook", "save", vault_path, password, (char*)NULL);
        _exit(127);
    } else if (pid > 0) {
        int wstat;
        waitpid(pid, &wstat, 0);
        if (WIFEXITED(wstat) && WEXITSTATUS(wstat) == 0)
            status = 0;
    }
    return status;
}

int main(int argc, char *argv[]) {
    char *password = NULL;
    const char *infile = NULL;
    size_t pass_bytes = 0, cp_count = 0;
    int pw_len = 0;

    // --- CLI handling ---
    if (argc == 4 && strcmp(argv[1], "pw") == 0) {
        password = strdup(argv[2]);
        infile = argv[3];
    } else if (argc == 2) {
        infile = argv[1];
        // password will be generated randomly below if not set
    } else {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s <input_file>\n", argv[0]);
        fprintf(stderr, "  %s pw <password> <input_file>\n", argv[0]);
        return 1;
    }

    /* open input and get size */
    FILE *fin = fopen(infile, "rb");
    if (!fin) { perror("open input"); return 1; }
    if (fseek(fin, 0, SEEK_END) != 0) { perror("fseek"); fclose(fin); return 1; }
    long fsize = ftell(fin);
    if (fsize < 0) { perror("ftell"); fclose(fin); return 1; }
    if (fseek(fin, 0, SEEK_SET) != 0) { perror("fseek"); fclose(fin); return 1; }
    size_t size = (size_t)fsize;

    setlocale(LC_CTYPE, "");

    if (password) {
        // --- User-supplied password mode ---
        pass_bytes = strlen(password);
        uint32_t *indices = (uint32_t*)malloc((pass_bytes+1)*sizeof(uint32_t));
        if (!indices) { fprintf(stderr, "OOM\n"); fclose(fin); return 1; }
        cp_count = 0;
        for (size_t i = 0; i < pass_bytes; ++i)
            if ((password[i] & 0xC0) != 0x80) ++cp_count;
        free(indices);

        if (cp_count < 30 || cp_count > 100) {
            fprintf(stderr, "Password must be 30-100 Unicode codepoints.\n");
            secure_zero(password, pass_bytes);
            free(password);
            fclose(fin);
            return 1;
        }
        pw_len = (int)cp_count;
    } else {
        // --- Random Unicode password mode ---
        pw_len = 30 + (urand32() % 71);
        password = (char*)malloc((size_t)pw_len * 4 + 1);
        if (!password) { fclose(fin); fprintf(stderr,"OOM\n"); return 1; }
        memset(password, 0, (size_t)pw_len*4+1);
        while ((int)cp_count < pw_len) {
            uint32_t cp; do { uint32_t r1=urand32(), r2=urand32(); cp=(r1^(r2<<1))%0x110000u; } while ((cp>=0xD800&&cp<=0xDFFF)||cp<0x20);
            if (cp<=0x7F) password[pass_bytes++]=(char)cp;
            else if (cp<=0x7FF){ password[pass_bytes++]=(char)(0xC0|(cp>>6)); password[pass_bytes++]=(char)(0x80|(cp&0x3F)); }
            else if (cp<=0xFFFF){ password[pass_bytes++]=(char)(0xE0|(cp>>12)); password[pass_bytes++]=(char)(0x80|((cp>>6)&0x3F)); password[pass_bytes++]=(char)(0x80|(cp&0x3F)); }
            else { password[pass_bytes++]=(char)(0xF0|(cp>>18)); password[pass_bytes++]=(char)(0x80|((cp>>12)&0x3F)); password[pass_bytes++]=(char)(0x80|((cp>>6)&0x3F)); password[pass_bytes++]=(char)(0x80|(cp&0x3F)); }
            cp_count++;
        }
        password[pass_bytes]='\0';
    }

    /* timestamp + nonce */
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t timestamp_ns = (uint64_t)ts.tv_sec*1000000000ull + (uint64_t)ts.tv_nsec;

    uint8_t nonce[12] = {0};
    FILE *urnonce = fopen("/dev/urandom", "rb");
    if (!urnonce || fread(nonce,1,12,urnonce) != 12) {
        if (urnonce) fclose(urnonce);
        fprintf(stderr,"nonce gen failed\n");
        secure_zero(password,(size_t)pw_len*4+1); free(password);
        fclose(fin);
        return 1;
    }
    fclose(urnonce);

    /* salt = BLAKE3(timestamp||nonce) */
    uint8_t salt[32], salt_input[8+12];
    u64_to_be(timestamp_ns, salt_input);
    memcpy(salt_input+8, nonce, 12);
    blake3_hasher htmp; blake3_hasher_init(&htmp);
    blake3_hasher_update(&htmp, salt_input, sizeof(salt_input));
    blake3_hasher_finalize(&htmp, salt, 32);

    /* Argon2id: OKM = k_stream_len + 32 */
    size_t k_stream_len = round_up_32(pass_bytes);
    if (k_stream_len == 0) k_stream_len = 32;  /* never zero */
    size_t okm_len      = k_stream_len + 32;
    uint8_t *okm = (uint8_t*)malloc(okm_len ? okm_len : 1);
    if (!okm) {
        fprintf(stderr,"OOM\n");
        secure_zero(password,(size_t)pw_len*4+1); free(password);
        fclose(fin);
        return 1;
    }
    if (argon2id_hash_raw(3, (1u<<17), 1,
                          password, pass_bytes, salt, 32,
                          okm, okm_len) != ARGON2_OK) {
        fprintf(stderr,"Argon2id failed\n");
        secure_zero(okm,okm_len); free(okm);
        secure_zero(password,(size_t)pw_len*4+1); free(password);
        fclose(fin);
        return 1;
    }
    uint8_t *k_stream = okm;
    uint8_t *k_mac    = okm + k_stream_len;

    /* config from RAW password */
    MCES_Config config = (MCES_Config){0};
    if (generate_config_with_timestamp(password, NULL, 0, timestamp_ns, &config) != 0) {
        fprintf(stderr,"generate_config failed\n");
        secure_zero(okm,okm_len); free(okm);
        secure_zero(password,(size_t)pw_len*4+1); free(password);
        fclose(fin);
        return 1;
    }

    /* postmix = label || k_stream || nonce || ts_be */
    size_t postmix_len = 16 + k_stream_len + 12 + 8;
    uint8_t *postmix = (uint8_t*)malloc(postmix_len ? postmix_len : 1);
    if (!postmix) {
        fprintf(stderr,"OOM\n");
        free_config(&config);
        secure_zero(okm,okm_len); free(okm);
        secure_zero(password,(size_t)pw_len*4+1); free(password);
        fclose(fin);
        return 1;
    }
    memset(postmix, 0, postmix_len);
    memcpy(postmix, "MCES2DU-POST\x00\x00\x00\x00", 16);
    memcpy(postmix + 16, k_stream, k_stream_len);
    memcpy(postmix + 16 + k_stream_len, nonce, 12);
    u64_to_be(timestamp_ns, postmix + 16 + k_stream_len + 12);

    /* header (61 bytes with Argon2 params) */
    uint8_t t_cost = 3;
    uint8_t m_cost = 17; // log2(128 MiB)
    uint8_t lanes  = 1;
    uint8_t kdf_id = 2;  // Argon2id v1.3

    size_t hdr_len = 61;
    uint8_t header[61];
    memset(header, 0, hdr_len);
    memcpy(header,"MCES",4);
    header[4] = VAULT_VERSION;
    memcpy(header+5,  salt, 32);
    for (int i=0;i<8;++i) header[37+i] = (uint8_t)((timestamp_ns >> (56-8*i)) & 0xFF);
    memcpy(header+45, nonce, 12);
    header[57] = t_cost;
    header[58] = m_cost;
    header[59] = lanes;
    header[60] = kdf_id;

    /* open output, write header + reserve tag */
    size_t outlen = strlen(infile) + 7;
    char *outname = (char*)malloc(outlen ? outlen : 1);
    if (!outname) {
        fprintf(stderr,"OOM\n");
        free_config(&config);
        secure_zero(postmix, postmix_len); free(postmix);
        secure_zero(okm,okm_len); free(okm);
        secure_zero(password,(size_t)pw_len*4+1); free(password);
        fclose(fin);
        return 1;
    }
    snprintf(outname, outlen, "%s.vault", infile);
    FILE *fout = fopen(outname, "wb+");
    if (!fout) { perror("open output");
        free(outname); free_config(&config); secure_zero(postmix, postmix_len); free(postmix);
        secure_zero(okm,okm_len); free(okm); secure_zero(password,(size_t)pw_len*4+1); free(password);
        fclose(fin); return 1; }

    if (fwrite(header,1,hdr_len,fout) != hdr_len) {
        fprintf(stderr,"write header fail\n");
        fclose(fout); remove(outname); free(outname);
        free_config(&config); secure_zero(postmix, postmix_len); free(postmix);
        secure_zero(okm,okm_len); free(okm); secure_zero(password,(size_t)pw_len*4+1); free(password);
        fclose(fin); return 1;
    }
    long tag_pos = ftell(fout); /* start of 32-byte tag region */
    uint8_t zero_tag[32] = {0};
    if (fwrite(zero_tag,1,32,fout) != 32) {
        fprintf(stderr,"reserve tag fail\n");
        fclose(fout); remove(outname); free(outname);
        free_config(&config); secure_zero(postmix, postmix_len); free(postmix);
        secure_zero(okm,okm_len); free(okm); secure_zero(password,(size_t)pw_len*4+1); free(password);
        fclose(fin); return 1;
    }

    /* init MAC over domain || header[0..60] || len_le || ciphertext */
    blake3_hasher mac;
    blake3_hasher_init_keyed(&mac, k_mac);
    blake3_hasher_update(&mac, (const uint8_t*)"MCES2DU-MAC-v1", 14);
    blake3_hasher_update(&mac, header, 61);  /* full header */
    uint8_t len_le[8]; for (int i=0;i<8;++i) len_le[i] = (uint8_t)((size >> (8*i)) & 0xFF);
    blake3_hasher_update(&mac, len_le, 8);

    /* ---------- streaming with per-chunk threading ---------- */
    const size_t CHUNK = pick_chunk_size();
    int threads = pick_thread_count();
    if ((size_t)threads > CHUNK) threads = (int)CHUNK; /* avoid 0-len slices */

    uint8_t *pt_buf = (uint8_t*)malloc(CHUNK);
    uint8_t *ct_buf = (uint8_t*)malloc(CHUNK);
    if (!pt_buf || !ct_buf) {
        fprintf(stderr,"OOM\n");
        free(pt_buf); free(ct_buf);
        fclose(fout); remove(outname); free(outname);
        free_config(&config); secure_zero(postmix, postmix_len); free(postmix);
        secure_zero(okm,okm_len); free(okm); secure_zero(password,(size_t)pw_len*4+1); free(password);
        fclose(fin); return 1;
    }

    xor_job_t *jobs = (xor_job_t*)malloc(sizeof(xor_job_t)*(size_t)threads);
    pthread_t *ths  = (pthread_t*)malloc(sizeof(pthread_t)*(size_t)threads);
    if (!jobs || !ths) {
        fprintf(stderr,"OOM\n");
        free(jobs); free(ths);
        free(pt_buf); free(ct_buf);
        fclose(fout); remove(outname); free(outname);
        free_config(&config); secure_zero(postmix, postmix_len); free(postmix);
        secure_zero(okm,okm_len); free(okm); secure_zero(password,(size_t)pw_len*4+1); free(password);
        fclose(fin); return 1;
    }

    uint64_t abs_offset = 0;
    size_t n;
    while ((n = fread(pt_buf, 1, CHUNK, fin)) > 0) {
        /* slice this chunk among T threads */
        build_jobs(jobs, threads, &config, postmix, postmix_len, pt_buf, ct_buf, abs_offset, n);
        for (int i=0;i<threads;++i) {
            if (jobs[i].length == 0) { ths[i]=0; continue; }
            pthread_create(&ths[i], NULL, xor_worker, &jobs[i]);
        }
        int rc_all = 0;
        for (int i=0;i<threads;++i) {
            if (ths[i]) { pthread_join(ths[i], NULL); ths[i] = 0; }
            if (jobs[i].length && jobs[i].rc != 0) rc_all = -1;
        }
        if (rc_all != 0) {
            fprintf(stderr,"parallel encrypt failed\n");
            free(jobs); free(ths);
            free(pt_buf); free(ct_buf);
            fclose(fout); remove(outname); free(outname);
            free_config(&config); secure_zero(postmix, postmix_len); free(postmix);
            secure_zero(okm,okm_len); free(okm); secure_zero(password,(size_t)pw_len*4+1); free(password);
            fclose(fin); return 1;
        }

        /* MAC the ciphertext chunk and write it */
        blake3_hasher_update(&mac, ct_buf, n);
        if (fwrite(ct_buf, 1, n, fout) != n) {
            fprintf(stderr,"write ciphertext fail\n");
            free(jobs); free(ths);
            free(pt_buf); free(ct_buf);
            fclose(fout); remove(outname); free(outname);
            free_config(&config); secure_zero(postmix, postmix_len); free(postmix);
            secure_zero(okm,okm_len); free(okm); secure_zero(password,(size_t)pw_len*4+1); free(password);
            fclose(fin); return 1;
        }

        abs_offset += n;
    }
    if (ferror(fin)) {
        fprintf(stderr,"read plaintext fail\n");
        free(jobs); free(ths);
        free(pt_buf); free(ct_buf);
        fclose(fout); remove(outname); free(outname);
        free_config(&config); secure_zero(postmix, postmix_len); free(postmix);
        secure_zero(okm,okm_len); free(okm); secure_zero(password,(size_t)pw_len*4+1); free(password);
        fclose(fin); return 1;
    }

    /* finalize tag and patch */
    uint8_t tag[32] = {0};
    blake3_hasher_finalize(&mac, tag, 32);
    if (fseek(fout, tag_pos, SEEK_SET) != 0 || fwrite(tag,1,32,fout) != 32) {
        fprintf(stderr,"write tag fail\n");
        free(jobs); free(ths);
        free(pt_buf); free(ct_buf);
        fclose(fout); remove(outname); free(outname);
        free_config(&config); secure_zero(postmix, postmix_len); free(postmix);
        secure_zero(okm,okm_len); free(okm); secure_zero(password,(size_t)pw_len*4+1); free(password);
        fclose(fin); return 1;
    }

    /* cleanup */
    free(jobs); free(ths);
    free(pt_buf); free(ct_buf);
    fflush(fout); /* optional: fsync(fileno(fout)); */
    fclose(fout);
    
    /* --- Save password to sigilbook or print it, handler-friendly --- */
    int saved = try_save_to_sigilbook(outname, password);

    if (saved == 0) {
        printf("Password securely saved to sigilbook.\n");
    } else {
        printf("Password: %s\n", password);
    }

    fflush(stdout);
    
    free(outname);
    fclose(fin);
    free_config(&config);
    secure_zero(postmix, postmix_len); free(postmix);
    secure_zero(okm, okm_len); free(okm);
    secure_zero(password,(size_t)pw_len*4+1); free(password);
    return 0;
}