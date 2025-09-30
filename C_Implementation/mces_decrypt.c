// MCES v1 — Cantor-Immune Stream Cipher
/* mces_decrypt.c — MAC verify (streaming) + per-chunk multithreaded decrypt */
#define _POSIX_C_SOURCE 200809L
#include "mces.h"
#include "blake3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <termios.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifdef USE_ARGON2
#include <argon2.h>
#else
#error "Argon2id is required for uncapped KDF. Compile with -DUSE_ARGON2 and link -largon2."
#endif

#define DEFAULT_CHUNK (16u * 1024u * 1024u)
#define MAX_THREADS_CAP 1024

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
static inline size_t round_up_32(size_t x){ return (x + 31u) & ~((size_t)31u); }
static int ctcmp32(const uint8_t *a, const uint8_t *b){
    uint32_t d=0; for(int i=0;i<32;++i) d |= (uint32_t)(a[i]^b[i]); return (int)d;
}
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

/* Portable XOR helper (works everywhere) */
static inline void xor_neon(uint8_t *dst, const uint8_t *src, const uint8_t *ks, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        dst[i] = src[i] ^ ks[i];
    }
}

/* same per-chunk slice job as encrypt */
typedef struct {
    const MCES_Config *cfg;
    const uint8_t *postmix;
    size_t postmix_len;

    const uint8_t *src;  /* ciphertext slice */
    uint8_t *dst;        /* plaintext slice */
    uint64_t offset;
    size_t   length;

    int rc;
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

// Returns malloc'd string with password, or NULL if not found
static char *get_password_from_sigilbook(const char *vault_path) {
    int pipefd[2];
    if (pipe(pipefd) == -1) return NULL;

    pid_t pid = fork();
    if (pid == 0) {
        // Child: redirect stdout to pipe, exec sigilbook get
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[0]); close(pipefd[1]);
        execlp("sigilbook", "sigilbook", "get", vault_path, (char*)NULL);
        _exit(127);
    }
    // Parent
    close(pipefd[1]);
    char buf[4096];
    ssize_t n = read(pipefd[0], buf, sizeof(buf)-1);
    close(pipefd[0]);
    int status = 1;
    waitpid(pid, &status, 0);
    if (n <= 0) return NULL;
    buf[n] = '\0';
    // Remove trailing newlines
    char *end = buf + n - 1;
    while (end >= buf && (*end == '\n' || *end == '\r')) *end-- = '\0';
    // Sigilbook prints 'None', '' or '(not found)' if not found
    if (strcmp(buf, "") == 0 || strcmp(buf, "None") == 0 || strstr(buf, "(not found)"))
        return NULL;
    return strdup(buf);
}

int main(int argc, char *argv[]) {
    char *password_arg = NULL;
    const char *infile = NULL;

    if (argc == 4 && strcmp(argv[1], "pw") == 0) {
        password_arg = strdup(argv[2]);
        infile = argv[3];
    } else if (argc == 2) {
        infile = argv[1];
    } else {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s <vault_file>\n", argv[0]);
        fprintf(stderr, "  %s pw <password> <vault_file>\n", argv[0]);
        return 1;
    }

    FILE *fin = fopen(infile, "rb");
    if (!fin) { perror("open"); return 1; }

    /* header */
    char magic[4];
    if (fread(magic,1,4,fin)!=4 || memcmp(magic,"MCES",4)!=0) { fprintf(stderr,"bad magic\n"); fclose(fin); return 1; }
    uint8_t version=0; if (fread(&version,1,1,fin)!=1 || version!=VAULT_VERSION) { fprintf(stderr,"bad version\n"); fclose(fin); return 1; }
    uint8_t salt[32]; if (fread(salt,1,32,fin)!=32) { fprintf(stderr,"salt read fail\n"); fclose(fin); return 1; }
    uint8_t ts_be[8]; if (fread(ts_be,1,8,fin)!=8) { fprintf(stderr,"ts read fail\n"); fclose(fin); return 1; }
    uint64_t timestamp_ns = 0; for(int i=0;i<8;++i) timestamp_ns = (timestamp_ns<<8) | ts_be[i];
    uint8_t nonce[12]; if (fread(nonce,1,12,fin)!=12) { fprintf(stderr,"nonce read fail\n"); fclose(fin); return 1; }
    uint8_t t_cost, m_cost, lanes, kdf_id;
    if (fread(&t_cost,1,1,fin)!=1 || fread(&m_cost,1,1,fin)!=1 ||
        fread(&lanes,1,1,fin)!=1 || fread(&kdf_id,1,1,fin)!=1) {
        fprintf(stderr,"argon2 param read fail\n"); fclose(fin); return 1;
    }

    /* Argon2id parameter validation (reject before KDF/DoS/UB) */
    if (kdf_id != 2)                    { fprintf(stderr,"kdf_id unsupported\n"); fclose(fin); return 1; }
    if (t_cost < 1 || t_cost > 10)      { fprintf(stderr,"t_cost out of range\n"); fclose(fin); return 1; }
    if (m_cost < 10 || m_cost > 24)     { fprintf(stderr,"m_cost out of range\n"); fclose(fin); return 1; } /* mem_kib = 1u<<m_cost */
    if (lanes  < 1 || lanes  > 4)       { fprintf(stderr,"lanes out of range\n");  fclose(fin); return 1; }

    /* now read tag */
    uint8_t tag_file[32];
    if (fread(tag_file,1,32,fin)!=32) { fprintf(stderr,"tag read fail\n"); fclose(fin); return 1; }

    /* ciphertext extent */
    if (fseek(fin, 0, SEEK_END) != 0) { perror("fseek"); fclose(fin); return 1; }
    long file_size = ftell(fin);
    /* 61-byte header + 32-byte tag = 93 */
    if (file_size < 93) { fprintf(stderr,"invalid vault\n"); fclose(fin); return 1; }
    size_t clen = (size_t)file_size - 93;
    long ct_start = 93;
    if (fseek(fin, ct_start, SEEK_SET) != 0) { perror("fseek"); fclose(fin); return 1; }

    /* password selection */
    char password[65536] = {0};
    size_t pass_bytes = 0;

    if (password_arg) {
        // CLI password mode
        strncpy(password, password_arg, sizeof(password)-1);
        password[sizeof(password)-1] = '\0';
        pass_bytes = strlen(password);
    } else {
        // Always try sigilbook
        char *pw = get_password_from_sigilbook(infile);
        if (pw && strlen(pw) > 0) {
            strncpy(password, pw, sizeof(password)-1);
            password[sizeof(password)-1] = '\0';
            pass_bytes = strlen(password);
            fprintf(stderr, "Password retrieved from sigilbook.\n");
            free(pw);
        } else {
            // If sigilbook is missing or doesn't contain password, prompt the user
            printf("Password: "); fflush(stdout);
            if (!fgets(password, sizeof(password), stdin)) {
                fprintf(stderr, "pw read fail\n"); fclose(fin); return 1;
            }
            pass_bytes = strcspn(password, "\r\n");
            password[pass_bytes] = '\0';
        }
    }
    

    /* derive k_stream/k_mac */
    size_t k_stream_len = round_up_32(pass_bytes);
    if (k_stream_len == 0) k_stream_len = 32;  /* never zero */
    size_t okm_len      = k_stream_len + 32;
    uint8_t *okm = (uint8_t*)malloc(okm_len ? okm_len : 1);
    if (!okm) { fprintf(stderr,"OOM\n"); fclose(fin); secure_zero(password,sizeof(password)); return 1; }
    if (argon2id_hash_raw(t_cost, (1u<<m_cost), lanes,
                          password, pass_bytes, salt, 32,
                          okm, okm_len) != ARGON2_OK) {
        fprintf(stderr,"Argon2id failed\n");
        secure_zero(okm,okm_len); free(okm); fclose(fin); secure_zero(password,sizeof(password)); return 1;
    }
    uint8_t *k_stream = okm;
    uint8_t *k_mac    = okm + k_stream_len;

    /* build full 61-byte header exactly as writer did */
    uint8_t header[61];
    memset(header, 0, sizeof(header));
    memcpy(header, "MCES", 4);
    header[4] = VAULT_VERSION;
    memcpy(header + 5,  salt, 32);
    memcpy(header + 37, ts_be, 8);
    memcpy(header + 45, nonce, 12);
    header[57] = t_cost;
    header[58] = m_cost;
    header[59] = lanes;
    header[60] = kdf_id;

    /* MAC over domain || header[0..60] || len_le || ciphertext */
    blake3_hasher mac;
    blake3_hasher_init_keyed(&mac, k_mac);
    blake3_hasher_update(&mac, (const uint8_t*)"MCES2DU-MAC-v1", 14);
    blake3_hasher_update(&mac, header, 61);

    uint8_t len_le[8];
    for (int i=0;i<8;++i) len_le[i] = (uint8_t)((clen >> (8*i)) & 0xFF);
    blake3_hasher_update(&mac, len_le, 8);

    const size_t CHUNK = pick_chunk_size();
    uint8_t *ct_buf = (uint8_t*)malloc(CHUNK);
    if (!ct_buf) { fprintf(stderr,"OOM\n"); secure_zero(okm,okm_len); free(okm); fclose(fin); secure_zero(password,sizeof(password)); return 1; }

    size_t n;
    while ((n = fread(ct_buf, 1, CHUNK, fin)) > 0) {
        blake3_hasher_update(&mac, ct_buf, n);
    }
    if (ferror(fin)) {
        fprintf(stderr,"read fail\n");
        free(ct_buf); secure_zero(okm,okm_len); free(okm); fclose(fin); secure_zero(password,sizeof(password)); return 1;
    }
    uint8_t tag_calc[32]={0};
    blake3_hasher_finalize(&mac, tag_calc, 32);
    if (ctcmp32(tag_calc, tag_file) != 0) {
        fprintf(stderr,"HMAC mismatch (corrupted/tampered)\n");
        free(ct_buf); secure_zero(okm,okm_len); free(okm); fclose(fin); secure_zero(password,sizeof(password)); return 1;
    }

    /* back to start of ciphertext for decrypt pass */
    if (fseek(fin, ct_start, SEEK_SET) != 0) { perror("fseek"); free(ct_buf); secure_zero(okm,okm_len); free(okm); fclose(fin); secure_zero(password,sizeof(password)); return 1; }

    /* config + postmix */
    MCES_Config config = (MCES_Config){0};
    if (generate_config_with_timestamp(password, NULL, 0, timestamp_ns, &config) != 0) {
        fprintf(stderr,"generate_config failed\n");
        free(ct_buf); secure_zero(okm,okm_len); free(okm); fclose(fin); secure_zero(password,sizeof(password)); return 1;
    }
    size_t postmix_len = 16 + k_stream_len + 12 + 8;
    uint8_t *postmix = (uint8_t*)malloc(postmix_len ? postmix_len : 1);
    if (!postmix) {
        fprintf(stderr,"OOM\n");
        free_config(&config); free(ct_buf); secure_zero(okm,okm_len); free(okm); fclose(fin); secure_zero(password,sizeof(password)); return 1;
    }
    memset(postmix,0,postmix_len);
    memcpy(postmix, "MCES2DU-POST\x00\x00\x00\x00", 16);
    memcpy(postmix + 16, k_stream, k_stream_len);
    memcpy(postmix + 16 + k_stream_len, nonce, 12);
    u64_to_be(timestamp_ns, postmix + 16 + k_stream_len + 12);

    /* open output (strip .vault) */
    char *outname = (char*)malloc(strlen(infile) + 1);
    if (!outname) {
        fprintf(stderr,"OOM\n");
        free_config(&config); free(ct_buf); secure_zero(postmix,postmix_len); free(postmix);
        secure_zero(okm,okm_len); free(okm); fclose(fin); secure_zero(password,sizeof(password)); return 1;
    }
    strcpy(outname, infile);
    char *ext = strstr(outname, ".vault");
    if (ext && ext[6] == '\0') *ext = '\0';

    FILE *fout = fopen(outname, "wb");
    if (!fout) { perror("create out"); free(outname);
        free_config(&config); free(ct_buf); secure_zero(postmix,postmix_len); free(postmix);
        secure_zero(okm,okm_len); free(okm); fclose(fin); secure_zero(password,sizeof(password));
        return 1; }

    /* per-chunk threaded decrypt */
    uint8_t *pt_buf = (uint8_t*)malloc(CHUNK);
    if (!pt_buf) {
        fprintf(stderr,"OOM\n");
        fclose(fout); remove(outname); free(outname);
        free_config(&config); free(ct_buf); secure_zero(postmix,postmix_len); free(postmix);
        secure_zero(okm,okm_len); free(okm); fclose(fin); secure_zero(password,sizeof(password));
        return 1;
    }

    int threads = pick_thread_count();
    if ((size_t)threads > CHUNK) threads = (int)CHUNK;

    xor_job_t *jobs = (xor_job_t*)malloc(sizeof(xor_job_t)*(size_t)threads);
    pthread_t *ths  = (pthread_t*)malloc(sizeof(pthread_t)*(size_t)threads);
    if (!jobs || !ths) {
        fprintf(stderr,"OOM\n");
        free(jobs); free(ths);
        free(pt_buf);
        fclose(fout); remove(outname); free(outname);
        free_config(&config); free(ct_buf); secure_zero(postmix,postmix_len); free(postmix);
        secure_zero(okm,okm_len); free(okm); fclose(fin); secure_zero(password,sizeof(password));
        return 1;
    }

    uint64_t abs_offset = 0;
    while ((n = fread(ct_buf, 1, CHUNK, fin)) > 0) {
        build_jobs(jobs, threads, &config, postmix, postmix_len, ct_buf, pt_buf, abs_offset, n);
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
            fprintf(stderr,"parallel decrypt failed\n");
            free(jobs); free(ths); free(pt_buf);
            fclose(fout); remove(outname); free(outname);
            free_config(&config); free(ct_buf); secure_zero(postmix,postmix_len); free(postmix);
            secure_zero(okm,okm_len); free(okm); fclose(fin); secure_zero(password,sizeof(password));
            return 1;
        }

        if (fwrite(pt_buf, 1, n, fout) != n) {
            fprintf(stderr,"write plaintext fail\n");
            free(jobs); free(ths); free(pt_buf);
            fclose(fout); remove(outname); free(outname);
            free_config(&config); free(ct_buf); secure_zero(postmix,postmix_len); free(postmix);
            secure_zero(okm,okm_len); free(okm); fclose(fin); secure_zero(password,sizeof(password));
            return 1;
        }
        abs_offset += n;
    }
    if (ferror(fin)) {
        fprintf(stderr,"read ciphertext fail\n");
        free(jobs); free(ths); free(pt_buf);
        fclose(fout); remove(outname); free(outname);
        free_config(&config); free(ct_buf); secure_zero(postmix,postmix_len); free(postmix);
        secure_zero(okm,okm_len); free(okm); fclose(fin); secure_zero(password,sizeof(password));
        return 1;
    }

    /* optional: remove source when exact .vault suffix */
    if (ext && ext[0] == '\0') { (void)remove(infile); }

    /* cleanup */
    free(jobs); free(ths); free(pt_buf);
    fclose(fout); free(outname);
    free_config(&config);
    free(ct_buf);
    secure_zero(postmix, postmix_len); free(postmix);
    secure_zero(okm, okm_len); free(okm);
    fclose(fin);
    secure_zero(password, sizeof(password));
    return 0;
}