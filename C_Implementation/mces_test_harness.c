// MCES v1 — Cantor-Immune Stream Cipher
// Full-system Verdult-7 harness for MCES vault scheme
// - Uses Argon2id salt=BLAKE3(ts||nonce), header/tag layout, postmix "MCES2DU-POST...."
// - Keystream via mces_generate_stream with config from generate_config_with_timestamp()
// - Tests:
//   1) AEAD malleability (auth detection on ct/header flips)
//   2) Known-plaintext recovery (log KS head)
//   3) Seek equivalence (whole vs piecemeal keystream)
//   4) Distinguishing (chi^2 on bytes, serial correlation)
//   5) Bit-position bias across IVs
//   6) Weak-key scan (head collisions across IVs)
//   7) Key sensitivity (avalanche vs 1-char key tweak)
//   8) Tag forgery (randomized tag must fail)
//   9) Header invariants (salt==BLAKE3(ts||nonce))
// Output: mces_v7.log
#define _POSIX_C_SOURCE 200809L
#include "mces.h"
#include "blake3.h"
#include <argon2.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <math.h>

/* ---------------- params / CLI ---------------- */
typedef struct {
    int n_keys;
    int n_ivs;
    size_t bytes_per_stream;
    uint64_t seed;
    const char *log_path;
} params_t;

static void parse_args(int argc, char **argv, params_t *P){
    P->n_keys = 10;
    P->n_ivs  = 64;
    P->bytes_per_stream = 1u<<20;
    P->seed   = 0xC0DEFACE12345678ULL;
    P->log_path = "mces_v7.log";
    for(int i=1;i<argc;++i){
        if(!strcmp(argv[i],"-keys") && i+1<argc){ P->n_keys = atoi(argv[++i]); }
        else if(!strcmp(argv[i],"-ivs") && i+1<argc){ P->n_ivs = atoi(argv[++i]); }
        else if(!strcmp(argv[i],"-bytes") && i+1<argc){ P->bytes_per_stream = (size_t)strtoull(argv[++i],NULL,10); }
        else if(!strcmp(argv[i],"-seed") && i+1<argc){ P->seed = strtoull(argv[++i],NULL,16); }
        else if(!strcmp(argv[i],"-log") && i+1<argc){ P->log_path = argv[++i]; }
    }
}

/* ---------------- rng (deterministic) ---------------- */
static uint64_t splitmix64(uint64_t *x){
    uint64_t z = (*x += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static uint64_t g_seed;
static void rng_seed(uint64_t s){ g_seed = s ? s : 1; }
static uint64_t rng_u64(){ return splitmix64(&g_seed); }
static uint32_t rng_u32(){ return (uint32_t)(splitmix64(&g_seed) >> 32); }

/* ---------------- small utils ---------------- */
static inline size_t round_up_32(size_t x){ return (x + 31u) & ~((size_t)31u); }

static size_t hamming_bits(const uint8_t *a, const uint8_t *b, size_t len){
    size_t d = 0;
    for (size_t i = 0; i < len; ++i) {
        d += (size_t)__builtin_popcount((unsigned)(a[i] ^ b[i]));
    }
    return d;
}

static double serial_corr(const uint8_t *buf, size_t n){
    if(n<3) return 0.0;
    double sx=0, sxx=0, sxy=0;
    for(size_t i=0;i<n-1;++i){ double x=buf[i], y=buf[i+1]; sx+=x; sxx+=x*x; sxy+=x*y; }
    double N = (double)(n-1);
    double num = N*sxy - sx*sx;
    double den = sqrt((N*sxx - sx*sx)*(N*sxx - sx*sx));
    if(den==0.0) return 0.0;
    return num/den;
}
static double chi2_bytes(const uint8_t *buf, size_t n){
    uint32_t f[256]={0};
    for(size_t i=0;i<n;++i) f[buf[i]]++;
    double exp = (double)n / 256.0, chi2=0.0;
    for(int b=0;b<256;++b){ double d=f[b]-exp; chi2 += (d*d)/exp; }
    return chi2; // df = 255
}

static inline int ctcmp32(const uint8_t *a, const uint8_t *b) {
    uint32_t d = 0;
    for (int i = 0; i < 32; ++i) d |= (uint32_t)(a[i] ^ b[i]);
    return (int)d;
}

static inline void be32(uint32_t x, uint8_t out[4]) {
    out[0] = (uint8_t)((x >> 24) & 0xFF);
    out[1] = (uint8_t)((x >> 16) & 0xFF);
    out[2] = (uint8_t)((x >>  8) & 0xFF);
    out[3] = (uint8_t)( x        & 0xFF);
}

/* --- endian helpers (place above first use) --- */
static inline void be64(uint64_t x, uint8_t out[8]) {
    for (int i = 0; i < 8; ++i) out[i] = (uint8_t)((x >> (56 - 8*i)) & 0xFF);
}
static inline void le64(uint64_t x, uint8_t out[8]) {
    for (int i = 0; i < 8; ++i) out[i] = (uint8_t)((x >> (8*i)) & 0xFF);
}

/* ---------------- deterministic ts/nonce ---------------- */
static void derive_ts_nonce(uint64_t seed, int key_idx, int iv_idx,
                            uint64_t *ts_ns, uint8_t nonce[12]){
    uint8_t in[16 + 8 + 4 + 4];
    memset(in, 0, sizeof(in));
    memcpy(in, "HARNESS-TSNONCE", 15);

    be64(seed,      in + 16);

    uint8_t kid_be[4], iv_be[4];
    be32((uint32_t)key_idx, kid_be);
    be32((uint32_t)iv_idx,  iv_be);
    memcpy(in + 24, kid_be, 4);
    memcpy(in + 28, iv_be,  4);

    uint8_t out[32];
    blake3_hasher h; blake3_hasher_init(&h);
    blake3_hasher_update(&h, in, sizeof(in));
    blake3_hasher_finalize(&h, out, 32);

    memcpy(nonce, out, 12);                    /* first 12 bytes */
    uint64_t t = 0; for (int i = 12; i < 20; ++i) t = (t << 8) | out[i];
    if (t == 0) t = 1;
    *ts_ns = t;
}

/* ---------------- passwords & configs ---------------- */
typedef struct {
    MCES_Config cfg;
    char *password;
} key_slot_t;

static char *make_password(size_t cps){
    if(cps<30) cps=30; if(cps>200) cps=200;
    char *s=(char*)malloc(cps+1); if(!s) return NULL;
    for(size_t i=0;i<cps;++i){ s[i] = (char)(33 + (rng_u32()%94)); }
    s[cps]='\0'; return s;
}

static key_slot_t *setup_keys(int n_keys){
    key_slot_t *K=(key_slot_t*)calloc((size_t)n_keys,sizeof(key_slot_t));
    if(!K){ fprintf(stderr,"OOM\n"); exit(1); }
    for(int i=0;i<n_keys;++i){
        K[i].password = make_password(64);
        if(!K[i].password){ fprintf(stderr,"OOM pw\n"); exit(1); }
        if(generate_config_with_timestamp(K[i].password, NULL, 0, 123456789ULL, &K[i].cfg)!=0){
            fprintf(stderr,"generate_config failed for key %d\n", i); exit(1);
        }
    }
    return K;
}
static void free_keys(key_slot_t *K, int n_keys){
    if(!K) return;
    for(int i=0;i<n_keys;++i){
        free_config(&K[i].cfg);
        if(K[i].password){ memset(K[i].password,0,strlen(K[i].password)); free(K[i].password); }
    }
    free(K);
}

static void salt_from_ts_nonce(uint64_t ts_ns, const uint8_t nonce[12], uint8_t salt32[32]){
    uint8_t in[8+12]; be64(ts_ns,in); memcpy(in+8,nonce,12);
    blake3_hasher h; blake3_hasher_init(&h);
    blake3_hasher_update(&h,in,sizeof(in));
    blake3_hasher_finalize(&h,salt32,32);
}

static int derive_okm_from_pw(const char *pw, const uint8_t salt32[32],
                              uint8_t **k_stream, size_t *k_stream_len, uint8_t k_mac[32]){
    size_t pass_bytes = strlen(pw);
    size_t ks_len = round_up_32(pass_bytes);
    if (ks_len == 0) ks_len = 32;         
    size_t okm_len = ks_len + 32;
    uint8_t *okm = (uint8_t*)malloc(okm_len ? okm_len : 1);
    if(!okm) return -1;
    if(argon2id_hash_raw(3, (1u<<17), 1, pw, pass_bytes, salt32, 32, okm, okm_len) != ARGON2_OK){
        free(okm); return -1;
    }
    *k_stream_len = ks_len;
    *k_stream = (uint8_t*)malloc(ks_len);
    if(!*k_stream){ free(okm); return -1; }
    memcpy(*k_stream, okm, ks_len);
    memcpy(k_mac, okm+ks_len, 32);
    memset(okm,0,okm_len); free(okm);
    return 0;
}

static void build_postmix(const uint8_t *k_stream, size_t ks_len,
                          const uint8_t nonce[12], uint64_t ts_ns,
                          uint8_t **pm, size_t *pm_len){
    size_t L = 16 + ks_len + 12 + 8;
    uint8_t *p = (uint8_t*)malloc(L);
    memset(p,0,L);
    memcpy(p, "MCES2DU-POST\x00\x00\x00\x00", 16);
    memcpy(p+16, k_stream, ks_len);
    memcpy(p+16+ks_len, nonce, 12);
    be64(ts_ns, p+16+ks_len+12);
    *pm = p; *pm_len = L;
}

static void build_header61(uint64_t ts_ns, const uint8_t nonce[12],
                           const uint8_t salt32[32],
                           uint8_t t_cost, uint8_t m_cost, uint8_t lanes, uint8_t kdf_id,
                           uint8_t header[61]){
    memset(header, 0, 61);
    memcpy(header, "MCES", 4);
    header[4] = VAULT_VERSION;
    memcpy(header + 5,  salt32, 32);
    be64(ts_ns, header + 37);
    memcpy(header + 45, nonce, 12);
    header[57] = t_cost;
    header[58] = m_cost;
    header[59] = lanes;
    header[60] = kdf_id;
}

/* produce vault blob in memory: header(57) || tag(32) || ciphertext */
static int scheme_encrypt_vault(const key_slot_t *key,
                                const uint8_t *plaintext, size_t plen,
                                uint64_t ts_ns, const uint8_t nonce[12],
                                uint8_t **out_vault, size_t *out_vlen){
    uint8_t salt[32]; salt_from_ts_nonce(ts_ns, nonce, salt);

    // derive okm
    uint8_t *k_stream=NULL, k_mac[32]={0}; size_t ks_len=0;
    if(derive_okm_from_pw(key->password, salt, &k_stream, &ks_len, k_mac)!=0) return -1;

    // config (walker uses raw password; timestamp is ignored in impl, still pass it)
    MCES_Config cfg = {0};
    if(generate_config_with_timestamp(key->password, NULL, 0, ts_ns, &cfg)!=0){
        memset(k_stream,0,ks_len); free(k_stream); return -1;
    }

    // postmix
    uint8_t *pm=NULL; size_t pm_len=0;
    build_postmix(k_stream, ks_len, nonce, ts_ns, &pm, &pm_len);

    // keystream + XOR
    uint8_t *ct = (uint8_t*)malloc(plen ? plen : 1);
    uint8_t *ks = (uint8_t*)malloc(plen ? plen : 1);
    if(!ct || !ks){ free(ct); free(ks); free_config(&cfg); memset(k_stream,0,ks_len); free(k_stream); free(pm); return -1; }
    if(mces_generate_stream(&cfg, pm, pm_len, 0, plen, ks)!=0){
        free(ct); free(ks); free_config(&cfg); memset(k_stream,0,ks_len); free(k_stream); free(pm); return -1;
    }
    for(size_t i=0;i<plen;++i) ct[i] = plaintext[i] ^ ks[i];

    /* header (61 bytes with Argon2 params) */
    uint8_t t_cost = 3, m_cost = 17, lanes = 1, kdf_id = 2;  /* Argon2id v1.3, 128 MiB */
    uint8_t header[61]; build_header61(ts_ns, nonce, salt, t_cost, m_cost, lanes, kdf_id, header);
    
    /* MAC over "MCES2DU-MAC-v1" || header[0..60] || len_le || ciphertext */
    uint8_t len_le[8]; le64(plen, len_le);
    blake3_hasher mac;
    blake3_hasher_init_keyed(&mac, k_mac);
    blake3_hasher_update(&mac, (const uint8_t*)"MCES2DU-MAC-v1", 14);
    blake3_hasher_update(&mac, header, 61);
    blake3_hasher_update(&mac, len_le, 8);
    blake3_hasher_update(&mac, ct, plen);
    uint8_t tag[32]; blake3_hasher_finalize(&mac, tag, 32);

    // assemble blob
    size_t vlen = 61 + 32 + plen;              /* header(61) + tag(32) + ct */
    uint8_t *vault = (uint8_t*)malloc(vlen ? vlen : 1);
    memcpy(vault,      header, 61);
    memcpy(vault+61,   tag,    32);
    memcpy(vault+93,   ct,     plen);          /* ct starts at 93 */

    // cleanup
    memset(k_stream,0,ks_len); free(k_stream);
    free_config(&cfg);
    memset(ks,0,plen); free(ks);
    free(pm);
    free(ct);

    *out_vault = vault; *out_vlen = vlen;
    return 0;
}

/* returns 0 ok, -1 parse, -2 tag fail */
static int scheme_decrypt_vault(const key_slot_t *key,
                                const uint8_t *vault, size_t vlen,
                                uint8_t **out_plain, size_t *out_plen){
    if (vlen < 93) return -1;  
    if(memcmp(vault,"MCES",4)!=0) return -1;
    if(vault[4] != VAULT_VERSION) return -1;

    const uint8_t *salt = vault+5;
    uint8_t ts_be[8]; memcpy(ts_be, vault+37, 8);
    uint64_t ts_ns=0; for(int i=0;i<8;++i) ts_ns = (ts_ns<<8) | ts_be[i];
    const uint8_t *nonce = vault+45;
    const uint8_t *tag_file = vault + 61;
    const uint8_t *ct       = vault + 93;
    size_t clen = vlen - 93;

    // derive okm
    uint8_t *k_stream=NULL, k_mac[32]={0}; size_t ks_len=0;
    if(derive_okm_from_pw(key->password, salt, &k_stream, &ks_len, k_mac)!=0) return -1;

    /* MAC over "MCES2DU-MAC-v1" || header[0..60] || len_le || ct */
    uint8_t len_le[8]; le64(clen, len_le);
    blake3_hasher mac;
    blake3_hasher_init_keyed(&mac, k_mac);
    blake3_hasher_update(&mac, (const uint8_t*)"MCES2DU-MAC-v1", 14);
    blake3_hasher_update(&mac, vault, 61);          /* full header in-place */
    blake3_hasher_update(&mac, len_le, 8);
    blake3_hasher_update(&mac, ct, clen);
    uint8_t tag_calc[32]; blake3_hasher_finalize(&mac, tag_calc, 32);
    if (ctcmp32(tag_calc, tag_file) != 0) { memset(k_stream,0,ks_len); free(k_stream); return -2; }
    
    // config + postmix + decrypt
    MCES_Config cfg={0};
    if(generate_config_with_timestamp(key->password,NULL,0,ts_ns,&cfg)!=0){ memset(k_stream,0,ks_len); free(k_stream); return -1; }
    uint8_t *pm=NULL; size_t pm_len=0; build_postmix(k_stream, ks_len, nonce, ts_ns, &pm, &pm_len);
    uint8_t *plain = (uint8_t*)malloc(clen ? clen : 1);
    uint8_t *ks = (uint8_t*)malloc(clen ? clen : 1);
    if(!plain || !ks){ free(plain); free(ks); free_config(&cfg); memset(k_stream,0,ks_len); free(k_stream); free(pm); return -1; }
    if(mces_generate_stream(&cfg, pm, pm_len, 0, clen, ks)!=0){
        free(plain); free(ks); free_config(&cfg); memset(k_stream,0,ks_len); free(k_stream); free(pm); return -1;
    }
    for(size_t i=0;i<clen;++i) plain[i] = ct[i]^ks[i];

    // cleanup
    free_config(&cfg);
    memset(k_stream,0,ks_len); free(k_stream);
    memset(ks,0,clen); free(ks);
    free(pm);

    *out_plain = plain; *out_plen = clen;
    return 0;
}

/* ---------------- Tests ---------------- */

static void test1_aead(FILE *log, const params_t *P, key_slot_t *K){
    fprintf(log,"[Test 1: AEAD malleability (auth detection)]\n");
    size_t N = P->bytes_per_stream;
    uint8_t *pt = (uint8_t*)malloc(N); for(size_t i=0;i<N;++i) pt[i]=(uint8_t)i;

    for(int k=0;k<P->n_keys;++k){
        uint64_t ts; uint8_t nonce[12]; derive_ts_nonce(P->seed, k, 0, &ts, nonce);
        uint8_t *vault=NULL; size_t vlen=0;
        if(scheme_encrypt_vault(&K[k], pt, N, ts, nonce, &vault, &vlen)!=0){ fprintf(stderr,"enc fail\n"); exit(1); }

        // flip random bit in ciphertext
        size_t ct_off = 93;
        size_t bitpos = (size_t)(rng_u64() % ((vlen-ct_off)*8ULL));
        vault[ct_off + (bitpos>>3)] ^= (uint8_t)(1u<<(bitpos&7));
        uint8_t *out=NULL; size_t outlen=0;
        int rc = scheme_decrypt_vault(&K[k], vault, vlen, &out, &outlen);
        fprintf(log,"Key%d IV0 ct_bitflip_auth_detected=%d\n", k, (rc==-2)?1:0);
        if(out) free(out);

        // flip header bit (in salt)
        vault[ct_off + (bitpos>>3)] ^= (uint8_t)(1u<<(bitpos&7)); // undo
        vault[5 + (rng_u32()%32)] ^= 0x01;
        rc = scheme_decrypt_vault(&K[k], vault, vlen, &out, &outlen);
        fprintf(log,"Key%d IV0 header_bitflip_auth_detected=%d\n", k, (rc==-2)?1:0);
        if(out) free(out);

        free(vault);
    }
    free(pt);
}

static void test2_kpa_heads(FILE *log, const params_t *P, key_slot_t *K){
    fprintf(log,"[Test 2: Known-plaintext recovery]\n");
    const size_t N = 4;
    uint8_t pt[4]; for(int i=0;i<4;++i) pt[i]=(uint8_t)i;

    for(int k=0;k<P->n_keys;++k){
        for(int iv=0; iv<P->n_ivs; ++iv){
            uint64_t ts; uint8_t nonce[12]; derive_ts_nonce(P->seed, k, iv, &ts, nonce);
            uint8_t *vault=NULL; size_t vlen=0;
            if(scheme_encrypt_vault(&K[k], pt, N, ts, nonce, &vault, &vlen)!=0){ fprintf(stderr,"enc fail\n"); exit(1); }

            // derive keystream head via decrypt path
            uint8_t *out=NULL; size_t outlen=0;
            int rc = scheme_decrypt_vault(&K[k], vault, vlen, &out, &outlen);
            if(rc!=0 || outlen!=N){ fprintf(stderr,"dec fail\n"); exit(1); }
            uint32_t head = ((uint32_t)pt[0]^vault[93+0])<<24 |
                            ((uint32_t)pt[1]^vault[93+1])<<16 |
                            ((uint32_t)pt[2]^vault[93+2])<<8  |
                            ((uint32_t)pt[3]^vault[93+3]);
            fprintf(log,"K%d IV%d KS_head=0x%08X\n", k, iv, head);
            free(out); free(vault);
        }
    }
}

static void test3_seek_equivalence(FILE *log, const params_t *P, key_slot_t *K){
    fprintf(log,"[Test 3: Seek-equivalence]\n");
    size_t N = P->bytes_per_stream;
    uint8_t *pt=(uint8_t*)malloc(N); for(size_t i=0;i<N;++i) pt[i]=(uint8_t)(i*3u);
    int kcap = P->n_keys<6?P->n_keys:6;
    int ivcap= P->n_ivs<6?P->n_ivs:6;

    for(int k=0;k<kcap;++k){
        for(int iv=0; iv<ivcap; ++iv){
            uint64_t ts; uint8_t nonce[12]; derive_ts_nonce(P->seed, k, iv, &ts, nonce);
            uint8_t *vault=NULL; size_t vlen=0;
            if(scheme_encrypt_vault(&K[k], pt, N, ts, nonce, &vault, &vlen)!=0){ fprintf(stderr,"enc fail\n"); exit(1); }

            // piecewise vs whole keystream from postmix
            uint8_t salt[32]; salt_from_ts_nonce(ts, nonce, salt);
            uint8_t *k_stream=NULL, k_mac[32]; size_t ks_len=0;
            derive_okm_from_pw(K[k].password, salt, &k_stream, &ks_len, k_mac);

            MCES_Config cfg={0}; generate_config_with_timestamp(K[k].password,NULL,0,ts,&cfg);
            uint8_t *pm=NULL; size_t pm_len=0; build_postmix(k_stream, ks_len, nonce, ts, &pm, &pm_len);

            uint8_t *whole=(uint8_t*)malloc(N), *piec=(uint8_t*)malloc(N);
            mces_generate_stream(&cfg, pm, pm_len, 0, N, whole);
            size_t a = 1 + (rng_u64()%(N/3 ? N/3 : 1));
            size_t b = a + 1 + (rng_u64()%(N/3 ? N/3 : 1)); if(b>=N) b=N-1;
            mces_generate_stream(&cfg, pm, pm_len, 0, a, piec);
            mces_generate_stream(&cfg, pm, pm_len, a, b-a, piec+a);
            mces_generate_stream(&cfg, pm, pm_len, b, N-b, piec+b);

            size_t mism=0; for(size_t i=0;i<N;++i) if(whole[i]!=piec[i]) ++mism;
            fprintf(log,"K%d IV%d seek_mismatch_bytes=%zu\n", k, iv, mism);

            free(whole); free(piec); free(pm);
            free_config(&cfg); memset(k_stream,0,ks_len); free(k_stream); free(vault);
        }
    }
    free(pt);
}

static void test4_distinguishing(FILE *log, const params_t *P, key_slot_t *K){
    fprintf(log,"[Test 4: Distinguishing (chi2 & serial corr)]\n");
    size_t N=P->bytes_per_stream;
    int kcap=P->n_keys<6?P->n_keys:6;
    int ivcap=P->n_ivs<8?P->n_ivs:8;
    uint8_t *buf=(uint8_t*)malloc(N);

    double chi_min=1e300, chi_max=0.0, chi_sum=0.0;
    double sc_min=1e300,  sc_max=-1e300, sc_sum=0.0;
    int count=0;

    // evaluate raw keystream
    for(int k=0;k<kcap;++k){
        for(int iv=0; iv<ivcap; ++iv){
            uint64_t ts; uint8_t nonce[12]; derive_ts_nonce(P->seed,k,iv,&ts,nonce);
            uint8_t salt[32]; salt_from_ts_nonce(ts,nonce,salt);
            uint8_t *k_stream=NULL,k_mac[32]; size_t ks_len=0;
            derive_okm_from_pw(K[k].password, salt,&k_stream,&ks_len,k_mac);
            MCES_Config cfg={0}; generate_config_with_timestamp(K[k].password,NULL,0,ts,&cfg);
            uint8_t *pm=NULL; size_t pm_len=0; build_postmix(k_stream,ks_len,nonce,ts,&pm,&pm_len);

            mces_generate_stream(&cfg, pm, pm_len, 0, N, buf);
            double c2=chi2_bytes(buf,N), sc=serial_corr(buf,N);
            chi_min=fmin(chi_min,c2); chi_max=fmax(chi_max,c2); chi_sum+=c2;
            sc_min=fmin(sc_min,sc); sc_max=fmax(sc_max,sc); sc_sum+=sc; ++count;

            free(pm); free_config(&cfg); memset(k_stream,0,ks_len); free(k_stream);
        }
    }
    fprintf(log,"keystream chi2(df=255) min=%.2f max=%.2f avg=%.2f\n",
            chi_min, chi_max, chi_sum/(double)count);
    fprintf(log,"keystream serial_corr min=%.4f max=%.4f avg=%.4f\n",
            sc_min, sc_max, sc_sum/(double)count);
    free(buf);
}

static void test5_bit_bias(FILE *log, const params_t *P, key_slot_t *K){
    fprintf(log,"[Test 5: Bit-position bias across IVs]\n");
    const size_t W=4096;
    uint32_t *ones=(uint32_t*)calloc(W*8,sizeof(uint32_t));
    uint8_t *buf=(uint8_t*)malloc(W);
    for(int k=0;k<P->n_keys;++k){
        memset(ones,0,(W*8)*sizeof(uint32_t));
        for(int iv=0; iv<P->n_ivs; ++iv){
            uint64_t ts; uint8_t nonce[12]; derive_ts_nonce(P->seed,k,iv,&ts,nonce);
            uint8_t salt[32]; salt_from_ts_nonce(ts,nonce,salt);
            uint8_t *k_stream=NULL,k_mac[32]; size_t ks_len=0;
            derive_okm_from_pw(K[k].password,salt,&k_stream,&ks_len,k_mac);
            MCES_Config cfg={0}; generate_config_with_timestamp(K[k].password,NULL,0,ts,&cfg);
            uint8_t *pm=NULL; size_t pm_len=0; build_postmix(k_stream,ks_len,nonce,ts,&pm,&pm_len);

            mces_generate_stream(&cfg, pm, pm_len, 0, W, buf);
            for(size_t i=0;i<W;++i){
                uint8_t b=buf[i];
                for(int bit=0; bit<8; ++bit) if(b&(1u<<bit)) ones[i*8+bit]++;
            }
            free(pm); free_config(&cfg); memset(k_stream,0,ks_len); free(k_stream);
        }
        double worst=0.0, avg=0.0;
        for(size_t i=0;i<W*8;++i){
            double p1=(double)ones[i]/(double)P->n_ivs;
            double dev=fabs(p1-0.5); worst=fmax(worst,dev); avg+=dev;
        }
        avg/=(double)(W*8);
        fprintf(log,"Key%d bias: worst=%.4f avg=%.4f\n", k, worst, avg);
    }
    free(ones); free(buf);
}

static void test6_weak_keys(FILE *log, const params_t *P, key_slot_t *K){
    fprintf(log,"[Test 6: Weak-key scan (IV head collisions)]\n");
    for(int k=0;k<P->n_keys;++k){
        uint32_t *heads=(uint32_t*)malloc((size_t)P->n_ivs*sizeof(uint32_t));
        for(int iv=0; iv<P->n_ivs; ++iv){
            uint64_t ts; uint8_t nonce[12]; derive_ts_nonce(P->seed,k,iv,&ts,nonce);
            uint8_t salt[32]; salt_from_ts_nonce(ts,nonce,salt);
            uint8_t *k_stream=NULL,k_mac[32]; size_t ks_len=0;
            derive_okm_from_pw(K[k].password,salt,&k_stream,&ks_len,k_mac);
            MCES_Config cfg={0}; generate_config_with_timestamp(K[k].password,NULL,0,ts,&cfg);
            uint8_t *pm=NULL; size_t pm_len=0; build_postmix(k_stream,ks_len,nonce,ts,&pm,&pm_len);
            uint8_t b[4]; mces_generate_stream(&cfg, pm, pm_len, 0, 4, b);
            heads[iv] = ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];
            free(pm); free_config(&cfg); memset(k_stream,0,ks_len); free(k_stream);
        }
        int dups=0;
        for(int i=0;i<P->n_ivs;++i) for(int j=i+1;j<P->n_ivs;++j) if(heads[i]==heads[j]) ++dups;
        fprintf(log,"Key%d head-collisions=%d (ivs=%d)\n", k, dups, P->n_ivs);
        free(heads);
    }
}

static void test7_key_sensitivity(FILE *log, const params_t *P, key_slot_t *K){
    fprintf(log,"[Test 7: Key sensitivity (avalanche)]\n");
    size_t N=P->bytes_per_stream;
    for(int k=0;k<P->n_keys;++k){
        // same ts/nonce for both keys
        uint64_t ts; uint8_t nonce[12]; derive_ts_nonce(P->seed,k,0,&ts,nonce);
        // neighbor password
        char *pw2=strdup(K[k].password); size_t L=strlen(pw2); if(L==0) L=1;
        pw2[rng_u64()%L] ^= 0x01;
        key_slot_t K2 = {.password=pw2};
        if(generate_config_with_timestamp(pw2,NULL,0,ts,&K2.cfg)!=0){ fprintf(stderr,"cfg2 fail\n"); exit(1); }

        // produce two keystreams via scheme postmix
        uint8_t salt[32]; salt_from_ts_nonce(ts,nonce,salt);
        uint8_t *ksA=NULL,*ksB=NULL,*pm=NULL; size_t pm_len=0; uint8_t km[32]; size_t ks_len=0;

        derive_okm_from_pw(K[k].password,salt,&ksA,&ks_len,km); build_postmix(ksA,ks_len,nonce,ts,&pm,&pm_len);
        uint8_t *a=(uint8_t*)malloc(N); mces_generate_stream(&K[k].cfg, pm, pm_len, 0, N, a);
        free(pm); memset(ksA,0,ks_len); free(ksA);

        derive_okm_from_pw(K2.password,salt,&ksB,&ks_len,km); build_postmix(ksB,ks_len,nonce,ts,&pm,&pm_len);
        uint8_t *b=(uint8_t*)malloc(N); mces_generate_stream(&K2.cfg, pm, pm_len, 0, N, b);
        size_t diff=hamming_bits(a,b,N);
        fprintf(log,"Key%d avalanche bit_ratio=%.6f\n", k, (double)diff/(double)(N*8ULL));

        free(pm); memset(ksB,0,ks_len); free(ksB); free(a); free(b);
        free_config(&K2.cfg); memset(pw2,0,L); free(pw2);
    }
}

static void test8_tag_forgery(FILE *log, const params_t *P, key_slot_t *K){
    fprintf(log,"[Test 8: Tag forgery (randomized tag must fail)]\n");
    size_t N=4096; uint8_t *pt=(uint8_t*)malloc(N); for(size_t i=0;i<N;++i) pt[i]=(uint8_t)(i^0xA5);
    int kcap=P->n_keys<6?P->n_keys:6, ivcap=P->n_ivs<6?P->n_ivs:6;
    for(int k=0;k<kcap;++k){
        for(int iv=0; iv<ivcap; ++iv){
            uint64_t ts; uint8_t nonce[12]; derive_ts_nonce(P->seed,k,iv,&ts,nonce);
            uint8_t *vault=NULL; size_t vlen=0; scheme_encrypt_vault(&K[k], pt, N, ts, nonce, &vault, &vlen);
            // randomize 4 bytes of tag
            for (int t=0; t<4; ++t) vault[61 + (rng_u32()%32)] ^= (uint8_t)rng_u32();
            uint8_t *out=NULL; size_t outlen=0;
            int rc = scheme_decrypt_vault(&K[k], vault, vlen, &out, &outlen);
            fprintf(log,"K%d IV%d random_tag_detected=%d\n", k, iv, (rc==-2)?1:0);
            if(out) free(out); free(vault);
        }
    }
    free(pt);
}

static void test9_header_invariants(FILE *log, const params_t *P, key_slot_t *K){
    fprintf(log,"[Test 9: Header invariants]\n");
    size_t N=1024; uint8_t *pt=(uint8_t*)malloc(N); memset(pt,0x42,N);
    int kcap=P->n_keys<6?P->n_keys:6, ivcap=P->n_ivs<6?P->n_ivs:6;
    for(int k=0;k<kcap;++k){
        for(int iv=0; iv<ivcap; ++iv){
            uint64_t ts; uint8_t nonce[12]; derive_ts_nonce(P->seed,k,iv,&ts,nonce);
            uint8_t *vault=NULL; size_t vlen=0; scheme_encrypt_vault(&K[k], pt, N, ts, nonce, &vault, &vlen);
            // recompute salt(ts,nonce) and compare to header salt
            uint8_t salt[32]; salt_from_ts_nonce(ts,nonce,salt);
            int ok = memcmp(vault+5, salt, 32)==0 ? 1 : 0;
            fprintf(log,"K%d IV%d salt_ok=%d\n", k, iv, ok);
            free(vault);
        }
    }
    free(pt);
}

/* ---------------- main ---------------- */
int main(int argc, char **argv){
    params_t P; parse_args(argc, argv, &P);
    rng_seed(P.seed);

    FILE *log=fopen(P.log_path,"w");
    if(!log){ fprintf(stderr,"open log failed: %s\n", strerror(errno)); return 1; }
    fprintf(log,"[MCES Full-System Verdult-7]\nkeys=%d ivs=%d bytes=%zu seed=0x%016llx\n\n",
            P.n_keys, P.n_ivs, P.bytes_per_stream, (unsigned long long)P.seed);

    key_slot_t *K = setup_keys(P.n_keys);

    test1_aead(log,&P,K);
    test2_kpa_heads(log,&P,K);
    test3_seek_equivalence(log,&P,K);
    test4_distinguishing(log,&P,K);
    test5_bit_bias(log,&P,K);
    test6_weak_keys(log,&P,K);
    test7_key_sensitivity(log,&P,K);
    test8_tag_forgery(log,&P,K);
    test9_header_invariants(log,&P,K);

    fprintf(log,"\n[Done]\n");
    fclose(log);
    free_keys(K,P.n_keys);

    printf("Wrote %s\n", P.log_path);
    return 0;
}