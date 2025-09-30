// MCES v1 — Cantor-Immune Stream Cipher
#include "mces.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <locale.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "blake3.h"

#ifdef USE_ARGON2
#include <argon2.h>
#endif

/* ===== secure wipe ===== */
static void secure_zero(void *v, size_t n) {
#if defined(__STDC_LIB_EXT1__)
    memset_s(v, n, 0, n);
#else
    volatile unsigned char *p = (volatile unsigned char*)v;
    while (n--) *p++ = 0;
#endif
}

/* =========================
   BLAKE3 helpers
   ========================= */
static inline void blake3_hash32(const void *data, size_t len, uint8_t out[32]) {
    blake3_hasher h;
    blake3_hasher_init(&h);
    if (data && len) blake3_hasher_update(&h, data, len);
    blake3_hasher_finalize(&h, out, 32);
}

/* Split secret32 (+ optional salt32) into k_stream and k_mac */
void kdf_blake3_split(const uint8_t secret32[32],
                      const uint8_t salt32[32],
                      uint8_t k_stream[32],
                      uint8_t k_mac[32]) {
    uint8_t ikm[32];
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, secret32, 32);
    if (salt32) blake3_hasher_update(&h, salt32, 32);
    blake3_hasher_finalize(&h, ikm, 32);

    blake3_hasher_init_derive_key(&h, "MCES k_stream v1");
    blake3_hasher_update(&h, ikm, 32);
    blake3_hasher_finalize(&h, k_stream, 32);

    blake3_hasher_init_derive_key(&h, "MCES k_mac v1");
    blake3_hasher_update(&h, ikm, 32);
    blake3_hasher_finalize(&h, k_mac, 32);

    secure_zero(ikm, 32);
}

/* BLAKE3 keyed tag */
void mces_tag_blake3(const uint8_t k_mac[32],
                     const uint8_t *msg, size_t msg_len,
                     uint8_t out_tag32[32]) {
    blake3_hasher h;
    blake3_hasher_init_keyed(&h, k_mac);
    if (msg && msg_len) blake3_hasher_update(&h, msg, msg_len);
    blake3_hasher_finalize(&h, out_tag32, 32);
}

/* Legacy helpers */
void sha256(const uint8_t *data, size_t len, uint8_t out[32]) { SHA256(data, len, out); }

void hmac_sha256(const uint8_t *key, size_t keylen,
                 const uint8_t *data, size_t datalen,
                 uint8_t out[32]) {
    unsigned int outlen = 32;
    HMAC(EVP_sha256(), key, keylen, data, datalen, out, &outlen);
}

void hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                 const uint8_t *salt, size_t salt_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *okm, size_t okm_len) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return;
    if (EVP_PKEY_derive_init(pctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) goto done;
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)salt_len) <= 0) goto done;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, (int)ikm_len) <= 0) goto done;
    if (info && info_len > 0) {
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)info_len) <= 0) goto done;
    }
    { size_t outlen = okm_len; (void)EVP_PKEY_derive(pctx, okm, &outlen); }
done:
    EVP_PKEY_CTX_free(pctx);
}

#ifdef USE_ARGON2
static int pw_to_secret_argon2id(const uint8_t *pw, size_t pw_len,
                                 const uint8_t salt32[32],
                                 uint8_t out_secret32[32]) {
    uint32_t t_cost = 3;
    uint32_t m_cost = 1u << 17; /* 128 MiB */
    uint32_t lanes  = 1;
    return argon2id_hash_raw(t_cost, m_cost, lanes, pw, pw_len, salt32, 32, out_secret32, 32);
}
#endif

/* =====================
   Core config & walker
   ===================== */

static size_t utf8_codepoints(const char *s, uint32_t *indices) {
    size_t count = 0;
    for (size_t i = 0; s[i]; ++i) if ((s[i] & 0xC0) != 0x80) indices[count++] = (uint32_t)i;
    return count;
}

/* === portable big-endian serializer (visible to this TU) === */
static inline void mces_be64(uint64_t x, uint8_t out[8]) {
    for (int i = 0; i < 8; ++i) out[i] = (uint8_t)((x >> (56 - 8*i)) & 0xFF);
}

int generate_config_with_timestamp(const char *password,
                                   const uint8_t *plaintext, size_t plen,
                                   uint64_t timestamp_ns,
                                   MCES_Config *config) {
    (void)plaintext; (void)plen; (void)timestamp_ns;
    const size_t buflen = strlen(password);

    uint32_t *cp_indices = (uint32_t*)malloc((buflen + 1) * sizeof(uint32_t));
    if (!cp_indices) return -1;
    memset(cp_indices, 0, (buflen + 1) * sizeof(uint32_t));

    const size_t codepoints = utf8_codepoints(password, cp_indices);
    if (codepoints < 30 || codepoints > 512) { free(cp_indices); return -1; }
    cp_indices[codepoints] = (uint32_t)buflen;

    size_t count = 0;
    for (size_t i = 0; i < codepoints; ++i)
        for (size_t j = i; j < codepoints; ++j) ++count;

    config->count  = count;
    config->hashes = (uint8_t*)malloc(count * 32);
    if (!config->hashes) { free(cp_indices); return -1; }
    memset(config->hashes, 0, count * 32);

    /* base_key32 = BLAKE3(password || ts_be)  */
    uint8_t ts_be[8];
    mces_be64(timestamp_ns, ts_be);

    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, (const uint8_t*)password, buflen);
    blake3_hasher_update(&h, ts_be, sizeof(ts_be));
    blake3_hasher_finalize(&h, config->base_key32, 32);

    size_t idx = 0;
    for (size_t i = 0; i < codepoints; ++i) {
        for (size_t j = i; j < codepoints; ++j) {
            const uint32_t start  = cp_indices[i];
            const uint32_t end    = cp_indices[j+1];
            const uint32_t length = end - start;
            uint8_t digest[32];
            blake3_hash32((const uint8_t*)(password + start), length, digest);
            memcpy(config->hashes + idx*32, digest, 32);
            ++idx;
        }
    }

    secure_zero(cp_indices, (buflen + 1) * sizeof(uint32_t));
    free(cp_indices);
    return 0;
}

int generate_config(const char *password, const uint8_t *plaintext, size_t plen, MCES_Config *config) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    const uint64_t timestamp_ns = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
    return generate_config_with_timestamp(password, plaintext, plen, timestamp_ns, config);
}

void free_config(MCES_Config *config) {
    if (!config) return;
    if (config->hashes) {
        secure_zero(config->hashes, config->count * 32);
        free(config->hashes);
        config->hashes = NULL;
        config->count = 0;
    }
    secure_zero(config->base_key32, 32);
}

static inline void mces_epoch_seed(const MCES_Config *config,
                                   uint64_t epoch,
                                   size_t *current_index,
                                   uint8_t drift_digest[32]);

/* Walker-only keystream with safe tail */
int _generate_keystream(const MCES_Config *config, size_t length, uint8_t *keystream) {
    if (!config || !config->hashes || config->count == 0 || !keystream) return -1;
    if (length == 0) return 0;

    const size_t hash_len   = 32;
    const size_t total_rows = config->count;
    const size_t last_index = total_rows - 1;

    /* --- short-term side-channel hardening: warm the table once --- */
    {
        volatile uint8_t sink = 0;
        const uint8_t *h = config->hashes;
        for (size_t i = 0; i < total_rows; ++i) sink ^= h[i * 32];
        (void)sink;
    }

    /* --- epoch parity with stream path: start at epoch 0 --- */
    uint64_t epoch = 0;
    size_t   current_index = 0;
    uint8_t  drift_digest[32];
    mces_epoch_seed(config, epoch, &current_index, drift_digest);

    size_t written = 0;

    while (written < length) {
        /* write up to 32 bytes from current node */
        size_t to_write = hash_len;
        if (written + to_write > length) to_write = length - written;
        memcpy(keystream + written, config->hashes + current_index * hash_len, to_write);
        written += to_write;

        if (written >= length) break;

        /* choose next index (same logic as before), but when at tail → reseed epoch n+1 */
        if (current_index == last_index) {
            /* tail parity: do NOT repeat last node; reseed next epoch like stream mode */
            epoch += 1;
            mces_epoch_seed(config, epoch, &current_index, drift_digest);
            continue;
        }

        /* jump/dir logic derived from first 8 bytes of this node + drift */
        const uint8_t *h = config->hashes + current_index * hash_len;
        uint64_t h_int = 0;
        for (int i = 0; i < 8; ++i) h_int = (h_int << 8) | h[i];

        const int      jump_flag      = (int)(h_int & 1);
        const int      direction_flag = (int)((h_int >> 1) & 1);
        const uint8_t  drift          = drift_digest[current_index % 32];
        const uint64_t offset_val     = (h_int >> 2) ^ drift;

        size_t next_index;
        if (jump_flag) {
            if (direction_flag == 0 && current_index < last_index) {
                const size_t span = last_index - current_index;
                const size_t off  = span ? (size_t)(offset_val % span) : 0;
                next_index = current_index + (off ? off : 1);
            } else if (current_index > 0) {
                const size_t span = current_index;
                const size_t off  = span ? (size_t)(offset_val % span) : 0;
                next_index = current_index - (off ? off : 1);
            } else {
                next_index = current_index + 1;
            }
        } else {
            next_index = (current_index < last_index) ? (current_index + 1) : last_index;
        }

        current_index = next_index;
    }

    secure_zero(drift_digest, 32);
    return 0;
}

/* Portable in-place XOR helper */
static inline void xor_neon_inplace(uint8_t *dst, const uint8_t *src, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        dst[i] ^= src[i];
    }
}

/* One-time final mask (postmix): BLAKE3 XOF(postmix) XOR onto keystream. */
int mces_apply_final_mask(uint8_t *keystream, size_t length,
                          const uint8_t *postmix, size_t postmix_len) {
    if (!keystream) return -1;
    if (!length) return 0;

    blake3_hasher h; blake3_hasher_init(&h);
    if (postmix && postmix_len) blake3_hasher_update(&h, postmix, postmix_len);

    const size_t CHUNK = MCES_CHUNK;
    uint8_t *buf = (uint8_t*)malloc(CHUNK);
    if (!buf) return -1;

    for (size_t off = 0; off < length; ) {
        size_t n = (length - off < CHUNK) ? (length - off) : CHUNK;
        blake3_hasher_finalize_seek(&h, off, buf, n);
        xor_neon_inplace(keystream + off, buf, n);
        off += n;
    }
    secure_zero(buf, CHUNK); free(buf);
    return 0;
}

/* =======================
   Encrypt / Decrypt / MAC
   ======================= */

int encrypt_mces(const uint8_t *plaintext, size_t plen, const MCES_Config *config,
                 const uint8_t *postmix, size_t postmix_len,
                 uint8_t *ciphertext) {
    if (plen == 0) return 0;
    if (!plaintext || !ciphertext) return -1;

    uint8_t *keystream = (uint8_t*)malloc(plen ? plen : 1);
    if (!keystream) return -1;
    memset(keystream, 0, plen);

    int rc = _generate_keystream(config, plen, keystream);
    if (rc == 0) rc = mces_apply_final_mask(keystream, plen, postmix, postmix_len);
    if (rc != 0) { secure_zero(keystream, plen); free(keystream); return -1; }

    for (size_t i = 0; i < plen; ++i) ciphertext[i] = plaintext[i] ^ keystream[i];

    secure_zero(keystream, plen);
    free(keystream);
    return 0;
}

int decrypt_mces(const uint8_t *ciphertext, size_t clen, const MCES_Config *config,
                 const uint8_t *postmix, size_t postmix_len,
                 uint8_t *plaintext) {
    return encrypt_mces(ciphertext, clen, config, postmix, postmix_len, plaintext);
}

int encrypt_mces_and_hash(const uint8_t *plaintext, size_t plen,
                          const MCES_Config *config,
                          const uint8_t *postmix, size_t postmix_len,
                          uint8_t *ciphertext,
                          uint8_t out_keystream_hash[32]) {
    if (!out_keystream_hash) return -1;
    if (plen == 0) { blake3_hash32(NULL, 0, out_keystream_hash); return 0; }

    uint8_t *keystream = (uint8_t*)malloc(plen ? plen : 1);
    if (!keystream) return -1;
    memset(keystream, 0, plen);

    int rc = _generate_keystream(config, plen, keystream);
    if (rc == 0) rc = mces_apply_final_mask(keystream, plen, postmix, postmix_len);
    if (rc != 0) { secure_zero(keystream, plen); free(keystream); return -1; }

    blake3_hash32(keystream, plen, out_keystream_hash);
    for (size_t i = 0; i < plen; ++i) ciphertext[i] = plaintext[i] ^ keystream[i];

    secure_zero(keystream, plen); free(keystream);
    return 0;
}

/* ==================================
   STREAMING KEYSTREAM (CTR-like PRF)
   ================================== */
/* Stream mode that *walks* and, upon reaching the last node, restarts
   from a *new epoch* (n+1) with a new start derived from base_key32||epoch. */

static inline void mces_epoch_seed(const MCES_Config *config,
                                   uint64_t epoch,
                                   size_t *current_index,
                                   uint8_t drift_digest[32])
{
    blake3_hasher hh;

    uint8_t epoch_be[8];
    mces_be64(epoch, epoch_be);

    /* seed = BLAKE3(base_key32 || epoch_be) → start_index */
    uint8_t seed_digest[32];
    blake3_hasher_init(&hh);
    blake3_hasher_update(&hh, config->base_key32, 32);
    blake3_hasher_update(&hh, epoch_be, 8);
    blake3_hasher_finalize(&hh, seed_digest, 32);

    uint64_t start_seed = 0;
    for (int i = 0; i < 8; ++i) start_seed = (start_seed << 8) | seed_digest[i];
    *current_index = (size_t)(start_seed % config->count);

    /* drift = BLAKE3("MCES-drift-v2" || base_key32 || epoch_be) */
    blake3_hasher_init(&hh);
    blake3_hasher_update(&hh, "MCES-drift-v2", 13);
    blake3_hasher_update(&hh, config->base_key32, 32);
    blake3_hasher_update(&hh, epoch_be, 8);
    blake3_hasher_finalize(&hh, drift_digest, 32);

    secure_zero(seed_digest, 32);
}

static inline size_t mces_advance_next_index(const MCES_Config *config,
                                             size_t current_index,
                                             const uint8_t drift_digest[32])
{
    const size_t last_index = config->count - 1;
    const uint8_t *h = config->hashes + current_index * 32;

    uint64_t h_int = 0;
    for (int i = 0; i < 8; ++i) h_int = (h_int << 8) | h[i];

    const int jump_flag       = (int)(h_int & 1);
    const int direction_flag  = (int)((h_int >> 1) & 1);
    const uint8_t drift       = drift_digest[current_index % 32];
    const uint64_t offset_val = (h_int >> 2) ^ drift;

    size_t next_index;
    if (jump_flag) {
        if (direction_flag == 0 && current_index < last_index) {
            const size_t span = last_index - current_index;
            const size_t off  = span ? (size_t)(offset_val % span) : 0;
            next_index = current_index + (off ? off : 1);
        } else if (current_index > 0) {
            const size_t span = current_index;
            const size_t off  = span ? (size_t)(offset_val % span) : 0;
            next_index = current_index - (off ? off : 1);
        } else {
            next_index = current_index + 1;
        }
    } else {
        next_index = (current_index < last_index) ? (current_index + 1) : last_index;
    }
    return next_index;
}

int mces_generate_stream(const MCES_Config *config,
                         const uint8_t *postmix, size_t postmix_len,
                         uint64_t offset, size_t length,
                         uint8_t *keystream)
{
    if (!config || !config->hashes || config->count == 0 || !keystream) return -1;
    if (length == 0) return 0;

    const size_t hash_len   = 32;
    const size_t last_index = config->count - 1;

    /* -------- Thread-local stream cache (no external API change) -------- */
#if defined(__STDC_NO_THREADS__)
    static __thread int      tl_inited = 0;
    static __thread uint64_t tl_epoch;
    static __thread size_t   tl_index;
    static __thread size_t   tl_intra;
    static __thread uint8_t  tl_drift[32];
    static __thread uint64_t tl_abs_pos;
    static __thread uint8_t  tl_base_key32[32];
    static __thread size_t   tl_count;
    static __thread const uint8_t *tl_postmix_ptr;
    static __thread size_t   tl_postmix_len;
#else
    static _Thread_local int      tl_inited = 0;
    static _Thread_local uint64_t tl_epoch;
    static _Thread_local size_t   tl_index;
    static _Thread_local size_t   tl_intra;
    static _Thread_local uint8_t  tl_drift[32];
    static _Thread_local uint64_t tl_abs_pos;
    static _Thread_local uint8_t  tl_base_key32[32];
    static _Thread_local size_t   tl_count;
    static _Thread_local const uint8_t *tl_postmix_ptr;
    static _Thread_local size_t   tl_postmix_len;
#endif

    /* Detect config/postmix changes or rewinds → reset to epoch 0 */
    int need_reset = 0;
    if (!tl_inited) {
        need_reset = 1;
    } else {
        if (tl_count != config->count) need_reset = 1;
        else if (memcmp(tl_base_key32, config->base_key32, 32) != 0) need_reset = 1;
        else if ((tl_postmix_ptr != postmix) || (tl_postmix_len != postmix_len)) need_reset = 1;
        else if (offset < tl_abs_pos) need_reset = 1; /* rewind */
    }

    if (need_reset) {
        /* Seed epoch 0 to mirror non-stream behavior */
        mces_epoch_seed(config, 0, &tl_index, tl_drift);
        tl_epoch      = 0;
        tl_intra      = 0;
        tl_abs_pos    = 0;
        memcpy(tl_base_key32, config->base_key32, 32);
        tl_count      = config->count;
        tl_postmix_ptr = postmix;
        tl_postmix_len = postmix_len;
        tl_inited     = 1;
    }

    /* Fast-forward from current cached position to requested 'offset' in O(delta) */
    if (offset > tl_abs_pos) {
        uint64_t to_skip = offset - tl_abs_pos;
        while (to_skip) {
            size_t avail = hash_len - tl_intra;
            if (to_skip < avail) {
                tl_intra   += (size_t)to_skip;
                tl_abs_pos += to_skip;
                to_skip     = 0;
                break;
            }
            /* consume remainder of this node */
            to_skip   -= avail;
            tl_abs_pos += avail;
            tl_intra   = 0;

            if (tl_index == last_index) {
                tl_epoch += 1;
                mces_epoch_seed(config, tl_epoch, &tl_index, tl_drift);
            } else {
                tl_index = mces_advance_next_index(config, tl_index, tl_drift);
            }
        }
    }
    /* else (offset == tl_abs_pos) aligned; if offset < tl_abs_pos we reset above */

    /* ---- Emit 'length' bytes starting at current cached state ---- */
    size_t out_written = 0;
    while (out_written < length) {
        size_t avail = hash_len - tl_intra;
        size_t need  = length - out_written;
        size_t take  = (avail < need) ? avail : need;

        const uint8_t *src = config->hashes + tl_index * hash_len + tl_intra;
        memcpy(keystream + out_written, src, take);

        out_written += take;
        tl_intra    += take;
        tl_abs_pos  += take;

        if (tl_intra == hash_len) {
            tl_intra = 0;
            if (tl_index == last_index) {
                tl_epoch += 1;
                mces_epoch_seed(config, tl_epoch, &tl_index, tl_drift);
            } else {
                tl_index = mces_advance_next_index(config, tl_index, tl_drift);
            }
        }
    }

    /* ---- Apply postmix mask over [offset, offset+length) using BLAKE3 seek ---- */
    if (postmix && postmix_len) {
        blake3_hasher h; blake3_hasher_init(&h);
        blake3_hasher_update(&h, postmix, postmix_len);
        const size_t CHUNK = MCES_CHUNK;

        uint8_t *mask = (uint8_t*)malloc(CHUNK ? CHUNK : 1);
        if (!mask) return -1;

        size_t done = 0;
        uint64_t seek = offset; /* absolute start for this emission */
        while (done < length) {
            size_t n = (length - done < CHUNK) ? (length - done) : CHUNK;
            blake3_hasher_finalize_seek(&h, seek, mask, n);
            xor_neon_inplace(keystream + done, mask, n);
            seek += n;
            done += n;
        }
        secure_zero(mask, CHUNK);
        free(mask);
    }

    return 0;
}