// ███╗   ███╗ ██████╗ ███████╗ ███████╗
// ████╗ ████║██╔════╝ ██╔════╝ ██╔════╝
// ██╔████╔██║██║      ███████  ███████╗
// ██║╚██╔╝██║██║      ██═══╝   ╚════██║
// ██║ ╚═╝ ██║╚██████╗ ███████╗ ███████║
// ╚═╝     ╚═╝ ╚═════╝ ╚══════╝ ╚══════╝
// MCES v1 — Cantor-Immune Stream Cipher
#ifndef MCES_H
#define MCES_H

#include <stdint.h>
#include <stddef.h>

#define VAULT_VERSION 0x03
#define MCES_CHUNK (1u << 20) /* 1 MiB */
#define MCES_HEADER_BYTES 61
#define MCES_TAG_BYTES    32
#define MCES_T_COST_MIN 1
#define MCES_T_COST_MAX 10
#define MCES_M_COST_MIN 10
#define MCES_M_COST_MAX 24
#define MCES_LANES_MIN  1
#define MCES_LANES_MAX  4
#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    size_t   count;          /* number of 32-byte hashes in walker table */
    uint8_t *hashes;         /* walker table (count * 32), may be NULL */
    uint8_t  base_key32[32]; /* 32-byte binary base key (NO hex) */
} MCES_Config;

/* --- Config --- */
int generate_config(const char *password, const uint8_t *plaintext, size_t plen, MCES_Config *config);
int generate_config_with_timestamp(const char *password, const uint8_t *plaintext, size_t plen,
                                   uint64_t timestamp_ns, MCES_Config *config);
void free_config(MCES_Config *config);

/* --- Keystream core + postmix --- */
int  _generate_keystream(const MCES_Config *config, size_t length, uint8_t *keystream);
int  mces_apply_final_mask(uint8_t *keystream, size_t length,
                           const uint8_t *postmix, size_t postmix_len);

/* --- Encrypt / Decrypt (walker + one-time postmix) --- */
int encrypt_mces(const uint8_t *plaintext, size_t plen, const MCES_Config *config,
                 const uint8_t *postmix, size_t postmix_len,
                 uint8_t *ciphertext);
int decrypt_mces(const uint8_t *ciphertext, size_t clen, const MCES_Config *config,
                 const uint8_t *postmix, size_t postmix_len,
                 uint8_t *plaintext);

/* Optional helper: generate + hash keystream (with postmix) */
int encrypt_mces_and_hash(const uint8_t *plaintext, size_t plen,
                          const MCES_Config *config,
                          const uint8_t *postmix, size_t postmix_len,
                          uint8_t *ciphertext,
                          uint8_t out_keystream_hash[32]);

/* --- SHA/HKDF (legacy) --- */
void sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void hmac_sha256(const uint8_t *key, size_t keylen,
                 const uint8_t *data, size_t datalen,
                 uint8_t out[32]);
void hkdf_sha256(
    const uint8_t *ikm, size_t ikm_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len);

/* --- BLAKE3-based KDF + keyed MAC --- */
void kdf_blake3_split(const uint8_t secret32[32],
                      const uint8_t salt32[32],
                      uint8_t k_stream[32],
                      uint8_t k_mac[32]);

void mces_tag_blake3(const uint8_t k_mac[32],
                     const uint8_t *msg, size_t msg_len,
                     uint8_t out_tag32[32]);

/* --- Streaming keystream (CTR-like), seekable by byte offset --- */
int mces_generate_stream(const MCES_Config *config,
                         const uint8_t *postmix, size_t postmix_len,
                         uint64_t offset, size_t length,
                         uint8_t *keystream);

#ifdef __cplusplus
}
#endif
#endif /* MCES_H */