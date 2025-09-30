//! §1.1.0 Overview — MCES core library (Rust mirror of your C)
//! - Config generation (UTF-8 substring table + base_key32)
//! - Walker keystream + epoch reseed at tail
//! - Postmix (BLAKE3 XOF seek)
//! - Encrypt/Decrypt wrappers
//! - Streaming keystream with thread-local cache (parity with __thread)

/* =============================================================================
 * MCES — mces.rs — Program v1.0.0
 * Numbering: Program=1.0.0, Sections=§1.X.0, Subsections=§1.X.Y
 * Cross-reference these tags later when building the ToC.
 * =============================================================================
 */

// ============================================================================
// §1.2.0 Imports & Crate Uses
// ============================================================================
use anyhow::{bail, Result};
use blake3::Hasher as Blake3;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;
use std::cell::RefCell;

use crate::headers::MCES_CHUNK;

// ============================================================================
// §1.3.0 Primitives & Helpers
// Purpose: zeroization, tiny helpers, legacy parity functions.
// ============================================================================

/* §1.3.1 secure_zero */
#[inline]
fn secure_zero(buf: &mut [u8]) { buf.zeroize(); }

/* §1.3.2 Small Helpers (group marker) */

/* §1.3.21 be64: big-endian u64 */
#[inline]
fn be64(x: u64) -> [u8; 8] { x.to_be_bytes() }

/* §1.3.22 blake3_hash32: 32-byte XOF read */
#[inline]
fn blake3_hash32(data: &[u8]) -> [u8; 32] {
    let mut h = Blake3::new();
    if !data.is_empty() { h.update(data); }
    let mut out = [0u8; 32];
    h.finalize_xof().fill(&mut out);
    out
}

/* §1.3.23 sha256 (legacy parity) */
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut a = [0u8; 32]; a.copy_from_slice(&out); a
}

/* §1.3.24 hmac_sha256 (legacy parity) */
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut a = [0u8; 32]; a.copy_from_slice(&out); a
}

/* §1.3.25 hkdf_sha256 (legacy parity) */
pub fn hkdf_sha256(ikm: &[u8], salt: Option<&[u8]>, info: Option<&[u8]>, okm_len: usize) -> Vec<u8> {
    let hk = match salt {
        Some(s) => Hkdf::<Sha256>::new(Some(s), ikm),
        None    => Hkdf::<Sha256>::new(None, ikm),
    };
    let mut out = vec![0u8; okm_len.max(1)];
    hk.expand(info.unwrap_or(&[]), &mut out).expect("HKDF expand");
    out
}

// ============================================================================
// §1.4.0 BLAKE3 KDF & MAC
// ============================================================================
/* §1.4.1 kdf_blake3_split: derive (k_stream, k_mac) */
pub fn kdf_blake3_split(secret32: &[u8; 32], salt32: Option<&[u8; 32]>) -> ([u8; 32], [u8; 32]) {
    // ikm = blake3(secret || salt?)
    let mut hh = Blake3::new();
    hh.update(secret32);
    if let Some(s) = salt32 { hh.update(s); }
    let mut ikm = [0u8; 32]; hh.finalize_xof().fill(&mut ikm);

    // derive k_stream
    let mut h1 = blake3::Hasher::new_derive_key("MCES k_stream v1");
    h1.update(&ikm);
    let mut k_stream = [0u8; 32]; h1.finalize_xof().fill(&mut k_stream);

    // derive k_mac
    let mut h2 = blake3::Hasher::new_derive_key("MCES k_mac v1");
    h2.update(&ikm);
    let mut k_mac = [0u8; 32]; h2.finalize_xof().fill(&mut k_mac);

    ikm.zeroize();
    (k_stream, k_mac)
}

/* §1.4.2 mces_mac_blake3: keyed XOF tag */
pub fn mces_mac_blake3(k_mac32: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(k_mac32);
    if !msg.is_empty() { h.update(msg); }
    let mut out = [0u8; 32];
    h.finalize_xof().fill(&mut out);
    out
}

// ============================================================================
// §1.5.0 Configuration Objects
// ============================================================================
/* §1.5.1 MCESConfig struct + Drop */
#[derive(Clone)]
pub struct MCESConfig {
    pub count: usize,       // number of 32-byte hashes
    pub hashes: Vec<u8>,    // count * 32
    pub base_key32: [u8; 32],
}
impl Drop for MCESConfig {
    fn drop(&mut self) {
        secure_zero(&mut self.hashes);
        self.base_key32.zeroize();
    }
}

/* §1.5.2 utf8_codepoints_indices: byte-start indices (sentinel at end) */
fn utf8_codepoints_indices(s: &str) -> Vec<u32> {
    // return byte indices where a new codepoint begins + a sentinel end
    let b = s.as_bytes();
    let mut idxs = Vec::with_capacity(b.len() + 1);
    for (i, &ch) in b.iter().enumerate() {
        if (ch & 0b1100_0000) != 0b1000_0000 { idxs.push(i as u32); }
    }
    idxs.push(s.len() as u32);
    idxs
}

// ============================================================================
// §1.6.0 Config Generation
// ============================================================================
/* §1.6.1 generate_config_with_timestamp */
pub fn generate_config_with_timestamp(password: &str, _plaintext: Option<&[u8]>, _plen: usize, ts_ns: u64) -> Result<MCESConfig> {
    let indices = utf8_codepoints_indices(password);
    let cps = indices.len().saturating_sub(1);
    if cps < 30 || cps > 512 { bail!("password codepoints out of range"); }

    // base_key32 = BLAKE3(password || ts_be)
    let mut h = Blake3::new();
    h.update(password.as_bytes());
    h.update(&be64(ts_ns));
    let mut base_key32 = [0u8; 32]; h.finalize_xof().fill(&mut base_key32);

    // count = triangular number
    let mut count: usize = 0;
    for i in 0..cps { for _j in i..cps { count += 1; } }
    let mut hashes = vec![0u8; count * 32];

    let mut idx = 0usize;
    for i in 0..cps {
        for j in i..cps {
            let start = indices[i] as usize;
            let end   = indices[j + 1] as usize;
            let digest = blake3_hash32(&password.as_bytes()[start..end]);
            hashes[idx*32 .. (idx+1)*32].copy_from_slice(&digest);
            idx += 1;
        }
    }
    Ok(MCESConfig { count, hashes, base_key32 })
}

/* §1.6.2 generate_config (now) */
pub fn generate_config(password: &str, plaintext: Option<&[u8]>, plen: usize) -> Result<MCESConfig> {
    let ts_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap()
        .as_nanos() as u64;
    generate_config_with_timestamp(password, plaintext, plen, ts_ns)
}

// ============================================================================
// §1.7.0 Epoch Seed & Walker Advance
// ============================================================================
/* §1.7.1 mces_epoch_seed: initialize start index + drift digest */
fn mces_epoch_seed(cfg: &MCESConfig, epoch: u64, current_index: &mut usize, drift_digest: &mut [u8; 32]) {
    // seed = BLAKE3(base_key32 || epoch_be) -> start index
    let mut hh = Blake3::new();
    hh.update(&cfg.base_key32);
    hh.update(&be64(epoch));
    let mut seed = [0u8; 32]; hh.finalize_xof().fill(&mut seed);
    let mut start_seed: u64 = 0;
    for i in 0..8 { start_seed = (start_seed << 8) | seed[i] as u64; }
    *current_index = (start_seed % (cfg.count as u64)) as usize;

    // drift = BLAKE3("MCES-drift-v2" || base_key32 || epoch_be)
    let mut h2 = Blake3::new();
    h2.update(b"MCES-drift-v2");
    h2.update(&cfg.base_key32);
    h2.update(&be64(epoch));
    h2.finalize_xof().fill(drift_digest);
    seed.zeroize();
}

/* §1.7.2 mces_advance_next_index: walker step with drift */
fn mces_advance_next_index(cfg: &MCESConfig, current_index: usize, drift_digest: &[u8; 32]) -> usize {
    let last = cfg.count - 1;
    let h = &cfg.hashes[current_index*32..current_index*32+32];

    let mut h_int: u64 = 0;
    for i in 0..8 { h_int = (h_int << 8) | h[i] as u64; }

    let jump_flag      = (h_int & 1) as u8;
    let direction_flag = ((h_int >> 1) & 1) as u8;
    let drift          = drift_digest[current_index % 32] as u64;
    let offset_val     = (h_int >> 2) ^ drift;

    if jump_flag == 1 {
        if direction_flag == 0 && current_index < last {
            let span = last - current_index;
            let off  = if span > 0 { (offset_val as usize) % span } else { 0 };
            current_index + if off == 0 { 1 } else { off }
        } else if current_index > 0 {
            let span = current_index;
            let off  = if span > 0 { (offset_val as usize) % span } else { 0 };
            current_index - if off == 0 { 1 } else { off }
        } else {
            current_index + 1
        }
    } else {
        if current_index < last { current_index + 1 } else { last }
    }
}

// ============================================================================
// §1.8.0 Core Keystream (tail-safe)
// ============================================================================
/* §1.8.1 generate_keystream */
pub fn generate_keystream(cfg: &MCESConfig, length: usize, out: &mut [u8]) -> Result<()> {
    if length == 0 { return Ok(()); }
    if cfg.count == 0 || out.len() < length { bail!("bad args"); }

    // warm table (tiny side-channel hardening)
    let mut sink: u8 = 0;
    for i in 0..cfg.count { sink ^= cfg.hashes[i*32]; }
    let _ = sink;

    let mut epoch: u64 = 0;
    let mut idx: usize = 0;
    let mut drift = [0u8; 32];
    mces_epoch_seed(cfg, epoch, &mut idx, &mut drift);

    let last = cfg.count - 1;
    let mut written = 0usize;

    while written < length {
        let take = (32).min(length - written);
        out[written..written+take].copy_from_slice(&cfg.hashes[idx*32 .. idx*32 + take]);
        written += take;

        if written >= length { break; }

        if idx == last {
            // epoch rollover to keep parity with stream behavior
            epoch += 1;
            mces_epoch_seed(cfg, epoch, &mut idx, &mut drift);
            continue;
        }
        idx = mces_advance_next_index(cfg, idx, &drift);
    }
    Ok(())
}

// ============================================================================
// §1.9.0 Postmix Mask (BLAKE3 XOF seek)
// ============================================================================
/* §1.9.1 apply_final_mask */
pub fn apply_final_mask(keystream: &mut [u8], postmix: Option<&[u8]>) -> Result<()> {
    if keystream.is_empty() { return Ok(()); }
    if let Some(pm) = postmix {
        let mut h = Blake3::new(); h.update(pm);
        let mut rdr = h.finalize_xof();

        let mut off = 0usize;
        let mut tmp: Vec<u8> = Vec::with_capacity(MCES_CHUNK);
        while off < keystream.len() {
            let n = (keystream.len() - off).min(MCES_CHUNK);
            if tmp.len() < n { tmp.resize(n, 0); }
            rdr.set_position(off as u64);
            rdr.fill(&mut tmp[..n]);
            for i in 0..n { keystream[off + i] ^= tmp[i]; }
            off += n;
        }
        secure_zero(&mut tmp);
    }
    Ok(())
}

// ============================================================================
// §1.10.0 Encrypt / Decrypt Wrappers
// ============================================================================
/* §1.10.1 encrypt_mces */
pub fn encrypt_mces(pt: &[u8], cfg: &MCESConfig, postmix: Option<&[u8]>, ct: &mut [u8]) -> Result<()> {
    if pt.len() != ct.len() { bail!("len mismatch"); }
    let mut ks = vec![0u8; pt.len().max(1)];
    generate_keystream(cfg, pt.len(), &mut ks)?;
    apply_final_mask(&mut ks, postmix)?;
    for i in 0..pt.len() { ct[i] = pt[i] ^ ks[i]; }
    secure_zero(&mut ks);
    Ok(())
}

/* §1.10.2 decrypt_mces (xor-symmetric) */
pub fn decrypt_mces(ct: &[u8], cfg: &MCESConfig, postmix: Option<&[u8]>, pt: &mut [u8]) -> Result<()> {
    encrypt_mces(ct, cfg, postmix, pt)
}

// ============================================================================
// §1.11.0 Streaming Keystream (THREAD-LOCAL parity with C)
// ============================================================================
/* §1.11.1 StreamTLS state */
struct StreamTLS {
    inited: bool,
    epoch: u64,
    index: usize,
    intra: usize,
    drift: [u8; 32],
    abs_pos: u64,
    base_key32: [u8; 32],
    count: usize,
    postmix_ptr: usize,
    postmix_len: usize,
}

/* §1.11.2 STREAM_TLS thread-local cache */
thread_local! {
    static STREAM_TLS: RefCell<StreamTLS> = RefCell::new(StreamTLS{
        inited:false, epoch:0, index:0, intra:0, drift:[0u8;32], abs_pos:0,
        base_key32:[0u8;32], count:0, postmix_ptr:0, postmix_len:0
    });
}

/* §1.11.3 generate_stream: offset/length window with postmix seek */
pub fn generate_stream(cfg: &MCESConfig,
                       postmix: Option<&[u8]>,
                       offset: u64,
                       length: usize,
                       out: &mut [u8]) -> Result<()> {
    if cfg.count == 0 || out.len() < length { bail!("bad args"); }
    if length == 0 { return Ok(()); }

    const HASH_LEN: usize = 32;
    let hash_len = HASH_LEN;
    let last_index = cfg.count - 1;
    let pm_ptr = postmix.map(|s| s.as_ptr() as usize).unwrap_or(0);
    let pm_len = postmix.map(|s| s.len()).unwrap_or(0);

    STREAM_TLS.with(|cell| {
        let mut st = cell.borrow_mut();

        // reset on any change, or rewind, exactly as C version
        let need_reset =
            !st.inited ||
            st.count != cfg.count ||
            st.base_key32.ct_eq(&cfg.base_key32).unwrap_u8() == 0 ||
            st.postmix_ptr != pm_ptr ||
            st.postmix_len != pm_len ||
            offset < st.abs_pos;

        if need_reset {
            // use locals to avoid multiple mutable borrows
            let mut new_index: usize = 0;
            let mut new_drift: [u8; 32] = [0u8; 32];
            mces_epoch_seed(cfg, 0, &mut new_index, &mut new_drift);

            st.epoch = 0;
            st.index = new_index;
            st.intra = 0;
            st.abs_pos = 0;
            st.drift = new_drift;
            st.base_key32 = cfg.base_key32;
            st.count = cfg.count;
            st.postmix_ptr = pm_ptr;
            st.postmix_len = pm_len;
            st.inited = true;
        }

        // fast-forward from cached abs_pos to requested offset
        if offset > st.abs_pos {
            let mut to_skip = offset - st.abs_pos;
            while to_skip > 0 {
                let avail = (hash_len - st.intra) as u64;
                if to_skip < avail {
                    st.intra   += to_skip as usize;
                    st.abs_pos += to_skip;
                    break;
                }
                to_skip   -= avail;
                st.abs_pos += avail;
                st.intra   = 0;

                if st.index == last_index {
                    st.epoch += 1;
                    let mut idx = st.index;
                    let mut drift = st.drift;
                    mces_epoch_seed(cfg, st.epoch, &mut idx, &mut drift);
                    st.index = idx;
                    st.drift = drift;
                } else {
                    st.index = mces_advance_next_index(cfg, st.index, &st.drift);
                }
            }
        }

        // emit bytes
        let mut written = 0usize;
        while written < length {
            let avail = hash_len - st.intra;
            let need  = length - written;
            let take  = avail.min(need);

            let src = &cfg.hashes[st.index*32 + st.intra .. st.index*32 + st.intra + take];
            out[written..written+take].copy_from_slice(src);

            written += take;
            st.intra += take;
            st.abs_pos += take as u64;

            if st.intra == hash_len {
                st.intra = 0;
                if st.index == last_index {
                    st.epoch += 1;
                    let mut idx = st.index;
                    let mut drift = st.drift;
                    mces_epoch_seed(cfg, st.epoch, &mut idx, &mut drift);
                    st.index = idx;
                    st.drift = drift;
                } else {
                    st.index = mces_advance_next_index(cfg, st.index, &st.drift);
                }
            }
        }

        // postmix over [offset, offset+length)
        if let Some(pm) = postmix {
            let mut h = Blake3::new();
            h.update(pm);
            let mut rdr = h.finalize_xof();

            let mut done = 0usize;
            let mut tmp: Vec<u8> = Vec::with_capacity(MCES_CHUNK);
            let mut seek = offset;
            while done < length {
                let n = (length - done).min(MCES_CHUNK);
                if tmp.len() < n { tmp.resize(n, 0); }
                rdr.set_position(seek);
                rdr.fill(&mut tmp[..n]);
                for i in 0..n { out[done + i] ^= tmp[i]; }
                seek += n as u64;
                done += n;
            }
            secure_zero(&mut tmp);
        }

        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}