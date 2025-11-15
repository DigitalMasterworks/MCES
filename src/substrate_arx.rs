// src/substrate_arx.rs
//
// Substrate ARX-256 keystream core (stateless CTR mode).
// - 256-bit key: (k0,k1,k2,k3)
// - 64-bit counter per block
// - Block size: 32 bytes (4×u64)
// - We map (postmix, offset) → (k0..k3, ctr0) via BLAKE3 in sarx.rs.

#![allow(dead_code)]

const ROUNDS: usize = 8; // same as substrate_stream prototype

#[inline]
fn arx_rounds(mut x0: u64, mut x1: u64, mut x2: u64, mut x3: u64) -> (u64, u64, u64, u64) {
    for _ in 0..ROUNDS {
        // "column" step
        x0 = x0.wrapping_add(x1);
        x3 ^= x0;
        x3 = x3.rotate_left(27);

        x2 = x2.wrapping_add(x3);
        x1 ^= x2;
        x1 = x1.rotate_left(31);

        // "diagonal-ish" cross step
        x0 = x0.wrapping_add(x2);
        x3 ^= x0;
        x3 = x3.rotate_left(17);

        x1 = x1.wrapping_add(x3);
        x2 ^= x1;
        x2 = x2.rotate_left(23);
    }
    (x0, x1, x2, x3)
}

/// One 256-bit block: keyed by (k0..k3), indexed by counter `ctr`.
#[inline]
fn arx_block(state: (u64, u64, u64, u64), ctr: u64) -> (u64, u64, u64, u64) {
    let (k0, k1, k2, k3) = state;

    // simple ctr injection (same structure as your substrate_stream)
    let mut x0 = k0 ^ ctr.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let mut x1 = k1;
    let mut x2 = k2;
    let mut x3 = k3 ^ ctr;

    let o0 = x0;
    let o1 = x1;
    let o2 = x2;
    let o3 = x3;

    let (y0, y1, y2, y3) = arx_rounds(x0, x1, x2, x3);

    x0 = y0.wrapping_add(o0);
    x1 = y1.wrapping_add(o1);
    x2 = y2.wrapping_add(o2);
    x3 = y3.wrapping_add(o3);

    (x0, x1, x2, x3)
}

/// Fill `out` with keystream bytes produced from:
///   - 256-bit key/state `state`
///   - base counter `ctr0`
///   - *byte* offset `offset` within the infinite stream.
///
/// We treat the stream as 32-byte blocks:
///   block i = ARX(state, ctr0 + i)
/// and slice appropriately using offset and out.len().
pub fn arx256_fill(state: (u64, u64, u64, u64), ctr0: u64, offset: u64, out: &mut [u8]) {
    let n = out.len();
    if n == 0 {
        return;
    }

    const BLOCK_BYTES: usize = 32;

    // which block to start from, and where inside that block
    let start_block = (offset / BLOCK_BYTES as u64) as u64;
    let mut skip = (offset % BLOCK_BYTES as u64) as usize;

    let mut produced = 0usize;
    let mut ctr = ctr0 + start_block;
    let mut block_buf = [0u8; BLOCK_BYTES];

    while produced < n {
        let (x0, x1, x2, x3) = arx_block(state, ctr);
        ctr = ctr.wrapping_add(1);

        block_buf[0..8].copy_from_slice(&x0.to_le_bytes());
        block_buf[8..16].copy_from_slice(&x1.to_le_bytes());
        block_buf[16..24].copy_from_slice(&x2.to_le_bytes());
        block_buf[24..32].copy_from_slice(&x3.to_le_bytes());

        let available = BLOCK_BYTES - skip;
        let needed = n - produced;
        let take = if available < needed { available } else { needed };

        out[produced..produced + take].copy_from_slice(&block_buf[skip..skip + take]);
        produced += take;
        skip = 0;
    }
}