// src/headers.rs
use anyhow::{bail, Result};

pub const VAULT_VERSION: u8 = 0x03;
pub const MCES_CHUNK: usize = 4 << 20;      // 4 MiB
pub const MCES_HEADER_BYTES: usize = 61;    // fixed header size
pub const MCES_TAG_BYTES: usize = 32;       // BLAKE3 keyed tag size

#[derive(Clone, Debug)]
pub struct VaultHeader {
    pub salt32: [u8; 32],
    pub timestamp_ns: u64,
    pub nonce12: [u8; 12],
    pub t_cost: u8,
    pub m_cost: u8,
    pub lanes: u8,
    pub kdf_id: u8, // 2 = Argon2id v1.3
}

impl VaultHeader {
    pub fn encode(&self) -> [u8; MCES_HEADER_BYTES] {
        let mut out = [0u8; MCES_HEADER_BYTES];
        out[0..4].copy_from_slice(b"MCES");
        out[4] = VAULT_VERSION;
        out[5..37].copy_from_slice(&self.salt32);
        out[37..45].copy_from_slice(&self.timestamp_ns.to_be_bytes());
        out[45..57].copy_from_slice(&self.nonce12);
        out[57] = self.t_cost;
        out[58] = self.m_cost;
        out[59] = self.lanes;
        out[60] = self.kdf_id;
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < MCES_HEADER_BYTES { bail!("short header"); }
        if &buf[0..4] != b"MCES" { bail!("bad magic"); }
        if buf[4] != VAULT_VERSION { bail!("bad version"); }

        let mut salt32 = [0u8; 32];
        salt32.copy_from_slice(&buf[5..37]);

        let mut ts_be = [0u8; 8];
        ts_be.copy_from_slice(&buf[37..45]);
        let timestamp_ns = u64::from_be_bytes(ts_be);

        let mut nonce12 = [0u8; 12];
        nonce12.copy_from_slice(&buf[45..57]);

        let t_cost = buf[57];
        let m_cost = buf[58];
        let lanes  = buf[59];
        let kdf_id = buf[60];

        Ok(Self { salt32, timestamp_ns, nonce12, t_cost, m_cost, lanes, kdf_id })
    }

    /// Decode a header but also return the exact raw 61 bytes as read.
    pub fn decode_with_raw(buf: &[u8]) -> Result<(Self, [u8; MCES_HEADER_BYTES])> {
        if buf.len() < MCES_HEADER_BYTES { bail!("short header"); }
        let mut raw = [0u8; MCES_HEADER_BYTES];
        raw.copy_from_slice(&buf[0..MCES_HEADER_BYTES]);
        let header = Self::decode(&raw)?;
        Ok((header, raw))
    }
}