//! On-disk header, slot table, AAD construction.
use crate::error::VaultError;

pub const MAGIC: &[u8; 4] = b"LTCV";
pub const VERSION: u8 = 1;
pub const SUITE: u8 = 1;
pub const FIXED_LEN: usize = 32;
pub const SLOT_LEN: usize = 97;
pub const MAX_SLOTS: usize = 8;
pub const MIN_MEM_KIB: u32 = 16 * 1024;
pub const MIN_TIME: u32 = 2;

#[derive(Clone, Copy, Debug)]
pub struct Argon2Params { pub mem_kib: u32, pub time: u32, pub par: u8 }
impl Default for Argon2Params {
    fn default() -> Self { Self { mem_kib: 65536, time: 3, par: 1 } }
}

#[derive(Clone)]
pub struct Slot {
    pub params: Argon2Params,
    pub salt: [u8; 16],
    pub wrap_nonce: [u8; 24],
    pub wrapped: [u8; 48],
}

pub struct Header {
    pub flags: u8,
    pub payload_nonce: [u8; 24],
    pub slots: Vec<Slot>,
}

impl Header {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(FIXED_LEN + SLOT_LEN * self.slots.len());
        b.extend_from_slice(MAGIC);
        b.push(VERSION);
        b.push(SUITE);
        b.push(self.slots.len() as u8);
        b.push(self.flags);
        b.extend_from_slice(&self.payload_nonce);
        for s in &self.slots {
            b.extend_from_slice(&s.params.mem_kib.to_le_bytes());
            b.extend_from_slice(&s.params.time.to_le_bytes());
            b.push(s.params.par);
            b.extend_from_slice(&s.salt);
            b.extend_from_slice(&s.wrap_nonce);
            b.extend_from_slice(&s.wrapped);
        }
        b
    }

    /// Returns (header, header_len)
    pub fn decode(buf: &[u8]) -> Result<(Header, usize), VaultError> {
        if buf.len() < FIXED_LEN { return Err(VaultError::Truncated); }
        if &buf[0..4] != MAGIC { return Err(VaultError::BadMagic); }
        if buf[4] != VERSION { return Err(VaultError::Version(buf[4])); }
        if buf[5] != SUITE { return Err(VaultError::Suite(buf[5])); }
        let n = buf[6] as usize;
        if n == 0 || n > MAX_SLOTS { return Err(VaultError::Truncated); }
        let total = FIXED_LEN + SLOT_LEN * n;
        if buf.len() < total + 16 { return Err(VaultError::Truncated); }
        let mut payload_nonce = [0u8; 24];
        payload_nonce.copy_from_slice(&buf[8..32]);
        let mut slots = Vec::with_capacity(n);
        for i in 0..n {
            let o = FIXED_LEN + i * SLOT_LEN;
            let s = &buf[o..o + SLOT_LEN];
            let params = Argon2Params {
                mem_kib: u32::from_le_bytes(s[0..4].try_into().unwrap()),
                time: u32::from_le_bytes(s[4..8].try_into().unwrap()),
                par: s[8],
            };
            if params.mem_kib < MIN_MEM_KIB || params.time < MIN_TIME || params.par == 0 {
                return Err(VaultError::WeakParams);
            }
            let mut salt = [0u8; 16]; salt.copy_from_slice(&s[9..25]);
            let mut wrap_nonce = [0u8; 24]; wrap_nonce.copy_from_slice(&s[25..49]);
            let mut wrapped = [0u8; 48]; wrapped.copy_from_slice(&s[49..97]);
            slots.push(Slot { params, salt, wrap_nonce, wrapped });
        }
        Ok((Header { flags: buf[7], payload_nonce, slots }, total))
    }

    /// AAD for slot i = fixed header bytes || i
    pub fn slot_aad(&self, i: usize) -> Vec<u8> {
        let enc = self.encode();
        let mut a = enc[..FIXED_LEN].to_vec();
        a.push(i as u8);
        a
    }
}