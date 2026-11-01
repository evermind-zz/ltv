use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Serialize, Deserialize, Default)]
pub struct Inventory {
    pub schema_version: u16,
    pub created_at: u64,
    pub modified_at: u64,
    pub profiles: Vec<Profile>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Profile {
    pub uuid: [u8; 16],
    pub name: String,
    pub notes: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub initramfs_host_key: Option<HostKey>,
    pub os_host_key: Option<HostKey>,
    pub host_key_pinned_at: u64,
    pub client_public_key: Vec<u8>,          // ssh wire blob
    pub targets_meta: Vec<TargetMeta>,
    pub resume: ResumePolicy,
    pub connect_timeout_s: u16,
    pub exec_timeout_s: u16,
    pub envelope_nonce: [u8; 24],
    pub envelope_ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct HostKey { pub key_type: String, pub key_bytes: Vec<u8> }

#[derive(Serialize, Deserialize, Clone)]
pub struct TargetMeta {
    pub luks_uuid: String,
    pub fallback_path: Option<String>,
    pub mapped_name: String,
    pub order: u8,
    pub keyslot: Option<u8>,
    pub token_id: Option<u32>,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum ResumePolicy { DeviceMapperPoll, Command(String) }

impl Default for ResumePolicy {
    fn default() -> Self { ResumePolicy::Command("touch /run/ltv/resume".into()) }
}

// ---------- JIT-decrypted, zeroized ----------
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretPayload {
    pub client_private_seed: [u8; 32],      // Ed25519 seed
    pub keyfiles: Vec<TargetKey>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct TargetKey { pub luks_uuid: String, pub keyfile: Vec<u8> }

pub fn fingerprint_sha256(blob: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;
    let d = Sha256::digest(blob);
    // base64 without padding, like OpenSSH
    let mut s = String::from("SHA256:");
    let _ = write!(s, "{}", base64_nopad(&d));
    s
}

fn base64_nopad(b: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        if c.len() > 1 { out.push(T[(n >> 6) as usize & 63] as char); }
        if c.len() > 2 { out.push(T[n as usize & 63] as char); }
    }
    out
}

/// How to reach the *booted* OS (not the initramfs) for enroll/fetch operations.
#[derive(Debug, Clone)]
pub struct BootedAccess {
    pub username: String,
    pub auth: BootedAuth,
    pub use_sudo: bool,
    pub connect_timeout_s: u16,
}

/// Authentication method for the booted OS.
#[derive(Debug, Clone)]
pub enum BootedAuth {
    Password(secrecy::SecretString),
    /// Ed25519 seed loaded by the frontend (e.g. from ~/.ssh/id_ed25519)
    Ed25519Seed([u8; 32]),
}