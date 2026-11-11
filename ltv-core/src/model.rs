use base64::Engine;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
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
    /// Unlock SSH (initramfs Dropbear) address for LUKS unlock
    pub unlock_host: String,
    pub unlock_port: u16,
    /// OS SSH address (falls back to `unlock_host`/`unlock_port` if None)
    pub os_host: Option<String>,
    pub os_port: Option<u16>,
    pub username: String,
    pub unlock_host_key: Option<HostKey>,
    pub os_host_key: Option<HostKey>,
    pub host_key_pinned_at: u64,
    pub client_public_key: Vec<u8>,          // ssh wire blob
    pub targets_meta: Vec<TargetMeta>,
    pub connect_timeout_s: u16,
    pub exec_timeout_s: u16,
    pub envelope_nonce: [u8; 24],
    pub envelope_ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HostKey { pub key_type: String, pub key_bytes: Vec<u8> }

impl PartialEq for HostKey {
    fn eq(&self, other: &Self) -> bool {
        self.key_type == other.key_type && self.key_bytes.ct_eq(&other.key_bytes).into()
    }
}
impl Eq for HostKey {}

#[derive(Serialize, Deserialize, Clone)]
pub struct TargetMeta {
    pub luks_uuid: String,
    pub fallback_path: Option<String>,
    pub mapped_name: String,
    pub order: u8,
    pub keyslot: Option<u8>,
    pub token_id: Option<u32>,
}

/// Execution mode for multi-target operations (unlock, enroll, rotate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionMode {
    /// Process targets sequentially (one at a time)
    Sequential,
    /// Process targets in parallel (concurrent SSH channels)
    Parallel,
}

impl Default for ExecutionMode {
    fn default() -> Self { ExecutionMode::Parallel }
}

// ---------- JIT-decrypted, zeroized ----------
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretPayload {
    pub client_private_seed: [u8; 32],      // Ed25519 seed
    pub keyfiles: Vec<TargetKey>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
pub struct TargetKey { pub luks_uuid: String, pub keyfile: Vec<u8> }

pub fn fingerprint_sha256(blob: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    
    let d = Sha256::digest(blob);
    // base64 without padding, like OpenSSH
    format!("SHA256:{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(d))
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