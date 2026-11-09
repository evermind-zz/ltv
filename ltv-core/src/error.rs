use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("bad magic")] BadMagic,
    #[error("unsupported format version {0}")] Version(u8),
    #[error("unsupported cipher suite {0}")] Suite(u8),
    #[error("file truncated")] Truncated,
    #[error("argon2 parameters below minimum")] WeakParams,
    #[error("wrong passphrase or corrupted file")] AuthFailed,
    #[error("serialization: {0}")] Serde(String),
    #[error("profile not found")] NoProfile,
    #[error("target not found")] NoTarget,
    #[error("invariant violated: {0}")] Invariant(&'static str),
    #[error("slot table full")] SlotsFull,
    #[error("crypto failure")] Crypto,
}

#[derive(Debug, Error)]
pub enum NetError {
    #[error("connect: {0}")] Connect(String),
    #[error("ssh: {0}")] Ssh(String),
    #[error("timeout")] Timeout,
}

#[derive(Debug, Clone)]
pub struct HostKeyMismatchError {
    pub expected: crate::model::HostKey,
    pub actual: crate::model::HostKey,
}

impl std::fmt::Display for HostKeyMismatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "host key mismatch\n  expected: {} {}\n  actual:   {} {}",
            self.expected.key_type,
            crate::model::fingerprint_sha256(&self.expected.key_bytes),
            self.actual.key_type,
            crate::model::fingerprint_sha256(&self.actual.key_bytes))
    }
}

impl std::error::Error for HostKeyMismatchError {}

#[derive(Debug, Error)]
pub enum UnlockError {
    #[error(transparent)] Vault(#[from] VaultError),
    #[error(transparent)] Net(#[from] NetError),
    #[error(transparent)] HostKeyMismatch(#[from] HostKeyMismatchError),
    #[error("host key not pinned")] HostKeyNotPinned,
    #[error("server already booted into OS")] StateBootedOs,
    #[error("authentication rejected")] AuthRejected,
    #[error("key rejected for target {0}")] KeyRejected(String),
    #[error("cryptsetup failed on {target}: exit {code}: {stderr}")]
    CryptsetupFailed { target: String, code: u32, stderr: String },
    #[error("resume command failed: {0}")] ResumeFailed(String),
}