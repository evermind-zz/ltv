//! Central constants. No magic numbers in code.

// ---------- network / timing ----------
pub const DEFAULT_SSH_PORT: u16 = 22;
pub const DEFAULT_CONNECT_TIMEOUT: u16 = 10;
pub const DEFAULT_EXEC_TIMEOUT: u16 = 30;
pub const HOOK_TIMEOUT_SECS: u32 = 300;

/// Maximum number of targets processed concurrently in parallel mode.
/// Kept low so we don't overwhelm the initramfs SSH daemon.
pub const MAX_CONCURRENT_TARGETS: usize = 4;

// ---------- tmpfs staging (initramfs side) ----------
pub const TMPFS_BASE: &str = "/run/ltv";
pub const TMPFS_KEYFILE: &str = "/run/ltv/key";
pub const TMPFS_PASSFILE: &str = "/run/ltv/pass";
pub const TMPFS_NEWKEYFILE: &str = "/run/ltv/newkey";

/// Returns a per-target staging directory (e.g., /run/ltv/0, /run/ltv/1, etc.)
/// Index ensures unique paths for parallel execution.
pub fn target_tmpfs_dir(index: usize) -> String {
    format!("{}/{}", TMPFS_BASE, index)
}

/// Returns the keyfile path within a target's staging directory.
pub fn target_keyfile(index: usize) -> String {
    format!("{}/key", target_tmpfs_dir(index))
}

// ---------- shell ----------
pub const SSH_KEY_TYPE: &str = "ssh-ed25519";
pub const ENV_PREFIX: &[u8] = b"ltv-envelope:v1:";

// ---------- crypto lengths ----------
pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const WRAPPED_LEN: usize = 48;

// ---------- Argon2 defaults ----------
pub const DEFAULT_ARGON2_MEM_MIB: u32 = 64;
pub const DEFAULT_ARGON2_TIME: u32 = 3;
pub const DEFAULT_ARGON2_PAR: u8 = 1;

// ---------- mapper / target defaults ----------
pub const UMASK_TMPFS: &str = "077";
pub const TMPFS_DIR_MODE: &str = "0755";

// ---------- cleanup on unlock ----------
pub const KILL_CMD: &str =
    "pkill -9 nlplug-findfs 2>/dev/null; pkill dropbear 2>/dev/null; pkill cryptsetup 2>/dev/null; true";

// ---------- script builder fragments ----------
pub const TMPFS_CREATE: &str = "sh -c 'mkdir -p /run/ltv && umask 077 && cat >";
