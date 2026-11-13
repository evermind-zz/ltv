//! Common utilities for the admin tool.
use std::path::PathBuf;
use secrecy::{SecretVec, SecretString};
use rpassword;
use ltv_core::{Vault, model::Profile};
use crate::error::{AdminError, AdminResult, ToAdminResult};

/// Prompt for a non-empty passphrase, returning a zeroizing SecretVec.
pub fn prompt_passphrase(prompt: &str) -> SecretVec<u8> {
    loop {
        let p = rpassword::prompt_password(prompt).unwrap_or_default();
        if !p.is_empty() {
            return SecretVec::new(p.into_bytes());
        }
        eprintln!("Passphrase cannot be empty.");
    }
}

/// Prompt for an optional passphrase (allows empty), returning String.
pub fn prompt_passphrase_optional(prompt: &str) -> String {
    rpassword::prompt_password(prompt).unwrap_or_default()
}

/// Prompt for a yes/no confirmation. Returns true for 'y' or 'Y'.
pub(crate) fn confirm(prompt: &str) -> bool {
    use std::io::{self, Write};
    print!("{prompt} [y/N]: ");
    io::stdout().flush().ok();
    let mut s = String::new();
    io::stdin().read_line(&mut s).ok();
    matches!(s.trim().to_lowercase().as_str(), "y" | "yes")
}

/// Prompt for a string with a default value.
pub(crate) fn prompt_with_default(prompt: &str, default: &str) -> String {
    use std::io::{self, Write};
    print!("{prompt} [{default}]: ");
    io::stdout().flush().ok();
    let mut s = String::new();
    io::stdin().read_line(&mut s).ok();
    let s = s.trim();
    if s.is_empty() { default.into() } else { s.into() }
}

/// Require the user to type an exact confirmation string (e.g., "YES").
pub(crate) fn require_exact(prompt: &str, expected: &str) -> AdminResult<()> {
    use std::io::{self, Write};
    print!("{prompt} ");
    io::stdout().flush().ok();
    let mut s = String::new();
    io::stdin().read_line(&mut s).ok();
    if s.trim() == expected {
        Ok(())
    } else {
        Err(AdminError::Aborted)
    }
}

/// Open a vault file from disk with the given passphrase.
pub(crate) fn open_vault_file(path: &PathBuf, pass: &SecretVec<u8>) -> AdminResult<Vault> {
    let bytes = std::fs::read(path).admin_ctx("read vault file")?;
    Vault::open(&bytes, pass).map_err(|_| AdminError::IncorrectPassphrase)
}

/// Verify the current vault's master passphrase by re-reading the file.
pub(crate) fn verify_vault_passphrase(_vault: &Vault, path: &PathBuf) -> AdminResult<()> {
    let pass = prompt_passphrase("Confirm vault passphrase: ");
    open_vault_file(path, &pass)?;
    println!("✓ Passphrase verified.");
    Ok(())
}

/// Get the vault path from State, or return error.
pub fn require_vault_path(state: &crate::State) -> AdminResult<&PathBuf> {
    state.path.as_ref().ok_or(AdminError::NoVaultPath)
}

/// Get a mutable reference to the vault, or return error.
pub fn require_vault_mut(state: &mut crate::State) -> AdminResult<&mut Vault> {
    state.vault.as_mut().ok_or(AdminError::NoVaultOpen)
}

/// Get an immutable reference to the vault, or return error.
pub fn require_vault_ref(state: &crate::State) -> AdminResult<&Vault> {
    state.vault.as_ref().ok_or(AdminError::NoVaultOpen)
}

/// Find a profile by name in the vault, or return error.
pub fn find_profile<'a>(vault: &'a Vault, name: &str) -> AdminResult<&'a Profile> {
    vault.find_by_name(name).ok_or_else(|| AdminError::ProfileNotFound(name.into()))
}

/// Find a profile by name in a mutable vault, or return error.
pub(crate) fn find_profile_mut<'a>(vault: &'a mut Vault, name: &str) -> AdminResult<&'a mut Profile> {
    vault.inventory.profiles.iter_mut()
        .find(|p| p.name == name)
        .ok_or_else(|| AdminError::ProfileNotFound(name.into()))
}

/// Parse a target selection string (indices, "all", "none").
pub fn parse_selection(input: &str, max: usize) -> AdminResult<Vec<usize>> {
    let s = input.trim().to_lowercase();
    match s.as_str() {
        "" | "n" | "no" | "none" => Ok(vec![]),
        "y" | "yes" | "all" => Ok((0..max).collect()),
        _ => {
            let mut idx = Vec::new();
            for tok in s.split(|c: char| c == ',' || c.is_whitespace()) {
                if tok.is_empty() { continue; }
                let i: usize = tok.parse()
                    .map_err(|_| AdminError::InvalidSelection(format!("invalid selection '{tok}' (expected numbers, 'all', or 'none')")))?;
                if i >= max { return Err(AdminError::InvalidSelection(format!("selection {i} out of range (valid: 0-{})", max - 1))); }
                if !idx.contains(&i) { idx.push(i); }
            }
            idx.sort_unstable();
            Ok(idx)
        }
    }
}

/// Sanitize a filename component to be safe.
pub fn safe_filename(name: &str) -> String {
    let s: String = name.chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '_' })
        .collect();
    if s.is_empty() || s == "." || s == ".." { "target".into() } else { s }
}

/// Create a directory with restricted permissions (0o700 on Unix).
#[cfg(unix)]
pub fn secure_dir(path: &PathBuf) -> AdminResult<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| AdminError::Io(e))
}

/// Create a directory with restricted permissions (no-op on non-Unix).
#[cfg(not(unix))]
pub fn secure_dir(_path: &PathBuf) -> AdminResult<()> {
    Ok(())
}

/// Write a secret file with mode 0o600 from creation (no world-readable window).
#[cfg(unix)]
pub fn write_secret_file(path: &PathBuf, bytes: &[u8]) -> AdminResult<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = std::fs::OpenOptions::new()
        .write(true).create(true).truncate(true).mode(0o600).open(path)
        .map_err(AdminError::Io)?;
    f.write_all(bytes).map_err(AdminError::Io)?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600)).map_err(AdminError::Io)?;
    Ok(())
}

/// Write a secret file (non-Unix fallback).
#[cfg(not(unix))]
pub fn write_secret_file(path: &PathBuf, bytes: &[u8]) -> AdminResult<()> {
    std::fs::write(path, bytes).map_err(AdminError::Io)
}

/// Effective OS SSH endpoint (falls back to unlock host/port).
pub fn os_ssh_addr(profile: &Profile) -> (String, u16) {
    (
        profile.os_host.clone().unwrap_or_else(|| profile.unlock_host.clone()),
        profile.os_port.unwrap_or(profile.unlock_port),
    )
}

/// Get the user's home directory, with fallback.
pub fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

/// Format a profile for the `ls` command output.
pub fn format_profile_for_list(p: &Profile) -> String {
    let unlock_ssh = format!("{}:{}", p.unlock_host, p.unlock_port);
    let (os_h, os_p) = os_ssh_addr(p);
    let os_ssh = format!("{}:{}", os_h, os_p);
    let hostkey = if p.unlock_host_key.is_some() { "pinned" } else { "MISSING" };
    format!("{:<16} {:<21} {:<21} {:>7}  {}", p.name, unlock_ssh, os_ssh, p.targets_meta.len(), hostkey)
}

/// Prompt for a string input (no default).
pub fn ask(prompt: &str) -> String {
    use std::io::{self, Write};
    print!("{prompt}"); io::stdout().flush().ok();
    let mut s = String::new(); io::stdin().read_line(&mut s).ok(); s.trim().to_string()
}

/// Prompt for a string with a default value.
pub fn ask_or(prompt: &str, default: &str) -> String {
    let v = ask(&format!("{prompt} [{default}]: ")); if v.is_empty() { default.into() } else { v }
}