// LTV (LUKS Tunnel Vault) - Remote LUKS unlock over SSH
// Copyright (C) 2024 LTV Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Common utilities for the admin tool.
use std::path::{Path, PathBuf};
use secrecy::{SecretString, SecretVec};
use rpassword;
use ltv_core::{Vault, model::{Profile, BootedAccess, BootedAuth, TargetMeta}};
use russh_keys;
use crate::constants::*;
use crate::error::{AdminError, AdminResult, ToAdminResult};

/// Prompt for a non-empty passphrase, returning a zeroizing SecretVec.
pub fn prompt_passphrase(prompt: &str) -> AdminResult<SecretVec<u8>> {
    loop {
        let p = rpassword::prompt_password(prompt)
            .map_err(|e| AdminError::InvalidArgument(format!("prompt failed: {e}")))?;
        if !p.is_empty() {
            return Ok(SecretVec::new(p.into_bytes()));
        }
        eprintln!("{}", ERR_EMPTY_PASSPHRASE);
    }
}

/// Prompt for an optional passphrase (allows empty), returning String.
pub fn prompt_passphrase_optional(prompt: &str) -> AdminResult<String> {
    rpassword::prompt_password(prompt)
        .map_err(|e| AdminError::InvalidArgument(format!("prompt failed: {e}")))
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
    let pass = prompt_passphrase("Confirm vault passphrase: ")?;
    open_vault_file(path, &pass)?;
    println!("{}", MSG_PASSPHRASE_VERIFIED);
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
pub fn secure_dir<P: AsRef<Path>>(path: P) -> AdminResult<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| AdminError::Io(e))
}

/// Create a directory with restricted permissions (no-op on non-Unix).
#[cfg(not(unix))]
pub fn secure_dir<P: AsRef<Path>>(_path: P) -> AdminResult<()> {
    Ok(())
}

/// Write a secret file with mode 0o600 from creation (no world-readable window).
#[cfg(unix)]
pub fn write_secret_file<P: AsRef<Path>>(path: P, bytes: &[u8]) -> AdminResult<()> {
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
pub fn write_secret_file<P: AsRef<Path>>(path: P, bytes: &[u8]) -> AdminResult<()> {
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

/// Setup SSH authentication for booted OS operations (enroll, rotate, fetch).
/// Returns (username, BootedAuth, connect_timeout_s).
pub fn setup_booted_access(profile: &Profile) -> AdminResult<(String, BootedAuth, u16)> {
    let username = ask_or(PROMPT_OS_SSH_USER, DEFAULT_OS_SSH_USER);
    let auth = match ask_or(PROMPT_AUTH_METHOD, DEFAULT_AUTH_METHOD).as_str() {
        "p" => {
            let pass = prompt_passphrase_optional(PROMPT_OS_PASSWORD)?;
            BootedAuth::Password(SecretString::new(pass))
        }
        _ => {
            let home = home_dir();
            let path = ask_or(PROMPT_KEY_FILE, &format!("{}/.ssh/id_ed25519", home.display()));
            let key_passphrase = prompt_passphrase_optional(PROMPT_KEY_PASSPHRASE)?;
            let kp = russh_keys::load_secret_key(&path, None)
                .or_else(|_| russh_keys::load_secret_key(&path, Some(&key_passphrase)))
                .map_err(|e| AdminError::InvalidArgument(format!("load key: {e}")))?;
            match kp {
                russh_keys::key::KeyPair::Ed25519(sk) => BootedAuth::Ed25519Seed(sk.to_bytes()),
                _ => return Err(AdminError::InvalidArgument(ERR_ONLY_ED25519.into())),
            }
        }
    };
    Ok((username, auth, profile.connect_timeout_s))
}

/// Build BootedAccess from username, auth, and timeout.
pub fn make_booted_access(username: String, auth: BootedAuth, timeout: u16) -> BootedAccess {
    BootedAccess { use_sudo: username != "root", username, auth, connect_timeout_s: timeout }
}

/// Collect LUKS passphrases for the given targets.
/// If `same_passphrase` is true, prompts once for all targets.
/// Returns a map of luks_uuid -> SecretString.
pub fn collect_luks_passphrases(
    targets: &[TargetMeta],
    same_passphrase: bool,
) -> AdminResult<std::collections::HashMap<String, SecretString>> {
    let mut passphrases = std::collections::HashMap::new();
    
    if same_passphrase {
        let pass = loop {
            let p = rpassword::prompt_password(PROMPT_LUKS_PASSPHRASE_ALL)
                .map_err(|e| AdminError::InvalidArgument(format!("prompt failed: {e}")))?;
            if !p.is_empty() { break SecretString::new(p); }
            eprintln!("{}", ERR_EMPTY_PASSPHRASE);
        };
        for tm in targets {
            passphrases.insert(tm.luks_uuid.clone(), pass.clone());
        }
    } else {
        for tm in targets {
            let pass = loop {
                let prompt = format!("Existing LUKS passphrase for {} ({}): ", tm.mapped_name, tm.luks_uuid);
                let p = rpassword::prompt_password(&prompt)
                    .map_err(|e| AdminError::InvalidArgument(format!("prompt failed: {e}")))?;
                if !p.is_empty() { break SecretString::new(p); }
                eprintln!("{}", ERR_EMPTY_PASSPHRASE);
            };
            passphrases.insert(tm.luks_uuid.clone(), pass);
        }
    }
    Ok(passphrases)
}

/// Filter targets by the optional --target filter (UUID or mapper name).
pub fn filter_targets(
    profile: &Profile,
    only: Option<&str>,
) -> Vec<TargetMeta> {
    profile.targets_meta.iter()
        .filter(|tm| only.map_or(true, |f| f == &tm.luks_uuid || f == &tm.mapped_name))
        .cloned()
        .collect()
}

/// Check targets for missing keyslots and print warnings.
pub fn check_target_keyslots(targets: &[TargetMeta]) {
    for tm in targets {
        if tm.keyslot.is_none() {
            eprintln!("Warning: target {} ({}) has no keyslot recorded. Run 'enroll' first.", tm.mapped_name, tm.luks_uuid);
        }
    }
}

/// Ask if all targets use the same LUKS passphrase (only if >1 target).
pub fn ask_same_passphrase(targets: &[TargetMeta]) -> bool {
    if targets.len() > 1 {
        ask(PROMPT_SAME_LUKS_PASSPHRASE).to_lowercase() != "n"
    } else {
        true
    }
}