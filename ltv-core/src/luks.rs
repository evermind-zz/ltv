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

//! Shared LUKS utilities for enroll, rotate, and unlock operations.

use crate::constants::*;
use crate::error::UnlockError;
use crate::model::TargetMeta;
use crate::net::exec;
use russh::client::Handle;
use secrecy::SecretString;
use std::collections::HashMap;
use std::time::Duration;

/// Parse enabled keyslots from `cryptsetup luksDump` output.
/// Handles both LUKS1 ("Key Slot N: ENABLED") and LUKS2 ("Keyslots: ... N: luks2") formats.
pub fn parse_used_slots(dump: &str) -> Vec<u8> {
    let mut v = Vec::new();
    let mut in_keyslots = false;
    for line in dump.lines() {
        let l = line.trim();
        if l.starts_with(LUKS2_KEYSLOTS_HEADER) {
            in_keyslots = true;
            continue;
        }
        if in_keyslots {
            if l.ends_with(':') && !l.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                in_keyslots = false;
                continue;
            }
            if let Some((n, rest)) = l.split_once(':') {
                if rest.trim().starts_with(LUKS2_KEYSLOT_TYPE) {
                    if let Ok(x) = n.trim().parse() {
                        v.push(x);
                    }
                }
            }
        }
        if let Some(rest) = l.strip_prefix(LUKS1_KEY_SLOT_PREFIX) {
            if let Some((n, st)) = rest.split_once(':') {
                if st.trim() == SLOT_ENABLED {
                    if let Ok(x) = n.trim().parse() {
                        v.push(x);
                    }
                }
            }
        }
    }
    v
}

/// Find the first free keyslot (0-31) not in `used`.
pub fn first_free(used: &[u8]) -> Option<u8> {
    (0u8..MAX_KEYSLOTS).find(|s| !used.contains(s))
}

/// Resolve a LUKS device, trying UUID first then falling back to fallback_path.
/// Returns the device path (e.g., "UUID=..." or "/dev/sda2").
pub async fn resolve_device<Hk: russh::client::Handler>(
    session: &Handle<Hk>,
    tm: &TargetMeta,
    sudo: &str,
    timeout: Duration,
    log: &mut dyn FnMut(&str),
) -> Result<String, UnlockError> {
    let mut dev = format!("UUID={}", tm.luks_uuid);

    // 0. sanity: device exists & is LUKS
    let cmd = format!("{sudo}{CRYPTSETUP} {CMD_IS_LUKS} {dev}");
    log(&cmd);
    let mut r = exec(session, &cmd, None, timeout).await?;

    if r.code != 0 && r.stderr.to_lowercase().contains("not exist") {
        if let Some(fp) = &tm.fallback_path {
            dev = fp.clone();
            let cmd = format!("{sudo}{CRYPTSETUP} {CMD_IS_LUKS} {dev}");
            log(&cmd);
            r = exec(session, &cmd, None, timeout).await?;
        }
    }
    if r.code != 0 {
        return Err(UnlockError::CryptsetupFailed {
            target: tm.mapped_name.clone(),
            code: r.code,
            stderr: format!("not a LUKS device: {}", r.stderr.trim()),
        });
    }

    Ok(dev)
}

/// Find the slot containing our keyfile by testing each enabled slot.
pub async fn find_existing_slot<Hk: russh::client::Handler>(
    session: &Handle<Hk>,
    dev: &str,
    keyfile: &[u8],
    sudo: &str,
    timeout: Duration,
    log: &mut dyn FnMut(&str),
) -> Result<Option<u8>, UnlockError> {
    let cmd = format!("{sudo}{CRYPTSETUP} {CMD_LUKS_DUMP} {dev}");
    log(&cmd);
    let dump = exec(session, &cmd, None, timeout).await?;
    if dump.code != 0 {
        return Ok(None);
    }
    let used = parse_used_slots(&dump.stdout);

    for slot in used {
        let cmd = format!("{sudo}{CRYPTSETUP} {CMD_LUKS_OPEN} {ARG_TEST_PASSPHRASE} {ARG_KEY_FILE}=- {ARG_KEY_SLOT} {slot} {dev}");
        log(&cmd);
        let r = exec(session, &cmd, Some(keyfile), timeout).await?;
        if r.code == 0 {
            return Ok(Some(slot));
        }
    }
    Ok(None)
}

/// Per-target passphrase file path in tmpfs.
pub fn target_passfile(index: usize) -> String {
    format!("{}/{}/pass", TMPFS_BASE, index)
}

/// Per-target new keyfile path in tmpfs (for rotate).
pub fn target_newkeyfile(index: usize) -> String {
    format!("{}/{}/newkey", TMPFS_BASE, index)
}

/// Stage passphrases for sequential execution with caching.
pub fn make_sequential_passphrase_provider<F>(
    mut provider: F,
) -> impl FnMut(&str) -> Result<SecretString, String>
where
    F: FnMut(&str) -> Result<SecretString, String>,
{
    let mut cache: HashMap<String, SecretString> = HashMap::new();
    move |uuid: &str| -> Result<SecretString, String> {
        if let Some(c) = cache.get(uuid) {
            return Ok(c.clone());
        }
        let p = provider(uuid)?;
        cache.insert(uuid.to_string(), p.clone());
        Ok(p)
    }
}

/// Pre-fetch all passphrases for parallel execution.
pub fn make_parallel_passphrase_map<F>(
    targets: &[(usize, TargetMeta)],
    mut provider: F,
) -> Result<HashMap<String, SecretString>, UnlockError>
where
    F: FnMut(&str) -> Result<SecretString, String>,
{
    let mut pass_map: HashMap<String, SecretString> = HashMap::new();
    for (_, tm) in targets {
        if !pass_map.contains_key(&tm.luks_uuid) {
            let pass = provider(&tm.luks_uuid).map_err(|e| UnlockError::CryptsetupFailed {
                target: tm.mapped_name.clone(),
                code: 0,
                stderr: e,
            })?;
            pass_map.insert(tm.luks_uuid.clone(), pass);
        }
    }
    Ok(pass_map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_used_slots_luks1() {
        let dump = r#"Key Slot 0: ENABLED
Key Slot 1: ENABLED
Key Slot 2: DISABLED"#;
        assert_eq!(parse_used_slots(dump), vec![0, 1]);
    }

    #[test]
    fn test_parse_used_slots_luks2() {
        let dump = r#"Keyslots:
  0: luks2
  3: luks2
  5: luks2"#;
        assert_eq!(parse_used_slots(dump), vec![0, 3, 5]);
    }

    #[test]
    fn test_first_free() {
        assert_eq!(first_free(&[0, 1, 2]), Some(3));
        assert_eq!(first_free(&[0, 2]), Some(1));
        assert_eq!(
            first_free(&[
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31
            ]),
            None
        );
    }
}
