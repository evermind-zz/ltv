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

//! Shared LUKS operations for enroll and rotate.
//! Both operations: dump header -> find/pick slot -> stage passphrase/key -> add key -> verify.

use crate::constants::*;
use crate::error::UnlockError;
use crate::luks::{first_free, parse_used_slots};
use crate::net::tmpfs_stage;
use russh::client::Handle;
use secrecy::{ExposeSecret, SecretString};
use std::time::Duration;

/// Result of finding or picking a slot.
#[derive(Debug, Clone)]
pub struct SlotInfo {
    pub slot: u8,
    pub is_existing: bool, // true if key was already in this slot (enroll update)
}

/// Find an existing slot containing the given keyfile, or pick a free slot.
/// If `current_keyfile` is Some, searches for that key (for rotation).
/// If `current_keyfile` is None, picks a free slot (for enrollment).
pub async fn find_or_pick_slot<Hk: russh::client::Handler>(
    session: &Handle<Hk>,
    dev: &str,
    current_keyfile: Option<&[u8]>,
    sudo: &str,
    timeout: Duration,
    log: &mut dyn FnMut(&str),
) -> Result<SlotInfo, UnlockError> {
    // If we have a current keyfile, check if it's already enrolled
    if let Some(keyfile) = current_keyfile {
        if let Some(existing_slot) =
            crate::luks::find_existing_slot(session, dev, keyfile, sudo, timeout, log).await?
        {
            return Ok(SlotInfo {
                slot: existing_slot,
                is_existing: true,
            });
        }
    }

    // Dump LUKS header to find free slots
    let cmd = format!("{sudo}{CRYPTSETUP} {CMD_LUKS_DUMP} {dev}");
    log(&cmd);
    let dump = crate::net::exec(session, &cmd, None, timeout).await?;
    if dump.code != 0 {
        log(&format!(
            "! cmd={} exit={} stderr: {}",
            cmd,
            dump.code,
            dump.stderr.trim()
        ));
        return Err(UnlockError::CryptsetupFailed {
            target: dev.into(),
            code: dump.code,
            stderr: format!("luksDump failed: {}", dump.stderr.trim()),
        });
    }
    let used = parse_used_slots(&dump.stdout);
    let slot = first_free(&used).ok_or_else(|| UnlockError::CryptsetupFailed {
        target: dev.into(),
        code: 0,
        stderr: "no free keyslot".into(),
    })?;

    Ok(SlotInfo {
        slot,
        is_existing: false,
    })
}

/// Stage passphrase and new keyfile to tmpfs, returning the paths.
pub async fn stage_passphrase_and_key<Hk: russh::client::Handler>(
    session: &Handle<Hk>,
    idx: usize,
    passphrase: &SecretString,
    new_keyfile: &[u8],
    sudo: &str,
    timeout: Duration,
) -> Result<(String, String), UnlockError> {
    let passfile = crate::luks::target_passfile(idx);
    let newkeyfile = crate::luks::target_newkeyfile(idx);

    tmpfs_stage(
        session,
        &passfile,
        passphrase.expose_secret().as_bytes(),
        sudo,
        timeout,
    )
    .await
    .map_err(|e| UnlockError::CryptsetupFailed {
        target: crate::constants::target_error_fmt(idx),
        code: 0,
        stderr: format!("stage passphrase: {e}"),
    })?;

    tmpfs_stage(session, &newkeyfile, new_keyfile, sudo, timeout)
        .await
        .map_err(|e| UnlockError::CryptsetupFailed {
            target: crate::constants::target_error_fmt(idx),
            code: 0,
            stderr: format!("stage keyfile: {e}"),
        })?;

    Ok((passfile, newkeyfile))
}

/// Add a new key to the specified slot using staged tmpfs files.
#[allow(clippy::too_many_arguments)]
pub async fn add_key_to_slot<Hk: russh::client::Handler>(
    session: &Handle<Hk>,
    dev: &str,
    passfile: &str,
    newkeyfile: &str,
    slot: u8,
    sudo: &str,
    timeout: Duration,
    log: &mut dyn FnMut(&str),
) -> Result<(), UnlockError> {
    let cmd = format!(
        "{sudo}{CRYPTSETUP} {CMD_LUKS_ADD_KEY} {ARG_KEY_FILE}={passfile} {ARG_NEW_KEY_FILE}={newkeyfile} {ARG_KEY_SLOT} {slot} {dev}"
    );
    log(&cmd);
    let add = crate::net::exec(session, &cmd, None, timeout).await?;

    // Always clean up tmpfs
    let _ = crate::net::tmpfs_cleanup(session, &[passfile, newkeyfile], sudo, timeout).await;

    if add.code != 0 {
        log(&format!(
            "! cmd={} exit={} stderr: {}",
            cmd,
            add.code,
            add.stderr.trim()
        ));
        match add.code {
            2 => Err(UnlockError::KeyRejected(format!(
                "{}: existing passphrase wrong",
                dev
            ))),
            c => Err(UnlockError::CryptsetupFailed {
                target: dev.into(),
                code: c,
                stderr: add.stderr,
            }),
        }
    } else {
        Ok(())
    }
}

/// Verify a keyfile works for the given slot (using --test-passphrase).
pub async fn verify_key<Hk: russh::client::Handler>(
    session: &Handle<Hk>,
    dev: &str,
    keyfile: &[u8],
    slot: u8,
    sudo: &str,
    timeout: Duration,
    log: &mut dyn FnMut(&str),
) -> Result<(), UnlockError> {
    let cmd = format!(
        "{sudo}{CRYPTSETUP} {CMD_LUKS_OPEN} {ARG_TEST_PASSPHRASE} {ARG_KEY_FILE}=- {ARG_KEY_SLOT} {slot} {dev}"
    );
    log(&cmd);
    let verify = crate::net::exec(session, &cmd, Some(keyfile), timeout).await?;
    if verify.code != 0 {
        log(&format!(
            "! cmd={} exit={} stderr: {}",
            cmd,
            verify.code,
            verify.stderr.trim()
        ));
        return Err(UnlockError::CryptsetupFailed {
            target: dev.into(),
            code: verify.code,
            stderr: format!("verification failed: {}", verify.stderr),
        });
    }
    Ok(())
}

/// Kill (remove) a keyslot.
pub async fn kill_slot<Hk: russh::client::Handler>(
    session: &Handle<Hk>,
    dev: &str,
    slot: u8,
    sudo: &str,
    timeout: Duration,
    log: &mut dyn FnMut(&str),
) -> Result<(), UnlockError> {
    let cmd = format!("{sudo}{CRYPTSETUP} {CMD_LUKS_KILL_SLOT} {dev} {slot}");
    log(&cmd);
    let kill = crate::net::exec(session, &cmd, None, timeout).await?;
    if kill.code != 0 {
        log(&format!(
            "! {} failed: exit {}: {}",
            CMD_LUKS_KILL_SLOT,
            kill.code,
            kill.stderr.trim()
        ));
        Err(UnlockError::CryptsetupFailed {
            target: dev.into(),
            code: kill.code,
            stderr: kill.stderr,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_slot_info() {
        let info = SlotInfo {
            slot: 3,
            is_existing: true,
        };
        assert_eq!(info.slot, 3);
        assert!(info.is_existing);
    }
}
