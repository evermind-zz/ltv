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

use crate::{
    constants::{CMD_LUKS_KILL_SLOT, CRYPTSETUP, KEYFILE_SIZE},
    error::*,
    execution::{run_execution, ExecutionStrategy, TargetInput, VerboseCb},
    luks::{find_existing_slot, resolve_device},
    luks_ops::{add_key_to_slot, find_or_pick_slot, stage_passphrase_and_key, verify_key},
    model::{BootedAccess, ExecutionMode, SecretPayload, TargetMeta},
    net::{connect_and_auth, exec, Hk},
    vault::Vault,
};
use rand::RngCore;
use russh::client;
use secrecy::SecretString;
use std::sync::Arc;
use std::time::Duration;

/// Type alias for the per-target save callback
type PerTargetSaveCb<'a> = Option<&'a mut dyn FnMut(&mut Vault) -> Result<(), UnlockError>>;

#[derive(Debug, Clone)]
pub enum RotateEvent {
    Connected,
    Authenticated,
    TargetStart(String),
    OldSlotFound(String, u8),  // old slot containing our key
    SlotChosen(String, u8),    // new slot chosen for rotation
    SlotAdded(String, u8),     // new key added
    Verified(String),          // new key verified
    OldSlotKilled(String, u8), // old slot removed
    Skipped(String, String),
    Done,
}

impl std::fmt::Display for RotateEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RotateEvent::Connected => write!(f, "connected to OS SSH"),
            RotateEvent::Authenticated => write!(f, "authenticated"),
            RotateEvent::TargetStart(t) => write!(f, "{t}: rotating keyfile"),
            RotateEvent::OldSlotFound(uuid, slot) => write!(f, "{uuid}: found old slot {slot}"),
            RotateEvent::SlotChosen(uuid, slot) => write!(f, "{uuid}: chosen new slot {slot}"),
            RotateEvent::SlotAdded(uuid, slot) => write!(f, "{uuid}: added new key to slot {slot}"),
            RotateEvent::Verified(uuid) => write!(f, "{uuid}: verified new key"),
            RotateEvent::OldSlotKilled(uuid, slot) => {
                write!(f, "{uuid}: removed old key from slot {slot}")
            }
            RotateEvent::Skipped(uuid, why) => write!(f, "{uuid}: skipped ({why})"),
            RotateEvent::Done => write!(f, "rotation complete"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RotateResult {
    pub luks_uuid: String,
    pub old_keyslot: u8,
    pub new_keyslot: u8,
}

/// Result of the SSH-side portion of rotating one target. The vault update and
/// old-slot removal happen after this, so the vault is never mutated from
/// concurrent tasks.
#[derive(Debug, Clone)]
struct RotateSshResult {
    target: TargetMeta,
    dev: String,
    old_slot: u8,
    new_slot: u8,
    new_keyfile: Vec<u8>,
}

/// Rotation execution strategy implementing the shared framework.
struct RotateStrategy {
    secrets: Arc<SecretPayload>,
}

impl RotateStrategy {
    fn new(secrets: SecretPayload) -> Self {
        Self {
            secrets: Arc::new(secrets),
        }
    }
}

impl ExecutionStrategy for RotateStrategy {
    type Event = RotateEvent;
    type Result = RotateSshResult;
    type Error = UnlockError;
    type Session = Arc<client::Handle<Hk>>;

    async fn initialize(
        &self,
        vault: &Vault,
        uuid: &[u8; 16],
        access: &BootedAccess,
    ) -> Result<(Self::Session, Vec<TargetInput>), Self::Error> {
        let p = vault.profile(uuid)?.clone();
        let os_key = p.os_host_key.clone().ok_or(UnlockError::HostKeyNotPinned)?;

        // Resolve OS address (fallback to unlock SSH address if not set)
        let os_host = p.os_host.as_deref().unwrap_or(&p.unlock_host);
        let os_port = p.os_port.unwrap_or(p.unlock_port);

        // Connect and authenticate using the shared helper.
        let (s, _) = connect_and_auth(
            os_host,
            os_port,
            access.connect_timeout_s,
            Some(os_key),
            &access.username,
            &access.auth,
        )
        .await?;

        // Build target inputs
        let targets: Vec<TargetInput> = p
            .targets_meta
            .iter()
            .enumerate()
            .map(|(i, tm)| TargetInput {
                index: i,
                target: tm.clone(),
            })
            .collect();

        Ok((Arc::new(s), targets))
    }

    async fn execute_one(
        &self,
        input: TargetInput,
        session: &Self::Session,
        passphrase: &SecretString,
        sudo: &str,
        timeout: Duration,
        log: &mut dyn FnMut(&str),
        emit: &mut dyn FnMut(Self::Event),
    ) -> Result<Option<Self::Result>, Self::Error> {
        let tm = &input.target;
        let idx = input.index;

        emit(RotateEvent::TargetStart(tm.mapped_name.clone()));

        // 0. Resolve device (try UUID, then fallback)
        let dev = resolve_device(session, tm, sudo, timeout, log).await?;

        // 1. Find current slot (where our key lives)
        let keyfile = self
            .secrets
            .keyfiles
            .iter()
            .find(|k| k.luks_uuid == tm.luks_uuid)
            .ok_or(VaultError::Invariant("missing keyfile"))?;

        let old_slot =
            match find_existing_slot(session, &dev, &keyfile.keyfile, sudo, timeout, log).await? {
                Some(slot) => slot,
                None => {
                    emit(RotateEvent::Skipped(
                        tm.mapped_name.clone(),
                        "current key not found in any slot".into(),
                    ));
                    return Ok(None);
                }
            };
        emit(RotateEvent::OldSlotFound(tm.mapped_name.clone(), old_slot));

        // 2. Generate new keyfile
        let mut new_keyfile = vec![0u8; KEYFILE_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut new_keyfile);

        // 3. Pick free slot for new key
        let slot_info =
            find_or_pick_slot(session, &dev, Some(&keyfile.keyfile), sudo, timeout, log).await?;
        let new_slot = slot_info.slot;
        emit(RotateEvent::SlotChosen(tm.mapped_name.clone(), new_slot));

        // 4. Stage passphrase and keyfile to tmpfs
        let (passfile, newkeyfile) =
            stage_passphrase_and_key(session, idx, passphrase, &new_keyfile, sudo, timeout).await?;

        // 5. Add new key to free slot
        add_key_to_slot(
            session,
            &dev,
            &passfile,
            &newkeyfile,
            new_slot,
            sudo,
            timeout,
            log,
        )
        .await?;

        emit(RotateEvent::SlotAdded(tm.mapped_name.clone(), new_slot));

        // 6. Verify new key
        verify_key(session, &dev, &new_keyfile, new_slot, sudo, timeout, log).await?;

        emit(RotateEvent::Verified(tm.mapped_name.clone()));

        Ok(Some(RotateSshResult {
            target: tm.clone(),
            dev,
            old_slot,
            new_slot,
            new_keyfile,
        }))
    }

    async fn finish_one(
        &self,
        vault: &mut Vault,
        uuid: &[u8; 16],
        r: Self::Result,
        session: &Self::Session,
        sudo: &str,
        timeout: Duration,
        emit: &mut dyn FnMut(Self::Event),
        verbose: &mut VerboseCb,
    ) -> Result<Self::Result, Self::Error> {
        // 10. Update vault with new keyfile and slot, then SAVE atomically
        vault
            .rotate_keyfile(uuid, &r.target.luks_uuid, r.new_keyfile.clone(), r.new_slot)
            .map_err(UnlockError::Vault)?;
        vault.save().map_err(UnlockError::Vault)?;

        // 11. Kill old slot
        let dev = &r.dev;
        let old_slot = r.old_slot;
        let cmd = format!("{sudo}{CRYPTSETUP} {CMD_LUKS_KILL_SLOT} {dev} {old_slot}");
        if let Some(v) = verbose.as_mut() {
            v(&cmd);
        }
        let kill = exec(session, &cmd, None, timeout).await?;
        if kill.code != 0 {
            if let Some(v) = verbose.as_mut() {
                v(&format!(
                    "! {} failed: exit {}: {}",
                    CMD_LUKS_KILL_SLOT,
                    kill.code,
                    kill.stderr.trim()
                ));
            }
        } else {
            emit(RotateEvent::OldSlotKilled(
                r.target.mapped_name.clone(),
                old_slot,
            ));
        }

        Ok(r)
    }

    fn on_target_filtered(&self, filter: &str, emit: &mut dyn FnMut(Self::Event)) {
        emit(RotateEvent::Skipped(
            "--target".into(),
            format!("no target matches filter '{}'", filter),
        ));
    }

    fn on_done(&self, emit: &mut dyn FnMut(Self::Event)) {
        emit(RotateEvent::Done);
    }

    fn force_sequential(&self) -> bool {
        true // Paranoid rotation: force sequential mode for safety
    }
}

/// Rotates the keyfile for each target: adds new key, verifies, kills old slot.
/// Updates vault with new keyfile and slot, saves atomically after each target.
///
/// If `per_target_save` is provided, it is called after each target's vault update
/// (after verification, before killing old slot) to persist the vault to disk.
/// The callback receives the vault so it can serialize and save it.
/// This enables a paranoid rotation procedure where each step is persisted.
#[allow(clippy::too_many_arguments)]
pub async fn rotate_key(
    vault: &mut Vault,
    uuid: &[u8; 16],
    access: &BootedAccess,
    mode: ExecutionMode,
    passphrase_provider: impl FnMut(&str) -> Result<SecretString, String> + Send,
    only_target: Option<&str>,
    mut on: impl FnMut(RotateEvent),
    verbose: VerboseCb,
    mut per_target_save: PerTargetSaveCb<'_>,
) -> Result<Vec<RotateResult>, UnlockError> {
    let p = vault.profile(uuid)?.clone();
    let secrets = vault.open_secrets(&p)?;
    let strategy = RotateStrategy::new(secrets);

    // Convert the results from SSH-side (RotateSshResult) to public API (RotateResult)
    let ssh_results = run_execution(
        vault,
        uuid,
        access,
        mode,
        passphrase_provider,
        only_target,
        &strategy,
        &mut on,
        verbose,
        per_target_save
            .as_mut()
            .map(|f| f as &mut dyn FnMut(&mut Vault) -> Result<(), UnlockError>),
    )
    .await?;

    let results: Vec<RotateResult> = ssh_results
        .into_iter()
        .map(|r| RotateResult {
            luks_uuid: r.target.luks_uuid,
            old_keyslot: r.old_slot,
            new_keyslot: r.new_slot,
        })
        .collect();

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_luks2_slots() {
        let d = "LUKS header information\nVersion: 2\nKeyslots:\n  0: luks2\n\tKey: 512 bits\n  3: luks2\nTokens:\nDigests:\n  0: pbkdf2\n";
        assert_eq!(crate::luks::parse_used_slots(d), vec![0, 3]);
        assert_eq!(crate::luks::first_free(&[0, 3]), Some(1));
    }
    #[test]
    fn parse_luks1_slots() {
        let d = "Key Slot 0: ENABLED\nKey Slot 1: DISABLED\nKey Slot 2: ENABLED\n";
        assert_eq!(crate::luks::parse_used_slots(d), vec![0, 2]);
    }
}
