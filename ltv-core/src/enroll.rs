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
    error::*,
    execution::{run_execution, ExecutionStrategy, TargetInput, VerboseCb},
    luks::{find_existing_slot, resolve_device},
    luks_ops::{add_key_to_slot, find_or_pick_slot, stage_passphrase_and_key, verify_key},
    model::{BootedAccess, ExecutionMode, SecretPayload, TargetMeta},
    net::{connect_and_auth, Hk},
    vault::Vault,
};
use russh::client;
use secrecy::SecretString;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum EnrollEvent {
    Connected,
    Authenticated,
    TargetStart(String),
    SlotChosen(String, u8),
    SlotAdded(String, u8),
    SlotUpdated(String, u8),
    Verified(String),
    Skipped(String, String),
    Done,
}

impl std::fmt::Display for EnrollEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrollEvent::Connected => write!(f, "connected to OS SSH"),
            EnrollEvent::Authenticated => write!(f, "authenticated"),
            EnrollEvent::TargetStart(t) => write!(f, "{t}: enrolling keyfile"),
            EnrollEvent::SlotChosen(uuid, slot) => write!(f, "{uuid}: chosen slot {slot}"),
            EnrollEvent::SlotAdded(uuid, slot) => write!(f, "{uuid}: added key to slot {slot}"),
            EnrollEvent::SlotUpdated(uuid, slot) => write!(f, "{uuid}: updated key in slot {slot}"),
            EnrollEvent::Verified(uuid) => write!(f, "{uuid}: verified new key"),
            EnrollEvent::Skipped(uuid, why) => write!(f, "{uuid}: skipped ({why})"),
            EnrollEvent::Done => write!(f, "enrollment complete"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EnrollResult {
    pub luks_uuid: String,
    pub keyslot: u8,
}

/// Result of the SSH-side portion of enrolling one target.
#[derive(Debug, Clone)]
struct EnrollSshResult {
    target: TargetMeta,
    keyslot: u8,
}

/// Enrollment execution strategy implementing the shared framework.
struct EnrollStrategy {
    secrets: Arc<SecretPayload>,
}

impl EnrollStrategy {
    fn new(secrets: SecretPayload) -> Self {
        Self {
            secrets: Arc::new(secrets),
        }
    }
}

impl ExecutionStrategy for EnrollStrategy {
    type Event = EnrollEvent;
    type Result = EnrollSshResult;
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

        emit(EnrollEvent::TargetStart(tm.mapped_name.clone()));

        // 0. Resolve device (try UUID, then fallback)
        let dev = resolve_device(session, tm, sudo, timeout, log).await?;

        // 1. Check if our key is already enrolled in any slot
        let keyfile = self
            .secrets
            .keyfiles
            .iter()
            .find(|k| k.luks_uuid == tm.luks_uuid)
            .ok_or(VaultError::Invariant("missing keyfile"))?;

        if let Some(existing_slot) =
            find_existing_slot(session, &dev, &keyfile.keyfile, sudo, timeout, log).await?
        {
            emit(EnrollEvent::SlotChosen(
                tm.mapped_name.clone(),
                existing_slot,
            ));
            emit(EnrollEvent::SlotUpdated(
                tm.mapped_name.clone(),
                existing_slot,
            ));
            emit(EnrollEvent::Verified(tm.mapped_name.clone()));
            return Ok(Some(EnrollSshResult {
                target: tm.clone(),
                keyslot: existing_slot,
            }));
        }

        // 2. Pick a free slot (or use pre-assigned keyslot if available and free)
        let slot_info = find_or_pick_slot(session, &dev, None, sudo, timeout, log).await?;
        let slot = match tm.keyslot {
            Some(k) if k == slot_info.slot => k,
            Some(_) => slot_info.slot, // pre-assigned slot not free, use the one we found
            None => slot_info.slot,
        };
        emit(EnrollEvent::SlotChosen(tm.mapped_name.clone(), slot));

        // 3. Stage passphrase and keyfile to tmpfs
        let (passfile, newkeyfile) =
            stage_passphrase_and_key(session, idx, passphrase, &keyfile.keyfile, sudo, timeout)
                .await?;

        // 4. Add key to slot
        add_key_to_slot(
            session,
            &dev,
            &passfile,
            &newkeyfile,
            slot,
            sudo,
            timeout,
            log,
        )
        .await?;

        emit(EnrollEvent::SlotAdded(tm.mapped_name.clone(), slot));

        // 5. Verify with the new key itself
        verify_key(session, &dev, &keyfile.keyfile, slot, sudo, timeout, log).await?;

        emit(EnrollEvent::Verified(tm.mapped_name.clone()));
        Ok(Some(EnrollSshResult {
            target: tm.clone(),
            keyslot: slot,
        }))
    }

    fn on_target_filtered(&self, filter: &str, emit: &mut dyn FnMut(Self::Event)) {
        emit(EnrollEvent::Skipped(
            "--target".into(),
            format!("no target matches filter '{}'", filter),
        ));
    }

    fn on_done(&self, emit: &mut dyn FnMut(Self::Event)) {
        emit(EnrollEvent::Done);
    }
}

/// Enrolls every target keyfile of `uuid` into its LUKS header over the booted OS.
/// `passphrase_provider` is called per target (by luks_uuid) to get the existing LUKS passphrase.
/// Returns per-target slot numbers; frontend persists them via `Vault::set_keyslot`.
/// If `verbose` is provided, it will be called with each command executed on the target.
#[allow(clippy::too_many_arguments)]
pub async fn enroll(
    vault: &mut Vault,
    uuid: &[u8; 16],
    access: &BootedAccess,
    mode: ExecutionMode,
    passphrase_provider: impl FnMut(&str) -> Result<SecretString, String> + Send,
    only_target: Option<&str>,
    mut on: impl FnMut(EnrollEvent),
    verbose: VerboseCb,
) -> Result<Vec<EnrollResult>, UnlockError> {
    let p = vault.profile(uuid)?.clone();
    let secrets = vault.open_secrets(&p)?;
    let strategy = EnrollStrategy::new(secrets);

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
        None::<&mut dyn FnMut(&mut Vault) -> Result<(), UnlockError>>,
    )
    .await?;

    let results: Vec<EnrollResult> = ssh_results
        .into_iter()
        .map(|r| EnrollResult {
            luks_uuid: r.target.luks_uuid,
            keyslot: r.keyslot,
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
