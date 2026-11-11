use std::time::Duration;
use secrecy::{ExposeSecret, SecretString};
use russh::client;
use rand::RngCore;
use crate::{constants::*, error::*, model::{BootedAccess, ExecutionMode, TargetMeta}, net::*, vault::Vault};
use std::collections::HashMap;
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::{mpsc, Semaphore};

#[derive(Debug, Clone)]
pub enum RotateEvent {
    Connected, Authenticated,
    TargetStart(String),
    SlotChosen(String, u8),      // new slot chosen
    SlotAdded(String, u8),       // new key added
    Verified(String),            // new key verified
    OldSlotKilled(String, u8),   // old slot removed
    Skipped(String, String),
    Done,
}

#[derive(Debug, Clone)]
pub struct RotateResult {
    pub luks_uuid: String,
    pub old_keyslot: u8,
    pub new_keyslot: u8,
}

/// Find the slot containing our keyfile by testing each enabled slot.
async fn find_existing_slot(
    session: &client::Handle<Hk>,
    dev: &str,
    keyfile: &[u8],
    sudo: &str,
    timeout: Duration,
    log: &mut dyn FnMut(&str),
) -> Result<Option<u8>, UnlockError> {
    let cmd = format!("{sudo}cryptsetup luksDump {dev}");
    log(&cmd);
    let dump = exec(session, &cmd, None, timeout).await?;
    if dump.code != 0 {
        return Ok(None);
    }
    let used = parse_used_slots(&dump.stdout);

    for slot in used {
        let cmd = format!("{sudo}cryptsetup open --test-passphrase --key-file=- --key-slot {slot} {dev}");
        log(&cmd);
        let r = exec(session, &cmd, Some(keyfile), timeout).await?;
        if r.code == 0 {
            return Ok(Some(slot));
        }
    }
    Ok(None)
}

fn parse_used_slots(dump: &str) -> Vec<u8> {
    let mut v = Vec::new();
    let mut in_keyslots = false;
    for line in dump.lines() {
        let l = line.trim();
        if l.starts_with("Keyslots:") { in_keyslots = true; continue; }
        if in_keyslots {
            if l.ends_with(':') && !l.chars().next().map_or(false, |c| c.is_ascii_digit()) { in_keyslots = false; continue; }
            if let Some((n, rest)) = l.split_once(':') {
                if rest.trim().starts_with("luks2") { if let Ok(x) = n.trim().parse() { v.push(x); } }
            }
        }
        if let Some(rest) = l.strip_prefix("Key Slot ") {
            if let Some((n, st)) = rest.split_once(':') {
                if st.trim() == "ENABLED" { if let Ok(x) = n.trim().parse() { v.push(x); } }
            }
        }
    }
    v
}

fn first_free(used: &[u8]) -> Option<u8> { (0u8..32).find(|s| !used.contains(s)) }

/// Result of the SSH-side portion of rotating one target. The vault update and
/// old-slot removal happen after this, so the vault is never mutated from
/// concurrent tasks.
struct RotateSshResult {
    target: TargetMeta,
    dev: String,
    old_slot: u8,
    new_slot: u8,
    new_keyfile: Vec<u8>,
}

/// Adds a freshly generated key to a free slot and verifies it. Shared by the
/// sequential and parallel drivers. Returns `Ok(None)` for a skipped target.
async fn rotate_one(
    idx: usize,
    tm: &TargetMeta,
    session: &client::Handle<Hk>,
    current_keyfile: &[u8],
    passphrase: &mut dyn FnMut(&str) -> Result<SecretString, String>,
    sudo: &str,
    t: Duration,
    log: &mut dyn FnMut(&str),
    emit: &mut dyn FnMut(RotateEvent),
) -> Result<Option<RotateSshResult>, UnlockError> {
    emit(RotateEvent::TargetStart(tm.mapped_name.clone()));

    // Try UUID first, then fallback to fallback_path if device not found
    let mut dev = format!("UUID={}", tm.luks_uuid);

    // 0. sanity: device exists & is LUKS
    let cmd = format!("{sudo}cryptsetup isLuks {dev}");
    log(&cmd);
    let mut r = exec(session, &cmd, None, t).await?;
    if r.code != 0 && r.stderr.to_lowercase().contains("not exist") {
        if let Some(fp) = &tm.fallback_path {
            dev = fp.clone();
            let cmd = format!("{sudo}cryptsetup isLuks {dev}");
            log(&cmd);
            r = exec(session, &cmd, None, t).await?;
        }
    }
    if r.code != 0 {
        log(&format!("! cmd={} exit={} stderr: {}", &cmd, r.code, r.stderr.trim()));
        emit(RotateEvent::Skipped(tm.mapped_name.clone(), format!("not a LUKS device: {}", r.stderr.trim())));
        return Ok(None);
    }

    // 1. Find current slot (where our key lives)
    let old_slot = match find_existing_slot(session, &dev, current_keyfile, sudo, t, log).await? {
        Some(slot) => slot,
        None => {
            emit(RotateEvent::Skipped(tm.mapped_name.clone(), "current key not found in any slot".into()));
            return Ok(None);
        }
    };
    emit(RotateEvent::SlotChosen(tm.mapped_name.clone(), old_slot)); // reuse for old slot

    // 2. Generate new keyfile
    let mut new_keyfile = vec![0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut new_keyfile);

    // 3. Get passphrase for this target
    let luks_pass = passphrase(&tm.luks_uuid).map_err(|e| UnlockError::CryptsetupFailed {
        target: tm.mapped_name.clone(), code: 0, stderr: e })?;

    // 4. Pick free slot for new key
    let cmd = format!("{sudo}cryptsetup luksDump {dev}");
    log(&cmd);
    let dump = exec(session, &cmd, None, t).await?;
    if dump.code != 0 {
        log(&format!("! cmd={} exit={} stderr: {}", &cmd, dump.code, dump.stderr.trim()));
        emit(RotateEvent::Skipped(tm.mapped_name.clone(), format!("luksDump failed: {}", dump.stderr.trim())));
        return Ok(None);
    }
    let used = parse_used_slots(&dump.stdout);
    let new_slot = first_free(&used).ok_or_else(|| UnlockError::CryptsetupFailed {
        target: tm.mapped_name.clone(), code: 0, stderr: "no free keyslot".into() })?;
    emit(RotateEvent::SlotChosen(tm.mapped_name.clone(), new_slot));

    // 5. Stage existing passphrase in a per-target tmpfs file
    let passfile = target_passfile(idx);
    let newkeyfile = target_newkeyfile(idx);
    tmpfs_stage(session, &passfile, luks_pass.expose_secret().as_bytes(), sudo, t).await
        .map_err(|e| UnlockError::CryptsetupFailed {
            target: tm.mapped_name.clone(), code: 0, stderr: format!("stage passphrase: {e}") })?;

    // 6. Stage new key in a per-target tmpfs file
    tmpfs_stage(session, &newkeyfile, &new_keyfile, sudo, t).await
        .map_err(|e| UnlockError::CryptsetupFailed {
            target: tm.mapped_name.clone(), code: 0, stderr: format!("stage keyfile: {e}") })?;

    // 7. Add new key to free slot
    let cmd = format!("{sudo}cryptsetup luksAddKey --key-file={passfile} --new-keyfile={newkeyfile} --key-slot {new_slot} {dev}");
    log(&cmd);
    let add = exec(session, &cmd, None, t).await;

    // 8. Always clean up tmpfs
    let _ = tmpfs_cleanup(session, &[&passfile, &newkeyfile], sudo, t).await;

    let add = add?;
    if add.code != 0 {
        log(&format!("! cmd={} exit={} stderr: {}", &cmd, add.code, add.stderr.trim()));
        match add.code {
            2 => return Err(UnlockError::KeyRejected(format!("{}: existing passphrase wrong", tm.mapped_name))),
            c => return Err(UnlockError::CryptsetupFailed { target: tm.mapped_name.clone(), code: c, stderr: add.stderr }),
        }
    }
    emit(RotateEvent::SlotAdded(tm.mapped_name.clone(), new_slot));

    // 9. Verify new key
    let cmd = format!("{sudo}cryptsetup open --test-passphrase --key-file=- --key-slot {new_slot} {dev}");
    log(&cmd);
    let verify = exec(session, &cmd, Some(&new_keyfile), t).await?;
    if verify.code != 0 {
        log(&format!("! cmd={} exit={} stderr: {}", &cmd, verify.code, verify.stderr.trim()));
        return Err(UnlockError::CryptsetupFailed { target: tm.mapped_name.clone(), code: verify.code,
            stderr: format!("verification failed: {}", verify.stderr) });
    }
    emit(RotateEvent::Verified(tm.mapped_name.clone()));

    Ok(Some(RotateSshResult { target: tm.clone(), dev, old_slot, new_slot, new_keyfile }))
}

/// Persist the new keyfile/slot in the vault, then remove the old slot.
async fn finish_rotate(
    vault: &mut Vault,
    uuid: &[u8; 16],
    r: RotateSshResult,
) -> Result<RotateResult, UnlockError> {
    // 10. Update vault with new keyfile and slot, then SAVE atomically
    vault.rotate_keyfile(uuid, &r.target.luks_uuid, r.new_keyfile.clone(), r.new_slot)
        .map_err(|e| UnlockError::Vault(e))?;
    vault.save().map_err(|e| UnlockError::Vault(e))?;

    Ok(RotateResult { luks_uuid: r.target.luks_uuid, old_keyslot: r.old_slot, new_keyslot: r.new_slot })
}

/// Message emitted from a parallel rotate task back to the driver loop.
enum RotateMsg {
    Event(RotateEvent),
    Verbose(String),
}

fn emit_rotate_msg(msg: RotateMsg, on: &mut impl FnMut(RotateEvent),
                   verbose: &mut Option<Box<dyn FnMut(&str) + Send>>) {
    match msg {
        RotateMsg::Event(e) => on(e),
        RotateMsg::Verbose(s) => { if let Some(v) = verbose.as_mut() { v(&s); } }
    }
}

/// Rotates the keyfile for each target: adds new key, verifies, kills old slot.
/// Updates vault with new keyfile and slot, saves atomically after each target.
pub async fn rotate_key(
    vault: &mut Vault, uuid: &[u8; 16], access: &BootedAccess, mode: ExecutionMode,
    mut passphrase_provider: impl FnMut(&str) -> Result<SecretString, String>,
    only_target: Option<&str>, mut on: impl FnMut(RotateEvent),
    mut verbose: Option<Box<dyn FnMut(&str) + Send>>,
) -> Result<Vec<RotateResult>, UnlockError> {
    let p = vault.profile(uuid)?.clone();
    let os_key = p.os_host_key.clone().ok_or(UnlockError::HostKeyNotPinned)?;

    // Resolve OS address (fallback to unlock SSH address if not set)
    let os_host = p.os_host.as_deref().unwrap_or(&p.unlock_host);
    let os_port = p.os_port.unwrap_or(p.unlock_port);

    // Connect and authenticate using the shared helper.
    let (s, _) = connect_and_auth(
        os_host, os_port, access.connect_timeout_s,
        Some(os_key), &access.username, &access.auth,
    ).await?;
    on(RotateEvent::Connected);
    on(RotateEvent::Authenticated);

    let sudo = if access.use_sudo && access.username != "root" { "sudo -n " } else { "" };
    let t = Duration::from_secs(p.exec_timeout_s.max(60) as u64);
    let secrets = vault.open_secrets(&p)?;

    let targets: Vec<(usize, TargetMeta)> = p.targets_meta.iter().enumerate()
        .filter(|(_, tm)| only_target.map_or(true, |f| f == tm.luks_uuid || f == tm.mapped_name))
        .map(|(i, tm)| (i, tm.clone()))
        .collect();

    let mut results: Vec<RotateResult> = Vec::new();

    match mode {
        ExecutionMode::Sequential => {
            let mut passphrase_cache: HashMap<String, SecretString> = HashMap::new();
            for (idx, tm) in &targets {
                let current_key = secrets.keyfiles.iter().find(|k| k.luks_uuid == tm.luks_uuid)
                    .ok_or(VaultError::Invariant("missing keyfile"))?;

                let mut log = |s: &str| { if let Some(v) = verbose.as_mut() { v(s); } };
                let mut emit = |e: RotateEvent| on(e);
                let mut pass = |uuid: &str| -> Result<SecretString, String> {
                    if let Some(c) = passphrase_cache.get(uuid) { return Ok(c.clone()); }
                    let p = passphrase_provider(uuid)?;
                    passphrase_cache.insert(uuid.to_string(), p.clone());
                    Ok(p)
                };

                let done = rotate_one(*idx, tm, &s, &current_key.keyfile, &mut pass, sudo, t, &mut log, &mut emit).await?;
                let Some(done) = done else { continue };

                let dev = done.dev.clone();
                let old_slot = done.old_slot;
                let name = done.target.mapped_name.clone();
                let res = finish_rotate(vault, uuid, done).await?;

                // 11. Kill old slot
                let cmd = format!("{sudo}cryptsetup luksKillSlot {dev} {old_slot}");
                if let Some(v) = verbose.as_mut() { v(&cmd); }
                let kill = exec(&s, &cmd, None, t).await?;
                if kill.code != 0 {
                    if let Some(v) = verbose.as_mut() { v(&format!("! luksKillSlot failed: exit {}: {}", kill.code, kill.stderr.trim())); }
                } else {
                    on(RotateEvent::OldSlotKilled(name, old_slot));
                }

                results.push(res);
            }
        }
        ExecutionMode::Parallel => {
            // Fetch every needed passphrase up front (provider is FnMut).
            let mut pass_map: HashMap<String, SecretString> = HashMap::new();
            for (_, tm) in &targets {
                if !pass_map.contains_key(&tm.luks_uuid) {
                    let pass = passphrase_provider(&tm.luks_uuid).map_err(|e| UnlockError::CryptsetupFailed {
                        target: tm.mapped_name.clone(), code: 0, stderr: e })?;
                    pass_map.insert(tm.luks_uuid.clone(), pass);
                }
            }

            if let Some(v) = verbose.as_mut() { v(&format!("running {} target(s) in parallel", targets.len())); }

            let semaphore = Semaphore::new(MAX_CONCURRENT_TARGETS);
            let (tx, mut rx) = mpsc::unbounded_channel::<RotateMsg>();

            let mut futs: FuturesUnordered<_> = targets.iter().map(|(idx, tm)| {
                let idx = *idx;
                let tx = tx.clone();
                let sem = &semaphore;
                let pass = pass_map.get(&tm.luks_uuid).cloned();
                let s = &s;
                let secrets = &secrets;
                async move {
                    let _permit = sem.acquire().await;
                    let res: Result<Option<RotateSshResult>, UnlockError> = async {
                        let key = secrets.keyfiles.iter().find(|k| k.luks_uuid == tm.luks_uuid)
                            .ok_or(VaultError::Invariant("missing keyfile"))?;
                        let pass = pass.ok_or_else(|| VaultError::Invariant("missing passphrase"))?;
                        let mut log = |s: &str| { let _ = tx.send(RotateMsg::Verbose(s.to_string())); };
                        let mut emit = |e: RotateEvent| { let _ = tx.send(RotateMsg::Event(e)); };
                        let mut provider = |_: &str| -> Result<SecretString, String> { Ok(pass.clone()) };
                        rotate_one(idx, tm, s, &key.keyfile, &mut provider, sudo, t, &mut log, &mut emit).await
                    }.await;
                    res
                }
            }).collect();

            let mut first_err: Option<UnlockError> = None;
            let mut completed: Vec<RotateSshResult> = Vec::new();
            let mut pending = targets.len();

            while pending > 0 {
                tokio::select! {
                    biased;
                    Some(msg) = rx.recv() => emit_rotate_msg(msg, &mut on, &mut verbose),
                    Some(res) = futs.next() => {
                        pending -= 1;
                        match res {
                            Ok(Some(r)) => completed.push(r),
                            Ok(None) => {}
                            Err(e) => { if first_err.is_none() { first_err = Some(e); } }
                        }
                    }
                }
            }

            while let Ok(msg) = rx.try_recv() { emit_rotate_msg(msg, &mut on, &mut verbose); }

            // Persist successful rotations in target order, then remove old slots.
            completed.sort_by_key(|r| targets.iter().position(|(_, tm)| tm.luks_uuid == r.target.luks_uuid).unwrap_or(usize::MAX));
            for done in completed {
                let dev = done.dev.clone();
                let old_slot = done.old_slot;
                let name = done.target.mapped_name.clone();
                let res = finish_rotate(vault, uuid, done).await?;

                let cmd = format!("{sudo}cryptsetup luksKillSlot {dev} {old_slot}");
                if let Some(v) = verbose.as_mut() { v(&cmd); }
                match exec(&s, &cmd, None, t).await {
                    Ok(kill) if kill.code != 0 => {
                        if let Some(v) = verbose.as_mut() { v(&format!("! luksKillSlot failed: exit {}: {}", kill.code, kill.stderr.trim())); }
                    }
                    Ok(_) => on(RotateEvent::OldSlotKilled(name, old_slot)),
                    Err(e) => { if let Some(v) = verbose.as_mut() { v(&format!("! luksKillSlot error: {e}")); } }
                }

                results.push(res);
            }

            if let Some(e) = first_err { return Err(e); }
        }
    }

    if only_target.is_some() && targets.is_empty() {
        on(RotateEvent::Skipped("--target".into(), format!("no target matches filter '{}'", only_target.unwrap())));
    }

    results.sort_by_key(|r| targets.iter().position(|(_, tm)| tm.luks_uuid == r.luks_uuid).unwrap_or(usize::MAX));

    drop(secrets);
    on(RotateEvent::Done);
    Ok(results)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_luks2_slots() {
        let d = "LUKS header information\nVersion: 2\nKeyslots:\n  0: luks2\n\tKey: 512 bits\n  3: luks2\nTokens:\nDigests:\n  0: pbkdf2\n";
        assert_eq!(parse_used_slots(d), vec![0, 3]);
        assert_eq!(first_free(&[0, 3]), Some(1));
    }
    #[test]
    fn parse_luks1_slots() {
        let d = "Key Slot 0: ENABLED\nKey Slot 1: DISABLED\nKey Slot 2: ENABLED\n";
        assert_eq!(parse_used_slots(d), vec![0, 2]);
    }
}