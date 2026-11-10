use std::time::Duration;
use secrecy::{ExposeSecret, SecretString};
use russh::client;
use crate::{constants::*, error::*, model::{BootedAccess, ExecutionMode, TargetMeta}, net::*, vault::Vault};
use std::collections::HashMap;
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::{mpsc, Semaphore};

#[derive(Debug, Clone)]
pub enum EnrollEvent {
    Connected, Authenticated,
    TargetStart(String), SlotChosen(String, u8), SlotAdded(String, u8), SlotUpdated(String, u8), Verified(String),
    Skipped(String, String),
    Done,
}

#[derive(Debug, Clone)]
pub struct EnrollResult { pub luks_uuid: String, pub keyslot: u8 }

fn parse_used_slots(dump: &str) -> Vec<u8> {
    // LUKS2: "Keyslots:\n  0: luks2\n ..." ; LUKS1: "Key Slot 0: ENABLED"
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

/// Try to find which slot (if any) contains our keyfile by testing each enabled slot.
/// Returns Some(slot) if our key works, None otherwise.
async fn find_existing_slot(
    session: &client::Handle<Hk>,
    dev: &str,
    keyfile: &[u8],
    sudo: &str,
    timeout: Duration,
    log: &mut dyn FnMut(&str),
) -> Result<Option<u8>, UnlockError> {
    // First dump to get enabled slots
    let cmd = format!("{sudo}cryptsetup luksDump {dev}");
    log(&cmd);
    let dump = exec(session, &cmd, None, timeout).await?;
    if dump.code != 0 {
        return Ok(None);
    }
    let used = parse_used_slots(&dump.stdout);

    // Test each enabled slot with our keyfile
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

/// Enrolls one target's keyfile into its LUKS header. Shared by sequential and
/// parallel drivers. Uses per-target tmpfs staging paths so parallel targets
/// never collide. Returns `Ok(None)` for a target that was skipped.
async fn enroll_one(
    idx: usize,
    tm: &TargetMeta,
    session: &client::Handle<Hk>,
    keyfile: &[u8],
    passphrase: &mut dyn FnMut(&str) -> Result<SecretString, String>,
    sudo: &str,
    t: Duration,
    log: &mut dyn FnMut(&str),
    emit: &mut dyn FnMut(EnrollEvent),
) -> Result<Option<EnrollResult>, UnlockError> {
    emit(EnrollEvent::TargetStart(tm.mapped_name.clone()));

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
        emit(EnrollEvent::Skipped(tm.mapped_name.clone(), format!("not a LUKS device: {}", r.stderr.trim())));
        return Ok(None);
    }

    // 1. Check if our key is already enrolled in any slot
    if let Some(existing_slot) = find_existing_slot(session, &dev, keyfile, sudo, t, log).await? {
        emit(EnrollEvent::SlotChosen(tm.mapped_name.clone(), existing_slot));
        emit(EnrollEvent::SlotUpdated(tm.mapped_name.clone(), existing_slot));
        emit(EnrollEvent::Verified(tm.mapped_name.clone()));
        return Ok(Some(EnrollResult { luks_uuid: tm.luks_uuid.clone(), keyslot: existing_slot }));
    }

    // 2. Pick a free slot: dump LUKS header
    let cmd = format!("{sudo}cryptsetup luksDump {dev}");
    log(&cmd);
    let dump = exec(session, &cmd, None, t).await?;
    if dump.code != 0 {
        log(&format!("! cmd={} exit={} stderr: {}", &cmd, dump.code, dump.stderr.trim()));
        emit(EnrollEvent::Skipped(tm.mapped_name.clone(), format!("luksDump failed: {}", dump.stderr.trim())));
        return Ok(None);
    }
    let used = parse_used_slots(&dump.stdout);
    let slot = match tm.keyslot {
        Some(k) if !used.contains(&k) => k,
        _ => first_free(&used).ok_or_else(|| UnlockError::CryptsetupFailed {
            target: tm.mapped_name.clone(), code: 0, stderr: "no free keyslot".into() })?,
    };
    emit(EnrollEvent::SlotChosen(tm.mapped_name.clone(), slot));

    // 3. Get passphrase for this target
    let luks_pass = passphrase(&tm.luks_uuid).map_err(|e| UnlockError::CryptsetupFailed {
        target: tm.mapped_name.clone(), code: 0, stderr: e })?;

    // 4. Stage existing passphrase in a per-target tmpfs file
    let passfile = target_passfile(idx);
    let newkeyfile = target_newkeyfile(idx);
    let stage_pass_cmd = format!("{sudo}sh -c 'umask {UMASK_TMPFS} && mkdir -p {TMPFS_BASE} && cat > {passfile}'");
    log(&stage_pass_cmd);
    tmpfs_stage(session, &passfile, luks_pass.expose_secret().as_bytes(), sudo, t).await
        .map_err(|e| UnlockError::CryptsetupFailed {
            target: tm.mapped_name.clone(),
            code: 0,
            stderr: format!("stage passphrase: {e}"),
        })?;

    // 5. Stage new key in a per-target tmpfs file
    let stage_key_cmd = format!("{sudo}sh -c 'umask {UMASK_TMPFS} && cat > {newkeyfile}'");
    log(&stage_key_cmd);
    tmpfs_stage(session, &newkeyfile, keyfile, sudo, t).await
        .map_err(|e| UnlockError::CryptsetupFailed {
            target: tm.mapped_name.clone(),
            code: 0,
            stderr: format!("stage keyfile: {e}"),
        })?;

    // 6. Add key using both tmpfs files
    let cmd = format!("{sudo}cryptsetup luksAddKey --key-file={passfile} --new-keyfile={newkeyfile} --key-slot {slot} {dev}");
    log(&cmd);
    let add = exec(session, &cmd, None, t).await;

    // 7. Always clean up tmpfs
    let _ = tmpfs_cleanup(session, &[&passfile, &newkeyfile], sudo, t).await;

    let add = add?;
    if add.code != 0 {
        log(&format!("! cmd={} exit={} stderr: {}", &cmd, add.code, add.stderr.trim()));
    }
    match add.code {
        0 => emit(EnrollEvent::SlotAdded(tm.mapped_name.clone(), slot)),
        2 => return Err(UnlockError::KeyRejected(format!("{}: existing passphrase wrong", tm.mapped_name))),
        c => return Err(UnlockError::CryptsetupFailed { target: tm.mapped_name.clone(), code: c, stderr: add.stderr }),
    }

    // 8. Verify with the new key itself (--test-passphrase doesn't open the device)
    let cmd = format!("{sudo}cryptsetup open --test-passphrase --key-file=- --key-slot {slot} {dev}");
    log(&cmd);
    let verify = exec(session, &cmd, Some(keyfile), t).await?;
    if verify.code != 0 {
        log(&format!("! cmd={} exit={} stderr: {}", &cmd, verify.code, verify.stderr.trim()));
        return Err(UnlockError::CryptsetupFailed { target: tm.mapped_name.clone(), code: verify.code,
            stderr: format!("verification failed: {}", verify.stderr) });
    }
    emit(EnrollEvent::Verified(tm.mapped_name.clone()));
    Ok(Some(EnrollResult { luks_uuid: tm.luks_uuid.clone(), keyslot: slot }))
}

/// Message emitted from a parallel enroll task back to the driver loop.
enum EnrollMsg {
    Event(EnrollEvent),
    Verbose(String),
}

fn emit_enroll_msg(msg: EnrollMsg, on: &mut impl FnMut(EnrollEvent),
                   verbose: &mut Option<Box<dyn FnMut(&str) + Send>>) {
    match msg {
        EnrollMsg::Event(e) => on(e),
        EnrollMsg::Verbose(s) => { if let Some(v) = verbose.as_mut() { v(&s); } }
    }
}

/// Enrolls every target keyfile of `uuid` into its LUKS header over the booted OS.
/// `passphrase_provider` is called per target (by luks_uuid) to get the existing LUKS passphrase.
/// Returns per-target slot numbers; frontend persists them via `Vault::set_keyslot`.
/// If `verbose` is provided, it will be called with each command executed on the target.
pub async fn enroll(
    vault: &Vault, uuid: &[u8; 16], access: &BootedAccess, mode: ExecutionMode,
    mut passphrase_provider: impl FnMut(&str) -> Result<SecretString, String>,
    only_target: Option<&str>, mut on: impl FnMut(EnrollEvent),
    mut verbose: Option<Box<dyn FnMut(&str) + Send>>,
) -> Result<Vec<EnrollResult>, UnlockError> {
    let p = vault.profile(uuid)?.clone();
    let os_key = p.os_host_key.clone().ok_or(UnlockError::HostKeyNotPinned)?;

    // Resolve OS address (fallback to initramfs address if not set)
    let os_host = p.os_host.as_deref().unwrap_or(&p.host);
    let os_port = p.os_port.unwrap_or(p.port);

    // Connect and authenticate using the shared helper.
    let (s, _) = connect_and_auth(
        os_host, os_port, access.connect_timeout_s,
        Some(os_key), &access.username, &access.auth,
    ).await?;
    on(EnrollEvent::Connected);
    on(EnrollEvent::Authenticated);

    let sudo = if access.use_sudo && access.username != "root" { "sudo -n " } else { "" };
    let t = Duration::from_secs(p.exec_timeout_s.max(60) as u64); // luksAddKey runs PBKDF, be generous
    let secrets = vault.open_secrets(&p)?;

    // Apply target filter up front.
    let targets: Vec<(usize, TargetMeta)> = p.targets_meta.iter().enumerate()
        .filter(|(_, tm)| only_target.map_or(true, |f| f == tm.luks_uuid || f == tm.mapped_name))
        .map(|(i, tm)| (i, tm.clone()))
        .collect();

    let mut results = Vec::new();

    match mode {
        ExecutionMode::Sequential => {
            let mut passphrase_cache: HashMap<String, SecretString> = HashMap::new();
            for (idx, tm) in &targets {
                let key = secrets.keyfiles.iter().find(|k| k.luks_uuid == tm.luks_uuid)
                    .ok_or(VaultError::Invariant("missing keyfile"))?;

                let mut log = |s: &str| { if let Some(v) = verbose.as_mut() { v(s); } };
                let mut emit = |e: EnrollEvent| on(e);
                let mut pass = |uuid: &str| -> Result<SecretString, String> {
                    if let Some(c) = passphrase_cache.get(uuid) { return Ok(c.clone()); }
                    let p = passphrase_provider(uuid)?;
                    passphrase_cache.insert(uuid.to_string(), p.clone());
                    Ok(p)
                };

                if let Some(r) = enroll_one(*idx, tm, &s, &key.keyfile, &mut pass, sudo, t, &mut log, &mut emit).await? {
                    results.push(r);
                }
            }
        }
        ExecutionMode::Parallel => {
            // Fetch every needed passphrase up front (provider is FnMut, called once here).
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
            let (tx, mut rx) = mpsc::unbounded_channel::<EnrollMsg>();

            let mut futs: FuturesUnordered<_> = targets.iter().map(|(idx, tm)| {
                let idx = *idx;
                let tx = tx.clone();
                let sem = &semaphore;
                let pass = pass_map.get(&tm.luks_uuid).cloned();
                let s = &s;
                let secrets = &secrets;
                async move {
                    let _permit = sem.acquire().await;
                    let res: Result<Option<EnrollResult>, UnlockError> = async {
                        let key = secrets.keyfiles.iter().find(|k| k.luks_uuid == tm.luks_uuid)
                            .ok_or(VaultError::Invariant("missing keyfile"))?;
                        let pass = pass.ok_or_else(|| VaultError::Invariant("missing passphrase"))?;
                        let mut log = |s: &str| { let _ = tx.send(EnrollMsg::Verbose(s.to_string())); };
                        let mut emit = |e: EnrollEvent| { let _ = tx.send(EnrollMsg::Event(e)); };
                        let mut provider = |_: &str| -> Result<SecretString, String> { Ok(pass.clone()) };
                        enroll_one(idx, tm, s, &key.keyfile, &mut provider, sudo, t, &mut log, &mut emit).await
                    }.await;
                    res
                }
            }).collect();

            let mut first_err: Option<UnlockError> = None;
            let mut pending = targets.len();

            while pending > 0 {
                tokio::select! {
                    biased;
                    Some(msg) = rx.recv() => emit_enroll_msg(msg, &mut on, &mut verbose),
                    Some(res) = futs.next() => {
                        pending -= 1;
                        match res {
                            Ok(Some(r)) => results.push(r),
                            Ok(None) => {}
                            Err(e) => { if first_err.is_none() { first_err = Some(e); } }
                        }
                    }
                }
            }

            while let Ok(msg) = rx.try_recv() { emit_enroll_msg(msg, &mut on, &mut verbose); }

            if let Some(e) = first_err { return Err(e); }
        }
    }

    if only_target.is_some() && targets.is_empty() {
        on(EnrollEvent::Skipped("--target".into(), format!("no target matches filter '{}'", only_target.unwrap())));
    }

    // Sort results by original target order for deterministic output.
    results.sort_by_key(|r| targets.iter().position(|(_, tm)| tm.luks_uuid == r.luks_uuid).unwrap_or(usize::MAX));

    drop(secrets);
    on(EnrollEvent::Done);
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