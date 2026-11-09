use std::time::Duration;
use secrecy::{ExposeSecret, SecretString};
use russh::client;
use rand::RngCore;
use crate::{constants::*, error::*, model::BootedAccess, net::*, vault::Vault};
use std::collections::HashMap;

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
    session: &mut client::Handle<Hk>,
    dev: &str,
    keyfile: &[u8],
    sudo: &str,
    timeout: Duration,
    verbose: &mut Option<Box<dyn FnMut(&str) + Send>>,
) -> Result<Option<u8>, UnlockError> {
    let cmd = format!("{sudo}cryptsetup luksDump {dev}");
    if let Some(verb) = verbose.as_mut() { verb(&cmd); }
    let dump = exec(session, &cmd, None, timeout).await?;
    if dump.code != 0 {
        return Ok(None);
    }
    let used = parse_used_slots(&dump.stdout);

    for slot in used {
        let cmd = format!("{sudo}cryptsetup open --test-passphrase --key-file=- --key-slot {slot} {dev}");
        if let Some(verb) = verbose.as_mut() { verb(&cmd); }
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

/// Rotates the keyfile for each target: adds new key, verifies, kills old slot.
/// Updates vault with new keyfile and slot, saves atomically after each target.
pub async fn rotate_key(
    vault: &mut Vault, uuid: &[u8; 16], access: &BootedAccess,
    mut passphrase_provider: impl FnMut(&str) -> Result<SecretString, String>,
    only_target: Option<&str>, mut on: impl FnMut(RotateEvent),
    mut verbose: Option<Box<dyn FnMut(&str) + Send>>,
) -> Result<Vec<RotateResult>, UnlockError> {
    let p = vault.profile(uuid)?.clone();
    let os_key = p.os_host_key.clone().ok_or(UnlockError::HostKeyNotPinned)?;

    // Resolve OS address (fallback to initramfs address if not set)
    let os_host = p.os_host.as_deref().unwrap_or(&p.host);
    let os_port = p.os_port.unwrap_or(p.port);

    // Connect and authenticate using the shared helper.
    let (mut s, _) = connect_and_auth(
        os_host, os_port, access.connect_timeout_s,
        Some(os_key), &access.username, &access.auth,
    ).await?;
    on(RotateEvent::Connected);
    on(RotateEvent::Authenticated);

    let sudo = if access.use_sudo && access.username != "root" { "sudo -n " } else { "" };
    let t = Duration::from_secs(p.exec_timeout_s.max(60) as u64);
    let mut passphrase_cache: HashMap<String, SecretString> = HashMap::new();
    let mut results = Vec::new();
    let mut matched = false;

    for tm in &p.targets_meta {
        if let Some(f) = only_target {
            if f != tm.luks_uuid && f != tm.mapped_name { continue; }
            matched = true;
        }
        on(RotateEvent::TargetStart(tm.mapped_name.clone()));

        // Try UUID first, then fallback to fallback_path if device not found
        let mut dev = format!("UUID={}", tm.luks_uuid);

        // 0. sanity: device exists & is LUKS
        let cmd = format!("{sudo}cryptsetup isLuks {dev}");
        if let Some(verb) = verbose.as_mut() { verb(&cmd); }
        let mut r = exec(&mut s, &cmd, None, t).await?;
        if r.code != 0 && r.stderr.to_lowercase().contains("not exist") {
            if let Some(fp) = &tm.fallback_path {
                dev = fp.clone();
                let cmd = format!("{sudo}cryptsetup isLuks {dev}");
                if let Some(verb) = verbose.as_mut() { verb(&cmd); }
                r = exec(&mut s, &cmd, None, t).await?;
            }
        }
        if r.code != 0 {
            if let Some(verb) = verbose.as_mut() { verb(&format!("  [rotate] ! cmd={} exit={} stderr: {}", &cmd, r.code, r.stderr.trim())); }
            on(RotateEvent::Skipped(tm.mapped_name.clone(), format!("not a LUKS device: {}", r.stderr.trim())));
            continue;
        }

        // Get current key for this target
        let secrets = vault.open_secrets(&p)?;
        let current_key = secrets.keyfiles.iter().find(|k| k.luks_uuid == tm.luks_uuid)
            .ok_or(VaultError::Invariant("missing keyfile"))?;

        // 1. Find current slot (where our key lives)
        let old_slot = match find_existing_slot(&mut s, &dev, &current_key.keyfile, sudo, t, &mut verbose).await? {
            Some(slot) => slot,
            None => {
                on(RotateEvent::Skipped(tm.mapped_name.clone(), "current key not found in any slot".into()));
                continue;
            }
        };
        on(RotateEvent::SlotChosen(tm.mapped_name.clone(), old_slot)); // reuse for old slot

        // 2. Generate new keyfile
        let mut new_keyfile = vec![0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut new_keyfile);

        // 3. Get passphrase for this target
        let luks_pass = if let Some(cached) = passphrase_cache.get(&tm.luks_uuid) {
            cached.clone()
        } else {
            let pass = passphrase_provider(&tm.luks_uuid).map_err(|e| UnlockError::CryptsetupFailed {
                target: tm.mapped_name.clone(), code: 0, stderr: e })?;
            passphrase_cache.insert(tm.luks_uuid.clone(), pass.clone());
            pass
        };

        // 4. Pick free slot for new key
        let cmd = format!("{sudo}cryptsetup luksDump {dev}");
        if let Some(verb) = verbose.as_mut() { verb(&cmd); }
        let dump = exec(&mut s, &cmd, None, t).await?;
        if dump.code != 0 {
            if let Some(verb) = verbose.as_mut() { verb(&format!("  [rotate] ! cmd={} exit={} stderr: {}", &cmd, dump.code, dump.stderr.trim())); }
            on(RotateEvent::Skipped(tm.mapped_name.clone(), format!("luksDump failed: {}", dump.stderr.trim())));
            continue;
        }
        let used = parse_used_slots(&dump.stdout);
        let new_slot = first_free(&used).ok_or_else(|| UnlockError::CryptsetupFailed {
            target: tm.mapped_name.clone(), code: 0, stderr: "no free keyslot".into() })?;
        on(RotateEvent::SlotChosen(tm.mapped_name.clone(), new_slot));

        // 5. Stage existing passphrase in tmpfs
        tmpfs_stage(&mut s, TMPFS_PASSFILE, luks_pass.expose_secret().as_bytes(), sudo, t).await
            .map_err(|e| UnlockError::CryptsetupFailed {
                target: tm.mapped_name.clone(), code: 0, stderr: format!("stage passphrase: {e}") })?;

        // 6. Stage new key in tmpfs
        tmpfs_stage(&mut s, TMPFS_NEWKEYFILE, &new_keyfile, sudo, t).await
            .map_err(|e| UnlockError::CryptsetupFailed {
                target: tm.mapped_name.clone(), code: 0, stderr: format!("stage keyfile: {e}") })?;

        // 7. Add new key to free slot
        let cmd = format!("{sudo}cryptsetup luksAddKey --key-file={TMPFS_PASSFILE} --new-keyfile={TMPFS_NEWKEYFILE} --key-slot {new_slot} {dev}");
        if let Some(verb) = verbose.as_mut() { verb(&cmd); }
        let add = exec(&mut s, &cmd, None, t).await;

        // 8. Always clean up tmpfs
        let _ = tmpfs_cleanup(&mut s, &[TMPFS_PASSFILE, TMPFS_NEWKEYFILE], sudo, t).await;

        let add = add?;
        if add.code != 0 {
            if let Some(verb) = verbose.as_mut() { verb(&format!("  [rotate] ! cmd={} exit={} stderr: {}", &cmd, add.code, add.stderr.trim())); }
            match add.code {
                2 => return Err(UnlockError::KeyRejected(format!("{}: existing passphrase wrong", tm.mapped_name))),
                c => return Err(UnlockError::CryptsetupFailed { target: tm.mapped_name.clone(), code: c, stderr: add.stderr }),
            }
        }
        on(RotateEvent::SlotAdded(tm.mapped_name.clone(), new_slot));

        // 9. Verify new key
        let cmd = format!("{sudo}cryptsetup open --test-passphrase --key-file=- --key-slot {new_slot} {dev}");
        if let Some(verb) = verbose.as_mut() { verb(&cmd); }
        let verify = exec(&mut s, &cmd, Some(&new_keyfile), t).await?;
        if verify.code != 0 {
            if let Some(verb) = verbose.as_mut() { verb(&format!("  [rotate] ! cmd={} exit={} stderr: {}", &cmd, verify.code, verify.stderr.trim())); }
            return Err(UnlockError::CryptsetupFailed { target: tm.mapped_name.clone(), code: verify.code,
                stderr: format!("verification failed: {}", verify.stderr) });
        }
        on(RotateEvent::Verified(tm.mapped_name.clone()));

        // 10. Update vault with new keyfile and slot, then SAVE atomically
        {
            // Update vault with new keyfile and slot, then SAVE atomically
            vault.rotate_keyfile(uuid, &tm.luks_uuid, new_keyfile.clone(), new_slot)
                .map_err(|e| UnlockError::Vault(e))?;
            vault.save().map_err(|e| UnlockError::Vault(e))?;
        }

        // 11. Kill old slot
        let cmd = format!("{sudo}cryptsetup luksKillSlot {dev} {old_slot}");
        if let Some(verb) = verbose.as_mut() { verb(&cmd); }
        let kill = exec(&mut s, &cmd, None, t).await?;
        if kill.code != 0 {
            // Log but don't fail - vault is already updated
            if let Some(verb) = verbose.as_mut() { verb(&format!("  [rotate] ! luksKillSlot failed: exit {}: {}", kill.code, kill.stderr.trim())); }
        } else {
            on(RotateEvent::OldSlotKilled(tm.mapped_name.clone(), old_slot));
        }

        results.push(RotateResult { luks_uuid: tm.luks_uuid.clone(), old_keyslot: old_slot, new_keyslot: new_slot });
    }

    if only_target.is_some() && !matched {
        on(RotateEvent::Skipped("--target".into(), format!("no target matches filter '{}'", only_target.unwrap())));
    }

    let _ = s.disconnect(russh::Disconnect::ByApplication, "done", "en").await;
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