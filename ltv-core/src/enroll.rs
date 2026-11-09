use std::time::Duration;
use secrecy::{ExposeSecret, SecretString};
use crate::{constants::*, error::*, model::BootedAccess, model::BootedAuth, net::*, vault::Vault};

#[derive(Debug, Clone)]
pub enum EnrollEvent {
    Connected, Authenticated,
    TargetStart(String), SlotChosen(String, u8), SlotAdded(String, u8), Verified(String),
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

/// Enrolls every target keyfile of `uuid` into its LUKS header over the booted OS.
/// `luks_pass` is the existing passphrase (same for all targets, or ask per target in frontend).
/// Returns per-target slot numbers; frontend persists them via `Vault::set_keyslot`.
/// If `verbose` is provided, it will be called with each command executed on the target.
pub async fn enroll(
    vault: &Vault, uuid: &[u8; 16], access: &BootedAccess, luks_pass: &SecretString,
    only_target: Option<&str>, mut on: impl FnMut(EnrollEvent),
    mut verbose: Option<Box<dyn FnMut(&str) + Send>>,
) -> Result<Vec<EnrollResult>, UnlockError> {
    let p = vault.profile(uuid)?.clone();
    let os_key = p.os_host_key.clone().ok_or(UnlockError::HostKeyMismatch)?;

    // Connect and authenticate using the shared helper.
    let (mut s, _) = connect_and_auth(
        &p.host, p.port, access.connect_timeout_s,
        Some(os_key), &access.username, &access.auth,
    ).await?;
    on(EnrollEvent::Connected);
    on(EnrollEvent::Authenticated);

    let sudo = if access.use_sudo && access.username != "root" { "sudo -n " } else { "" };
    let t = Duration::from_secs(p.exec_timeout_s.max(60) as u64); // luksAddKey runs PBKDF, be generous
    let secrets = vault.open_secrets(&p)?;
    let mut results = Vec::new();
    let mut matched = false;

    for tm in &p.targets_meta {
        if let Some(f) = only_target {
            if f != tm.luks_uuid && f != tm.mapped_name { continue; }
            matched = true;
        }
        on(EnrollEvent::TargetStart(tm.mapped_name.clone()));

        // Try UUID first, then fallback to fallback_path if device not found
        let mut dev = format!("UUID={}", tm.luks_uuid);

        // 0. sanity: device exists & is LUKS
        let cmd = format!("{sudo}cryptsetup isLuks {dev}");
        if let Some(verb) = verbose.as_mut() { verb(&cmd); }
        let mut r = exec(&mut s, &cmd, None, t).await?;
        if r.code != 0 && r.stderr.to_lowercase().contains("not exist") {
            // Try fallback path if available (device not found via UUID)
            if let Some(fp) = &tm.fallback_path {
                dev = fp.clone();
                let cmd = format!("{sudo}cryptsetup isLuks {dev}");
                if let Some(verb) = verbose.as_mut() { verb(&cmd); }
                r = exec(&mut s, &cmd, None, t).await?;
            }
        }
        if r.code != 0 {
            if let Some(verb) = verbose.as_mut() { verb(&format!("  [enroll] ! cmd={} exit={} stderr: {}", &cmd, r.code, r.stderr.trim())); }
            on(EnrollEvent::Skipped(tm.mapped_name.clone(), format!("not a LUKS device: {}", r.stderr.trim())));
            continue;
        }

        // 1. pick slot: dump LUKS header
        let cmd = format!("{sudo}cryptsetup luksDump {dev}");
        if let Some(verb) = verbose.as_mut() { verb(&cmd); }
        let dump = exec(&mut s, &cmd, None, t).await?;
        if dump.code != 0 {
            if let Some(verb) = verbose.as_mut() { verb(&format!("  [enroll] ! cmd={} exit={} stderr: {}", &cmd, dump.code, dump.stderr.trim())); }
            on(EnrollEvent::Skipped(tm.mapped_name.clone(), format!("luksDump failed: {}", dump.stderr.trim())));
            continue;
        }
        let used = parse_used_slots(&dump.stdout);
        let slot = match tm.keyslot {
            Some(k) if !used.contains(&k) => k,
            _ => first_free(&used).ok_or_else(|| UnlockError::CryptsetupFailed {
                target: tm.mapped_name.clone(), code: 0, stderr: "no free keyslot".into() })?,
        };
        on(EnrollEvent::SlotChosen(tm.mapped_name.clone(), slot));

        // Get key for this target
        let key = secrets.keyfiles.iter().find(|k| k.luks_uuid == tm.luks_uuid)
            .ok_or(VaultError::Invariant("missing keyfile"))?;

        // 2. stage existing passphrase in tmpfs
        let stage_pass_cmd = format!("{sudo}sh -c 'umask {UMASK_TMPFS} && mkdir -p {TMPFS_BASE} && cat > {TMPFS_PASSFILE}'");
        if let Some(verb) = verbose.as_mut() { verb(&stage_pass_cmd); }
        tmpfs_stage(&mut s, TMPFS_PASSFILE, luks_pass.expose_secret().as_bytes(), sudo, t).await
            .map_err(|e| UnlockError::CryptsetupFailed {
                target: tm.mapped_name.clone(),
                code: 0,
                stderr: format!("stage passphrase: {e}"),
            })?;

        // 3. stage new key in tmpfs
        let stage_key_cmd = format!("{sudo}sh -c 'umask {UMASK_TMPFS} && cat > {TMPFS_NEWKEYFILE}'");
        if let Some(verb) = verbose.as_mut() { verb(&stage_key_cmd); }
        tmpfs_stage(&mut s, TMPFS_NEWKEYFILE, &key.keyfile, sudo, t).await
            .map_err(|e| UnlockError::CryptsetupFailed {
                target: tm.mapped_name.clone(),
                code: 0,
                stderr: format!("stage keyfile: {e}"),
            })?;

        // 4. add key using both tmpfs files
        let cmd = format!("{sudo}cryptsetup luksAddKey --key-file={TMPFS_PASSFILE} --new-keyfile={TMPFS_NEWKEYFILE} --key-slot {slot} {dev}");
        if let Some(verb) = verbose.as_mut() { verb(&cmd); }
        let add = exec(&mut s, &cmd, None, t).await;

        // 5. always clean up tmpfs
        let cleanup_cmd = format!("{sudo}rm -f {TMPFS_PASSFILE} {TMPFS_NEWKEYFILE}");
        if let Some(verb) = verbose.as_mut() { verb(&cleanup_cmd); }
        let _ = tmpfs_cleanup(&mut s, &[TMPFS_PASSFILE, TMPFS_NEWKEYFILE], sudo, t).await;

        let add = add?;
        if add.code != 0 {
            if let Some(verb) = verbose.as_mut() { verb(&format!("  [enroll] ! cmd={} exit={} stderr: {}", &cmd, add.code, add.stderr.trim())); }
        }
        match add.code {
            0 => on(EnrollEvent::SlotAdded(tm.mapped_name.clone(), slot)),
            2 => return Err(UnlockError::KeyRejected(format!("{}: existing passphrase wrong", tm.mapped_name))),
            c => return Err(UnlockError::CryptsetupFailed { target: tm.mapped_name.clone(), code: c, stderr: add.stderr }),
        }

        // 6. verify with the new key itself (--test-passphrase doesn't open the device)
        let cmd = format!("{sudo}cryptsetup open --test-passphrase --key-file=- --key-slot {slot} {dev}");
        if let Some(verb) = verbose.as_mut() { verb(&cmd); }
        let verify = exec(&mut s, &cmd, Some(&key.keyfile), t).await?;
        if verify.code != 0 {
            if let Some(verb) = verbose.as_mut() { verb(&format!("  [enroll] ! cmd={} exit={} stderr: {}", &cmd, verify.code, verify.stderr.trim())); }
            return Err(UnlockError::CryptsetupFailed { target: tm.mapped_name.clone(), code: verify.code,
                stderr: format!("verification failed: {}", verify.stderr) });
        }
        on(EnrollEvent::Verified(tm.mapped_name.clone()));
        results.push(EnrollResult { luks_uuid: tm.luks_uuid.clone(), keyslot: slot });
    }

    if only_target.is_some() && !matched {
        on(EnrollEvent::Skipped("--target".into(), format!("no target matches filter '{}'", only_target.unwrap())));
    }

    let _ = s.disconnect(russh::Disconnect::ByApplication, "done", "en").await;
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