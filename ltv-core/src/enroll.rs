use std::time::Duration;
use secrecy::{ExposeSecret, SecretString};

use crate::{error::*, model::BootedAccess, model::BootedAuth, net::*, vault::Vault};

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
pub async fn enroll(
    vault: &Vault, uuid: &[u8; 16], access: &BootedAccess, luks_pass: &SecretString,
    only_target: Option<&str>, mut on: impl FnMut(EnrollEvent),
) -> Result<Vec<EnrollResult>, UnlockError> {
    let p = vault.profile(uuid)?.clone();
    let os_key = p.os_host_key.clone().ok_or(UnlockError::HostKeyMismatch)?;
    let (mut s, _) = connect(&p.host, p.port, access.connect_timeout_s, Some(os_key)).await?;
    on(EnrollEvent::Connected);

    let ok = match &access.auth {
        BootedAuth::Password(pw) => s.authenticate_password(&access.username, pw.expose_secret()).await,
        BootedAuth::Ed25519Seed(seed) => s.authenticate_publickey(&access.username, keypair_from_seed(seed)).await,
    }.map_err(|e| NetError::Ssh(e.to_string()))?;
    if !ok { return Err(UnlockError::AuthRejected); }
    on(EnrollEvent::Authenticated);

    let sudo = if access.use_sudo && access.username != "root" { "sudo -n " } else { "" };
    let t = Duration::from_secs(p.exec_timeout_s.max(60) as u64); // luksAddKey runs PBKDF, be generous
    let secrets = vault.open_secrets(&p)?;
    let mut results = Vec::new();

    for tm in &p.targets_meta {
        if let Some(f) = only_target { if f != tm.luks_uuid && f != tm.mapped_name { continue; } }
        on(EnrollEvent::TargetStart(tm.mapped_name.clone()));
        let dev = format!("UUID={}", tm.luks_uuid);

        // 0. sanity: device exists & is LUKS
        let r = exec(&mut s, &format!("{sudo}cryptsetup isLuks {dev}"), None, t).await?;
        if r.code != 0 {
            on(EnrollEvent::Skipped(tm.mapped_name.clone(), format!("not a LUKS device: {}", r.stderr.trim())));
            continue;
        }
        // 1. pick slot
        let dump = exec(&mut s, &format!("{sudo}cryptsetup luksDump {dev}"), None, t).await?;
        let used = parse_used_slots(&dump.stdout);
        let slot = match tm.keyslot {
            Some(k) if !used.contains(&k) => k,
            _ => first_free(&used).ok_or_else(|| UnlockError::CryptsetupFailed {
                target: tm.mapped_name.clone(), code: 0, stderr: "no free keyslot".into() })?,
        };
        on(EnrollEvent::SlotChosen(tm.mapped_name.clone(), slot));

        // 2. stage existing passphrase in tmpfs
        let r = exec(&mut s, &format!("{sudo}sh -c 'umask 077 && mkdir -p /run/ltv && cat > /run/ltv/pass'"),
                     Some(luks_pass.expose_secret().as_bytes()), t).await?;
        if r.code != 0 { return Err(UnlockError::CryptsetupFailed { target: tm.mapped_name.clone(), code: r.code, stderr: r.stderr }); }

        // 3. add key, 4. always clean up
        let key = secrets.keyfiles.iter().find(|k| k.luks_uuid == tm.luks_uuid)
            .ok_or(VaultError::Invariant("missing keyfile"))?;
        let add = exec(&mut s,
            &format!("{sudo}cryptsetup luksAddKey --key-file=/run/ltv/pass --new-keyfile=- --key-slot {slot} {dev}"),
            Some(&key.keyfile), t).await;
        let _ = exec(&mut s, &format!("{sudo}rm -f /run/ltv/pass"), None, t).await;
        let add = add?;
        match add.code {
            0 => on(EnrollEvent::SlotAdded(tm.mapped_name.clone(), slot)),
            2 => return Err(UnlockError::KeyRejected(format!("{}: existing passphrase wrong", tm.mapped_name))),
            c => return Err(UnlockError::CryptsetupFailed { target: tm.mapped_name.clone(), code: c, stderr: add.stderr }),
        }

        // 5. verify with the new key itself (--test-passphrase doesn't open the device)
        let v = exec(&mut s, &format!("{sudo}cryptsetup open --test-passphrase --key-file=- --key-slot {slot} {dev}"),
                     Some(&key.keyfile), t).await?;
        if v.code != 0 {
            return Err(UnlockError::CryptsetupFailed { target: tm.mapped_name.clone(), code: v.code,
                stderr: format!("verification failed: {}", v.stderr) });
        }
        on(EnrollEvent::Verified(tm.mapped_name.clone()));
        results.push(EnrollResult { luks_uuid: tm.luks_uuid.clone(), keyslot: slot });
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