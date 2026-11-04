use std::{sync::{Arc, Mutex}, time::Duration};
use secrecy::ExposeSecret;
use async_trait::async_trait;
use russh::{client, ChannelMsg};
use russh_keys::key::{KeyPair, PublicKey};
use russh_keys::PublicKeyBase64;
use tokio::time::timeout;

use crate::{error::*, model::{*, BootedAccess, BootedAuth}, vault::Vault};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResult {
    Unreachable(String),
    WaitingInInitramfs,
    BootedOs,
    /// host reachable, but key matches neither pinned key (or none pinned yet)
    UnknownHostKey(HostKey),
}

#[derive(Debug, Clone)]
pub enum UnlockEvent {
    Connecting, HostKeyVerified, Authenticated,
    TargetStart(String), TargetDone(String), TargetAlreadyOpen(String),
    ResumeSent, Disconnected,
}

pub(crate) type Seen = Arc<Mutex<Option<HostKey>>>;

/// Captures the presented host key. If `expected` is Some, only that key is accepted.
pub(crate) struct Hk { pub expected: Option<HostKey>, pub seen: Seen }

#[async_trait]
impl client::Handler for Hk {
    type Error = russh::Error;
    async fn check_server_key(&mut self, key: &PublicKey) -> Result<bool, Self::Error> {
        let k = HostKey { key_type: key.name().to_string(), key_bytes: key.public_key_bytes() };
        let ok = match &self.expected { None => true, Some(e) => e == &k };
        *self.seen.lock().unwrap() = Some(k);
        Ok(ok)
    }
}

pub(crate) fn cfg(connect_s: u16) -> Arc<client::Config> {
    Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(connect_s as u64 * 6)),
        ..Default::default()
    })
}

/// Connect with optional pinning. Returns session + the key the server presented.
pub(crate) async fn connect(host: &str, port: u16, connect_s: u16, expected: Option<HostKey>)
    -> Result<(client::Handle<Hk>, HostKey), UnlockError>
{
    let seen: Seen = Arc::new(Mutex::new(None));
    let h = Hk { expected, seen: seen.clone() };
    let fut = client::connect(cfg(connect_s), (host, port), h);
    let res = timeout(Duration::from_secs(connect_s as u64), fut).await
        .map_err(|_| NetError::Timeout)?;
    let presented = seen.lock().unwrap().clone();
    match res {
        Ok(s) => Ok((s, presented.expect("key seen on successful kex"))),
        // russh returns UnknownKey when check_server_key said false
        Err(russh::Error::UnknownKey) => Err(UnlockError::HostKeyMismatch),
        Err(e) => Err(NetError::Connect(e.to_string()).into()),
    }
}

/// TOFU helper for the admin: whatever key host:port presents right now.
pub async fn fetch_host_key(host: &str, port: u16, connect_s: u16) -> Result<HostKey, NetError> {
    match connect(host, port, connect_s, None).await {
        Ok((s, k)) => { let _ = s.disconnect(russh::Disconnect::ByApplication, "", "en").await; Ok(k) }
        Err(UnlockError::Net(e)) => Err(e),
        Err(e) => Err(NetError::Ssh(e.to_string())),
    }
}

/// Steps 1–2 only. No authentication, no secrets.
/// If `verbose` is provided, it will be called with connection details.
pub async fn probe(p: &Profile, mut verbose: Option<Box<dyn FnMut(&str) + Send>>) -> ProbeResult {
    if let Some(v) = verbose.as_mut() { v(&format!("Connecting to {}:{} (timeout {}s)", p.host, p.port, p.connect_timeout_s)); }
    match connect(&p.host, p.port, p.connect_timeout_s, None).await {
        Err(UnlockError::Net(NetError::Timeout)) => ProbeResult::Unreachable("timeout".into()),
        Err(e) => ProbeResult::Unreachable(e.to_string()),
        Ok((s, k)) => {
            if let Some(v) = verbose.as_mut() { v(&format!("SSH host key: {} {}", k.key_type, fingerprint_sha256(&k.key_bytes))); }
            let _ = s.disconnect(russh::Disconnect::ByApplication, "", "en").await;
            if p.initramfs_host_key.as_ref() == Some(&k) { ProbeResult::WaitingInInitramfs }
            else if p.os_host_key.as_ref() == Some(&k) { ProbeResult::BootedOs }
            else { ProbeResult::UnknownHostKey(k) }
        }
    }
}

pub(crate) struct ExecResult { pub code: u32, pub stdout: String, pub stderr: String }

pub(crate) async fn exec(session: &mut client::Handle<Hk>, cmd: &str, stdin: Option<&[u8]>, t: Duration)
    -> Result<ExecResult, NetError>
{
    let mut ch = session.channel_open_session().await.map_err(|e| NetError::Ssh(e.to_string()))?;
    ch.exec(true, cmd).await.map_err(|e| NetError::Ssh(e.to_string()))?;
    if let Some(d) = stdin { ch.data(d).await.map_err(|e| NetError::Ssh(e.to_string()))?; }
    ch.eof().await.map_err(|e| NetError::Ssh(e.to_string()))?;

    let (mut out, mut err, mut code) = (Vec::new(), Vec::new(), None);
    let fut = async {
        while let Some(m) = ch.wait().await {
            match m {
                ChannelMsg::Data { data } => out.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, .. } => err.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
    };
    timeout(t, fut).await.map_err(|_| NetError::Timeout)?;
    Ok(ExecResult {
        code: code.unwrap_or(255),
        stdout: String::from_utf8_lossy(&out).into_owned(),
        stderr: String::from_utf8_lossy(&err).into_owned(),
    })
}

pub(crate) fn keypair_from_seed(seed: &[u8; 32]) -> Arc<KeyPair> {
    Arc::new(KeyPair::Ed25519(ed25519_dalek::SigningKey::from_bytes(seed)))
}

/// Result of fetching LUKS details from a booted server
#[derive(Debug, Clone, serde::Serialize)]
pub struct FetchedLuksInfo {
    pub luks_uuid: String,
    pub device_path: String,
    pub cipher: String,
    pub key_size: u32,
    pub header_version: String,
}

/// Connect to the booted OS and discover all LUKS volumes.
/// Uses the profile's os_host_key (must be pinned first).
/// Auth: either the client's Ed25519 key (from vault) or password via BootedAuth.
/// If `verbose` is provided, it will be called with each command executed on the target.
pub async fn fetch_luks_info(
    vault: &Vault, uuid: &[u8; 16], access: &BootedAccess, only_mapped: Option<&str>,
    mut verbose: Option<Box<dyn FnMut(&str) + Send>>,
) -> Result<Vec<FetchedLuksInfo>, UnlockError> {
    let p = vault.profile(uuid)?.clone();
    let os_key = p.os_host_key.clone().ok_or(UnlockError::HostKeyMismatch)?;
    let (mut s, _) = connect(&p.host, p.port, access.connect_timeout_s, Some(os_key)).await?;

    let ok = match &access.auth {
        BootedAuth::Password(pw) => s.authenticate_password(&access.username, pw.expose_secret()).await,
        BootedAuth::Ed25519Seed(seed) => s.authenticate_publickey(&access.username, keypair_from_seed(seed)).await,
    }.map_err(|e| NetError::Ssh(e.to_string()))?;
    if !ok { return Err(UnlockError::AuthRejected); }

    let sudo = if access.use_sudo && access.username != "root" { "sudo -n " } else { "" };
    let t = Duration::from_secs(p.exec_timeout_s.max(30) as u64);

    // Find all LUKS devices via blkid
    let cmd = format!("{sudo}blkid -t TYPE=crypto_LUKS -o export");
    if let Some(v) = verbose.as_mut() { v(&cmd); }
    let r = exec(&mut s, &cmd, None, t).await?;
    if r.code != 0 {
        if let Some(v) = verbose.as_mut() { v(&format!("  [fetch] ! exit={} stderr: {}", r.code, r.stderr.trim())); }
        return Err(UnlockError::CryptsetupFailed { target: "discovery".into(), code: r.code, stderr: r.stderr });
    }

    let mut results = Vec::new();
    let mut current_uuid = String::new();
    let mut current_dev = String::new();

    for line in r.stdout.lines() {
        let line = line.trim();
        if line.starts_with("DEVNAME=") {
            current_dev = line["DEVNAME=".len()..].to_string();
        } else if line.starts_with("UUID=") && current_uuid.is_empty() {
            current_uuid = line["UUID=".len()..].to_string();
        } else if line.is_empty() && !current_uuid.is_empty() && !current_dev.is_empty() {
            // Got a complete device entry, now get details
            let _filter = only_mapped; // reserved for future filtering by mapper name
            let cmd = format!("{sudo}cryptsetup luksDump UUID={}", current_uuid);
            if let Some(v) = verbose.as_mut() { v(&cmd); }
            let dump = exec(&mut s, &cmd, None, t).await?;
            if dump.code != 0 {
                if let Some(v) = verbose.as_mut() { v(&format!("  [fetch] ! exit={} stderr: {}", dump.code, dump.stderr.trim())); }
            } else {
                // Parse cipher, key_size, version from luksDump
                let mut cipher = String::new();
                let mut key_size = 0;
                let mut version = String::new();
                for dl in dump.stdout.lines() {
                    let dl = dl.trim();
                    if dl.starts_with("Cipher name:") { cipher = dl["Cipher name:".len()..].trim().to_string(); }
                    else if dl.starts_with("Key size:") { key_size = dl["Key size:".len()..].trim().parse().unwrap_or(0); }
                    else if dl.starts_with("Version:") { version = dl["Version:".len()..].trim().to_string(); }
                }
                results.push(FetchedLuksInfo {
                    luks_uuid: current_uuid.clone(),
                    device_path: current_dev.clone(),
                    cipher,
                    key_size,
                    header_version: version,
                });
            }
            current_uuid.clear();
            current_dev.clear();
        }
    }

    let _ = s.disconnect(russh::Disconnect::ByApplication, "done", "en").await;
    Ok(results)
}

pub async fn unlock(
    vault: &Vault, uuid: &[u8; 16], mut on: impl FnMut(UnlockEvent),
    mut verbose: Option<Box<dyn FnMut(&str) + Send>>,
) -> Result<(), UnlockError> {
    let p = vault.profile(uuid)?.clone();
    let expected = p.initramfs_host_key.clone().ok_or(UnlockError::HostKeyMismatch)?;
    on(UnlockEvent::Connecting);

    let (mut session, _) = match connect(&p.host, p.port, p.connect_timeout_s, Some(expected)).await {
        Err(UnlockError::HostKeyMismatch) => {
            // distinguish "booted OS" from real mismatch via a probe (no verbose needed for this quick check)
            return Err(match probe(&p, None).await { ProbeResult::BootedOs => UnlockError::StateBootedOs, _ => UnlockError::HostKeyMismatch });
        }
        r => r?,
    };
    on(UnlockEvent::HostKeyVerified);

    let secrets = vault.open_secrets(&p)?;           // JIT, ZeroizeOnDrop
    let ok = session.authenticate_publickey(&p.username, keypair_from_seed(&secrets.client_private_seed))
        .await.map_err(|e| NetError::Ssh(e.to_string()))?;
    if !ok { return Err(UnlockError::AuthRejected); }
    on(UnlockEvent::Authenticated);

    let t = Duration::from_secs(p.exec_timeout_s as u64);
    let mut targets = p.targets_meta.clone();
    targets.sort_by_key(|x| x.order);
    for tm in &targets {
        on(UnlockEvent::TargetStart(tm.mapped_name.clone()));
        let key = secrets.keyfiles.iter().find(|k| k.luks_uuid == tm.luks_uuid)
            .ok_or(VaultError::Invariant("missing keyfile"))?;

        // Stage keyfile in tmpfs (binary safe, avoids stdin newline truncation)
        let cmd = format!("sudo sh -c 'umask 077 && cat > /run/ltv/key'");
        if let Some(v) = verbose.as_mut() { v(&cmd); }
        let r = exec(&mut session, &cmd, Some(&key.keyfile), t).await?;
        if r.code != 0 {
            if let Some(v) = verbose.as_mut() { v(&format!("  [unlock] ! exit={} stderr: {}", r.code, r.stderr.trim())); }
            return Err(UnlockError::CryptsetupFailed { target: tm.mapped_name.clone(), code: r.code, stderr: r.stderr });
        }

        // Use tmpfs file for unlock
        let cmd = format!("cryptsetup luksOpen --key-file=/run/ltv/key UUID={} {}", tm.luks_uuid, tm.mapped_name);
        if let Some(v) = verbose.as_mut() { v(&cmd); }
        let mut r = exec(&mut session, &cmd, None, t).await?;
        if r.code != 0 && r.stderr.to_lowercase().contains("not exist") {
            if let Some(fp) = &tm.fallback_path {
                let cmd = format!("cryptsetup luksOpen --key-file=/run/ltv/key {} {}", fp, tm.mapped_name);
                if let Some(v) = verbose.as_mut() { v(&cmd); }
                r = exec(&mut session, &cmd, None, t).await?;
            }
        }
        if r.code != 0 {
            if let Some(v) = verbose.as_mut() { v(&format!("  [unlock] ! exit={} stderr: {}", r.code, r.stderr.trim())); }
        }
        match r.code {
            0 => on(UnlockEvent::TargetDone(tm.mapped_name.clone())),
            2 => return Err(UnlockError::KeyRejected(tm.mapped_name.clone())),
            5 => on(UnlockEvent::TargetAlreadyOpen(tm.mapped_name.clone())),
            c => return Err(UnlockError::CryptsetupFailed { target: tm.mapped_name.clone(), code: c, stderr: r.stderr }),
        }

        // Cleanup keyfile
        let cmd = format!("sudo rm -f /run/ltv/key");
        if let Some(v) = verbose.as_mut() { v(&cmd); }
        let _ = exec(&mut session, &cmd, None, t).await;
    }

    if let ResumePolicy::Command(c) = &p.resume {
        if let Some(v) = &mut verbose { v(c); }
        let r = exec(&mut session, c, None, t).await?;
        if r.code != 0 {
            if let Some(v) = verbose.as_mut() { v(&format!("  [unlock] ! exit={} stderr: {}", r.code, r.stderr.trim())); }
            return Err(UnlockError::ResumeFailed(r.stderr));
        }
        on(UnlockEvent::ResumeSent);
    }
    let _ = session.disconnect(russh::Disconnect::ByApplication, "done", "en").await;
    drop(secrets);
    on(UnlockEvent::Disconnected);
    Ok(())
}