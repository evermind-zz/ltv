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

use std::{sync::{Arc, Mutex}, time::Duration};
use secrecy::ExposeSecret;
use crate::constants::*;
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

impl std::fmt::Display for UnlockEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnlockEvent::Connecting => write!(f, "connecting to unlock SSH"),
            UnlockEvent::HostKeyVerified => write!(f, "unlock SSH host key verified"),
            UnlockEvent::Authenticated => write!(f, "authenticated"),
            UnlockEvent::TargetStart(t) => write!(f, "{t}: unlocking"),
            UnlockEvent::TargetDone(t) => write!(f, "{t}: unlocked"),
            UnlockEvent::TargetAlreadyOpen(t) => write!(f, "{t}: already open"),
            UnlockEvent::ResumeSent => write!(f, "signaled initramfs to resume boot"),
            UnlockEvent::Disconnected => write!(f, "disconnected"),
        }
    }
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
    let h = Hk { expected: expected.clone(), seen: seen.clone() };
    let fut = client::connect(cfg(connect_s), (host, port), h);
    let res = timeout(Duration::from_secs(connect_s as u64), fut).await
        .map_err(|_| NetError::Timeout)?;
    let presented = seen.lock().unwrap().clone();
    match res {
        Ok(s) => Ok((s, presented.expect("key seen on successful kex"))),
        // russh returns UnknownKey when check_server_key said false
        Err(russh::Error::UnknownKey) => {
            let actual = presented.expect("key seen during kex");
            let expected = expected.expect("expected key required for mismatch");
            Err(UnlockError::HostKeyMismatch(HostKeyMismatchError { expected, actual }))
        }
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
    if let Some(v) = verbose.as_mut() { v(&format!("Connecting to {}:{} (timeout {}s)", p.unlock_host, p.unlock_port, p.connect_timeout_s)); }
    match connect(&p.unlock_host, p.unlock_port, p.connect_timeout_s, None).await {
        Err(UnlockError::Net(NetError::Timeout)) => ProbeResult::Unreachable("timeout".into()),
        Err(e) => ProbeResult::Unreachable(e.to_string()),
        Ok((s, k)) => {
            if let Some(v) = verbose.as_mut() { v(&format!("SSH host key: {} {}", k.key_type, fingerprint_sha256(&k.key_bytes))); }
            let _ = s.disconnect(russh::Disconnect::ByApplication, "", "en").await;
            if p.unlock_host_key.as_ref() == Some(&k) { ProbeResult::WaitingInInitramfs }
            else if p.os_host_key.as_ref() == Some(&k) { ProbeResult::BootedOs }
            else { ProbeResult::UnknownHostKey(k) }
        }
    }
}

pub(crate) struct ExecResult { pub code: u32, pub stdout: String, pub stderr: String }

pub(crate) async fn exec<Hk: russh::client::Handler>(session: &client::Handle<Hk>, cmd: &str, stdin: Option<&[u8]>, t: Duration)
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

/// Stage binary data to a tmpfs file on the remote (umask 077, mkdir -p).
/// `sudo` prefix (e.g. "sudo -n ") can be empty. Returns Ok(()) or NetError.
pub(crate) async fn tmpfs_stage<Hk: russh::client::Handler>(
    session: &client::Handle<Hk>,
    path: &str,
    data: &[u8],
    sudo: &str,
    timeout: Duration,
) -> Result<(), NetError> {
    // Create the parent directory so per-target paths like /run/ltv/0/key work.
    let dir = std::path::Path::new(path)
        .parent()
        .and_then(|p| p.to_str())
        .filter(|d| !d.is_empty())
        .unwrap_or(TMPFS_BASE);
    let cmd = format!("{}sh -c 'umask {UMASK_TMPFS} && mkdir -p {dir} && cat > {path}'", sudo);
    let r = exec(session, &cmd, Some(data), timeout).await?;
    if r.code != 0 {
        return Err(NetError::Ssh(format!(
            "tmpfs stage failed: exit {}: {}", r.code, r.stderr.trim()
        )));
    }
    Ok(())
}

/// Remove tmpfs files on the remote.
/// `sudo` prefix (e.g. "sudo -n ") can be empty. Best-effort, errors ignored.
pub(crate) async fn tmpfs_cleanup<Hk: russh::client::Handler>(
    session: &client::Handle<Hk>,
    paths: &[&str],
    sudo: &str,
    timeout: Duration,
) -> Result<(), NetError> {
    if paths.is_empty() { return Ok(()); }
    let cmd = format!("{}rm -f {}", sudo, paths.join(" "));
    let _ = exec(session, &cmd, None, timeout).await;
    Ok(())
}

/// Connect to host:port, verify host key matches `expected`, then authenticate.
/// Auth methods: "ed25519" with seed, or "password" with SecretString.
/// Returns authenticated session + presented HostKey.
pub(crate) async fn connect_and_auth(
    host: &str,
    port: u16,
    connect_timeout: u16,
    expected_key: Option<HostKey>,
    username: &str,
    auth: &BootedAuth,
) -> Result<(client::Handle<Hk>, HostKey), UnlockError> {
    let (mut session, presented) = connect(host, port, connect_timeout, expected_key).await?;
    let ok = match auth {
        BootedAuth::Password(pw) => session.authenticate_password(username, pw.expose_secret()).await,
        BootedAuth::Ed25519Seed(seed) => session.authenticate_publickey(username, keypair_from_seed(seed)).await,
    }.map_err(|e| NetError::Ssh(e.to_string()))?;
    if !ok { return Err(UnlockError::AuthRejected); }
    Ok((session, presented))
}

/// Result of fetching LUKS details from a booted server
#[derive(Debug, Clone, serde::Serialize)]
pub struct FetchedLuksInfo {
    pub luks_uuid: String,
    pub device_path: String,
    pub cipher: String,
    pub key_size: u32,
    pub header_version: String,
    pub mapper_name: Option<String>,  // active dm-crypt mapping if decrypted
}

/// Connect to the booted OS and discover all LUKS volumes.
/// Uses the profile's os_host_key (must be pinned first).
/// Auth: either the client's Ed25519 key (from vault) or password via BootedAuth.
/// If `verbose` is provided, it will be called with each command executed on the target.
pub async fn fetch_luks_info(
    vault: &Vault, uuid: &[u8; 16], access: &BootedAccess, _only_mapped: Option<&str>,
    mut verbose: Option<Box<dyn FnMut(&str) + Send>>,
) -> Result<Vec<FetchedLuksInfo>, UnlockError> {
    let p = vault.profile(uuid)?.clone();
    let os_key = p.os_host_key.clone().ok_or(UnlockError::HostKeyNotPinned)?;

    // Resolve OS address (fallback to unlock SSH address if not set)
    let os_host = p.os_host.as_deref().unwrap_or(&p.unlock_host);
    let os_port = p.os_port.unwrap_or(p.unlock_port);

    let (mut s, _) = connect_and_auth(os_host, os_port, access.connect_timeout_s, Some(os_key), &access.username, &access.auth).await?;

    let sudo = if access.use_sudo && access.username != "root" { "sudo -n " } else { "" };
    let t = Duration::from_secs(p.exec_timeout_s.max(30) as u64);

    // Find all LUKS devices via lsblk (works on Alpine with util-linux)
    let cmd = format!("{sudo}lsblk -J -o NAME,UUID,TYPE,FSTYPE,MOUNTPOINT");
    if let Some(v) = verbose.as_mut() { v(&cmd); }
    let r = exec(&mut s, &cmd, None, t).await?;
    if r.code != 0 {
        if let Some(v) = verbose.as_mut() { v(&format!("  [fetch] ! cmd={} exit={} stderr: {}", &cmd, r.code, r.stderr.trim())); }
        return Err(UnlockError::CryptsetupFailed { target: "discovery".into(), code: r.code, stderr: r.stderr });
    }

    // Parse JSON output
    use serde_json::Value;
    let json: Value = match serde_json::from_str(&r.stdout) {
        Ok(v) => v,
        Err(e) => {
            if let Some(v) = verbose.as_mut() { v(&format!("  [fetch] JSON parse error: {}", e)); }
            return Err(UnlockError::CryptsetupFailed { target: "discovery".into(), code: 1, stderr: format!("JSON parse: {}", e) });
        }
    };

    /// Find LUKS devices and their active mapper (if decrypted)
    /// Returns (luks_uuid, device_name, mapper_name)
    fn find_luks_devices(dev: &Value, results: &mut Vec<(String, String, Option<String>)>) {
        if let Some(fstype) = dev.get("fstype").and_then(|v| v.as_str()) {
            if fstype == "crypto_LUKS" {
                if let (Some(uuid), Some(name)) = (
                    dev.get("uuid").and_then(|v| v.as_str()),
                    dev.get("name").and_then(|v| v.as_str()),
                ) {
                    if !uuid.is_empty() && !name.is_empty() {
                        // Look for active mapper in children (TYPE="crypt")
                        let mapper = find_crypt_mapper(dev);
                        results.push((uuid.to_string(), name.to_string(), mapper));
                    }
                }
            }
        }
        if let Some(children) = dev.get("children").and_then(|v| v.as_array()) {
            for child in children {
                find_luks_devices(child, results);
            }
        }
    }

    fn find_crypt_mapper(dev: &Value) -> Option<String> {
        if let Some(children) = dev.get("children").and_then(|v| v.as_array()) {
            for child in children {
                if let Some(ctype) = child.get("type").and_then(|v| v.as_str()) {
                    if ctype == "crypt" {
                        if let Some(name) = child.get("name").and_then(|v| v.as_str()) {
                            if !name.is_empty() {
                                return Some(name.to_string());
                            }
                        }
                    }
                }
            }
        }
        None
    }

    let mut luks_devices = Vec::new();
    if let Some(blockdevices) = json.get("blockdevices").and_then(|v| v.as_array()) {
        for dev in blockdevices {
            find_luks_devices(dev, &mut luks_devices);
        }
    }

    let mut results = Vec::new();
    for (uuid, name, mapper) in luks_devices {
        let dev_path = format!("/dev/{}", name);

        // Get LUKS details
        let cmd = format!("{sudo}{CRYPTSETUP} {CMD_LUKS_DUMP} UUID={}", uuid);
        if let Some(v) = verbose.as_mut() { v(&cmd); }
        let dump = exec(&mut s, &cmd, None, t).await?;
        if dump.code != 0 {
            if let Some(v) = verbose.as_mut() { v(&format!("  [fetch] ! cmd={} exit={} stderr: {}", &cmd, dump.code, dump.stderr.trim())); }
        } else {
            let mut cipher = String::new();
            let mut key_size = 0;
            let mut version = String::new();
            for dl in dump.stdout.lines() {
                let dl = dl.trim();
                if dl.starts_with("cipher:") { cipher = dl["cipher:".len()..].trim().to_string(); }
                else if dl.starts_with("Cipher:") { cipher = dl["Cipher:".len()..].trim().to_string(); }
                else if dl.starts_with("Key:") { key_size = dl["Key:".len()..].trim().split_whitespace().next().unwrap_or("0").to_string().parse().unwrap_or(0); }
                else if dl.starts_with("Version:") { version = dl["Version:".len()..].trim().to_string(); }
            }
            results.push(FetchedLuksInfo {
                luks_uuid: uuid.to_string(),
                device_path: dev_path,
                cipher,
                key_size,
                header_version: version,
                mapper_name: mapper,
            });
        }
    }

    let _ = s.disconnect(russh::Disconnect::ByApplication, "done", "en").await;
    Ok(results)
}
 
pub async fn unlock(
    vault: &Vault, uuid: &[u8; 16], mode: ExecutionMode,
    mut on: impl FnMut(UnlockEvent),
    mut verbose: Option<Box<dyn FnMut(&str) + Send>>,
) -> Result<(), UnlockError> {
    let p = vault.profile(uuid)?.clone();
    let expected = p.unlock_host_key.clone().ok_or(UnlockError::HostKeyNotPinned)?;
    on(UnlockEvent::Connecting);

    let connect_result = connect(&p.unlock_host, p.unlock_port, p.connect_timeout_s, Some(expected)).await;
    let (mut session, _) = match connect_result {
        Ok(r) => r,
        Err(UnlockError::HostKeyMismatch(e)) => {
            let probe_result = probe(&p, None).await;
            if matches!(probe_result, ProbeResult::BootedOs) {
                return Err(UnlockError::StateBootedOs);
            } else {
                return Err(UnlockError::HostKeyMismatch(e));
            }
        }
        Err(e) => return Err(e),
    };
    on(UnlockEvent::HostKeyVerified);

    let secrets = vault.open_secrets(&p)?;           // JIT, ZeroizeOnDrop
    let ok = session.authenticate_publickey(&p.username, keypair_from_seed(&secrets.client_private_seed))
        .await.map_err(|e| NetError::Ssh(e.to_string()))?;
    if !ok { return Err(UnlockError::AuthRejected); }
    on(UnlockEvent::Authenticated);

    let t = Duration::from_secs(p.exec_timeout_s as u64);
    let sudo = ""; // initramfs runs as root, no sudo needed
    let mut targets = p.targets_meta.clone();
    targets.sort_by_key(|x| x.order);

    match mode {
        ExecutionMode::Sequential => {
            for (idx, tm) in targets.iter().enumerate() {
                process_unlock_target(idx, &mut session, tm, &secrets, sudo, t, &mut on, &mut verbose).await?;
            }
        }
        ExecutionMode::Parallel => {
            process_unlock_targets_parallel(&targets, &session, &secrets, sudo, t, &mut on, &mut verbose).await?;
        }
    }

    // Signal completion to ltv-luks-wrapper on initramfs
    let resume_cmd = "touch /run/ltv/resume";
    if let Some(v) = verbose.as_mut() { v(&format!("  [unlock] $ {}", resume_cmd)); }
    let r = exec(&mut session, resume_cmd, None, t).await?;
    if r.code != 0 {
        if let Some(v) = verbose.as_mut() { v(&format!("  [unlock] ! cmd={} exit={} stderr: {}", resume_cmd, r.code, r.stderr.trim())); }
        return Err(UnlockError::ResumeFailed(r.stderr));
    }
    on(UnlockEvent::ResumeSent);

    let _ = session.disconnect(russh::Disconnect::ByApplication, "done", "en").await;
    drop(secrets);
    on(UnlockEvent::Disconnected);
    Ok(())
}


/// Sequential helper: processes one target on the given session.
async fn process_unlock_target(
    idx: usize,
    session: &client::Handle<Hk>,
    tm: &TargetMeta,
    secrets: &SecretPayload,
    sudo: &str,
    t: Duration,
    on: &mut dyn FnMut(UnlockEvent),
    verbose: &mut Option<Box<dyn FnMut(&str) + Send>>,
) -> Result<(), UnlockError> {
    on(UnlockEvent::TargetStart(tm.mapped_name.clone()));
    let key = secrets.keyfiles.iter().find(|k| k.luks_uuid == tm.luks_uuid)
        .ok_or(VaultError::Invariant("missing keyfile"))?;

    let keyfile = target_keyfile(idx);

    // Stage keyfile in tmpfs (binary safe, avoids stdin newline truncation)
    if let Some(v) = verbose.as_mut() {
        v(&format!("  [unlock] $ sh -c 'umask {UMASK_TMPFS} && mkdir -p {} && cat > {}'", target_tmpfs_dir(idx), keyfile));
    }
    tmpfs_stage(session, &keyfile, &key.keyfile, sudo, t).await?;

    // Stage metadata for ltv-luks-wrapper (mapper name, uuid, order)
    let mapper_file = format!("{}/mapper", target_tmpfs_dir(idx));
    let uuid_file = format!("{}/uuid", target_tmpfs_dir(idx));
    let order_file = format!("{}/order", target_tmpfs_dir(idx));
    tmpfs_stage(session, &mapper_file, tm.mapped_name.as_bytes(), sudo, t).await?;
    tmpfs_stage(session, &uuid_file, tm.luks_uuid.as_bytes(), sudo, t).await?;
    tmpfs_stage(session, &order_file, idx.to_string().as_bytes(), sudo, t).await?;

    // Use tmpfs file for unlock
    let mut cmd = format!("{CRYPTSETUP} {CMD_LUKS_OPEN} {ARG_KEY_FILE}={} UUID={} {}", keyfile, tm.luks_uuid, tm.mapped_name);
    if let Some(v) = verbose.as_mut() { v(&cmd); }
    let mut r = exec(session, &cmd, None, t).await?;
    if r.code != 0 && r.stderr.to_lowercase().contains("not exist") {
        if let Some(fp) = &tm.fallback_path {
            cmd = format!("{CRYPTSETUP} {CMD_LUKS_OPEN} {ARG_KEY_FILE}={} {} {}", keyfile, fp, tm.mapped_name);
            if let Some(v) = verbose.as_mut() { v(&cmd); }
            r = exec(session, &cmd, None, t).await?;
        }
    }
    if r.code != 0 {
        if let Some(v) = verbose.as_mut() { v(&format!("  [unlock] ! cmd={} exit={} stderr: {}", &cmd, r.code, r.stderr.trim())); }
    }

    // Cleanup keyfile and metadata files
    let mapper_file = format!("{}/mapper", target_tmpfs_dir(idx));
    let uuid_file = format!("{}/uuid", target_tmpfs_dir(idx));
    let order_file = format!("{}/order", target_tmpfs_dir(idx));
    tmpfs_cleanup(session, &[&keyfile, &mapper_file, &uuid_file, &order_file], sudo, t).await?;

    match r.code {
        0 => on(UnlockEvent::TargetDone(tm.mapped_name.clone())),
        2 => return Err(UnlockError::KeyRejected(tm.mapped_name.clone())),
        5 => on(UnlockEvent::TargetAlreadyOpen(tm.mapped_name.clone())),
        c => return Err(UnlockError::CryptsetupFailed { target: tm.mapped_name.clone(), code: c, stderr: r.stderr }),
    }
    Ok(())
}

/// Message emitted from a parallel unlock task back to the driver loop.
enum UnlockMsg {
    Event(UnlockEvent),
    Verbose(String),
}

/// Unlocks every target concurrently on independent SSH channels of one
/// authenticated session. Concurrency is bounded so we don't overwhelm the
/// initramfs SSH daemon.
async fn process_unlock_targets_parallel(
    targets: &[TargetMeta],
    session: &client::Handle<Hk>,
    secrets: &SecretPayload,
    sudo: &str,
    t: Duration,
    on: &mut dyn FnMut(UnlockEvent),
    verbose: &mut Option<Box<dyn FnMut(&str) + Send>>,
) -> Result<(), UnlockError> {
    use futures::stream::{FuturesUnordered, StreamExt};
    use tokio::sync::{mpsc, Semaphore};

    if let Some(v) = verbose.as_mut() { v(&format!("running {} target(s) in parallel", targets.len())); }

    let semaphore = Semaphore::new(MAX_CONCURRENT_TARGETS);
    let (tx, mut rx) = mpsc::unbounded_channel::<UnlockMsg>();

    let mut futs: FuturesUnordered<_> = targets.iter().enumerate().map(|(idx, tm)| {
        let tx = tx.clone();
        let sem = &semaphore;
        async move {
            let _permit = sem.acquire().await;
            let res: Result<(), UnlockError> = async {
                let key = secrets.keyfiles.iter().find(|k| k.luks_uuid == tm.luks_uuid)
                    .ok_or(VaultError::Invariant("missing keyfile"))?;
                let keyfile = target_keyfile(idx);

                let stage_cmd = format!(
                    "sh -c 'umask {UMASK_TMPFS} && mkdir -p {} && cat > {}'",
                    target_tmpfs_dir(idx), keyfile);
                let _ = tx.send(UnlockMsg::Verbose(stage_cmd));
                let _ = tx.send(UnlockMsg::Event(UnlockEvent::TargetStart(tm.mapped_name.clone())));
                tmpfs_stage(session, &keyfile, &key.keyfile, sudo, t).await?;

                // Stage metadata for ltv-luks-wrapper (mapper name, uuid, order)
                let mapper_file = format!("{}/mapper", target_tmpfs_dir(idx));
                let uuid_file = format!("{}/uuid", target_tmpfs_dir(idx));
                let order_file = format!("{}/order", target_tmpfs_dir(idx));
                tmpfs_stage(session, &mapper_file, tm.mapped_name.as_bytes(), sudo, t).await?;
                tmpfs_stage(session, &uuid_file, tm.luks_uuid.as_bytes(), sudo, t).await?;
                tmpfs_stage(session, &order_file, idx.to_string().as_bytes(), sudo, t).await?;

                let mut cmd = format!("{CRYPTSETUP} {CMD_LUKS_OPEN} {ARG_KEY_FILE}={} UUID={} {}", keyfile, tm.luks_uuid, tm.mapped_name);
                let _ = tx.send(UnlockMsg::Verbose(cmd.clone()));
                let mut r = exec(session, &cmd, None, t).await?;
                if r.code != 0 && r.stderr.to_lowercase().contains("not exist") {
                    if let Some(fp) = &tm.fallback_path {
                        cmd = format!("{CRYPTSETUP} {CMD_LUKS_OPEN} {ARG_KEY_FILE}={} {} {}", keyfile, fp, tm.mapped_name);
                        let _ = tx.send(UnlockMsg::Verbose(cmd.clone()));
                        r = exec(session, &cmd, None, t).await?;
                    }
                }
                if r.code != 0 {
                    let _ = tx.send(UnlockMsg::Verbose(format!(
                        "! cmd={} exit={} stderr: {}", &cmd, r.code, r.stderr.trim())));
                }
                let mapper_file = format!("{}/mapper", target_tmpfs_dir(idx));
                let uuid_file = format!("{}/uuid", target_tmpfs_dir(idx));
                let order_file = format!("{}/order", target_tmpfs_dir(idx));
                let _ = tmpfs_cleanup(session, &[&keyfile, &mapper_file, &uuid_file, &order_file], sudo, t).await;

                match r.code {
                    0 => { let _ = tx.send(UnlockMsg::Event(UnlockEvent::TargetDone(tm.mapped_name.clone()))); Ok(()) }
                    2 => Err(UnlockError::KeyRejected(tm.mapped_name.clone())),
                    5 => { let _ = tx.send(UnlockMsg::Event(UnlockEvent::TargetAlreadyOpen(tm.mapped_name.clone()))); Ok(()) }
                    c => Err(UnlockError::CryptsetupFailed { target: tm.mapped_name.clone(), code: c, stderr: r.stderr }),
                }
            }.await;
            res
        }
    }).collect();

    let mut first_err: Option<UnlockError> = None;
    let mut pending = targets.len();

    while pending > 0 {
        tokio::select! {
            biased;
            Some(msg) = rx.recv() => match msg {
                UnlockMsg::Event(e) => on(e),
                UnlockMsg::Verbose(s) => { if let Some(v) = verbose.as_mut() { v(&s); } }
            },
            Some(res) = futs.next() => {
                pending -= 1;
                if let Err(e) = res {
                    if first_err.is_none() { first_err = Some(e); }
                }
            }
        }
    }

    // Drain any buffered messages.
    while let Ok(msg) = rx.try_recv() {
        match msg {
            UnlockMsg::Event(e) => on(e),
            UnlockMsg::Verbose(s) => { if let Some(v) = verbose.as_mut() { v(&s); } }
        }
    }

    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}
