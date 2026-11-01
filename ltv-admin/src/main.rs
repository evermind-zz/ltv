use std::{fs, path::PathBuf};
use ltv_core::{format::Argon2Params, model::*, net, vault::Vault, enroll::{BootedAccess, BootedAuth, EnrollEvent}};
use rustyline::{error::ReadlineError, DefaultEditor};
use secrecy::{ExposeSecret, SecretString, SecretVec};

struct State { path: Option<PathBuf>, vault: Option<Vault> }

fn pass(prompt: &str) -> SecretVec<u8> {
    SecretVec::new(rpassword::prompt_password(prompt).unwrap_or_default().into_bytes())
}
fn ask(prompt: &str) -> String {
    use std::io::{self, Write};
    print!("{prompt}"); io::stdout().flush().ok();
    let mut s = String::new(); io::stdin().read_line(&mut s).ok(); s.trim().to_string()
}
fn ask_or(prompt: &str, default: &str) -> String {
    let v = ask(&format!("{prompt} [{default}]: ")); if v.is_empty() { default.into() } else { v }
}

fn save_atomic(st: &mut State) -> Result<(), String> {
    let path = st.path.clone().ok_or("no vault open")?;
    let v = st.vault.as_mut().ok_or("no vault open")?;
    let bytes = v.save().map_err(|e| e.to_string())?;
    let tmp = path.with_extension("ltv.tmp");
    fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
    if path.exists() { let _ = fs::copy(&path, path.with_extension("ltv.bak")); }
    fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    println!("saved {}", path.display());
    Ok(())
}

fn resolve<'a>(v: &'a Vault, name: &str) -> Result<&'a Profile, String> {
    v.find_by_name(name).ok_or_else(|| format!("profile '{name}' not found"))
}

fn cmd_add(st: &mut State) -> Result<(), String> {
    let v = st.vault.as_mut().ok_or("no vault open")?;
    let name = ask("Profile name: ");
    let host = ask("Host (IP/DNS): ");
    let port: u16 = ask_or("Port", "22").parse().map_err(|_| "bad port")?;
    let user = ask_or("Username", "root");
    let uuid = v.add_profile(&name, &host, port, &user).map_err(|e| e.to_string())?;
    loop {
        let luks_uuid = ask("LUKS UUID (blank = done): ");
        if luks_uuid.is_empty() { break; }
        let fallback = ask("Fallback device path (optional): ");
        let mapped = ask_or("Mapper name", "cryptroot");
        let order: u8 = ask_or("Order", "0").parse().unwrap_or(0);
        let meta = TargetMeta { luks_uuid, fallback_path: if fallback.is_empty() { None } else { Some(fallback) },
                                mapped_name: mapped, order, keyslot: None, token_id: None };
        v.add_target(&uuid, meta, None).map_err(|e| e.to_string())?;
        println!("  target added, 64-byte keyfile generated.");
    }
    let p = v.profile(&uuid).map_err(|e| e.to_string())?.clone();
    println!("\nClient public key (deploy to initramfs authorized_keys):\n{}", v.authorized_keys_line(&p));
    println!("Next: 'hostkey fetch {name}' once the server is in initramfs, then 'enroll {name}'.");
    Ok(())
}

async fn cmd_enroll(st: &mut State, name: &str, only: Option<&str>) -> Result<(), String> {
    let v = st.vault.as_mut().ok_or("no vault open")?;
    let p = resolve(v, name)?.clone();

    // OS host key must be pinned first (admin-only TOFU)
    if p.os_host_key.is_none() {
        println!("No OS host key pinned. Fetching from {}:{} ...", p.host, p.port);
        let hk = net::fetch_host_key(&p.host, p.port, p.connect_timeout_s).await.map_err(|e| e.to_string())?;
        println!("{} {}", hk.key_type, fingerprint_sha256(&hk.key_bytes));
        if ask("Pin as OS host key? [y/N]: ").to_lowercase() != "y" { return Err("aborted".into()); }
        v.set_host_key(&p.uuid, hk, true).map_err(|e| e.to_string())?;
    }

    let username = ask_or("OS SSH user", "root");
    let auth = match ask_or("Auth: (p)assword / (k)ey file", "k").as_str() {
        "p" => BootedAuth::Password(SecretString::new(rpassword::prompt_password("OS password: ").unwrap_or_default())),
        _ => {
            let path = ask_or("Key file", &format!("{}/.ssh/id_ed25519", std::env::var("HOME").unwrap_or_default()));
            let kp = russh_keys::load_secret_key(&path, None)
                .or_else(|_| russh_keys::load_secret_key(&path, Some(&rpassword::prompt_password("Key passphrase: ").unwrap_or_default())))
                .map_err(|e| format!("load key: {e}"))?;
            match kp {
                russh_keys::key::KeyPair::Ed25519(sk) => BootedAuth::Ed25519Seed(sk.to_bytes()),
                _ => return Err("only Ed25519 keys supported".into()),
            }
        }
    };
    let access = BootedAccess { use_sudo: username != "root", username, auth, connect_timeout_s: p.connect_timeout_s };
    let luks_pass = SecretString::new(rpassword::prompt_password("Existing LUKS passphrase: ").unwrap_or_default());

    let results = ltv_core::enroll(v, &p.uuid, &access, &luks_pass, only, |e| match e {
        EnrollEvent::Skipped(t, why) => println!(" ! {t}: skipped ({why})"),
        other => println!(" ✓ {other:?}"),
    }).await.map_err(|e| e.to_string())?;

    for r in &results { v.set_keyslot(&p.uuid, &r.luks_uuid, r.keyslot).map_err(|e| e.to_string())?; }
    println!("enrolled {} target(s); keyslots recorded. Remember to 'save'.", results.len());
    Ok(())
}

async fn dispatch(st: &mut State, line: &str) -> Result<bool, String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    match parts.as_slice() {
        [] => {}
        ["quit"] | ["exit"] => {
            if st.vault.as_ref().map(|v| v.is_dirty()).unwrap_or(false) {
                if ask("Unsaved changes. Save? [Y/n]: ").to_lowercase() != "n" { save_atomic(st)?; }
            }
            return Ok(true);
        }
        ["help"] => println!("create <file> | open <file> | save | close | status | ls | show <p> | add | rm <p>\n\
                              edit <p> [field=value ...] | target add <p> | target rm <p> <uuid>\n\
                              pubkey <p> | hostkey fetch <p> [--os] | probe <p>|--all | unlock <p> | enroll <p> [--target <uuid|mapper>] | passwd | quit"),
        ["create", f] => {
            let p1 = pass("New passphrase: "); let p2 = pass("Repeat: ");
            if p1.expose_secret() != p2.expose_secret() { return Err("passphrases differ".into()); }
            st.vault = Some(Vault::create(&p1, Argon2Params::default()).map_err(|e| e.to_string())?);
            st.path = Some(PathBuf::from(f));
            save_atomic(st)?;
        }
        ["open", f] => {
            let bytes = fs::read(f).map_err(|e| e.to_string())?;
            let v = Vault::open(&bytes, &pass("Passphrase: ")).map_err(|e| e.to_string())?;
            println!("opened: {} profiles", v.inventory.profiles.len());
            st.vault = Some(v); st.path = Some(PathBuf::from(f));
        }
        ["save"] => save_atomic(st)?,
        ["close"] => { st.vault = None; st.path = None; }
        ["status"] => match (&st.path, &st.vault) {
            (Some(p), Some(v)) => println!("{} — {} profiles, dirty={}", p.display(), v.inventory.profiles.len(), v.is_dirty()),
            _ => println!("no vault open"),
        },
        ["ls"] => for p in &st.vault.as_ref().ok_or("no vault open")?.inventory.profiles {
            println!("{:<16} {:<24} targets={} hostkey={}", p.name, format!("{}:{}", p.host, p.port),
                     p.targets_meta.len(), if p.initramfs_host_key.is_some() { "pinned" } else { "MISSING" });
        },
        ["show", n] => {
            let v = st.vault.as_ref().ok_or("no vault open")?; let p = resolve(v, n)?;
            println!("name: {}\nhost: {}:{} user {}\nuuid: {}", p.name, p.host, p.port, p.username, uuid::Uuid::from_bytes(p.uuid));
            if let Some(k) = &p.initramfs_host_key { println!("initramfs hostkey: {} {}", k.key_type, fingerprint_sha256(&k.key_bytes)); }
            for t in &p.targets_meta { 
                let fallback = t.fallback_path.as_deref().unwrap_or("none");
                println!("  target {} UUID={} fallback={} slot={:?}", t.mapped_name, t.luks_uuid, fallback, t.keyslot); 
            }
            println!("pubkey: {}", v.export_public_key(p));
        }
        ["add"] => cmd_add(st)?,
        ["rm", n] => {
            let v = st.vault.as_mut().ok_or("no vault open")?;
            let uuid = resolve(v, n)?.uuid;
            if ask(&format!("Remove '{n}'? type YES: ")) == "YES" { v.remove_profile(&uuid).map_err(|e| e.to_string())?; }
        }
        ["edit", n, rest @ ..] => {
            let v = st.vault.as_mut().ok_or("no vault open")?;
            let uuid = resolve(v, n)?.uuid;
            let mut p = v.profile(&uuid).map_err(|e| e.to_string())?.clone();
            let mut changed = false;
            for arg in rest {
                if let Some((k, v)) = arg.split_once('=') {
                    match k {
                        "name" => { p.name = v.into(); changed = true; }
                        "host" => { p.host = v.into(); changed = true; }
                        "port" => { p.port = v.parse().map_err(|_| "bad port")?; changed = true; }
                        "user" | "username" => { p.username = v.into(); changed = true; }
                        "notes" => { p.notes = v.into(); changed = true; }
                        "connect_timeout" => { p.connect_timeout_s = v.parse().map_err(|_| "bad timeout")?; changed = true; }
                        "exec_timeout" => { p.exec_timeout_s = v.parse().map_err(|_| "bad timeout")?; changed = true; }
                        "resume" => {
                            if v == "poll" { p.resume = ResumePolicy::DeviceMapperPoll; }
                            else { p.resume = ResumePolicy::Command(v.into()); }
                            changed = true;
                        }
                        _ => return Err(format!("unknown field: {k}")),
                    }
                }
            }
            if changed { v.update_profile(&uuid, |p2| *p2 = p).map_err(|e| e.to_string())?; println!("profile updated"); } else { println!("no changes"); }
        }
        ["target", "add", n] => {
            let v = st.vault.as_mut().ok_or("no vault open")?;
            let uuid = resolve(v, n)?.uuid;
            let luks_uuid = ask("LUKS UUID: "); if luks_uuid.is_empty() { return Err("uuid required".into()); }
            let fallback = ask("Fallback device path (optional): ");
            let mapped = ask_or("Mapper name", "cryptroot");
            let order: u8 = ask_or("Order", "0").parse().unwrap_or(0);
            let meta = TargetMeta { luks_uuid, fallback_path: if fallback.is_empty() { None } else { Some(fallback) },
                                mapped_name: mapped, order, keyslot: None, token_id: None };
            v.add_target(&uuid, meta, None).map_err(|e| e.to_string())?;
            println!("  target added, 64-byte keyfile generated.");
        }
        ["target", "rm", n, uuid_str] => {
            let v = st.vault.as_mut().ok_or("no vault open")?;
            let uuid = resolve(v, n)?.uuid;
            v.remove_target(&uuid, uuid_str).map_err(|e| e.to_string())?;
            println!("target removed");
        }
        ["pubkey", n] => { let v = st.vault.as_ref().ok_or("no vault open")?; println!("{}", v.authorized_keys_line(resolve(v, n)?)); }
        ["hostkey", "fetch", n, rest @ ..] => {
            let v = st.vault.as_mut().ok_or("no vault open")?;
            let p = resolve(v, n)?.clone();
            let hk = net::fetch_host_key(&p.host, p.port, p.connect_timeout_s).await.map_err(|e| e.to_string())?;
            println!("{} {}", hk.key_type, fingerprint_sha256(&hk.key_bytes));
            if ask("Pin this key? [y/N]: ").to_lowercase() == "y" {
                v.set_host_key(&p.uuid, hk, rest.contains(&"--os")).map_err(|e| e.to_string())?;
            }
        }
        ["probe", n] => {
            let v = st.vault.as_ref().ok_or("no vault open")?;
            let ps: Vec<Profile> = if *n == "--all" { v.inventory.profiles.clone() } else { vec![resolve(v, n)?.clone()] };
            for p in ps { println!("{:<16} {:?}", p.name, net::probe(&p).await); }
        }
        ["unlock", n] => {
            let v = st.vault.as_ref().ok_or("no vault open")?;
            let uuid = resolve(v, n)?.uuid;
            net::unlock(v, &uuid, |e| println!(" ✓ {e:?}")).await.map_err(|e| e.to_string())?;
        }
        ["enroll", n] => cmd_enroll(st, n, None).await?,
        ["enroll", n, "--target", t] => cmd_enroll(st, n, Some(t)).await?,
        ["passwd"] => {
            let v = st.vault.as_mut().ok_or("no vault open")?;
            let p1 = pass("New passphrase: "); let p2 = pass("Repeat: ");
            if p1.expose_secret() != p2.expose_secret() { return Err("passphrases differ".into()); }
            v.change_passphrase(0, &p1, Argon2Params::default()).map_err(|e| e.to_string())?;
        }
        other => return Err(format!("unknown command: {}", other.join(" "))),
    }
    Ok(false)
}

trait Expose { fn expose(&self) -> &[u8]; }
impl Expose for SecretVec<u8> { fn expose(&self) -> &[u8] { use secrecy::ExposeSecret; self.expose_secret() } }

#[tokio::main]
async fn main() {
    let mut rl = DefaultEditor::new().expect("readline");
    let mut st = State { path: None, vault: None };
    loop {
        let prompt = match &st.path { Some(p) => format!("ltv-admin({})> ", p.file_stem().unwrap().to_string_lossy()), None => "ltv-admin> ".into() };
        match rl.readline(&prompt) {
            Ok(line) => {
                let _ = rl.add_history_entry(line.as_str());
                match dispatch(&mut st, &line).await {
                    Ok(true) => break,
                    Ok(false) => {}
                    Err(e) => eprintln!("error: {e}"),
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => break,
            Err(e) => { eprintln!("{e}"); break; }
        }
    }
}