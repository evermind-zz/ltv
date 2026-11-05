use std::{fs, path::PathBuf};
use ltv_core::{format::Argon2Params, model::{Profile, TargetMeta, ResumePolicy, BootedAccess, BootedAuth, fingerprint_sha256}, net::{fetch_host_key, fetch_luks_info, probe, unlock}, vault::Vault, enroll::EnrollEvent};
use std::path::Path;
use rustyline::{error::ReadlineError, DefaultEditor};
use secrecy::{ExposeSecret, SecretString, SecretVec};
use getopts::Options;

struct State { 
    path: Option<PathBuf>, 
    vault: Option<Vault>,
    verbose: bool,
}

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
    Ok(())
}

async fn cmd_server_setup(st: &mut State, name: &str, args: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optopt("o", "out", "output directory", "DIR");
    let matches = opts.parse(args).map_err(|e| e.to_string())?;
    let out_dir = matches.opt_str("o").unwrap_or_else(|| format!("./ltv-deploy-{}", name));

    let v = st.vault.as_ref().ok_or("no vault open")?;
    let p = resolve(v, name)?.clone();

    if p.initramfs_host_key.is_none() {
        return Err("initramfs host key not pinned. Run 'hostkey fetch <profile>' first.".into());
    }

    // Generate deployment artifacts
    let deploy_dir = Path::new(&out_dir);
    fs::create_dir_all(deploy_dir).map_err(|e| e.to_string())?;

    // Build kernel cmdline snippet
    let mut cmdline = String::from("ltv_mappers=");
    let mut first = true;
    for tm in &p.targets_meta {
        if !first { cmdline.push(','); }
        cmdline.push_str(&tm.mapped_name);
        first = false;
    }
    cmdline.push('\n');
    for tm in &p.targets_meta {
        cmdline.push_str(&format!("ltv_{}={}\n", tm.mapped_name, tm.luks_uuid));
    }

    // 1a. feature file list (installed to /etc/mkinitfs/features.d/ltv.files)
    // Full paths for mkinitfs feature files
    let files = "/usr/share/mkinitfs/ltv-hook.sh\n/usr/share/mkinitfs/ltv-common.sh\n/usr/sbin/dropbear\n";
    fs::write(deploy_dir.join("ltv.files"), files).map_err(|e| e.to_string())?;

    // 1b. kernel modules (empty - uses cryptsetup feature)
    fs::write(deploy_dir.join("ltv.modules"), "").map_err(|e| e.to_string())?;

    // 1c. APK packages needed - mkinitfs uses this to know what packages to install
    let packages = "dropbear\n";
    fs::write(deploy_dir.join("ltv.packages"), packages).map_err(|e| e.to_string())?;

    // 2. hook script
    let hook = r#"#!/bin/sh
# ltv-hook: push-to-stdin LUKS unlock via Dropbear
# Runs after configure_ip, before nlplug-findfs

. /lib/mkinitfs/ltv-common.sh

ltv_unlock() {
    local dev="$1" name="$2"
    cryptsetup open --key-file=- "UUID=${dev}" "${name}" || return 1
}

# Read mapper specs from kernel cmdline: ltv_mappers=cryptroot,cryptdata
mappers=$(getarg ltv_mappers=)
if [ -n "$mappers" ]; then
    OIFS=$IFS; IFS=,
    for m in $mappers; do
        IFS=$OIFS
        dev=$(getarg "ltv_${m}=")
        [ -n "$dev" ] && ltv_unlock "$dev" "$m"
    done
fi
"#;
    fs::write(deploy_dir.join("ltv-hook.sh"), hook).map_err(|e| e.to_string())?;

    // 3. common lib
    let common = r#"#!/bin/sh
# ltv-common: shared functions for ltv hooks

getarg() {
    local name="$1" value
    for x in $(cat /proc/cmdline); do
        case $x in
            ${name}=*) value=${x#*=} ;;
        esac
    done
    echo "$value"
}
"#;
    fs::write(deploy_dir.join("ltv-common.sh"), common).map_err(|e| e.to_string())?;

    // 4. initramfs init patch (sed script)
    let patch = r###"#!/bin/sh
# initramfs-init.patch: sed script to insert ltv-hook call
# Run with: sh initramfs-init.patch

INIT=/usr/share/mkinitfs/initramfs-init
if ! grep -q "ltv-hook" "$INIT"; then
    sed -i '/^configure_ip/a ### LTV PATCH START ###\n. /lib/mkinitfs/ltv-hook.sh\n### LTV PATCH END ###' "$INIT"
fi
"###;
    fs::write(deploy_dir.join("initramfs-init.patch"), patch).map_err(|e| e.to_string())?;

    // 5. authorized_keys for initramfs (restricted client pubkey)
    let auth_keys = v.authorized_keys_line(&p);
    fs::write(deploy_dir.join("authorized_keys"), auth_keys).map_err(|e| e.to_string())?;

    // 6. deploy.sh - run on target server
    let deploy_sh = r###"#!/bin/sh
# deploy.sh: Run on target Alpine server to install LTV
# Usage: sudo sh deploy.sh

set -e

echo "Installing mkinitfs feature files..."
cp ltv.files ltv.modules ltv.packages /etc/mkinitfs/features.d/

echo "Installing hook and common lib to /usr/share/mkinitfs/"
cp ltv-hook.sh /usr/share/mkinitfs/ltv-hook.sh
chmod 755 /usr/share/mkinitfs/ltv-hook.sh
cp ltv-common.sh /usr/share/mkinitfs/ltv-common.sh

echo "Installing /usr/sbin/dropbear (ensures binary in initramfs)"
# /usr/sbin/dropbear is listed in ltv.files, mkinitfs will copy it

echo "Patching initramfs init script..."
sh initramfs-init.patch

echo "Generating Dropbear Ed25519 host key..."
mkdir -p /etc/dropbear
dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key

echo "Creating authorized_keys overlay for initramfs..."
mkdir -p /etc/mkinitfs/features.d/ltv-ssh.keys/root/.ssh
cp authorized_keys /etc/mkinitfs/features.d/ltv-ssh.keys/root/.ssh/authorized_keys
chmod 600 /etc/mkinitfs/features.d/ltv-ssh.keys/root/.ssh/authorized_keys

echo "Regenerating initramfs..."
KERNEL=$(uname -r)
mkinitfs -F "base ltv cryptsetup network" -k "$KERNEL" \
  -o "/boot/initramfs-ltv-$KERNEL" "$KERNEL"

echo "Done! Update bootloader with kernel cmdline from cmdline.txt"
echo "Then reboot."
"###;
    fs::write(deploy_dir.join("deploy.sh"), deploy_sh).map_err(|e| e.to_string())?;
    // Make deploy.sh executable
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(deploy_dir.join("deploy.sh")).map_err(|e| e.to_string())?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(deploy_dir.join("deploy.sh"), perms).map_err(|e| e.to_string())?;

    // 7. cmdline.txt
    fs::write(deploy_dir.join("cmdline.txt"), &cmdline).map_err(|e| e.to_string())?;

    // 8. README
    let readme = format!(r#"# LTV Deployment Artifacts for profile: {}

## Files

- `ltv.files` - Feature file list for mkinitfs
- `ltv.modules` - Kernel modules (empty)
- `ltv.packages` - APK packages: dropbear
- `ltv-hook.sh` - Initramfs hook script
- `ltv-common.sh` - Shared functions for hooks
- `initramfs-init.patch` - Sed script to patch initramfs-init
- `authorized_keys` - Restricted client public key for initramfs SSH
- `deploy.sh` - Run this on the target server (sudo sh deploy.sh)
- `cmdline.txt` - Kernel command line parameters

## Quick Deploy

On target Alpine server:

```bash
# Copy this entire directory to the server, then:
sudo sh deploy.sh
```

## Bootloader Configuration

Add to kernel command line (from cmdline.txt):
{}
## From Admin Machine

After deployment and reboot:
    ltv-admin> unlock {}

# This will push keyfiles to initramfs Dropbear via SSH push-to-stdin
"#, p.name, &cmdline, p.name);
    fs::write(deploy_dir.join("README.md"), readme).map_err(|e| e.to_string())?;

    println!("Deployment artifacts written to {}", deploy_dir.display());
    println!("Run: sudo sh {}/deploy.sh on the target server", out_dir);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut st = State { path: None, vault: None, verbose: false };
    let mut rl = DefaultEditor::new()?;

    println!("ltv-admin — LUKS SSH Unlock Admin");
    println!("Type 'help' for commands.");

    loop {
        let line = match rl.readline("ltv-admin> ") {
            Ok(l) => l.trim().to_string(),
            Err(ReadlineError::Interrupted) => { println!("^C"); continue; }
            Err(ReadlineError::Eof) => break,
            Err(e) => return Err(e.into()),
        };
        if line.is_empty() { continue; }
        let _ = rl.add_history_entry(&line);

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() { continue; }

        match handle_command(&mut st, &parts).await {
            Ok(true) => break,
            Ok(false) => {},
            Err(e) => eprintln!("Error: {}", e),
        }
    }
    Ok(())
}

async fn handle_command(st: &mut State, parts: &[&str]) -> Result<bool, String> {
    match parts[0] {
        "quit" | "exit" => {
            if st.vault.as_ref().map_or(false, |v| v.is_dirty()) {
                if ask("Unsaved changes. Save? [Y/n]: ").to_lowercase() != "n" { save_atomic(st)?; }
            }
            return Ok(true);
        }
        "help" => { print_help(); }
        "verbose" => handle_verbose(st, parts)?,
        "create" => handle_create(st, parts)?,
        "open" => handle_open(st, parts)?,
        "save" => { save_atomic(st)?; }
        "close" => { st.vault = None; st.path = None; }
        "status" => handle_status(st)?,
        "ls" => handle_ls(st)?,
        "show" => handle_show(st, parts)?,
        "add" => { cmd_add(st)?; }
        "rm" => handle_rm(st, parts)?,
        "edit" => handle_edit(st, parts)?,
        "target" => handle_target(st, parts)?,
        "pubkey" => handle_pubkey(st, parts)?,
        "hostkey" => handle_hostkey(st, parts).await?,
        "probe" => handle_probe(st, parts).await?,
        "unlock" => handle_unlock(st, parts).await?,
        "enroll" => handle_enroll(st, parts).await?,
        "fetch" => handle_fetch(st, parts).await?,
        "server-setup" => handle_server_setup(st, parts).await?,
        "passwd" => handle_passwd(st, parts)?,
        "backup" => handle_backup(st, parts)?,
        "import-profile" => println!("import-profile: not yet implemented"),
        "export-profile" => println!("export-profile: not yet implemented"),
        "rotate-key" => println!("rotate-key: not yet implemented"),
        _ => return Err(format!("unknown command: {}. Type 'help' for list.", parts[0])),
    }
    Ok(false)
}

fn print_help() {
    println!(r#"Commands:
  create <file>                  Create new vault file, prompts passphrase twice
  open <file>                    Open existing vault file
  save                           Save changes to vault file (atomic write)
  close                          Close current vault
  status                         Show vault status (file, profile count, dirty flag)
  ls                             List profiles: name, host, target count, hostkey status
  show <profile>                 Show full profile details (public parts)
  add                            Add new profile interactively (wizard)
  rm <profile>                   Remove profile (requires confirmation)
  edit <profile> [field=val...]  Edit scalar fields: name, host, port, user, notes,
                                 connect_timeout, exec_timeout, resume
  target add <profile>           Add target to profile interactively
  target rm <profile> <uuid>     Remove target from profile
  pubkey <profile>               Print Ed25519 public key (restricted authorized_keys line)
  rotate-key <profile>           Generate new Ed25519 keypair for profile
  hostkey fetch <profile> [--os] TOFU-fetch Dropbear/OS host key, confirm, store
  probe <profile>|--all [--verbose]  State detection: Unreachable/WaitingInInitramfs/BootedOs/UnknownHostKey
  unlock <profile> [--verbose]   Full push-unlock with live progress
  enroll <profile> [--target <uuid|mapper>] [--verbose]
                                 Enroll keyfiles into LUKS headers over booted OS
  fetch <profile> [--verbose]    Discover LUKS volumes on booted OS, offer to add as targets
  server-setup <profile> [--out <dir>]
                                 Generate mkinitfs deployment artifacts for remote unlock
  passwd                         Change master passphrase (re-derives, new salt)
  backup <path>                  Create timestamped encrypted vault copy
  import-profile                 Import profile from another vault
  export-profile <profile> <dir> Export profile to directory
  verbose [on|off|toggle]        Toggle verbose output for enroll/fetch/unlock/probe
  quit | exit                    Exit (prompts to save if dirty)
"#);
}

fn handle_verbose(st: &mut State, parts: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optflag("h", "help", "show help");
    let matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    if matches.opt_present("h") || matches.free.is_empty() {
        st.verbose = !st.verbose;
    } else {
        match matches.free[0].as_str() {
            "on" => st.verbose = true,
            "off" => st.verbose = false,
            "toggle" => st.verbose = !st.verbose,
            _ => return Err("Usage: verbose [on|off|toggle]".into()),
        }
    }
    println!("Verbose: {}", if st.verbose { "on" } else { "off" });
    Ok(())
}

fn handle_create(st: &mut State, parts: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optflag("h", "help", "show help");
    let matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    if matches.free.is_empty() { return Err("Usage: create <file>".into()); }
    let f = matches.free[0].clone();
    let p1 = pass("New passphrase: "); let p2 = pass("Repeat: ");
    if p1.expose_secret() != p2.expose_secret() { return Err("passphrases differ".into()); }
    st.vault = Some(Vault::create(&p1, Argon2Params::default()).map_err(|e| e.to_string())?);
    st.path = Some(PathBuf::from(f));
    save_atomic(st)?;
    Ok(())
}

fn handle_open(st: &mut State, parts: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optflag("h", "help", "show help");
    let matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    if matches.free.is_empty() { return Err("Usage: open <file>".into()); }
    let f = matches.free[0].clone();
    let bytes = fs::read(&f).map_err(|e| e.to_string())?;
    let v = Vault::open(&bytes, &pass("Passphrase: ")).map_err(|e| e.to_string())?;
    println!("opened: {} profiles", v.inventory.profiles.len());
    st.vault = Some(v); st.path = Some(PathBuf::from(f));
    Ok(())
}

fn handle_status(st: &State) -> Result<(), String> {
    match (&st.path, &st.vault) {
        (Some(p), Some(v)) => println!("{} — {} profiles, dirty={}", p.display(), v.inventory.profiles.len(), v.is_dirty()),
        _ => println!("no vault open"),
    }
    Ok(())
}

fn handle_ls(st: &State) -> Result<(), String> {
    for p in &st.vault.as_ref().ok_or("no vault open")?.inventory.profiles {
        println!("{:<16} {:<24} targets={} hostkey={}", p.name, format!("{}:{}", p.host, p.port),
                 p.targets_meta.len(), if p.initramfs_host_key.is_some() { "pinned" } else { "MISSING" });
    }
    Ok(())
}

fn handle_show(st: &State, parts: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optflag("h", "help", "show help");
    let matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    if matches.free.is_empty() { return Err("Usage: show <profile>".into()); }
    let n = &matches.free[0];
    let v = st.vault.as_ref().ok_or("no vault open")?; let p = resolve(v, n)?;
    println!("name: {}\nhost: {}:{} user {}\nuuid: {}", p.name, p.host, p.port, p.username, uuid::Uuid::from_bytes(p.uuid));
    if let Some(k) = &p.initramfs_host_key { println!("initramfs hostkey: {} {}", k.key_type, fingerprint_sha256(&k.key_bytes)); }
    for t in &p.targets_meta { 
        let fallback = t.fallback_path.as_deref().unwrap_or("none");
        println!("  target {} UUID={} fallback={} slot={:?}", t.mapped_name, t.luks_uuid, fallback, t.keyslot); 
    }
    println!("pubkey: {}", v.export_public_key(p));
    Ok(())
}

fn handle_rm(st: &mut State, parts: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optflag("h", "help", "show help");
    let matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    if matches.free.is_empty() { return Err("Usage: rm <profile>".into()); }
    let n = &matches.free[0];
    let v = st.vault.as_mut().ok_or("no vault open")?;
    let uuid = resolve(v, n)?.uuid;
    if ask(&format!("Remove '{}'? type YES: ", n)) == "YES" { v.remove_profile(&uuid).map_err(|e| e.to_string())?; }
    Ok(())
}

fn handle_edit(st: &mut State, parts: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optflag("h", "help", "show help");
    let matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    if matches.free.is_empty() { return Err("Usage: edit <profile> [field=value ...]".into()); }
    let n = &matches.free[0];
    let rest = &matches.free[1..];
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
    Ok(())
}

fn handle_target(st: &mut State, parts: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optflag("h", "help", "show help");
    let matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    if matches.free.is_empty() { return Err("Usage: target add|rm <profile> ...".into()); }
    match matches.free[0].as_str() {
        "add" => {
            if matches.free.len() < 2 { return Err("Usage: target add <profile>".into()); }
            let n = &matches.free[1];
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
        "rm" => {
            if matches.free.len() < 3 { return Err("Usage: target rm <profile> <uuid>".into()); }
            let n = &matches.free[1];
            let uuid_str = &matches.free[2];
            let v = st.vault.as_mut().ok_or("no vault open")?;
            let uuid = resolve(v, n)?.uuid;
            v.remove_target(&uuid, uuid_str).map_err(|e| e.to_string())?;
            println!("target removed");
        }
        _ => return Err("Usage: target add|rm <profile> ...".into()),
    }
    Ok(())
}

fn handle_pubkey(st: &State, parts: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optflag("h", "help", "show help");
    let matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    if matches.free.is_empty() { return Err("Usage: pubkey <profile>".into()); }
    let n = &matches.free[0];
    let v = st.vault.as_ref().ok_or("no vault open")?; println!("{}", v.authorized_keys_line(resolve(v, n)?));
    Ok(())
}

async fn handle_hostkey(st: &mut State, parts: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optflag("", "os", "pin as OS host key instead of initramfs");
    opts.optflag("h", "help", "show help");
    let matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    if matches.free.len() < 2 || matches.free[0] != "fetch" { return Err("Usage: hostkey fetch <profile> [--os]".into()); }
    let n = &matches.free[1];
    let is_os = matches.opt_present("os");
    let v = st.vault.as_mut().ok_or("no vault open")?;
    let p = resolve(v, n)?.clone();
    let hk = fetch_host_key(&p.host, p.port, p.connect_timeout_s).await.map_err(|e| e.to_string())?;
    println!("{} {}", hk.key_type, fingerprint_sha256(&hk.key_bytes));
    if ask("Pin this key? [y/N]: ").to_lowercase() == "y" {
        v.set_host_key(&p.uuid, hk, is_os).map_err(|e| e.to_string())?;
    }
    Ok(())
}

async fn handle_probe(st: &State, parts: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optflag("", "verbose", "show SSH commands");
    opts.optflag("h", "help", "show help");
    let matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    if matches.free.is_empty() { return Err("Usage: probe <profile>|--all [--verbose]".into()); }
    let n = &matches.free[0];
    let verbose = matches.opt_present("verbose") || st.verbose;
    let v = st.vault.as_ref().ok_or("no vault open")?;
    let ps: Vec<Profile> = if n == "--all" { v.inventory.profiles.clone() } else { vec![resolve(v, n)?.clone()] };
    for p in ps {
        let verbose_fn = if verbose { Some(Box::new(|msg: &str| println!("  [probe] {msg}")) as Box<dyn FnMut(&str) + Send>) } else { None };
        let result = probe(&p, verbose_fn).await;
        if !verbose {
            println!("{:<16} {:?}", p.name, result);
        }
    }
    Ok(())
}

async fn handle_unlock(st: &State, parts: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optflag("", "verbose", "show cryptsetup commands");
    opts.optflag("h", "help", "show help");
    let matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    if matches.free.is_empty() { return Err("Usage: unlock <profile> [--verbose]".into()); }
    let n = &matches.free[0];
    let verbose = matches.opt_present("verbose") || st.verbose;
    let v = st.vault.as_ref().ok_or("no vault open")?;
    let uuid = resolve(v, n)?.uuid;
    let verbose_fn = if verbose { Some(Box::new(|cmd: &str| println!("  [unlock] $ {cmd}")) as Box<dyn FnMut(&str) + Send>) } else { None };
    unlock(v, &uuid, |e| {
        if !verbose {
            println!(" ✓ {e:?}");
        }
    }, verbose_fn).await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn handle_enroll(st: &mut State, parts: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optopt("", "target", "filter by LUKS UUID or mapper name", "UUID|MAPPER");
    opts.optflag("", "verbose", "show cryptsetup commands");
    opts.optflag("h", "help", "show help");
    let matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    if matches.free.is_empty() { return Err("Usage: enroll <profile> [--target <uuid|mapper>] [--verbose]".into()); }
    let n = &matches.free[0];
    let only = matches.opt_str("target");
    let verbose = matches.opt_present("verbose") || st.verbose;

    let v = st.vault.as_mut().ok_or("no vault open")?;
    let p = resolve(v, n)?.clone();

    if p.os_host_key.is_none() {
        println!("No OS host key pinned. Fetching from {}:{} ...", p.host, p.port);
        let hk = fetch_host_key(&p.host, p.port, p.connect_timeout_s).await.map_err(|e| e.to_string())?;
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

    let results = ltv_core::enroll(v, &p.uuid, &access, &luks_pass, only.as_deref(), |e| {
        match e {
            EnrollEvent::Skipped(t, why) => println!(" ! {t}: skipped ({why})"),
            other if !verbose => println!(" ✓ {other:?}"),
            _ => {}
        }
    }, if verbose { Some(Box::new(|cmd: &str| println!("  [enroll] $ {cmd}")) as Box<dyn FnMut(&str) + Send>) } else { None }).await.map_err(|e| e.to_string())?;

    for r in &results { v.set_keyslot(&p.uuid, &r.luks_uuid, r.keyslot).map_err(|e| e.to_string())?; }
    println!("enrolled {} target(s); keyslots recorded. Remember to 'save'.", results.len());
    Ok(())
}

async fn handle_fetch(st: &mut State, parts: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optflag("", "verbose", "show cryptsetup commands");
    opts.optflag("h", "help", "show help");
    let matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    if matches.free.is_empty() { return Err("Usage: fetch <profile> [--verbose]".into()); }
    let n = &matches.free[0];
    let verbose = matches.opt_present("verbose") || st.verbose;

    let v = st.vault.as_mut().ok_or("no vault open")?;
    let p = resolve(v, n)?.clone();

    if p.os_host_key.is_none() {
        println!("No OS host key pinned. Fetching from {}:{} ...", p.host, p.port);
        let hk = fetch_host_key(&p.host, p.port, p.connect_timeout_s).await.map_err(|e| e.to_string())?;
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

    let results = fetch_luks_info(v, &p.uuid, &access, None, if verbose { Some(Box::new(|cmd: &str| println!("  [fetch] $ {cmd}")) as Box<dyn FnMut(&str) + Send>) } else { None }).await.map_err(|e| e.to_string())?;

    if results.is_empty() {
        println!("No LUKS volumes found.");
        return Ok(());
    }

    println!("\nDiscovered LUKS volumes:");
    for (i, info) in results.iter().enumerate() {
        println!("  [{}] UUID: {}", i, info.luks_uuid);
        if verbose {
            println!("       Device: {}", info.device_path);
            println!("       Cipher: {}", info.cipher);
            println!("       Key size: {} bits", info.key_size);
            println!("       Version: {}", info.header_version);
        } else {
            println!("       Device: {} | Cipher: {} | Key size: {} bits | Version: {}", 
                info.device_path, info.cipher, info.key_size, info.header_version);
        }
    }

    let choice = ask("\nAdd all as targets? [y/N]: ").to_lowercase();
    if choice == "y" {
        for info in results {
            let mapped = format!("crypt{}", info.luks_uuid.split('-').next().unwrap_or("vol"));
            let meta = TargetMeta {
                luks_uuid: info.luks_uuid.clone(),
                fallback_path: Some(info.device_path.clone()),
                mapped_name: mapped.clone(),
                order: 0,
                keyslot: None,
                token_id: None,
            };
            v.add_target(&p.uuid, meta, None).map_err(|e| e.to_string())?;
            println!("  added target {}", mapped);
        }
        println!("targets added. Remember to 'save'.");
    }
    Ok(())
}

async fn handle_server_setup(st: &mut State, parts: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optopt("o", "out", "output directory", "DIR");
    opts.optflag("h", "help", "show help");
    let matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    if matches.free.is_empty() { return Err("Usage: server-setup <profile> [--out <dir>]".into()); }
    let n = &matches.free[0];
    let args: Vec<&str> = parts.iter().skip(2).map(|s| *s).collect();
    cmd_server_setup(st, n, &args).await
}

fn handle_passwd(st: &mut State, parts: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optflag("h", "help", "show help");
    let _matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    let v = st.vault.as_mut().ok_or("no vault open")?;
    let p1 = pass("New passphrase: "); let p2 = pass("Repeat: ");
    if p1.expose_secret() != p2.expose_secret() { return Err("passphrases differ".into()); }
    v.change_passphrase(0, &p1, Argon2Params::default()).map_err(|e| e.to_string())?;
    Ok(())
}

fn handle_backup(st: &mut State, parts: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optflag("h", "help", "show help");
    let matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    if matches.free.is_empty() { return Err("Usage: backup <path>".into()); }
    let path = &matches.free[0];
    let v = st.vault.as_mut().ok_or("no vault open")?;
    let bytes = v.save().map_err(|e| e.to_string())?;
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let backup_path = format!("{}.{}.bak", path, ts);
    fs::write(&backup_path, bytes).map_err(|e| e.to_string())?;
    println!("backup saved to {}", backup_path);
    Ok(())
}