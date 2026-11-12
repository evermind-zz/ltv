use std::{fs, path::PathBuf, env};
use ltv_core::{format::Argon2Params, model::{Profile, TargetMeta, BootedAccess, BootedAuth, fingerprint_sha256, HostKey, SecretPayload, ExecutionMode}, net::{fetch_host_key, fetch_luks_info, probe, unlock, ProbeResult}, vault::{Vault, ssh_ed25519_blob}, enroll::EnrollEvent, rotate::RotateEvent, scripts::{render_cmdline, render_deploy_sh, render_deploy_nopatch_sh, LTV_FILES, LTV_MODULES, LTV_PACKAGES, LTV_LUKS_WRAPPER, LTV_COMMON, LTV_PATCH_INIT, LTV_COMMIT_HOOK}};
use std::path::Path;
use rustyline::{error::ReadlineError, DefaultEditor};
use secrecy::{ExposeSecret, SecretString, SecretVec};
use getopts::Options;
use base64::Engine;
use ed25519_dalek::SigningKey;

const VERSION: &str = env!("CARGO_PKG_VERSION");

struct State { 
    path: Option<PathBuf>, 
    vault: Option<Vault>,
    vault_name: Option<String>,
    verbose: bool,
}

impl State {
    /// Get mutable reference to vault, or error if not open
    fn vault_mut(&mut self) -> Result<&mut Vault, String> {
        self.vault.as_mut().ok_or("no vault open".into())
    }

    /// Get immutable reference to vault, or error if not open
    fn vault_ref(&self) -> Result<&Vault, String> {
        self.vault.as_ref().ok_or("no vault open".into())
    }

    /// Resolve profile name and return (vault_mut, profile_uuid)
    fn vault_and_profile(&mut self, name: &str) -> Result<(&mut Vault, [u8; 16]), String> {
        let v = self.vault_mut()?;
        let uuid = resolve(v, name)?.uuid;
        Ok((v, uuid))
    }

    /// Resolve profile name and return (vault_ref, profile_ref)
    fn vault_and_profile_ref(&self, name: &str) -> Result<(&Vault, &Profile), String> {
        let v = self.vault_ref()?;
        let p = resolve(v, name)?;
        Ok((v, p))
    }
}

fn pass(prompt: &str) -> SecretVec<u8> {
    loop {
        let p = rpassword::prompt_password(prompt).unwrap_or_default();
        if !p.is_empty() { return SecretVec::new(p.into_bytes()); }
        println!("Passphrase cannot be empty.");
    }
}

/// Prompt for optional passphrase (allows empty) returning String
fn pass_optional_str(prompt: &str) -> String {
    rpassword::prompt_password(prompt).unwrap_or_default()
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

/// Effective OS SSH endpoint. Host falls back to the unlock host and port to the
/// unlock port independently, matching how enroll/rotate/fetch resolve it.
fn os_ssh_addr(p: &Profile) -> (String, u16) {
    (
        p.os_host.clone().unwrap_or_else(|| p.unlock_host.clone()),
        p.os_port.unwrap_or(p.unlock_port),
    )
}

fn cmd_add(st: &mut State) -> Result<(), String> {
    let v = st.vault.as_mut().ok_or("no vault open")?;
    let name = ask("Profile name: ");
    let unlock_host = ask("Unlock SSH host (IP/hostname): ");
    let unlock_port: u16 = ask_or("Unlock SSH port", "22").parse().map_err(|_| "bad port")?;
    let os_host = ask("OS SSH host (IP/hostname, blank = same as unlock SSH): ");
    let os_port_str = ask("OS SSH port (blank = same as unlock SSH): ");
    let os_host = if os_host.is_empty() { None } else { Some(os_host) };
    let os_port = if os_port_str.is_empty() { None } else { Some(os_port_str.parse().map_err(|_| "bad OS port")?) };
    let user = ask_or("Username", "root");
    let notes = ask("Notes (optional): ");
    let uuid = v.add_profile(&name, &unlock_host, unlock_port, &user, os_host, os_port).map_err(|e| e.to_string())?;
    if !notes.is_empty() {
        v.update_profile(&uuid, |p| p.notes = notes.clone()).map_err(|e| e.to_string())?;
    }
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

    let v = st.vault.as_mut().ok_or("no vault open")?;
    let p = resolve(&v, name)?.clone();

    // Generate deployment artifacts directory early for key generation
    let deploy_dir = Path::new(&out_dir);
    fs::create_dir_all(deploy_dir).map_err(|e| e.to_string())?;

    let key_path = deploy_dir.join("dropbear_ed25519_host_key");
    let pub_key_path = deploy_dir.join("dropbear_ed25519_host_key.pub");

    // Generate Dropbear host keypair LOCALLY using dropbearkey binary
    // Native dropbear format (83 bytes) with correct magic ensures russh connects
    println!("Generating dropbear host key locally using dropbearkey...");
    let key_path_str = key_path.to_str().ok_or("invalid key path: not valid UTF-8")?;
    let output = std::process::Command::new("dropbearkey")
        .args(["-t", "ed25519", "-f", key_path_str])
        .output()
        .map_err(|e| format!("dropbearkey failed: {}", e))?;

    if !output.status.success() {
        return Err(format!("dropbearkey failed: {}", String::from_utf8_lossy(&output.stderr)));
    }
    let gen_out = String::from_utf8_lossy(&output.stdout);
    for line in gen_out.lines() {
        if !line.starts_with("Generating") { println!("{}", line); }
    }

    // Extract public key locally
    let output = std::process::Command::new("dropbearkey")
        .args(["-y", "-f", key_path_str])
        .output()
        .map_err(|e| format!("dropbearkey -y failed: {}", e))?;

    if !output.status.success() {
        return Err(format!("dropbearkey -y failed: {}", String::from_utf8_lossy(&output.stderr)));
    }
    let pub_output = String::from_utf8_lossy(&output.stdout);
    for line in pub_output.lines() {
        if !line.starts_with("Generating") { println!("{}", line); }
    }

    // Parse public key line
    let pub_key_line = pub_output.lines()
        .find(|l| l.starts_with("ssh-ed25519 "))
        .ok_or("no public key in dropbearkey output")?;
    let pub_key_parts: Vec<&str> = pub_key_line.split_whitespace().collect();
    let pub_b64 = pub_key_parts.get(1).ok_or("invalid public key format")?;
    let host_key_public_bytes_full = base64::engine::general_purpose::STANDARD.decode(pub_b64).map_err(|e| e.to_string())?;

    // host_key_public_bytes_full is the full SSH wire format (51 bytes):
    // 4 bytes len("ssh-ed25519") + 11 bytes "ssh-ed25519" + 4 bytes len(pubkey) + 32 bytes pubkey
    // This matches what russh presents via PublicKey::public_key_bytes() and what dropbearkey fingerprint uses.

    // Compute fingerprint on FULL 51-byte blob (matches dropbearkey output)
    let fp = fingerprint_sha256(&host_key_public_bytes_full);
    println!("Pin unlock SSH host key fingerprint: {}", fp);

    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(&key_path).map_err(|e| e.to_string())?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&key_path, perms).map_err(|e| e.to_string())?;

    // Write public key in authorized_keys format locally
    fs::write(&pub_key_path, pub_key_line).map_err(|e| e.to_string())?;
    let mut perms = fs::metadata(&pub_key_path).map_err(|e| e.to_string())?.permissions();
    perms.set_mode(0o644);
    fs::set_permissions(&pub_key_path, perms).map_err(|e| e.to_string())?;

    // Store FULL 51-byte SSH wire format in vault (matches russh presented key)
    let host_key_public_bytes = host_key_public_bytes_full;

    // Always pin the freshly generated unlock SSH host key (overwrite any stale value)
    v.set_host_key(&p.uuid, HostKey {
        key_type: "ssh-ed25519".into(),
        key_bytes: host_key_public_bytes,
    }, false).map_err(|e| e.to_string())?;
    // Save vault immediately so the pinned key persists
    if let Some(path) = &st.path {
        let bytes = v.save().map_err(|e| e.to_string())?;
        fs::write(path, bytes).map_err(|e| e.to_string())?;
    }
    println!("Pinned unlock SSH host key in vault (fingerprint: {})", fp);

    // 1. mkinitfs feature files (from embedded scripts)
    fs::write(deploy_dir.join("ltv.files"), LTV_FILES).map_err(|e| e.to_string())?;
    fs::write(deploy_dir.join("ltv.modules"), LTV_MODULES).map_err(|e| e.to_string())?;
    fs::write(deploy_dir.join("ltv.packages"), LTV_PACKAGES).map_err(|e| e.to_string())?;

    // 2. luks wrapper & common lib
    // Template the port into the wrapper (replaces ${LTV_PORT:-22} with actual port)
    let wrapper = LTV_LUKS_WRAPPER.replace("${LTV_PORT:-22}", &p.unlock_port.to_string());
    fs::write(deploy_dir.join("ltv-luks-wrapper.sh"), wrapper).map_err(|e| e.to_string())?;
    let mut perms = fs::metadata(deploy_dir.join("ltv-luks-wrapper.sh")).map_err(|e| e.to_string())?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(deploy_dir.join("ltv-luks-wrapper.sh"), perms).map_err(|e| e.to_string())?;
    fs::write(deploy_dir.join("ltv-common.sh"), LTV_COMMON).map_err(|e| e.to_string())?;

    // 3. patch script + commit hook (idempotent re-patch after mkinitfs upgrade)
    fs::write(deploy_dir.join("ltv-patch-init.sh"), LTV_PATCH_INIT).map_err(|e| e.to_string())?;
    let mut perms = fs::metadata(deploy_dir.join("ltv-patch-init.sh")).map_err(|e| e.to_string())?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(deploy_dir.join("ltv-patch-init.sh"), perms).map_err(|e| e.to_string())?;

    fs::write(deploy_dir.join("ltv-commit-hook.sh"), LTV_COMMIT_HOOK).map_err(|e| e.to_string())?;
    let mut perms = fs::metadata(deploy_dir.join("ltv-commit-hook.sh")).map_err(|e| e.to_string())?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(deploy_dir.join("ltv-commit-hook.sh"), perms).map_err(|e| e.to_string())?;

    // 4. authorized_keys (runtime generated from vault)
    let auth_keys = v.authorized_keys_line(&p);
    // Ensure trailing newline for authorized_keys
    let auth_keys = if auth_keys.ends_with('\n') { auth_keys } else { format!("{}\n", auth_keys) };
    fs::write(deploy_dir.join("authorized_keys"), auth_keys).map_err(|e| e.to_string())?;

    // 5. deploy.sh (with kernel version template)
    let kernel_version = std::process::Command::new("uname").arg("-r").output().map_err(|e| e.to_string())?.stdout;
    let kernel_version = String::from_utf8_lossy(&kernel_version).trim().to_string();
    let deploy_sh = render_deploy_sh(&kernel_version);
    fs::write(deploy_dir.join("deploy.sh"), deploy_sh).map_err(|e| e.to_string())?;
    let mut perms = fs::metadata(deploy_dir.join("deploy.sh")).map_err(|e| e.to_string())?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(deploy_dir.join("deploy.sh"), perms).map_err(|e| e.to_string())?;

    // 7. deploy_nopatch.sh (alternative without patching)
    let deploy_nopatch_sh = render_deploy_nopatch_sh(&kernel_version);
    fs::write(deploy_dir.join("deploy_nopatch.sh"), deploy_nopatch_sh).map_err(|e| e.to_string())?;
    let mut perms = fs::metadata(deploy_dir.join("deploy_nopatch.sh")).map_err(|e| e.to_string())?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(deploy_dir.join("deploy_nopatch.sh"), perms).map_err(|e| e.to_string())?;

    // 8. cmdline.txt (from template)
    let cmdline = render_cmdline(&p);
    fs::write(deploy_dir.join("cmdline.txt"), &cmdline).map_err(|e| e.to_string())?;

    // 9. README
    let readme = format!(r#"# LTV Deployment Artifacts for profile: {}

## Files

- `ltv.files` - Feature file list for mkinitfs
- `ltv.modules` - Kernel modules (empty)
- `ltv.packages` - APK packages: dropbear
- `ltv-luks-wrapper.sh` - Luks wrapper (replaces nlplug-findfs, starts Dropbear, waits for resume)
- `ltv-common.sh` - Shared functions
- `ltv-patch-init.sh` - Script to patch initramfs-init (idempotent)
- `authorized_keys` - Client public key for initramfs SSH (no forced commands)
- `dropbear_ed25519_host_key` - Dropbear host private key (pre-generated)
- `dropbear_ed25519_host_key.pub` - Dropbear host public key
- `deploy.sh` - Run this on the target server (sudo sh deploy.sh)
- `deploy_nopatch.sh` - Alternative without patching initramfs-init
- `cmdline.txt` - Kernel command line parameters

## Quick Deploy

On target Alpine server:

```bash
# Copy this entire directory to the server, then:
sudo sh deploy.sh
# OR (if initramfs-init is handcrafted):
sudo sh deploy_nopatch.sh
```

## Bootloader Configuration

Add to kernel command line (from cmdline.txt):
{}
## From Admin Machine

After deployment and reboot:
    ltv-admin> unlock {}

# This will push keyfiles to initramfs Dropbear via SSH (full shell, not push-to-stdin yet)
"#, p.name, &cmdline, p.name);
    fs::write(deploy_dir.join("README.md"), readme).map_err(|e| e.to_string())?;

    println!("Deployment artifacts written to {}", deploy_dir.display());
    println!("Run: sudo sh {}/deploy.sh on the target server", out_dir);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse CLI arguments
    let args: Vec<String> = env::args().collect();
    let mut opts = Options::new();
    opts.optflag("h", "help", "Show usage information");
    opts.optflag("v", "version", "Show version");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => { eprintln!("{}", e); std::process::exit(1); }
    };

    if matches.opt_present("h") {
        print_usage(&args[0]);
        return Ok(());
    }
    if matches.opt_present("v") {
        println!("ltv-admin {}", VERSION);
        return Ok(());
    }

    let mut st = State { path: None, vault: None, vault_name: None, verbose: false };
    let mut rl = DefaultEditor::new()?;

    println!("ltv-admin — LUKS SSH Unlock Admin v{}", VERSION);
    println!("Type 'help' for commands.");

    loop {
        let dirty = st.vault.as_ref().map_or(false, |v| v.is_dirty());
        let prompt = if let Some(name) = &st.vault_name {
            format!("ltv-admin({}{name})> ", if dirty { "*" } else { "" })
        } else {
            "ltv-admin> ".to_string()
        };
        let line = match rl.readline(&prompt) {
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
        "close" => { close_vault(st)?; }
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
        "rotate-key" => handle_rotate(st, parts).await?,
        "copy-profile" => handle_copy_profile(st, parts).await?,
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
  ls                             List profiles: name, unlock SSH, target count, unlock hostkey status
  show <profile>                 Show full profile details (public parts)
  add                            Add new profile interactively (wizard)
  rm <profile>                   Remove profile (requires confirmation)
  edit <profile> [field=val...]  Edit fields: name, unlock_host, unlock_port, os_host, os_port, user, notes,
                                 connect_timeout, exec_timeout (run 'edit --help' for details)
  target add <profile>           Add target to profile interactively
  target rm <profile> <uuid>     Remove target from profile
  pubkey <profile>               Print profile's Ed25519 client identity public key
  rotate-key <profile> [--target <uuid|mapper>] [--verbose] [--sequential]
                                  Rotate LUKS keyfiles: add new key, verify, kill old slot (auto-saves)
  hostkey fetch <profile> [--os]    TOFU-fetch unlock SSH/OS host key, confirm, store
  hostkey repin <profile>           Re-pin unlock SSH host key (fix mismatch after redeploy)
  probe <profile>|--all [--verbose]  Check state: unreachable / waiting in initramfs / booted OS / unknown host key
  unlock <profile> [--verbose] [--sequential]   Full push-unlock with live progress
  enroll <profile> [--target <uuid|mapper>] [--verbose] [--sequential]
                                 Enroll keyfiles into LUKS headers over booted OS
  fetch <profile> [--verbose]    Discover LUKS volumes on booted OS, offer to add as targets
  server-setup <profile> [--out <dir>]
                                 Generate mkinitfs deployment artifacts for remote unlock
  passwd                         Change VAULT master passphrase (re-encrypts vault, not LUKS)
  backup <path>                  Create timestamped encrypted vault copy
  copy-profile <src> <prof> [--name <n>] [--keep]
                                  Copy profile from another vault
                                  --keep: identical copy (same client key + host keys)
  verbose [on|off|toggle]        Toggle verbose output for enroll/fetch/unlock/probe
  quit | exit                    Exit (prompts to save if dirty)
"#);
}

fn print_usage(program: &str) {
    println!("ltv-admin {} — LUKS SSH Unlock Admin", VERSION);
    println!();
    println!("Usage: {} [OPTIONS]", program);
    println!();
    println!("Options:");
    println!("  -h, --help     Show this usage information");
    println!("  -v, --version  Show version");
    println!();
    println!("Without options, starts interactive shell. Type 'help' for commands.");
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
    let path = PathBuf::from(&f);
    
    // Close current vault if open (with dirty check)
    if st.vault.is_some() {
        close_vault(st)?;
    }
    
    // Check if file already exists
    if path.exists() {
        let confirm = ask(&format!("File '{}' already exists. Overwrite? [y/N]: ", f));
        if confirm.to_lowercase() != "y" { return Err("aborted".into()); }
    }
    
    let p1 = pass("New passphrase: "); let p2 = pass("Repeat: ");
    if p1.expose_secret() != p2.expose_secret() { return Err("passphrases differ".into()); }
    st.vault = Some(Vault::create(&p1, Argon2Params::default()).map_err(|e| e.to_string())?);
    st.path = Some(path);
    st.vault_name = st.path.as_ref().and_then(|p| p.file_stem()).and_then(|s| s.to_str()).map(|s| s.to_string());
    save_atomic(st)?;
    Ok(())
}

fn handle_open(st: &mut State, parts: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optflag("h", "help", "show help");
    let matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    if matches.free.is_empty() { return Err("Usage: open <file>".into()); }
    let f = matches.free[0].clone();
    
    // Close current vault if open (with dirty check)
    if st.vault.is_some() {
        close_vault(st)?;
    }
    
    let bytes = fs::read(&f).map_err(|e| e.to_string())?;
    let v = Vault::open(&bytes, &pass("Passphrase: ")).map_err(|e| e.to_string())?;
    println!("opened: {} profiles", v.inventory.profiles.len());
    let path = PathBuf::from(f);
    st.vault_name = path.file_stem().and_then(|s| s.to_str()).map(|s| s.to_string());
    st.vault = Some(v); st.path = Some(path);
    Ok(())
}

fn close_vault(st: &mut State) -> Result<(), String> {
    if let Some(v) = &st.vault {
        if v.is_dirty() {
            let choice = ask("Unsaved changes. Save before closing? [Y/n/d]: ").to_lowercase();
            match choice.as_str() {
                "n" | "no" => {}, // discard changes
                "d" | "discard" => {}, // explicit discard
                _ => { save_atomic(st)?; } // default: save
            }
        }
    }
    st.vault = None;
    st.path = None;
    st.vault_name = None;
    println!("Vault closed.");
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
    let v = st.vault_ref()?;
    println!("{:<16} {:<21} {:<21} {:>7}  {}", "NAME", "UNLOCK SSH", "OS SSH", "TARGETS", "HOSTKEY");
    for p in &v.inventory.profiles {
        let unlock_ssh = format!("{}:{}", p.unlock_host, p.unlock_port);
        let (os_h, os_p) = os_ssh_addr(p);
        let os_ssh = format!("{}:{}", os_h, os_p);
        let hostkey = if p.unlock_host_key.is_some() { "pinned" } else { "MISSING" };
        println!("{:<16} {:<21} {:<21} {:>7}  {}", p.name, unlock_ssh, os_ssh, p.targets_meta.len(), hostkey);
    }
    Ok(())
}

fn handle_show(st: &State, parts: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optflag("h", "help", "show help");
    let matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    if matches.free.is_empty() { return Err("Usage: show <profile>".into()); }
    let n = &matches.free[0];
    let (v, p) = st.vault_and_profile_ref(n)?;
    let (os_host, os_port) = os_ssh_addr(p);
    let os_addr = if p.os_host.is_none() && p.os_port.is_none() {
        format!("{}:{} (same as unlock SSH)", os_host, os_port)
    } else {
        format!("{}:{}", os_host, os_port)
    };
    println!("name: {}\nunlock SSH: {}:{} user {}\nOS SSH: {}\nuuid: {}", p.name, p.unlock_host, p.unlock_port, p.username, os_addr, uuid::Uuid::from_bytes(p.uuid));
    println!("notes: {}", if p.notes.is_empty() { "(none)" } else { &p.notes });
    if let Some(k) = &p.unlock_host_key { println!("unlock SSH hostkey: {} {}", k.key_type, fingerprint_sha256(&k.key_bytes)); }
    if let Some(k) = &p.os_host_key { println!("OS SSH hostkey: {} {}", k.key_type, fingerprint_sha256(&k.key_bytes)); }
    for t in &p.targets_meta { 
        let fallback = t.fallback_path.as_deref().unwrap_or("none");
        println!("  target {} UUID={} fallback={} slot={:?}", t.mapped_name, t.luks_uuid, fallback, t.keyslot); 
    }
    println!("client public key: {}", v.export_public_key(p));
    Ok(())
}

fn handle_rm(st: &mut State, parts: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optflag("h", "help", "show help");
    let matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    if matches.free.is_empty() { return Err("Usage: rm <profile>".into()); }
    let n = &matches.free[0];
    let (v, uuid) = st.vault_and_profile(n)?;
    if ask(&format!("Remove '{}'? type YES: ", n)) == "YES" { v.remove_profile(&uuid).map_err(|e| e.to_string())?; }
    Ok(())
}

fn handle_edit(st: &mut State, parts: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optflag("h", "help", "show help");
    let matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    // Show help if no profile given or --help flag
    if matches.free.is_empty() || matches.opt_present("h") {
        println!("Usage: edit <profile> [field=value ...]");
        println!();
        println!("Editable fields:");
        println!("  name                Profile name");
        println!("  unlock_host         Unlock SSH host (IP/hostname)");
        println!("  unlock_port         Unlock SSH port (default 22)");
        println!("  os_host             OS SSH host (blank = same as unlock SSH)");
        println!("  os_port             OS SSH port (blank = same as unlock SSH)");
        println!("  user | username     SSH username (default root)");
        println!("  notes               Free-form notes (shown in 'show')");
        println!("  connect_timeout     SSH connect timeout seconds (default 10)");
        println!("  exec_timeout        Command execution timeout seconds (default 60)");
        println!();
        println!("Examples:");
        println!("  edit myvault unlock_host=10.0.0.5 unlock_port=2222");
        println!("  edit myvault os_host=10.0.0.5 os_port=22 user=admin");
        println!("  edit myvault notes=rack4");
        return Ok(());
    }
    
    let n = &matches.free[0];
    let rest = &matches.free[1..];
    let (v, uuid) = st.vault_and_profile(n)?;
    let mut p = v.profile(&uuid).map_err(|e| e.to_string())?.clone();
    let mut changed = false;
    for arg in rest {
        if let Some((k, v)) = arg.split_once('=') {
            match k {
                "name" => { p.name = v.into(); changed = true; }
                "unlock_host" => { p.unlock_host = v.into(); changed = true; }
                "unlock_port" => { p.unlock_port = v.parse().map_err(|_| "bad port")?; changed = true; }
                "os_host" => { p.os_host = if v.is_empty() { None } else { Some(v.into()) }; changed = true; }
                "os_port" => { p.os_port = if v.is_empty() { None } else { Some(v.parse().map_err(|_| "bad OS port")?) }; changed = true; }
                "user" | "username" => { p.username = v.into(); changed = true; }
                "notes" => { p.notes = v.into(); changed = true; }
                "connect_timeout" => { p.connect_timeout_s = v.parse().map_err(|_| "bad timeout")?; changed = true; }
                "exec_timeout" => { p.exec_timeout_s = v.parse().map_err(|_| "bad timeout")?; changed = true; }
                _ => return Err(format!("unknown field: {k}. Run 'edit --help' for available fields.")),
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
    opts.optflag("", "os", "pin as OS host key instead of unlock SSH");
    opts.optflag("h", "help", "show help");
    let matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    if matches.free.is_empty() { return Err("Usage: hostkey <fetch|repin> <profile> [--os]".into()); }
    let subcmd = &matches.free[0];
    let n = matches.free.get(1).ok_or("Usage: hostkey <fetch|repin> <profile> [--os]")?;
    let is_os = matches.opt_present("os");
    let v = st.vault.as_mut().ok_or("no vault open")?;
    let p = resolve(v, n)?.clone();

    match subcmd.as_str() {
        "fetch" => {
            println!("Fetching host key from {}:{} ...", p.unlock_host, p.unlock_port);
            let hk = match fetch_host_key(&p.unlock_host, p.unlock_port, p.connect_timeout_s).await {
                Ok(hk) => hk,
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("Connection refused") || msg.contains("Connection timed out") {
                        let svc = if is_os { "OS SSH" } else { "unlock SSH" };
                        return Err(format!("Failed to connect to {}:{}. Is {} running?", p.unlock_host, p.unlock_port, svc));
                    }
                    return Err(msg);
                }
            };
            println!("{} {}", hk.key_type, fingerprint_sha256(&hk.key_bytes));
            if ask("Pin this key? [y/N]: ").to_lowercase() == "y" {
                v.set_host_key(&p.uuid, hk, is_os).map_err(|e| e.to_string())?;
            }
        }
        "repin" => {
            if is_os {
                return Err("--os flag not supported for repin (use 'hostkey fetch --os' for OS key)".into());
            }
            println!("Re-pinning unlock SSH host key from {}:{} ...", p.unlock_host, p.unlock_port);
            let hk = match fetch_host_key(&p.unlock_host, p.unlock_port, p.connect_timeout_s).await {
                Ok(hk) => hk,
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("Connection refused") || msg.contains("Connection timed out") {
                        return Err(format!("Failed to connect to {}:{}. Is the unlock SSH running (target booted with ltv=yes)?", p.unlock_host, p.unlock_port));
                    }
                    return Err(msg);
                }
            };
            println!("{} {}", hk.key_type, fingerprint_sha256(&hk.key_bytes));
            if ask("Replace pinned unlock SSH host key? [y/N]: ").to_lowercase() == "y" {
                v.set_host_key(&p.uuid, hk, false).map_err(|e| e.to_string())?;
                println!("Unlock SSH host key updated.");
            }
        }
        _ => return Err("Usage: hostkey <fetch|repin> <profile> [--os]".into()),
    }
    Ok(())
}

fn fmt_probe_result(r: &ProbeResult) -> String {
    match r {
        ProbeResult::Unreachable(reason) => format!("unreachable ({})", reason),
        ProbeResult::WaitingInInitramfs => "waiting in initramfs (unlock SSH)".into(),
        ProbeResult::BootedOs => "booted OS".into(),
        ProbeResult::UnknownHostKey(k) => format!("unknown host key ({})", fingerprint_sha256(&k.key_bytes)),
    }
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
            println!("{:<16} {}", p.name, fmt_probe_result(&result));
        }
    }
    Ok(())
}

async fn handle_unlock(st: &State, parts: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optflag("", "verbose", "show cryptsetup commands");
    opts.optflag("", "sequential", "process targets sequentially (default: parallel)");
    opts.optflag("h", "help", "show help");
    let matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    if matches.free.is_empty() { return Err("Usage: unlock <profile> [--verbose] [--sequential]".into()); }
    let n = &matches.free[0];
    let verbose = matches.opt_present("verbose") || st.verbose;
    let sequential = matches.opt_present("sequential");
    let mode = if sequential { ExecutionMode::Sequential } else { ExecutionMode::Parallel };
    let v = st.vault.as_ref().ok_or("no vault open")?;
    let uuid = resolve(v, n)?.uuid;
    let verbose_fn = if verbose { Some(Box::new(|cmd: &str| println!("  [unlock] $ {cmd}")) as Box<dyn FnMut(&str) + Send>) } else { None };
    unlock(v, &uuid, mode, |e| {
        if !verbose {
            println!(" ✓ {e}");
        }
    }, verbose_fn).await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn handle_enroll(st: &mut State, parts: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optopt("", "target", "filter by LUKS UUID or mapper name", "UUID|MAPPER");
    opts.optflag("", "verbose", "show cryptsetup commands");
    opts.optflag("", "sequential", "process targets sequentially (default: parallel)");
    opts.optflag("h", "help", "show help");
    let matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    if matches.free.is_empty() { return Err("Usage: enroll <profile> [--target <uuid|mapper>] [--verbose] [--sequential]".into()); }
    let n = &matches.free[0];
    let only = matches.opt_str("target");
    let verbose = matches.opt_present("verbose") || st.verbose;
    let sequential = matches.opt_present("sequential");
    let mode = if sequential { ExecutionMode::Sequential } else { ExecutionMode::Parallel };

    let v = st.vault.as_mut().ok_or("no vault open")?;
    let p = resolve(v, n)?.clone();

    if p.os_host_key.is_none() {
        println!("No OS host key pinned. Fetching from {}:{} ...", p.unlock_host, p.unlock_port);
        let hk = fetch_host_key(&p.unlock_host, p.unlock_port, p.connect_timeout_s).await.map_err(|e| e.to_string())?;
        println!("{} {}", hk.key_type, fingerprint_sha256(&hk.key_bytes));
        if ask("Pin as OS host key? [y/N]: ").to_lowercase() != "y" { return Err("aborted".into()); }
        v.set_host_key(&p.uuid, hk, true).map_err(|e| e.to_string())?;
    }

    let username = ask_or("OS SSH user", "root");
    let auth = match ask_or("Auth: (p)assword / (k)ey file", "k").as_str() {
        "p" => BootedAuth::Password(SecretString::new(pass_optional_str("OS password: "))),
        _ => {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            let path = ask_or("Key file", &format!("{}/.ssh/id_ed25519", home));
            let kp = russh_keys::load_secret_key(&path, None)
                .or_else(|_| russh_keys::load_secret_key(&path, Some(&pass_optional_str("Key passphrase: "))))
                .map_err(|e| format!("load key: {e}"))?;
            match kp {
                russh_keys::key::KeyPair::Ed25519(sk) => BootedAuth::Ed25519Seed(sk.to_bytes()),
                _ => return Err("only Ed25519 keys supported".into()),
            }
        }
    };
    let access = BootedAccess { use_sudo: username != "root", username, auth, connect_timeout_s: p.connect_timeout_s };

    // Filter targets based on --target
    let targets: Vec<_> = p.targets_meta.iter()
        .filter(|tm| only.as_ref().map_or(true, |f| f == &tm.luks_uuid || f == &tm.mapped_name))
        .cloned()
        .collect();
    
    if targets.is_empty() {
        return Err(format!("no targets match filter '{}'", only.unwrap()));
    }

    // Ask if all targets use the same LUKS passphrase
    let same_passphrase = if targets.len() > 1 {
        ask("Do all targets use the same LUKS passphrase? [Y/n]: ").to_lowercase() != "n"
    } else {
        true
    };

    // Collect passphrases
    let mut passphrases: std::collections::HashMap<String, SecretString> = std::collections::HashMap::new();
    
    if same_passphrase {
        let pass = loop {
            let p = rpassword::prompt_password("Existing LUKS passphrase (for all targets): ").unwrap_or_default();
            if !p.is_empty() { break SecretString::new(p); }
            println!("Passphrase cannot be empty.");
        };
        for tm in &targets {
            passphrases.insert(tm.luks_uuid.clone(), pass.clone());
        }
    } else {
        for tm in &targets {
            let pass = loop {
                let prompt = format!("Existing LUKS passphrase for {} ({}): ", tm.mapped_name, tm.luks_uuid);
                let p = rpassword::prompt_password(&prompt).unwrap_or_default();
                if !p.is_empty() { break SecretString::new(p); }
                println!("Passphrase cannot be empty.");
            };
            passphrases.insert(tm.luks_uuid.clone(), pass);
        }
    }

    let results = ltv_core::enroll(v, &p.uuid, &access, mode, |luks_uuid| {
        passphrases.get(luks_uuid).cloned().ok_or_else(|| format!("no passphrase for {}", luks_uuid))
    }, only.as_deref(), |e| {
        match e {
            EnrollEvent::Skipped(t, why) => println!(" ! {t}: skipped ({why})"),
            other if !verbose => println!(" ✓ {other}"),
            _ => {}
        }
    }, if verbose { Some(Box::new(|cmd: &str| println!("  [enroll] $ {cmd}")) as Box<dyn FnMut(&str) + Send>) } else { None }).await.map_err(|e| e.to_string())?;

    for r in &results { v.set_keyslot(&p.uuid, &r.luks_uuid, r.keyslot).map_err(|e| e.to_string())?; }
    println!("enrolled {} target(s); keyslots recorded. Remember to 'save'.", results.len());
    Ok(())
}

async fn handle_rotate(st: &mut State, parts: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optopt("", "target", "filter by LUKS UUID or mapper name", "UUID|MAPPER");
    opts.optflag("", "verbose", "show cryptsetup commands");
    opts.optflag("", "sequential", "process targets sequentially (default: parallel)");
    opts.optflag("h", "help", "show help");
    let matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    if matches.free.is_empty() { return Err("Usage: rotate-key <profile> [--target <uuid|mapper>] [--verbose] [--sequential]".into()); }
    let n = &matches.free[0];
    let only = matches.opt_str("target");
    let verbose = matches.opt_present("verbose") || st.verbose;
    let sequential = matches.opt_present("sequential");
    let mode = if sequential { ExecutionMode::Sequential } else { ExecutionMode::Parallel };

    let v = st.vault.as_mut().ok_or("no vault open")?;
    let p = resolve(v, n)?.clone();

    if p.os_host_key.is_none() {
        println!("No OS host key pinned. Fetching from {}:{} ...", p.unlock_host, p.unlock_port);
        let hk = fetch_host_key(&p.unlock_host, p.unlock_port, p.connect_timeout_s).await.map_err(|e| e.to_string())?;
        println!("{} {}", hk.key_type, fingerprint_sha256(&hk.key_bytes));
        if ask("Pin as OS host key? [y/N]: ").to_lowercase() != "y" { return Err("aborted".into()); }
        v.set_host_key(&p.uuid, hk, true).map_err(|e| e.to_string())?;
    }

    let username = ask_or("OS SSH user", "root");
    let auth = match ask_or("Auth: (p)assword / (k)ey file", "k").as_str() {
        "p" => BootedAuth::Password(SecretString::new(pass_optional_str("OS password: "))),
        _ => {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            let path = ask_or("Key file", &format!("{}/.ssh/id_ed25519", home));
            let kp = russh_keys::load_secret_key(&path, None)
                .or_else(|_| russh_keys::load_secret_key(&path, Some(&pass_optional_str("Key passphrase: "))))
                .map_err(|e| format!("load key: {e}"))?;
            match kp {
                russh_keys::key::KeyPair::Ed25519(sk) => BootedAuth::Ed25519Seed(sk.to_bytes()),
                _ => return Err("only Ed25519 keys supported".into()),
            }
        }
    };
    let access = BootedAccess { use_sudo: username != "root", username, auth, connect_timeout_s: p.connect_timeout_s };

    // Filter targets based on --target
    let targets: Vec<_> = p.targets_meta.iter()
        .filter(|tm| only.as_ref().map_or(true, |f| f == &tm.luks_uuid || f == &tm.mapped_name))
        .cloned()
        .collect();
    
    if targets.is_empty() {
        return Err(format!("no targets match filter '{}'", only.unwrap()));
    }

    // Check that each target has a keyslot recorded
    for tm in &targets {
        if tm.keyslot.is_none() {
            println!("Warning: target {} ({}) has no keyslot recorded. Run 'enroll' first.", tm.mapped_name, tm.luks_uuid);
        }
    }

    // Ask if all targets use the same LUKS passphrase
    let same_passphrase = if targets.len() > 1 {
        ask("Do all targets use the same LUKS passphrase? [Y/n]: ").to_lowercase() != "n"
    } else {
        true
    };

    // Collect passphrases
    let mut passphrases: std::collections::HashMap<String, SecretString> = std::collections::HashMap::new();
    
    if same_passphrase {
        let pass = loop {
            let p = rpassword::prompt_password("Existing LUKS passphrase (for all targets): ").unwrap_or_default();
            if !p.is_empty() { break SecretString::new(p); }
            println!("Passphrase cannot be empty.");
        };
        for tm in &targets {
            passphrases.insert(tm.luks_uuid.clone(), pass.clone());
        }
    } else {
        for tm in &targets {
            let pass = loop {
                let prompt = format!("Existing LUKS passphrase for {} ({}): ", tm.mapped_name, tm.luks_uuid);
                let p = rpassword::prompt_password(&prompt).unwrap_or_default();
                if !p.is_empty() { break SecretString::new(p); }
                println!("Passphrase cannot be empty.");
            };
            passphrases.insert(tm.luks_uuid.clone(), pass);
        }
    }

    let results = ltv_core::rotate_key(v, &p.uuid, &access, mode, |luks_uuid| {
        passphrases.get(luks_uuid).cloned().ok_or_else(|| format!("no passphrase for {}", luks_uuid))
    }, only.as_deref(), |e| {
        match e {
            RotateEvent::Skipped(t, why) => println!(" ! {t}: skipped ({why})"),
            other if !verbose => println!(" ✓ {other}"),
            _ => {}
        }
    }, if verbose { Some(Box::new(|cmd: &str| println!("  [rotate] $ {cmd}")) as Box<dyn FnMut(&str) + Send>) } else { None }).await.map_err(|e| e.to_string())?;

    println!("rotated {} target(s); vault auto-saved.", results.len());
    Ok(())
}

async fn handle_copy_profile(st: &mut State, parts: &[&str]) -> Result<(), String> {
    let mut opts = Options::new();
    opts.optopt("", "name", "new profile name", "NAME");
    opts.optflag("k", "keep", "keep client keypair and host keys (identical copy)");
    opts.optflag("h", "help", "show help");
    let matches = opts.parse(&parts[1..]).map_err(|e| e.to_string())?;
    
    if matches.free.is_empty() { return Err("Usage: copy-profile <source-vault> <source-profile> [--name <new-name>] [--keep]".into()); }
    if matches.free.len() < 2 { return Err("Usage: copy-profile <source-vault> <source-profile> [--name <new-name>] [--keep]".into()); }
    
    let src_vault_path = &matches.free[0];
    let src_profile_name = &matches.free[1];
    let new_name = matches.opt_str("name");
    let keep = matches.opt_present("keep");
    
    // Open source vault
    let src_pass = pass("Source vault passphrase: ");
    let src_bytes = fs::read(src_vault_path).map_err(|e| e.to_string())?;
    let src_vault = Vault::open(&src_bytes, &src_pass).map_err(|e| e.to_string())?;
    
    let src_profile = src_vault.find_by_name(src_profile_name).ok_or_else(|| format!("source profile '{}' not found", src_profile_name))?.clone();
    let src_secrets = src_vault.open_secrets(&src_profile).map_err(|e| e.to_string())?;
    
    // Determine destination vault (current open vault or new)
    let dest_name = new_name.unwrap_or_else(|| ask("New profile name: "));
    if dest_name.is_empty() { return Err("profile name required".into()); }
    
    let v = st.vault.as_mut().ok_or("no destination vault open - open a vault first")?;
    
    // Check if name already exists in destination
    if v.find_by_name(&dest_name).is_some() {
        return Err(format!("profile '{}' already exists in destination vault", dest_name));
    }
    
    // Add profile to destination vault (with same OS address as source)
    let new_uuid = v.add_profile(&dest_name, &src_profile.unlock_host, src_profile.unlock_port, &src_profile.username, src_profile.os_host.clone(), src_profile.os_port).map_err(|e| e.to_string())?;
    
    if keep {
        // Keep client keypair and host keys - identical copy
        v.update_profile(&new_uuid, |p| {
            p.client_public_key = src_profile.client_public_key.clone();
            p.targets_meta = src_profile.targets_meta.clone();
            p.connect_timeout_s = src_profile.connect_timeout_s;
            p.exec_timeout_s = src_profile.exec_timeout_s;
            p.unlock_host_key = src_profile.unlock_host_key.clone();
            p.os_host_key = src_profile.os_host_key.clone();
            p.host_key_pinned_at = src_profile.host_key_pinned_at;
            p.notes = format!("Copied from {} ({}) [kept]", src_profile_name, src_profile.unlock_host);
        }).map_err(|e| e.to_string())?;
        
        // Use source secrets (same client key + keyfiles)
        let dest_secrets = SecretPayload {
            client_private_seed: src_secrets.client_private_seed,
            keyfiles: src_secrets.keyfiles.clone(),
        };
        v.set_secrets(&new_uuid, &dest_secrets).map_err(|e| e.to_string())?;
        
        println!("Profile '{}' copied to '{}' in current vault (kept client key + host keys).", src_profile_name, dest_name);
        println!("Same authorized_keys applies. Remember to 'save'.");
    } else {
        // Generate new client keypair for destination
        let signing = SigningKey::generate(&mut rand::rngs::OsRng);
        let pubblob = ssh_ed25519_blob(signing.verifying_key().as_bytes());
        
        v.update_profile(&new_uuid, |p| {
            p.client_public_key = pubblob;
            p.targets_meta = src_profile.targets_meta.clone();
            p.connect_timeout_s = src_profile.connect_timeout_s;
            p.exec_timeout_s = src_profile.exec_timeout_s;
            p.unlock_host_key = None; // Don't copy host keys
            p.os_host_key = None;
            p.host_key_pinned_at = 0;
            p.notes = format!("Copied from {} ({})", src_profile_name, src_profile.unlock_host);
        }).map_err(|e| e.to_string())?;
        
        // Replace secrets with new client key + copied keyfiles
        let dest_secrets = SecretPayload {
            client_private_seed: signing.to_bytes(),
            keyfiles: src_secrets.keyfiles.clone(),
        };
        v.set_secrets(&new_uuid, &dest_secrets).map_err(|e| e.to_string())?;
        
        println!("Profile '{}' copied to '{}' in current vault.", src_profile_name, dest_name);
        println!("New client keypair generated. Remember to 'save' and deploy new authorized_keys.");
    }
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

    // Fetch OS host key (for enroll/rotate against booted OS)
    if p.os_host_key.is_none() {
        println!("No OS host key pinned. Fetching from {}:{} ...", p.unlock_host, p.unlock_port);
        let hk = match fetch_host_key(&p.unlock_host, p.unlock_port, p.connect_timeout_s).await {
            Ok(hk) => hk,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("Connection refused") || msg.contains("Connection timed out") {
                    return Err(format!("Failed to connect to {}:{}. Is the OS booted and SSH running?", p.unlock_host, p.unlock_port));
                }
                return Err(msg);
            }
        };
        println!("{} {}", hk.key_type, fingerprint_sha256(&hk.key_bytes));
        if ask("Pin as OS host key? [y/N]: ").to_lowercase() != "y" { return Err("aborted".into()); }
        v.set_host_key(&p.uuid, hk, true).map_err(|e| e.to_string())?;
    }

    let username = ask_or("OS SSH user", "root");
    let auth = match ask_or("Auth: (p)assword / (k)ey file", "k").as_str() {
        "p" => BootedAuth::Password(SecretString::new(pass_optional_str("OS password: "))),
        _ => {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            let path = ask_or("Key file", &format!("{}/.ssh/id_ed25519", home));
            let kp = russh_keys::load_secret_key(&path, None)
                .or_else(|_| russh_keys::load_secret_key(&path, Some(&pass_optional_str("Key passphrase: "))))
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
        if let Some(mapper) = &info.mapper_name {
            println!("       Mapper: {} (active)", mapper);
        } else {
            println!("       Mapper: (not decrypted)");
        }
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
            // Use existing mapper name if available, otherwise ask user
            let mapped = if let Some(mapper) = info.mapper_name {
                mapper
            } else {
                let default = format!("crypt{}", info.luks_uuid.split('-').next().unwrap_or("vol"));
                ask_or(&format!("Mapper name for {}", info.luks_uuid), &default)
            };
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
    let path = st.path.clone().ok_or("no vault path")?;
    
    // Ask for old passphrase and verify
    let old_pass = pass("Old passphrase: ");
    let bytes = fs::read(&path).map_err(|e| e.to_string())?;
    Vault::open(&bytes, &old_pass).map_err(|_| "old passphrase incorrect")?;
    
    // Ask for new passphrase twice
    let p1 = pass("New passphrase: "); let p2 = pass("Repeat: ");
    if p1.expose_secret() != p2.expose_secret() { return Err("passphrases differ".into()); }
    v.change_passphrase(0, &p1, Argon2Params::default()).map_err(|e| e.to_string())?;
    println!("Passphrase changed successfully.");
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