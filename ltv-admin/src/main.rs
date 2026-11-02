use std::{fs, path::PathBuf};
use ltv_core::{format::Argon2Params, model::{Profile, TargetMeta, ResumePolicy, BootedAccess, BootedAuth, fingerprint_sha256}, net::{fetch_host_key, fetch_luks_info, probe, unlock}, vault::Vault, enroll::EnrollEvent};
use std::path::Path;
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

    let results = ltv_core::enroll(v, &p.uuid, &access, &luks_pass, only, |e| match e {
        EnrollEvent::Skipped(t, why) => println!(" ! {t}: skipped ({why})"),
        other => println!(" ✓ {other:?}"),
    }).await.map_err(|e| e.to_string())?;

    for r in &results { v.set_keyslot(&p.uuid, &r.luks_uuid, r.keyslot).map_err(|e| e.to_string())?; }
    println!("enrolled {} target(s); keyslots recorded. Remember to 'save'.", results.len());
    Ok(())
}

async fn cmd_fetch(st: &mut State, name: &str) -> Result<(), String> {
    let v = st.vault.as_mut().ok_or("no vault open")?;
    let p = resolve(v, name)?.clone();

    // OS host key must be pinned first
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

    let results = fetch_luks_info(v, &p.uuid, &access, None).await.map_err(|e| e.to_string())?;

    if results.is_empty() {
        println!("No LUKS volumes found.");
        return Ok(());
    }

    println!("\nDiscovered LUKS volumes:");
    for (i, info) in results.iter().enumerate() {
        println!("  [{}] UUID: {}", i, info.luks_uuid);
        println!("       Device: {}", info.device_path);
        println!("       Cipher: {}", info.cipher);
        println!("       Key size: {} bits", info.key_size);
        println!("       Version: {}", info.header_version);
    }

    let choice = ask("\nAdd all as targets? [y/N]: ").to_lowercase();
    if choice == "y" {
        for info in results {
            let mapped = format!("crypt{}", info.luks_uuid.split('-').next().unwrap_or("vol"));
            let meta = TargetMeta {
                luks_uuid: info.luks_uuid.clone(),
                fallback_path: Some(info.device_path.clone()),
                mapped_name: mapped,
                order: 0,
                keyslot: None,
                token_id: None,
            };
            v.add_target(&p.uuid, meta, None).map_err(|e| e.to_string())?;
            println!("  added target for {}", info.luks_uuid);
        }
        println!("Targets added. Remember to 'save'.");
    }
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
                              pubkey <p> | hostkey fetch <p> [--os] | probe <p>|--all | unlock <p> | enroll <p> [--target <uuid|mapper>]\n\
                              fetch <p> | server-setup <p> [--out <dir>] | passwd | quit"),
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
            let hk = fetch_host_key(&p.host, p.port, p.connect_timeout_s).await.map_err(|e| e.to_string())?;
            println!("{} {}", hk.key_type, fingerprint_sha256(&hk.key_bytes));
            if ask("Pin this key? [y/N]: ").to_lowercase() == "y" {
                v.set_host_key(&p.uuid, hk, rest.contains(&"--os")).map_err(|e| e.to_string())?;
            }
        }
        ["probe", n] => {
            let v = st.vault.as_ref().ok_or("no vault open")?;
            let ps: Vec<Profile> = if *n == "--all" { v.inventory.profiles.clone() } else { vec![resolve(v, n)?.clone()] };
            for p in ps { println!("{:<16} {:?}", p.name, probe(&p).await); }
        }
        ["unlock", n] => {
            let v = st.vault.as_ref().ok_or("no vault open")?;
            let uuid = resolve(v, n)?.uuid;
            unlock(v, &uuid, |e| println!(" ✓ {e:?}")).await.map_err(|e| e.to_string())?;
        }
        ["enroll", n] => cmd_enroll(st, n, None).await?,
        ["enroll", n, "--target", t] => cmd_enroll(st, n, Some(t)).await?,
        ["fetch", n] => cmd_fetch(st, n).await?,
        ["server-setup", n, rest @ ..] => cmd_server_setup(st, n, &rest).await?,
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

async fn cmd_server_setup(st: &mut State, name: &str, args: &[&str]) -> Result<(), String> {
    let v = st.vault.as_ref().ok_or("no vault open")?;
    let p = resolve(v, name)?.clone();

    // Check initramfs host key is pinned
    if p.initramfs_host_key.is_none() {
        return Err("initramfs host key not pinned. Run 'hostkey fetch <profile>' first.".into());
    }

    // Parse --out argument
    let mut out_dir = format!("./ltv-deploy-{}", p.name);
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--out" {
            if i + 1 >= args.len() { return Err("--out requires a directory".into()); }
            out_dir = args[i + 1].to_string();
            i += 2;
        } else {
            i += 1;
        }
    }

    let out_path = Path::new(&out_dir);
    fs::create_dir_all(out_path).map_err(|e| format!("create dir: {e}"))?;

    // Get mapper names from targets (ordered by order field)
    let mut targets: Vec<_> = p.targets_meta.clone();
    targets.sort_by_key(|t| t.order);
    let mappers: Vec<String> = targets.iter().map(|t| t.mapped_name.clone()).collect();
    let mappers_csv = mappers.join(",");

    // Get initramfs host key fingerprint for display
    let hk = p.initramfs_host_key.as_ref().unwrap();
    let hk_fp = fingerprint_sha256(&hk.key_bytes);

    // 1. Generate ltv.files
    let ltv_files = r#"/sbin/dropbear
/etc/dropbear/dropbear_ed25519_host_key
/usr/share/mkinitfs/features.d/ltv-hook.sh
/sbin/ltv-init-wrapper
"#;
    fs::write(out_path.join("ltv.files"), ltv_files).map_err(|e| format!("write ltv.files: {e}"))?;

    // 2. Generate ltv.modules (empty - depends on cryptsetup feature for modules)
    let ltv_modules = r#"# ltv feature depends on cryptsetup feature for kernel modules
# No additional modules needed
"#;
    fs::write(out_path.join("ltv.modules"), ltv_modules).map_err(|e| format!("write ltv.modules: {e}"))?;

    // 3. Generate ltv.packages
    let ltv_packages = r#"dropbear
"#;
    fs::write(out_path.join("ltv.packages"), ltv_packages).map_err(|e| format!("write ltv.packages: {e}"))?;

    // 4. Generate ltv-hook.sh
    let ltv_hook = format!(r#"#!/bin/sh
# ltv-hook: Start dropbear and wait for LTV mappers
# Called from initramfs init via ltv-init-wrapper
# Kernel cmdline: ltv_mappers={}

set -e

MAPPERS="{}"
TIMEOUT=300
ELAPSED=0

mkdir -p /run/ltv

# Ensure dropbear host keys exist (should be pre-installed by feature)
for keytype in ed25519 ecdsa rsa; do
    keyfile="/etc/dropbear/dropbear_${{keytype}}_host_key"
    [ -f "$keyfile" ] || dropbearkey -t "$keytype" -f "$keyfile" >/dev/null 2>&1
done

# Start dropbear on port 22
# -R: don't daemonize (we background manually)
# -s: disable password auth
# -j: disable local port forwarding
# -k: disable keepalive
# -p: port
# -r: host key file
dropbear -R -s -j -k -p 22 -r /etc/dropbear/dropbear_ed25519_host_key &
DROPBEAR_PID=$!

echo "ltv-hook: dropbear started (pid $DROPBEAR_PID), waiting for mappers: $MAPPERS"

# Wait for mappers or resume signal
while [ $ELAPSED -lt $TIMEOUT ]; do
    ready=1
    for m in $MAPPERS; do
        [ -e "/dev/mapper/$m" ] || ready=0
    done
    [ $ready -eq 1 ] && break
    [ -e /run/ltv/resume ] && break
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done

if [ $ELAPSED -ge $TIMEOUT ]; then
    echo "ltv-hook: TIMEOUT after ${{TIMEOUT}}s waiting for mappers"
    kill $DROPBEAR_PID 2>/dev/null
    wait $DROPBEAR_PID 2>/dev/null
    exit 1
fi

echo "ltv-hook: all mappers ready or resume signal received"
kill $DROPBEAR_PID 2>/dev/null
wait $DROPBEAR_PID 2>/dev/null

exit 0
"#, mappers_csv, mappers_csv);

    // Create usr/share/mkinitfs/features.d directory
    fs::create_dir_all(out_path.join("usr/share/mkinitfs/features.d"))
        .map_err(|e| format!("create dir: {e}"))?;
    fs::write(out_path.join("usr/share/mkinitfs/features.d/ltv-hook.sh"), ltv_hook)
        .map_err(|e| format!("write ltv-hook.sh: {e}"))?;

    // 5. Generate ltv-init-wrapper
    let ltv_init_wrapper = r#"#!/bin/sh
# ltv-init-wrapper: Run LTV hook then exec real init
# Kernel cmdline: init=/sbin/ltv-init-wrapper ltv_mappers=cryptroot,cryptdata

if [ -n "$KOPT_ltv_mappers" ]; then
    export LTV_MAPPERS="$KOPT_ltv_mappers"
    /usr/share/mkinitfs/features.d/ltv-hook.sh
fi

exec /init "$@"
"#;
    fs::create_dir_all(out_path.join("sbin")).map_err(|e| format!("create dir: {e}"))?;
    fs::write(out_path.join("sbin/ltv-init-wrapper"), ltv_init_wrapper)
        .map_err(|e| format!("write ltv-init-wrapper: {e}"))?;

    // 6. Note: dropbear host key will be generated on target by deploy.sh
    // (generating proper Dropbear key format requires dropbearkey binary)
    fs::create_dir_all(out_path.join("etc/dropbear")).map_err(|e| format!("create dir: {e}"))?;
    fs::write(out_path.join("etc/dropbear/README.txt"), 
        "Run on target: dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key\n")
        .map_err(|e| format!("write README.txt: {e}"))?;

    // 7. Generate authorized_keys for initramfs
    let authorized_keys = v.authorized_keys_line(&p);
    fs::write(out_path.join("authorized_keys"), authorized_keys)
        .map_err(|e| format!("write authorized_keys: {e}"))?;

    // 8. Generate cmdline.txt
    let cmdline = format!("init=/sbin/ltv-init-wrapper ltv_mappers={}", mappers_csv);
    fs::write(out_path.join("cmdline.txt"), &cmdline)
        .map_err(|e| format!("write cmdline.txt: {e}"))?;

    // 9. Generate deploy.sh
    let deploy_sh = format!(r#"#!/bin/sh
# deploy.sh - Run as root on target Alpine server
# Generated by ltv-admin server-setup for profile: {}
set -e

echo "Installing LTV mkinitfs feature..."

# 1. Install feature files
cp -r etc/mkinitfs/features.d/ltv.* /etc/mkinitfs/features.d/
cp usr/share/mkinitfs/features.d/ltv-hook.sh /usr/share/mkinitfs/features.d/
chmod 755 /usr/share/mkinitfs/features.d/ltv-hook.sh

# 2. Install init wrapper
cp sbin/ltv-init-wrapper /sbin/ltv-init-wrapper
chmod 755 /sbin/ltv-init-wrapper

# 3. Generate dropbear host key (run on target)
dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key

# 4. Install authorized_keys for initramfs (via apkovl overlay)
mkdir -p /etc/mkinitfs/features.d/ltv-ssh.keys/root/.ssh
cp authorized_keys /etc/mkinitfs/features.d/ltv-ssh.keys/root/.ssh/authorized_keys
chmod 600 /etc/mkinitfs/features.d/ltv-ssh.keys/root/.ssh/authorized_keys

# 5. Regenerate initramfs
KERNEL=$(uname -r)
echo "Regenerating initramfs for kernel $KERNEL..."
mkinitfs -F "base ltv cryptsetup network" -k "$KERNEL" -o "/boot/initramfs-ltv-$KERNEL" "$KERNEL"

# 6. Update bootloader
echo ""
echo "=== NEXT STEPS ==="
echo "1. Update your bootloader to use the new initramfs:"
echo "   /boot/initramfs-ltv-$KERNEL"
echo "2. Add kernel cmdline parameters:"
echo "   {}"
echo "3. For syslinux: edit /etc/syslinux.conf"
echo "   For GRUB: edit /etc/default/grub then run grub-mkconfig"
echo "4. Reboot to test"
"#, p.name, &cmdline);

    fs::write(out_path.join("deploy.sh"), deploy_sh)
        .map_err(|e| format!("write deploy.sh: {e}"))?;

    // 10. Generate README.md
    let readme = format!(r#"# LTV Deployment for {}

## Generated Files

- `ltv.files` - mkinitfs feature file list
- `ltv.modules` - kernel modules needed
- `ltv.packages` - APK packages to install
- `ltv-hook.sh` - initramfs hook (starts dropbear, waits for mappers)
- `ltv-init-wrapper` - init wrapper (runs hook before real init)
- `etc/dropbear/dropbear_ed25519_host_key` - Dropbear Ed25519 host key
- `authorized_keys` - Client public key for initramfs SSH
- `cmdline.txt` - Kernel cmdline to add
- `deploy.sh` - Run this on the target Alpine server

## Initramfs Host Key

**Fingerprint (SHA256): {}**

This key is pinned in the vault profile. Verify it matches on first connection.

## Target Mappers

{}
(Order matches target `order` field in profile)

## Deployment

```bash
# On target Alpine server (as root):
cd /path/to/this/directory
./deploy.sh
reboot
```

## Manual Deployment (if deploy.sh fails)

```bash
# 1. Copy feature files
cp ltv.files ltv.modules ltv.packages /etc/mkinitfs/features.d/
cp ltv-hook.sh /usr/share/mkinitfs/features.d/
chmod 755 /usr/share/mkinitfs/features.d/ltv-hook.sh

# 2. Copy init wrapper
cp ltv-init-wrapper /sbin/ltv-init-wrapper
chmod 755 /sbin/ltv-init-wrapper

# 3. Copy dropbear host key
mkdir -p /etc/dropbear
cp etc/dropbear/dropbear_ed25519_host_key /etc/dropbear/
chmod 600 /etc/dropbear/dropbear_ed25519_host_key

# 4. Create authorized_keys overlay
mkdir -p /etc/mkinitfs/features.d/ltv-ssh.keys/root/.ssh
cp authorized_keys /etc/mkinitfs/features.d/ltv-ssh.keys/root/.ssh/authorized_keys
chmod 600 /etc/mkinitfs/features.d/ltv-ssh.keys/root/.ssh/authorized_keys

# 5. Regenerate initramfs
mkinitfs -F "base ltv cryptsetup network" -k $(uname -r) -o /boot/initramfs-ltv-$(uname -r) $(uname -r)

# 6. Update bootloader with:
#    init=/sbin/ltv-init-wrapper ltv_mappers={}
```
"#, p.name, hk_fp, mappers.join("\n"), mappers_csv);

    fs::write(out_path.join("README.md"), readme)
        .map_err(|e| format!("write README.md: {e}"))?;

    println!("Generated deployment in: {}", out_path.display());
    println!("");
    println!("Initramfs host key fingerprint: {}", hk_fp);
    println!("Target mappers: {}", mappers_csv);
    println!("");
    println!("Next steps:");
    println!("  1. Copy {} to target server", out_dir);
    println!("  2. On target (as root): cd {} && ./deploy.sh", out_dir);
    println!("  3. Update bootloader with cmdline from cmdline.txt");
    println!("  4. Reboot");

    Ok(())
}

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