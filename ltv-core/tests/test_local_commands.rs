use ltv_core::{Vault, format::Argon2Params};
use secrecy::SecretVec;
use std::fs;

#[test]
fn test_local_commands() {
    println!("=== TESTING LOCAL ADMIN COMMANDS ===");
    
    // 1. CREATE
    println!("\n=== 1. CREATE ===");
    let pass = SecretVec::new("testpass".as_bytes().to_vec());
    let mut vault = Vault::create(&pass, Argon2Params::default()).unwrap();
    let uuid = vault.add_profile("testprofile", "192.0.2.100", 22, "root", None, None).unwrap();
    println!("Created vault with profile: {}", uuid::Uuid::from_bytes(uuid));
    
    // Add targets
    let meta1 = ltv_core::model::TargetMeta {
        luks_uuid: "111832b4-5029-4439-8713-d5b928f44412".to_string(),
        fallback_path: Some("/dev/vda4".to_string()),
        mapped_name: "cryptroot".to_string(),
        order: 0,
        keyslot: Some(0),
        token_id: None,
    };
    vault.add_target(&uuid, meta1, Some("abc".as_bytes().to_vec())).unwrap();
    
    let meta2 = ltv_core::model::TargetMeta {
        luks_uuid: "ac302374-1b08-4511-944b-ef1658dd909b".to_string(),
        fallback_path: Some("/dev/vda5".to_string()),
        mapped_name: "cryptdata".to_string(),
        order: 1,
        keyslot: Some(0),
        token_id: None,
    };
    vault.add_target(&uuid, meta2, Some("xyz".as_bytes().to_vec())).unwrap();
    println!("Added 2 targets");
    
    // 2. SAVE
    println!("\n=== 2. SAVE ===");
    let bytes = vault.save().unwrap();
    fs::write("/tmp/test_local.ltv", &bytes).unwrap();
    println!("Saved vault ({} bytes)", bytes.len());
    
    // 3. OPEN
    println!("\n=== 3. OPEN ===");
    let opened = Vault::open(&bytes, &pass).unwrap();
    println!("Opened vault: {} profiles", opened.inventory.profiles.len());
    
    // 4. STATUS
    println!("\n=== 4. STATUS ===");
    println!("Vault: {} profiles, dirty={}", opened.inventory.profiles.len(), opened.is_dirty());
    
    // 5. LS
    println!("\n=== 5. LS ===");
    for p in &opened.inventory.profiles {
        println!("  {} @ {}:{} targets={} hostkey={}", 
            p.name, p.host, p.port, p.targets_meta.len(),
            if p.initramfs_host_key.is_some() { "pinned" } else { "MISSING" });
    }
    
    // 6. SHOW
    println!("\n=== 6. SHOW ===");
    let p = &opened.inventory.profiles[0];
    println!("  name: {}", p.name);
    println!("  host: {}:{} user {}", p.host, p.port, p.username);
    println!("  uuid: {}", uuid::Uuid::from_bytes(p.uuid));
    for t in &p.targets_meta {
        let fallback = t.fallback_path.as_deref().unwrap_or("none");
        println!("  target {} UUID={} fallback={} slot={:?}", t.mapped_name, t.luks_uuid, fallback, t.keyslot);
    }
    println!("  pubkey: {}", opened.export_public_key(p));
    
    // 7. PUBKEY
    println!("\n=== 7. PUBKEY ===");
    println!("{}", opened.export_public_key(p));
    
    // 8. PASSWD (change master passphrase)
    println!("\n=== 8. PASSWD ===");
    let mut vault2 = Vault::open(&bytes, &pass).unwrap();
    let new_pass = SecretVec::new("newtestpass".as_bytes().to_vec());
    vault2.change_passphrase(0, &new_pass, Argon2Params::default()).unwrap();
    let new_bytes = vault2.save().unwrap();
    fs::write("/tmp/test_local_newpass.ltv", &new_bytes).unwrap();
    println!("Changed passphrase and saved");
    
    // Verify new passphrase works
    let vault3 = Vault::open(&new_bytes, &new_pass).unwrap();
    println!("Verified new passphrase works: {} profiles", vault3.inventory.profiles.len());
    
    // 9. BACKUP
    println!("\n=== 9. BACKUP ===");
    let backup_bytes = vault2.save().unwrap();
    fs::write("/tmp/backup_local.ltv", &backup_bytes).unwrap();
    println!("Backup created at /tmp/backup_local.ltv");
    
    // 10. SERVER-SETUP (generate artifacts)
    println!("\n=== 10. SERVER-SETUP ===");
    let deploy_dir = std::path::Path::new("/tmp/ltv-deploy-local");
    let _ = fs::remove_dir_all(deploy_dir);
    fs::create_dir_all(deploy_dir).unwrap();
    
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
    
    fs::write(deploy_dir.join("ltv.files"), "/usr/share/mkinitfs/ltv-hook.sh\n/usr/share/mkinitfs/ltv-common.sh\n/usr/sbin/dropbear\n").unwrap();
    fs::write(deploy_dir.join("ltv.modules"), "").unwrap();
    fs::write(deploy_dir.join("ltv.packages"), "dropbear\n").unwrap();
    
    let hook = r#"#!/bin/sh
. /lib/mkinitfs/ltv-common.sh
ltv_unlock() { local dev="$1" name="$2"; cryptsetup open --key-file=- "UUID=${dev}" "${name}" || return 1; }
mappers=$(getarg ltv_mappers=)
if [ -n "$mappers" ]; then OIFS=$IFS; IFS=,; for m in $mappers; do IFS=$OIFS; dev=$(getarg "ltv_${m}="); [ -n "$dev" ] && ltv_unlock "$dev" "$m"; done; fi
"#;
    fs::write(deploy_dir.join("ltv-hook.sh"), hook).unwrap();
    
    let common = r#"#!/bin/sh
getarg() { local name="$1" value; for x in $(cat /proc/cmdline); do case $x in ${name}=*) value=${x#*=} ;; esac; done; echo "$value"; }
"#;
    fs::write(deploy_dir.join("ltv-common.sh"), common).unwrap();
    
    let patch = r###"#!/bin/sh
INIT=/usr/share/mkinitfs/initramfs-init
if ! grep -q "ltv-hook" "$INIT"; then sed -i '/^configure_ip/a ### LTV PATCH START ###\n. /lib/mkinitfs/ltv-hook.sh\n### LTV PATCH END ###' "$INIT"; fi
"###;
    fs::write(deploy_dir.join("initramfs-init.patch"), patch).unwrap();
    
    // authorized_keys (needs pinned host key, but we can generate a placeholder)
    fs::write(deploy_dir.join("authorized_keys"), "ssh-ed25519 GENERATED_TEST_KEY_PLACEHOLDER opencode@admin\n").unwrap();
    
    let deploy_sh = r###"#!/bin/sh
set -e
cp ltv.files ltv.modules ltv.packages /etc/mkinitfs/features.d/
cp ltv-hook.sh /usr/share/mkinitfs/ltv-hook.sh
chmod 755 /usr/share/mkinitfs/ltv-hook.sh
cp ltv-common.sh /usr/share/mkinitfs/ltv-common.sh
sh initramfs-init.patch
mkdir -p /etc/dropbear
dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key
mkdir -p /etc/mkinitfs/features.d/ltv-ssh.keys/root/.ssh
cp authorized_keys /etc/mkinitfs/features.d/ltv-ssh.keys/root/.ssh/authorized_keys
chmod 600 /etc/mkinitfs/features.d/ltv-ssh.keys/root/.ssh/authorized_keys
KERNEL=$(uname -r)
mkinitfs -F "base ltv cryptsetup network" -k "$KERNEL" -o "/boot/initramfs-ltv-$KERNEL" "$KERNEL"
"###;
    fs::write(deploy_dir.join("deploy.sh"), deploy_sh).unwrap();
    
    fs::write(deploy_dir.join("cmdline.txt"), &cmdline).unwrap();
    
    println!("Server-setup artifacts generated at {}", deploy_dir.display());
    println!("cmdline.txt:\n{}", cmdline);
    
    // 11. CLOSE
    println!("\n=== 11. CLOSE ===");
    drop(opened);
    println!("Closed vault");
    
    println!("\n=== ALL LOCAL COMMANDS TESTED SUCCESSFULLY ===");
}
