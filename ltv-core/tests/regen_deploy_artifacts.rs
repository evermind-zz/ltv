use ltv_core::{Vault, fetch_host_key};
use secrecy::SecretVec;
use std::fs;
use std::path::Path;

#[tokio::test]
async fn regen_deploy() {
    let bytes = fs::read("../myTestVault.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let mut vault = Vault::open(&bytes, &pass).unwrap();

    let profile = vault.inventory.profiles[0].clone();
    let uuid = profile.uuid;

    // Pin BOTH initramfs and OS host keys (same server key)
    let hk = fetch_host_key(&profile.host, profile.port, profile.connect_timeout_s).await.unwrap();
    vault.set_host_key(&uuid, hk.clone(), false).unwrap();
    vault.set_host_key(&uuid, hk, true).unwrap();

    // Save the vault with pinned keys
    let vault_bytes = vault.save().unwrap();
    fs::write("../myTestVault.ltv", vault_bytes).unwrap();
    println!("Vault saved with pinned host keys");

    // Generate deployment artifacts
    let deploy_dir = Path::new("/tmp/ltv-deploy-myTestVault");
    let _ = fs::remove_dir_all(deploy_dir);
    fs::create_dir_all(deploy_dir).unwrap();

    let mut cmdline = String::from("ltv_mappers=");
    let mut first = true;
    for tm in &profile.targets_meta {
        if !first { cmdline.push(','); }
        cmdline.push_str(&tm.mapped_name);
        first = false;
    }
    cmdline.push('\n');
    for tm in &profile.targets_meta {
        cmdline.push_str(&format!("ltv_{}={}\n", tm.mapped_name, tm.luks_uuid));
    }

    fs::write(deploy_dir.join("ltv.files"),
        "/usr/share/mkinitfs/ltv-hook.sh\n/usr/share/mkinitfs/ltv-common.sh\n/usr/sbin/dropbear\n").unwrap();
    fs::write(deploy_dir.join("ltv.modules"), "").unwrap();
    fs::write(deploy_dir.join("ltv.packages"), "dropbear\n").unwrap();

    let hook = r#"#!/bin/sh
. /lib/mkinitfs/ltv-common.sh

ltv_unlock() {
    local dev="$1" name="$2"
    cryptsetup open --key-file=- "UUID=${dev}" "${name}" || return 1
}

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
    fs::write(deploy_dir.join("ltv-hook.sh"), hook).unwrap();

    let common = r#"#!/bin/sh
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
    fs::write(deploy_dir.join("ltv-common.sh"), common).unwrap();

    let patch = r###"#!/bin/sh
INIT=/usr/share/mkinitfs/initramfs-init
if ! grep -q "ltv-hook" "$INIT"; then
    sed -i '/^configure_ip/a ### LTV PATCH START ###\n. /lib/mkinitfs/ltv-hook.sh\n### LTV PATCH END ###' "$INIT"
fi
"###;
    fs::write(deploy_dir.join("initramfs-init.patch"), patch).unwrap();

    let auth_keys = vault.authorized_keys_line(&profile);
    fs::write(deploy_dir.join("authorized_keys"), auth_keys).unwrap();

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
echo "Done!"
"###;
    fs::write(deploy_dir.join("deploy.sh"), deploy_sh).unwrap();

    fs::write(deploy_dir.join("cmdline.txt"), &cmdline).unwrap();

    let readme = format!(r#"# LTV Deployment Artifacts for profile: {}

## Files
- `ltv.files` - Feature file list
- `ltv.modules` - Kernel modules (empty)
- `ltv.packages` - APK packages: dropbear
- `ltv-hook.sh` - Initramfs hook script
- `ltv-common.sh` - Shared functions for hooks
- `initramfs-init.patch` - Sed script to patch initramfs-init
- `authorized_keys` - Restricted client public key
- `deploy.sh` - Run this on the target server
- `cmdline.txt` - Kernel command line parameters

## Kernel command line
{}
## From Admin Machine
    ltv-admin> unlock {}
"#, profile.name, &cmdline, profile.name);
    fs::write(deploy_dir.join("README.md"), readme).unwrap();

    println!("Deployment artifacts regenerated at {}", deploy_dir.display());
    println!("cmdline.txt content:\n{}", cmdline);
}
