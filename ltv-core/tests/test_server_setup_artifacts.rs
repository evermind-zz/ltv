use ltv_core::Vault;
use secrecy::SecretVec;
use std::fs;
use std::path::Path;

#[test]
fn test_server_setup_artifacts() {
    let bytes = fs::read("../test_full2.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let vault = Vault::open(&bytes, &pass).unwrap();

    let profile = &vault.inventory.profiles[0];
    
    // Simulate what server-setup does
    let deploy_dir = Path::new("/tmp/ltv-deploy-test-artifacts");
    let _ = fs::remove_dir_all(deploy_dir);
    fs::create_dir_all(deploy_dir).unwrap();

    // 1a. feature file list
    let files = "ltv-hook.sh\nltv-common.sh\n";
    fs::write(deploy_dir.join("ltv.files"), files).unwrap();

    // 1b. kernel modules
    fs::write(deploy_dir.join("ltv.modules"), "").unwrap();

    // 1c. APK packages
    let packages = "dropbear\n";
    fs::write(deploy_dir.join("ltv.packages"), packages).unwrap();

    // 2. hook script
    let hook = r#"#!/bin/sh
# ltv-hook: push-to-stdin LUKS unlock via Dropbear
# Runs after configure_ip, before nlplug-findfs

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
    fs::write(deploy_dir.join("ltv-common.sh"), common).unwrap();

    // 4. initramfs init patch
    let patch = r###"#!/bin/sh
INIT=/usr/share/mkinitfs/initramfs-init
if ! grep -q "ltv-hook" "$INIT"; then
    sed -i '/^configure_ip/a ### LTV PATCH START ###\n. /lib/mkinitfs/ltv-hook.sh\n### LTV PATCH END ###' "$INIT"
fi
"###;
    fs::write(deploy_dir.join("initramfs-init.patch"), patch).unwrap();

    // 5. authorized_keys
    let auth_keys = vault.authorized_keys_line(profile);
    fs::write(deploy_dir.join("authorized_keys"), auth_keys).unwrap();

    // 6. deploy.sh
    let deploy_sh = r###"#!/bin/sh
# deploy.sh: Run on target Alpine server to install LTV
set -e

echo "Installing mkinitfs feature files..."
cp ltv.files ltv.modules ltv.packages /etc/mkinitfs/features.d/
cp ltv-hook.sh /usr/share/mkinitfs/ltv-hook.sh
chmod 755 /usr/share/mkinitfs/ltv-hook.sh
cp ltv-common.sh /usr/share/mkinitfs/ltv-common.sh

echo "Patching initramfs init script..."
sh initramfs-init.patch

echo "Generating Dropbear Ed25519 host key..."
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
    fs::write(deploy_dir.join("deploy.sh"), deploy_sh).unwrap();

    // 7. cmdline.txt
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
    fs::write(deploy_dir.join("cmdline.txt"), &cmdline).unwrap();

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
"#, profile.name, &cmdline, profile.name);
    fs::write(deploy_dir.join("README.md"), readme).unwrap();

    // Verify all files exist
    for f in ["ltv.files", "ltv.modules", "ltv.packages", "ltv-hook.sh", "ltv-common.sh", "initramfs-init.patch", "authorized_keys", "deploy.sh", "cmdline.txt", "README.md"] {
        assert!(deploy_dir.join(f).exists(), "Missing: {}", f);
    }

    // Verify content
    let auth_content = fs::read_to_string(deploy_dir.join("authorized_keys")).unwrap();
    assert!(auth_content.contains("ssh-ed25519"));
    assert!(auth_content.contains("no-port-forwarding"));

    let cmdline_content = fs::read_to_string(deploy_dir.join("cmdline.txt")).unwrap();
    assert!(cmdline_content.contains("ltv_mappers="));
    assert!(cmdline_content.contains("cryptroot"));
    assert!(cmdline_content.contains("cryptdata"));

    println!("All server-setup artifacts generated correctly!");
}
