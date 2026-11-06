#!/bin/sh
# deploy_nopatch.sh: Run on target Alpine server to install LTV (without patching initramfs-init)
# Usage: sudo sh deploy_nopatch.sh
# {kernel_version} -> replaced with `uname -r` at runtime

set -e

echo "Installing mkinitfs feature files..."
cp ltv.files ltv.modules ltv.packages /etc/mkinitfs/features.d/

echo "Installing hook and common lib to /usr/share/mkinitfs/"
cp ltv-hook.sh /usr/share/mkinitfs/ltv-hook.sh
chmod 755 /usr/share/mkinitfs/ltv-hook.sh
cp ltv-common.sh /usr/share/mkinitfs/ltv-common.sh

echo "Installing Dropbear host key and authorized_keys overlay..."
mkdir -p /etc/mkinitfs/features.d/ltv-ssh.keys/etc/dropbear
cp dropbear_ed25519_host_key /etc/mkinitfs/features.d/ltv-ssh.keys/etc/dropbear/
cp dropbear_ed25519_host_key.pub /etc/mkinitfs/features.d/ltv-ssh.keys/etc/dropbear/
mkdir -p /etc/mkinitfs/features.d/ltv-ssh.keys/root/.ssh
cp authorized_keys /etc/mkinitfs/features.d/ltv-ssh.keys/root/.ssh/authorized_keys
chmod 600 /etc/mkinitfs/features.d/ltv-ssh.keys/etc/dropbear/dropbear_ed25519_host_key
chmod 644 /etc/mkinitfs/features.d/ltv-ssh.keys/etc/dropbear/dropbear_ed25519_host_key.pub
chmod 600 /etc/mkinitfs/features.d/ltv-ssh.keys/root/.ssh/authorized_keys

echo "Regenerating initramfs (without patching initramfs-init)..."
KERNEL="{kernel_version}"
mkinitfs -F "virtio base cryptsetup ltv network keymap ata ide scsi usb phy ext4" -k "$KERNEL" \
  -o "/boot/initramfs-ltv-$KERNEL" "$KERNEL"

echo "Done! Update bootloader with kernel cmdline from cmdline.txt"
echo "Then reboot."