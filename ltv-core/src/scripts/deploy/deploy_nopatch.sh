#!/bin/sh
# deploy_nopatch.sh: Run on target Alpine server to install LTV (without patching initramfs-init)
# Usage: sudo sh deploy_nopatch.sh
# {kernel_version} -> replaced with `uname -r` at runtime

set -e

echo "Installing mkinitfs feature files..."
mkdir -p /etc/mkinitfs/ltv-stuff
cp ltv.files ltv.modules ltv.packages /etc/mkinitfs/ltv-stuff/

echo "Installing luks wrapper and common lib to /usr/share/mkinitfs/"
cp ltv-luks-wrapper.sh /usr/share/mkinitfs/ltv-luks-wrapper.sh
chmod 755 /usr/share/mkinitfs/ltv-luks-wrapper.sh
cp ltv-common.sh /usr/share/mkinitfs/ltv-common.sh

echo "Installing Dropbear host key and authorized_keys overlay..."
mkdir -p /etc/mkinitfs/ltv-stuff/etc/dropbear
cp dropbear_ed25519_host_key /etc/mkinitfs/ltv-stuff/etc/dropbear/
cp dropbear_ed25519_host_key.pub /etc/mkinitfs/ltv-stuff/etc/dropbear/
mkdir -p /etc/mkinitfs/ltv-stuff/root/.ssh
cp authorized_keys /etc/mkinitfs/ltv-stuff/root/.ssh/authorized_keys
chmod 600 /etc/mkinitfs/ltv-stuff/etc/dropbear/dropbear_ed25519_host_key
chmod 644 /etc/mkinitfs/ltv-stuff/etc/dropbear/dropbear_ed25519_host_key.pub
chmod 600 /etc/mkinitfs/ltv-stuff/root/.ssh/authorized_keys

echo "Regenerating initramfs (without patching initramfs-init)..."
KERNEL="{kernel_version}"
mkinitfs -F "virtio base cryptsetup ltv network keymap ata ide scsi usb phy ext4" -k "$KERNEL" \
  -o "/boot/initramfs-ltv-$KERNEL" "$KERNEL"

echo "Done! Update bootloader with kernel cmdline from cmdline.txt"
echo "Then reboot."