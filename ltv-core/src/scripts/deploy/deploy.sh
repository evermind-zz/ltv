#!/bin/sh
# deploy.sh: Run on target Alpine server to install LTV
# Usage: sudo sh deploy.sh
# {kernel_version} -> replaced with `uname -r` at runtime

set -e

echo "Installing mkinitfs feature files..."
cp ltv.files ltv.modules ltv.packages /etc/mkinitfs/features.d/

echo "Installing luks wrapper to /usr/share/mkinitfs/"
cp ltv-luks-wrapper.sh /usr/share/mkinitfs/ltv-luks-wrapper.sh
chmod 755 /usr/share/mkinitfs/ltv-luks-wrapper.sh

echo "Installing Dropbear host key and authorized_keys overlay..."
mkdir -p /etc/mkinitfs/ltv-stuff/etc/dropbear
cp dropbear_ed25519_host_key /etc/mkinitfs/ltv-stuff/etc/dropbear/
cp dropbear_ed25519_host_key.pub /etc/mkinitfs/ltv-stuff/etc/dropbear/
mkdir -p /etc/mkinitfs/ltv-stuff/root/.ssh
cp authorized_keys /etc/mkinitfs/ltv-stuff/root/.ssh/authorized_keys
chmod 600 /etc/mkinitfs/ltv-stuff/etc/dropbear/dropbear_ed25519_host_key
chmod 644 /etc/mkinitfs/ltv-stuff/etc/dropbear/dropbear_ed25519_host_key.pub
chmod 600 /etc/mkinitfs/ltv-stuff/root/.ssh/authorized_keys

echo "Installing patch script and commit hook..."
cp ltv-patch-init.sh /etc/mkinitfs/ltv-stuff/ltv-patch-init.sh
chmod 755 /etc/mkinitfs/ltv-stuff/ltv-patch-init.sh
mkdir -p /etc/apk/commit_hooks.d
cp ltv-commit-hook.sh /etc/apk/commit_hooks.d/ltv-commit-hook.sh
chmod 755 /etc/apk/commit_hooks.d/ltv-commit-hook.sh

echo "Patching initramfs init script..."
sh /etc/mkinitfs/ltv-stuff/ltv-patch-init.sh /usr/share/mkinitfs/initramfs-init

# Detect kernel version
KERNEL=$(uname -r)

echo ""
echo "======================================================================"
echo "DEPLOYMENT FILES INSTALLED - MANUAL STEP REQUIRED"
echo "======================================================================"
echo ""
echo "To complete the installation, you need to:"
echo ""
echo "1. Add 'ltv' to FEATURES in /etc/mkinitfs/mkinitfs.conf:"
echo "   FEATURES=\"virtio base cryptsetup ltv network keymap ata ide scsi usb phy ext4\""
echo ""
echo "2. Add kernel command line parameters (bootloader config):"
echo "   Required: ltv=yes"
echo "   Required for network: ip=dhcp (or static ip=... see Alpine docs)"
echo "   Recommended: modules=virtio_net (or your NIC driver, e.g. e1000, vmxnet3)"
echo "   Example: ltv=yes ip=dhcp modules=virtio_net"
echo ""
echo "3. Regenerate initramfs manually:"
echo "   mkinitfs -F \"virtio base cryptsetup ltv network keymap ata ide scsi usb phy ext4\" -k \"$KERNEL\" \\"
echo "     -o \"/boot/initramfs-ltv-$KERNEL\" \"$KERNEL\""
echo ""
echo "======================================================================"
echo "Then update your bootloader and reboot."
echo "======================================================================"
