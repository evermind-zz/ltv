# LTV Deployment Guide

This guide covers deploying LTV remote unlock to an Alpine Linux target server.
The authoritative deployment scripts are in `ltv-core/src/scripts/` and are embedded
in the `ltv-admin` binary - run `server-setup <profile>` to generate them.

## Target Server Requirements

- Alpine Linux (3.18+ recommended)
- `mkinitfs` (standard on Alpine)
- Root access for deployment
- Network connectivity during boot (DHCP or static)

## Deployment Artifacts

`server-setup <profile> --out ./deploy-<profile>` generates:

```
deploy-<profile>/
├── ltv.files                     # Feature file list -> /etc/mkinitfs/features.d/
├── ltv.modules                   # Kernel modules (empty - uses cryptsetup feature)
├── ltv.packages                  # APK packages: dropbear
├── ltv-luks-wrapper.sh           # Replaces nlplug-findfs, starts Dropbear, waits for resume
├── ltv-patch-init.sh             # Idempotent patcher for initramfs-init
├── ltv-commit-hook.sh            # apk commit hook for persistence across updates
├── authorized_keys               # Restricted client pubkey for initramfs SSH
├── dropbear_ed25519_host_key     # Dropbear host private key (pre-generated)
├── dropbear_ed25519_host_key.pub # Dropbear host public key
├── deploy.sh                     # Run on target (patches initramfs-init)
├── deploy_nopatch.sh             # Alternative without patching initramfs-init
└── README.md                     # Generated deployment instructions
```

The scripts are also available directly in the source tree:
- `ltv-core/src/scripts/deploy/deploy.sh`
- `ltv-core/src/scripts/deploy/deploy_nopatch.sh`
- `ltv-core/src/scripts/mkinitfs/ltv-luks-wrapper.sh`
- `ltv-core/src/scripts/mkinitfs/ltv-patch-init.sh`
- `ltv-core/src/scripts/deploy/ltv-commit-hook.sh`

## Deployment Workflow

### 1. Generate Artifacts (Admin Workstation)

```bash
ltv-admin> server-setup web01 --out ./deploy-web01
```

### 2. Copy to Target

```bash
scp -r ./deploy-web01 root@192.0.2.10:/root/
```

### 3. Run Deploy Script (Target Server, as root)

```bash
cd /root/deploy-web01
./deploy.sh
```

The script will:
1. Install feature files to `/etc/mkinitfs/features.d/`
2. Install `ltv-luks-wrapper.sh` to `/usr/share/mkinitfs/`
3. Create Dropbear key/authorized_keys overlay in `/etc/mkinitfs/ltv-stuff/`
4. Install patch script and apk commit hook
5. Patch `/usr/share/mkinitfs/initramfs-init` (idempotent)
6. **Print manual completion steps** (does NOT run `mkinitfs`)

### 4. Manual Completion (Printed by deploy.sh)

```bash
# a) Add 'ltv' to FEATURES in /etc/mkinitfs/mkinitfs.conf:
FEATURES="virtio base cryptsetup ltv network keymap ata ide scsi usb phy ext4"

# b) Add kernel cmdline parameters to your bootloader config:
#    Required: ltv=yes
#    Required for network: ip=dhcp (or static ip=... per Alpine docs)
#    Recommended: modules=virtio_net (or your NIC driver: e1000, vmxnet3, etc.)
#    Example: ltv=yes ip=dhcp modules=virtio_net

# c) Regenerate initramfs:
mkinitfs -F "virtio base cryptsetup ltv network keymap ata ide scsi usb phy ext4" \
  -k "$(uname -r)" -o "/boot/initramfs-ltv-$(uname -r)" "$(uname -r)"

# d) Update bootloader and reboot
```

### 5. Update Bootloader

**Important**: You must **integrate** the LTV parameters into your existing kernel command line,
not replace it entirely. Keep your existing `root=`, `rootfstype=`, `quiet`, etc. parameters.

#### Syslinux (`/etc/syslinux.conf`)

```conf
DEFAULT ltv
LABEL ltv
    MENU_LABEL Alpine Linux with LTV
    LINUX /boot/vmlinuz-virt
    INITRD /boot/initramfs-ltv-6.18.59-0-virt
    APPEND ltv=yes ip=dhcp modules=virtio_net root=UUID=<your-rootfs-uuid> quiet
```

#### GRUB (`/etc/default/grub`)

```bash
GRUB_CMDLINE_LINUX_DEFAULT="ltv=yes ip=dhcp modules=virtio_net"
# Keep any existing parameters, e.g.:
# GRUB_CMDLINE_LINUX_DEFAULT="ltv=yes ip=dhcp modules=virtio_net root=UUID=... quiet"
```

Then run: `grub-mkconfig -o /boot/grub/grub.cfg`

### 6. Reboot

```bash
reboot
```

## Kernel Cmdline Parameters

| Parameter | Description | Required? |
|-----------|-------------|-----------|
| `ltv=yes` | Enable LTV remote unlock | **Yes** |
| `ip=dhcp` | Configure network via DHCP in initramfs | **Yes** (for remote unlock) |
| `ip=<static>` | Static IP config (Alpine format) | Alternative to DHCP |
| `modules=<driver>` | Load network driver early (virtio_net, e1000, vmxnet3, etc.) | Recommended |

See [Alpine `mkinitfs` docs](https://wiki.alpinelinux.org/wiki/Mkinitfs) for full network options.

## What Happens at Boot

1. Kernel loads initramfs with LTV feature
2. Patched `initramfs-init` runs `configure_ip` when `ltv=yes` is set
3. `nlplug-findfs` call replaced with `ltv-luks-wrapper.sh`
4. Wrapper starts Dropbear on port 22 (Ed25519 host key, pubkey-only auth)
5. Wrapper runs `nlplug-findfs` (foreground, TTY password prompt available)
6. Background monitor waits for `/run/ltv/resume` (created by unlock client)
7. Admin runs `ltv-admin unlock web01` from workstation
8. Client pushes keyfiles over SSH to `cryptsetup --key-file=-`
9. On success, client writes `/run/ltv/resume`, wrapper kills first nlplug-findfs, runs second
10. Boot continues

## Security Notes

- Initramfs host key is **pre-generated and deployed** (not generated on target)
- Fingerprint is shown in generated `README.md` - verify on first connection
- Client public key in `authorized_keys` has restrictions: no port forwarding, no agent, no X11, no pty
- Wrapper has no hardcoded timeout - waits for `/run/ltv/resume` or TTY unlock

## Verification Checklist

After deployment, verify:

- [ ] `/etc/mkinitfs/features.d/ltv.*` files present
- [ ] `/usr/share/mkinitfs/ltv-luks-wrapper.sh` executable
- [ ] `/usr/share/mkinitfs/initramfs-init` patched (check for "LTV PATCH" markers)
- [ ] `/etc/mkinitfs/ltv-stuff/` contains dropbear keys and authorized_keys
- [ ] `/etc/apk/commit_hooks.d/ltv-commit-hook.sh` present
- [ ] Initramfs regenerated: `/boot/initramfs-ltv-<kernel>`
- [ ] Bootloader updated with new initramfs + kernel cmdline (`ltv=yes ip=dhcp modules=virtio_net`)

## Testing

```bash
# 1. Reboot target
reboot

# 2. From admin, wait for initramfs (Dropbear banner)
ssh -o ConnectTimeout=10 root@192.0.2.10
# Should show Dropbear banner, then disconnect (no shell)

# 3. Test unlock
ltv-admin> unlock web01

# 4. Verify boot completes
# Target should boot to login prompt
```