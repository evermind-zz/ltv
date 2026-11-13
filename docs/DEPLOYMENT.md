# LTV Deployment Guide

## Target Server Requirements

- Alpine Linux (3.18+ recommended)
- `mkinitfs` (standard on Alpine)
- Root access for deployment
- Network connectivity during boot (DHCP or static)

## Deployment Artifacts

`server-setup` generates:

```
deploy-<profile>/
├── ltv.files                     # Feature file list (installed to /etc/mkinitfs/features.d/)
├── ltv.modules                   # Kernel modules (empty - uses cryptsetup feature)
├── ltv.packages                  # APK packages: dropbear
├── ltv-luks-wrapper.sh           # Luks wrapper (replaces nlplug-findfs, starts Dropbear, waits for resume)
├── ltv-patch-init.sh             # Script to patch initramfs-init (idempotent)
├── authorized_keys               # Restricted client pubkey for initramfs SSH
├── dropbear_ed25519_host_key     # Dropbear host private key (pre-generated)
├── dropbear_ed25519_host_key.pub # Dropbear host public key
├── deploy.sh                     # Run on target server (patches initramfs-init)
├── deploy_nopatch.sh             # Alternative without patching initramfs-init
└── README.md                     # This guide
```

## deploy.sh Actions

```bash
#!/bin/sh
# 1. Install mkinitfs feature files
cp ltv.files ltv.modules ltv.packages /etc/mkinitfs/features.d/

# 2. Install luks wrapper
cp ltv-luks-wrapper.sh /usr/share/mkinitfs/ltv-luks-wrapper.sh
chmod 755 /usr/share/mkinitfs/ltv-luks-wrapper.sh

# 3. Install Dropbear host key and authorized_keys overlay
mkdir -p /etc/mkinitfs/ltv-stuff/etc/dropbear
cp dropbear_ed25519_host_key /etc/mkinitfs/ltv-stuff/etc/dropbear/
cp dropbear_ed25519_host_key.pub /etc/mkinitfs/ltv-stuff/etc/dropbear/
mkdir -p /etc/mkinitfs/ltv-stuff/root/.ssh
cp authorized_keys /etc/mkinitfs/ltv-stuff/root/.ssh/authorized_keys
chmod 600 /etc/mkinitfs/ltv-stuff/etc/dropbear/dropbear_ed25519_host_key
chmod 644 /etc/mkinitfs/ltv-stuff/etc/dropbear/dropbear_ed25519_host_key.pub
chmod 600 /etc/mkinitfs/ltv-stuff/root/.ssh/authorized_keys

# 4. Install patch script and commit hook
cp ltv-patch-init.sh /etc/mkinitfs/ltv-stuff/ltv-patch-init.sh
chmod 755 /etc/mkinitfs/ltv-stuff/ltv-patch-init.sh
mkdir -p /etc/apk/commit_hooks.d
cp ltv-commit-hook.sh /etc/apk/commit_hooks.d/ltv-commit-hook.sh
chmod 755 /etc/apk/commit_hooks.d/ltv-commit-hook.sh

# 5. Patch initramfs init script
sh /etc/mkinitfs/ltv-stuff/ltv-patch-init.sh /usr/share/mkinitfs/initramfs-init

# 6. Print next steps (user runs mkinitfs manually)
```

## Bootloader Configuration

### Syslinux (Alpine default)

Edit `/etc/syslinux.conf`:

```conf
DEFAULT ltv
LABEL ltv
    MENU_LABEL Alpine Linux with LTV
    LINUX /boot/vmlinuz-virt
    INITRD /boot/initramfs-ltv-6.18.59-0-virt
    APPEND ltv=yes ip=dhcp modules=virtio_net root=UUID=<rootfs-uuid> quiet
```

### GRUB

Edit `/etc/default/grub`:

```bash
GRUB_CMDLINE_LINUX_DEFAULT="ltv=yes ip=dhcp modules=virtio_net"
```

Then: `grub-mkconfig -o /boot/grub/grub.cfg`

## Kernel Cmdline Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `ltv=yes` | Enable LTV remote unlock (required) | Required |
| `ip=dhcp` | Configure network via DHCP (required for remote unlock) | Required for network |
| `ip=<static>` | Static IP config (Alpine format) | Alternative to DHCP |
| `modules=<driver>` | Load network driver early (e.g. virtio_net, e1000, vmxnet3) | Recommended |

## Network Configuration

The initramfs network is configured via standard Alpine kernel params:

| Method | Kernel Parameters |
|--------|-------------------|
| DHCP | `ip=dhcp` |
| Static | `ip=192.0.2.10::192.0.2.1:255.255.255.0::eth0:off` |
| VLAN | `vlan=eth0.100` + above |

See Alpine `mkinitfs` docs for full network options.

**Important**: Network must be configured in initramfs for Dropbear SSH to be reachable. The `ltv-patch-init.sh` patches `initramfs-init` to run `configure_ip` when `ltv=yes` is present.

## Dropbear Configuration

The wrapper starts Dropbear with:

```bash
dropbear -E -p ${LTV_PORT:-22} -r /etc/mkinitfs/ltv-stuff/etc/dropbear/dropbear_ed25519_host_key -D /etc/mkinitfs/ltv-stuff/root/.ssh/ &
```

| Flag | Purpose |
|------|---------|
| `-E` | Log to stderr |
| `-p 22` | Listen on port 22 (configurable via LTV_PORT) |
| `-r` | Host key file |
| `-D` | Authorized keys file directory |

**Authorized keys restrictions** (from `authorized_keys`):
```
no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 ...
```

## Wrapper Behavior (ltv-luks-wrapper.sh)

```bash
# 1. Filter crypto arguments from nlplug-findfs call
# 2. Start Dropbear SSH server
# 3. Background monitor for /run/ltv/resume signal
# 4. First nlplug-findfs run (foreground, TTY password prompt)
# 5. If unlocked via SSH: Second run without crypto options (triggers mdev/LVM)
```

**Timeout**: No built-in timeout - waits for `/run/ltv/resume` or TTY unlock.

## Init Script Patching

The `ltv-patch-init.sh` script patches `/usr/share/mkinitfs/initramfs-init` idempotently:

1. **Adds 'ltv' to myopts** - makes `ltv=yes` recognized as a kernel option
2. **Inserts network setup** - runs `configure_ip` when `ltv=yes` and networking is enabled
3. **Replaces nlplug-findfs call** - calls `ltv-luks-wrapper.sh` instead

This runs **after the second `configure_ip` call** (network is up) and **before `nlplug-findfs` for cryptroot**.

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