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
├── ltv.files                    # Feature file list (installed to /etc/mkinitfs/features.d/)
├── ltv.modules                  # Kernel modules (empty - uses cryptsetup feature)
├── ltv.packages                 # APK packages: dropbear
├── ltv-hook.sh                  # Initramfs hook script (installed to /usr/share/mkinitfs/)
├── initramfs-init.patch         # Sed script to patch /usr/share/mkinitfs/initramfs-init
├── etc/dropbear/
│   └── README.txt               # "Run: dropbearkey -t ed25519 ..."
├── authorized_keys              # Restricted client pubkey
├── cmdline.txt                  # Kernel cmdline snippet
├── deploy.sh                    # Run on target server
└── README.md                    # This guide
```

## deploy.sh Actions

```bash
#!/bin/sh
# 1. Install mkinitfs feature files
cp ltv.files ltv.modules ltv.packages /etc/mkinitfs/features.d/
cp ltv-hook.sh /usr/share/mkinitfs/ltv-hook.sh
chmod 755 /usr/share/mkinitfs/ltv-hook.sh

# 2. Patch initramfs init script to call ltv-hook
sh initramfs-init.patch

# 3. Generate Dropbear Ed25519 host key
dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key

# 4. Create authorized_keys overlay for initramfs
mkdir -p /etc/mkinitfs/features.d/ltv-ssh.keys/root/.ssh
cp authorized_keys /etc/mkinitfs/features.d/ltv-ssh.keys/root/.ssh/authorized_keys
chmod 600 /etc/mkinitfs/features.d/ltv-ssh.keys/root/.ssh/authorized_keys

# 5. Regenerate initramfs
KERNEL=$(uname -r)
mkinitfs -F "base ltv cryptsetup network" -k "$KERNEL" \
  -o "/boot/initramfs-ltv-$KERNEL" "$KERNEL"

# 6. Print next steps for bootloader
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
    APPEND ltv_mappers=cryptroot,cryptdata root=UUID=<rootfs-uuid> modules=sd-mod,usb-storage,ext4 quiet
```

**Note**: No `init=` wrapper needed - the hook is called from the patched init script.

### GRUB

Edit `/etc/default/grub`:

```bash
GRUB_CMDLINE_LINUX_DEFAULT="ltv_mappers=cryptroot,cryptdata"
```

Then: `grub-mkconfig -o /boot/grub/grub.cfg`

## Kernel Cmdline Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `ltv_mappers=cryptroot,cryptdata` | Comma-separated mapper names to wait for | Required |

## Network Configuration

The initramfs network is configured via standard Alpine kernel params:

| Method | Kernel Parameters |
|--------|-------------------|
| DHCP | `ip=dhcp` |
| Static | `ip=192.0.2.10::192.0.2.1:255.255.255.0::eth0:off` |
| VLAN | `vlan=eth0.100` + above |

See Alpine `mkinitfs` docs for full network options.

## Dropbear Configuration

The hook starts Dropbear with:

```bash
dropbear -R -s -j -k -p 22 -r /etc/dropbear/dropbear_ed25519_host_key
```

| Flag | Purpose |
|------|---------|
| `-R` | Don't daemonize (we background manually) |
| `-s` | Disable password auth |
| `-j` | Disable local port forwarding |
| `-k` | Disable keepalive |
| `-p 22` | Listen on port 22 |
| `-r` | Host key file |

**Authorized keys restrictions** (from `authorized_keys`):
```
no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 ...
```

## Hook Behavior (ltv-hook.sh)

```bash
# 1. Ensure host keys exist
for keytype in ed25519 ecdsa rsa; do
    [ -f /etc/dropbear/dropbear_${keytype}_host_key ] || dropbearkey -t $keytype -f ...
done

# 2. Start Dropbear
dropbear ... &
DROPBEAR_PID=$!

# 3. Wait for mappers or resume signal
while [ $ELAPSED -lt 300 ]; do
    ready=1
    for m in $LTV_MAPPERS; do
        [ -e /dev/mapper/$m ] || ready=0
    done
    [ $ready -eq 1 ] && break
    [ -e /run/ltv/resume ] && break
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done

# 4. Cleanup
kill $DROPBEAR_PID
wait $DROPBEAR_PID
```

**Timeout**: 300 seconds (5 minutes). After timeout, hook exits with error.

## Init Script Patching

The `initramfs-init.patch` inserts the hook call after the comment `run nlplug-findfs before SINGLEMODE` in `/usr/share/mkinitfs/initramfs-init`:

```bash
# LTV hook - start dropbear for remote unlock
if [ -n "$KOPT_ltv_mappers" ]; then
    export LTV_MAPPERS="$KOPT_ltv_mappers"
    /usr/share/mkinitfs/ltv-hook.sh
fi
```

This runs **after the second `configure_ip` call** (network is up) and **before `nlplug-findfs` for cryptroot**.

## Verification Checklist

After deployment, verify:

- [ ] `dropbearkey -t ed25519` generated host key in `/etc/dropbear/`
- [ ] `/etc/mkinitfs/features.d/ltv.*` files present
- [ ] `/usr/share/mkinitfs/ltv-hook.sh` executable
- [ ] `/usr/share/mkinitfs/initramfs-init` patched (backup at `.ltv-backup`)
- [ ] Initramfs regenerated: `/boot/initramfs-ltv-<kernel>`
- [ ] Bootloader updated with new initramfs + cmdline
- [ ] `authorized_keys` overlay created in `/etc/mkinitfs/features.d/ltv-ssh.keys/`

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

## Troubleshooting

| Issue | Check |
|-------|-------|
| Dropbear not starting | `ltv-hook.sh` executable? Host keys in `/etc/dropbear/`? |
| SSH connection refused | Port 22 open? `ltv_mappers` cmdline correct? |
| Host key mismatch | `hostkey fetch` run after deploy? |
| Mapper not appearing | Keyfile correct? `enroll` completed? LUKS UUID matches? |
| Timeout | Network up? `configure_ip` ran before hook? Increase timeout? |

## Updating

To update deployment (new key, new target, etc.):

```bash
# On admin
ltv-admin> server-setup web01 --out ./deploy-web01-v2
scp -r ./deploy-web01-v2 root@target:/root/
# On target
cd /root/deploy-web01-v2
./deploy.sh
# Update bootloader if kernel changed
reboot
```