# LTV Troubleshooting

## Common Issues

### 1. "Usage: <command> ..." Errors

All commands with required arguments now show clear usage:

```bash
ltv-admin> create
error: Usage: create <file>

ltv-admin> target add
error: Usage: target add <profile>
```

### 2. "no vault open"

```bash
ltv-admin> ls
error: no vault open
```
**Fix**: `open <file>` or `create <file>` first.

### 3. "profile 'X' not found"

```bash
ltv-admin> show web01
error: profile 'web01' not found
```
**Fix**: Use `ls` to see exact profile names (case-sensitive).

### 4. Host Key Verification Failed

```
 ✓ UnlockEvent::Connecting { host: "192.0.2.10", port: 22 }
error: Host key verification failed: expected SHA256:abc123..., got SHA256:def456...
```

**Causes:**
- Server re-deployed with new initramfs (new Dropbear key)
- Wrong server IP
- MITM attack

**Fix:**
```bash
ltv-admin> hostkey fetch web01
ssh-ed25519 SHA256:def456...
Pin this key? [y/N]: y
```

### 5. "initramfs host key not pinned"

```bash
ltv-admin> server-setup web01
error: initramfs host key not pinned. Run 'hostkey fetch <profile>' first.
```
**Fix**: Run `hostkey fetch <profile>` after server is in initramfs.

### 6. Enroll Fails: "KeyRejected"

```bash
 ✓ EnrollEvent::LuksAddKeyStarted { target: "aaaa-bbbb-cccc-dddd" }
error: KeyRejected: existing passphrase wrong
```

**Causes:**
- Wrong LUKS passphrase entered
- Volume uses different passphrase than expected
- Keyslot already full (32 slots max)

**Fix:**
- Verify passphrase with `cryptsetup open --test-passphrase /dev/sda2`
- Check free slots: `cryptsetup luksDump /dev/sda2 | grep "Key Slot"`

### 7. Unlock Fails: "TargetFailed"

```
 ✓ UnlockEvent::TargetStarted { target: "cryptroot", uuid: "aaaa-bbbb-cccc-dddd" }
error: TargetFailed: cryptsetup exited with code 2
```

**Exit codes:**
- 1: Wrong keyfile
- 2: Invalid arguments
- 4: Device not found / not a LUKS device
- 5: Device already mapped

**Fix:**
- Verify LUKS UUID matches: `blkid /dev/sda2`
- Check keyslot recorded: `show web01` → look for `slot=Some(1)`
- Re-run `enroll` if keyslot missing

### 8. Probe Shows "Unreachable"

```bash
ltv-admin> probe web01
web01           Unreachable
```

**Check:**
- Server powered on?
- Network reachable? `ping 192.0.2.10`
- Port 22 open? `nc -zv 192.0.2.10 22`
- Firewall blocking?

### 9. Probe Shows "UnknownHostKey"

```bash
ltv-admin> probe web01
web01           UnknownHostKey
```

**Fix**: Run `hostkey fetch web01` to pin the key.

### 10. "weak params rejected before KDF"

```bash
ltv-admin> open vault.ltv
error: weak params rejected before KDF
```

**Cause**: Argon2 params too low (mem < 8MiB or time < 1).
**Fix**: Re-create vault with defaults, or use `create <file> --argon-mem 65536 --argon-time 3`.

### 11. "tamper_ciphertext_fails_auth" / "tamper_header_fails_auth"

Vault file corrupted or modified. Restore from backup.

### 12. Deploy.sh Fails

| Error | Fix |
|-------|-----|
| `mkinitfs: command not found` | Install `mkinitfs` package (Alpine base) |
| `dropbearkey: not found` | Install `dropbear` package |
| `cp: cannot stat 'ltv-hook.sh'` | Run from deploy directory |
| Permission denied | Run as root |

## Debugging Tips

### Enable Verbose SSH

```bash
# In ltv-admin, modify net.rs or use ssh -v manually
ssh -v -i <key> -p 22 root@192.0.2.10
```

### Check Initramfs Contents

```bash
# On target server
mkdir -p /tmp/initramfs-test
cd /tmp/initramfs-test
zcat /boot/initramfs-ltv-$(uname -r) | cpio -idmv
ls -la sbin/dropbear usr/share/mkinitfs/features.d/ltv-hook.sh sbin/ltv-init-wrapper
```

### Test Hook Manually

```bash
# In initramfs (emergency shell)
export LTV_MAPPERS="cryptroot"
/usr/share/mkinitfs/features.d/ltv-hook.sh
```

### Verify LUKS Keyslots

```bash
cryptsetup luksDump /dev/sda2
# Look for:
# Key Slot 0: ENABLED (your original passphrase)
# Key Slot 1: ENABLED (LTV keyfile)  <-- should exist after enroll
```

### Check Vault Integrity

```bash
ltv-admin> status
/tmp/test.ltv — 1 profiles, dirty=false
```

### Logs

- Initramfs: `dmesg | grep -i ltv` (after boot)
- SSH: `journalctl -u sshd` (on booted OS)
- Dropbear: Runs in initramfs, no persistent logs

## Recovery Procedures

### Forgot Master Passphrase

**No recovery possible.** The vault uses Argon2id with salt - no backdoor.
- Restore from backup `.ltv.bak` file (created on each save)
- Or recreate from scratch

### Lost Vault File

- Restore from backup: `cp vault.ltv.1700000000.bak vault.ltv`
- No other recovery

### Server Won't Boot After Deploy

1. Boot Alpine ISO
2. Mount rootfs
3. Fix bootloader config
4. Or regenerate initramfs without `ltv` feature:
   ```bash
   mkinitfs -F "base cryptsetup network" -k $(uname -r) /boot/initramfs-$(uname -r) $(uname -r)
   ```

### Rollback Deployment

```bash
# On target
mkinitfs -F "base cryptsetup network" -k $(uname -r) -o /boot/initramfs-$(uname -r) $(uname -r)
# Update bootloader to use old initramfs
reboot
```

## Getting Help

1. Check this guide
2. Run `ltv-admin> help` for command list
3. Check `ltv-admin> show <profile>` for config
4. Run `ltv-admin> probe <profile>` for state
5. Check GitHub issues for known bugs