# LTV Workflows

## 1. Initial Setup (Admin Workstation)

```bash
# Create new vault
ltv-admin> create ~/.ltv/vault.ltv
New passphrase: ********
Repeat: ********

# Add a server profile
ltv-admin> add
Profile name: web01
Host (IP/DNS): 192.0.2.10
Port [22]: 22
Username [root]: root
LUKS UUID (blank = done): aaaa-bbbb-cccc-dddd
Fallback device path (optional): /dev/sda2
Mapper name [cryptroot]: cryptroot
Order [0]: 0
  target added, 64-byte keyfile generated.

LUKS UUID (blank = done): 
## 2. Server Preparation (Target Server)

**Option A: Automated via deploy.sh**

```bash
# On admin: generate deployment artifacts
ltv-admin> server-setup web01 --out ./deploy-web01

# Copy to target
scp -r ./deploy-web01 root@192.0.2.10:/root/

# On target server (as root):
cd /root/deploy-web01
./deploy.sh
# Output:
#   Regenerating initramfs for kernel 6.18.59-0-virt...
#   === NEXT STEPS ===
#   1. Update bootloader to use: /boot/initramfs-ltv-6.18.59-0-virt
#   2. Add kernel cmdline: ltv_mappers=cryptroot
#   3. Reboot

# Update bootloader (syslinux example)
# Edit /etc/syslinux.conf, change initramfs line and add:
#   ltv_mappers=cryptroot
reboot
```
# Output:
#   Regenerating initramfs for kernel 6.18.59-0-virt...
#   === NEXT STEPS ===
#   1. Update bootloader to use: /boot/initramfs-ltv-6.18.59-0-virt
#   2. Add kernel cmdline: ltv_mappers=cryptroot
#   3. Reboot

# Update bootloader (syslinux example)
# Edit /etc/syslinux.conf, change initramfs line and add:
#   ltv_mappers=cryptroot
reboot
```

**Option B: Manual**

See `deploy.sh` content for step-by-step.

## 3. Host Key Pinning (TOFU)

After server reboots into initramfs (Dropbear listening on port 22):

```bash
# On admin:
ltv-admin> hostkey fetch web01
ssh-ed25519 SHA256:abc123...
Pin this key? [y/N]: y
```

This pins the **initramfs Dropbear host key** in the vault. Future unlocks will verify this key.

Optionally pin the OS host key too:
```bash
ltv-admin> hostkey fetch web01 --os
ssh-ed25519 SHA256:def456...
Pin this key? [y/N]: y
```

## 4. Enrollment (Add LTV Keyfile to LUKS Header)

**Prerequisites:**
- Server booted normally (rootfs mounted)
- OS SSH access (password or key)
- Existing LUKS passphrase known

```bash
ltv-admin> enroll web01
No OS host key pinned. Fetching from 192.0.2.10:22 ...
ssh-ed25519 SHA256:def456...
Pin as OS host key? [y/N]: y

OS SSH user [root]: root
Auth: (p)assword / (k)ey file [k]: k
Key file [/home/user/.ssh/id_ed25519]: 
Existing LUKS passphrase: ********

 ✓ TargetStart("aaaa-bbbb-cccc-dddd")
 ✓ SlotAdded("aaaa-bbbb-cccc-dddd", 1)
 ✓ Verified("aaaa-bbbb-cccc-dddd")

enrolled 1 target(s); keyslots recorded. Remember to 'save'.
```

**What happens:**
1. Connects to **booted OS** via SSH
2. Stages existing LUKS passphrase in `/run/ltv/pass` (tmpfs)
3. Stages new keyfile in `/run/ltv/newkey` (tmpfs)
4. Runs `cryptsetup luksAddKey --key-file=/run/ltv/pass --new-keyfile=/run/ltv/newkey --key-slot N <dev>`
5. Verifies with `cryptsetup open --test-passphrase --key-file=- --key-slot N <dev>`
6. Records keyslot in vault
7. Cleans up tmpfs files

## 5. Remote Unlock (Boot Time)

Server reboots → initramfs → Dropbear starts → Admin runs:

```bash
ltv-admin> unlock web01
 ✓ UnlockEvent::Connecting { host: "192.0.2.10", port: 22 }
 ✓ UnlockEvent::HostKeyVerified { fingerprint: "SHA256:abc123..." }
 ✓ UnlockEvent::Authenticated
 ✓ UnlockEvent::TargetStarted { target: "cryptroot", uuid: "aaaa-bbbb-cccc-dddd" }
 ✓ UnlockEvent::TargetSuccess { target: "cryptroot", keyslot: 1 }
 ✓ UnlockEvent::ResumeCommand
```

**What happens:**
1. SSH to initramfs Dropbear (port 22)
2. Verify pinned host key
3. Ed25519 auth with client_private_seed
4. For each target: `exec cryptsetup luksOpen --key-file=- UUID=... <mapper>`
5. Push 64-byte keyfile to stdin
6. Hook detects mapper, exits, boot continues

## 6. Discovery (Find LUKS Volumes on Booted OS)

```bash
ltv-admin> fetch web01
...
Discovered LUKS volumes:
  [0] UUID: aaaa-bbbb-cccc-dddd
       Device: /dev/sda2
       Cipher: aes-xts-plain64
       Key size: 256 bits
       Version: 2

  [1] UUID: eeee-ffff-gggg-hhhh
       Device: /dev/sdb1
       Cipher: aes-xts-plain64
       Key size: 256 bits
       Version: 2

Add all as targets? [y/N]: y
  added target for aaaa-bbbb-cccc-dddd
  added target for eeee-ffff-gggg-hhhh
Targets added. Remember to 'save'.
```

## 7. Profile Management

```bash
# List profiles
ltv-admin> ls
web01           192.0.2.10:22             targets=1 hostkey=pinned

# Show details
ltv-admin> show web01

# Edit profile
ltv-admin> edit web01 host=192.0.2.11 port=2222 connect_timeout=15

# Add another target
ltv-admin> target add web01
LUKS UUID: eeee-ffff-gggg-hhhh
Fallback device path (optional): /dev/sdb1
Mapper name [cryptroot]: cryptdata
Order [0]: 1

# Remove target
ltv-admin> target rm web01 eeee-ffff-gggg-hhhh

# Change master passphrase
ltv-admin> passwd
New passphrase: ********
Repeat: ********

# Backup vault
ltv-admin> backup ~/.ltv/vault-backup.ltv
backup saved to /home/user/.ltv/vault-backup.ltv.1700000000.bak
```

## 8. State Probing

```bash
# Check single profile
ltv-admin> probe web01
web01           WaitingInInitramfs

# Check all
ltv-admin> probe --all
web01           WaitingInInitramfs
db01            BootedOs
web02           Unreachable
```

States:
- `Unreachable` - TCP connect failed
- `WaitingInInitramfs` - SSH connected, Dropbear banner matches pinned key
- `BootedOs` - SSH connected, OS host key matches pinned key
- `UnknownHostKey` - SSH connected but host key not pinned

## 9. Emergency Export

```bash
# Export keyfile for manual recovery (requires re-auth)
ltv-admin> export-keyfile web01 aaaa-bbbb-cccc-dddd /tmp/keyfile.bin
Re-enter master passphrase: ********
Type YES to confirm plaintext export: YES
keyfile written to /tmp/keyfile.bin
```

## Summary: Complete Onboarding Flow

```
1. create vault.ltv
2. add profile (name, host, targets)
3. server-setup profile → deploy.sh
4. Copy deploy to target, run deploy.sh, update bootloader, reboot
5. hostkey fetch profile (pin initramfs key)
6. enroll profile (add keyfile to LUKS header via booted OS)
7. save
8. Reboot target → unlock profile → boot complete
```

## Multi-Drive Setup

Each `target add` creates a new LUKS keyfile. At unlock, targets are processed in `order` sequence:

```
Target 1 (order=0): cryptroot (rootfs) - unlocks first
Target 2 (order=1): cryptdata (data volume) - unlocks second
Target 3 (order=2): cryptbackup (backup volume) - unlocks third
```

The hook waits for ALL mappers before exiting (300s timeout).