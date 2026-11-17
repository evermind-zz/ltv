# LTV Workflows

This document describes the operational workflows for LTV. For deployment details,
see [DEPLOYMENT.md](DEPLOYMENT.md).

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
```

## 2. Server Preparation (Target Server)

See [DEPLOYMENT.md](DEPLOYMENT.md#deployment-workflow) for the full deployment guide including:
- Generating artifacts with `server-setup`
- Copying and running `deploy.sh` on target
- Manual completion steps (FEATURES, kernel cmdline, mkinitfs, bootloader)
- Verification checklist and testing

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
Do all targets use the same LUKS passphrase? [Y/n]: y
Existing LUKS passphrase (for all targets): ********

  TargetStart("cryptroot")
  SlotChosen("cryptroot", 1)
  SlotAdded("cryptroot", 1)
  Verified("cryptroot")

enrolled 1 target(s); keyslots recorded. Remember to 'save'.
```

**What happens:**
1. Connects to **booted OS** via SSH
2. Asks if all targets share the same LUKS passphrase (default: yes)
3. Prompts for passphrase(s) — empty not allowed
4. For each target: checks if our key is already enrolled (tests each slot with `--test-passphrase`)
5. If already enrolled: shows `SlotUpdated`, records existing slot, skips to verification
6. Otherwise: picks free slot, stages passphrase + new key in tmpfs (`/run/ltv/pass`, `/run/ltv/newkey`)
7. Runs `cryptsetup luksAddKey --key-file=/run/ltv/pass --new-keyfile=/run/ltv/newkey --key-slot N <dev>`
8. Verifies with `cryptsetup open --test-passphrase --key-file=- --key-slot N <dev>`
9. Records keyslot in vault
10. Cleans up tmpfs files

**Pre-check output (key already enrolled):**
```
  TargetStart("cryptdata")
  SlotChosen("cryptdata", 0)
  SlotUpdated("cryptdata", 0)
  Verified("cryptdata")
```

**If targets have different passphrases:**
```
Do all targets use the same LUKS passphrase? [Y/n]: n
Existing LUKS passphrase for cryptroot (aaaa-bbbb-cccc-dddd): ********
Existing LUKS passphrase for cryptdata (eeee-ffff-gggg-hhhh): ********
```

## 5. Remote Unlock (Boot Time)

Server reboots -> initramfs -> Dropbear starts -> Admin runs:

```bash
ltv-admin> unlock web01
  UnlockEvent::Connecting { host: "192.0.2.10", port: 22 }
  UnlockEvent::HostKeyVerified { fingerprint: "SHA256:abc123..." }
  UnlockEvent::Authenticated
  UnlockEvent::TargetStarted { target: "cryptroot", uuid: "aaaa-bbbb-cccc-dddd" }
  UnlockEvent::TargetSuccess { target: "cryptroot", keyslot: 1 }
  UnlockEvent::ResumeCommand
```

**What happens:**
1. SSH to initramfs Dropbear (port 22)
2. Verify pinned host key
3. Ed25519 auth with client_private_seed
4. For each target: `exec cryptsetup luksOpen --key-file=- UUID=... <mapper>`
5. Push 64-byte keyfile to stdin
6. Wrapper detects `/run/ltv/resume`, exits, boot continues

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

## 10. Key Rotation

```bash
# Rotate LUKS keyfiles for all targets in a profile
ltv-admin> rotate-key web01
```

This performs a paranoid LUKS keyfile rotation per target:

1. Creates a timestamped backup of the vault
2. For each target (sequentially for safety):
   - Generates a new 64-byte keyfile
   - Adds it to a free LUKS keyslot (`cryptsetup luksAddKey`)
   - Verifies the new key works (`cryptsetup open --test-passphrase`)
   - **Saves the vault atomically** (persists new keyfile + slot)
   - Removes the old keyslot (`cryptsetup luksKillSlot`)
3. Cleans up the backup on success

Options:
- `--target <uuid|mapper>` — rotate only one target
- `--verbose` — show cryptsetup commands
- `--sequential` — force sequential (default when >0 targets for paranoid mode)

The vault is saved **after each target's verification** but **before old slot removal**, enabling recovery if something fails mid-rotation.

## Summary: Complete Onboarding Flow

See [QUICKSTART.md](QUICKSTART.md) for the 5-minute version, or follow the detailed steps:

1. **Create vault & profile** → [§1 Initial Setup](#1-initial-setup-admin-workstation)
2. **Deploy to target** → [DEPLOYMENT.md](DEPLOYMENT.md#deployment-workflow)
3. **Pin initramfs host key** → [§3 Host Key Pinning (TOFU)](#3-host-key-pinning-tofu)
4. **Enroll LUKS keyfiles** → [§4 Enrollment](#4-enrollment-add-ltv-keyfile-to-luks-header)
5. **Save vault** → `ltv-admin> save`
6. **Test unlock** → [§5 Remote Unlock](#5-remote-unlock-boot-time)

## Multi-Drive Setup

Each `target add` creates a new LUKS keyfile. At unlock, targets are processed in `order` sequence:

```
Target 1 (order=0): cryptroot (rootfs) - unlocks first
Target 2 (order=1): cryptdata (data volume) - unlocks second
Target 3 (order=2): cryptbackup (backup volume) - unlocks third
```

The wrapper waits for `/run/ltv/resume` signal before exiting (no hardcoded timeout).