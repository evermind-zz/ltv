# LTV Quickstart

## Prerequisites

- Admin workstation: Linux with Rust toolchain
- Target server: Alpine Linux with LUKS2-encrypted root

## 1. Build

```bash
git clone https://github.com/evermind-zz/ltv.git
cd ltv
cargo build --workspace --release
```

Binary: `target/release/ltv-admin`

## 2. Create Vault & Profile

```bash
./ltv-admin
ltv-admin> create ~/.ltv/vault.ltv
New passphrase: ********
Repeat: ********

ltv-admin> add
Profile name: myserver
Host (IP/DNS): 192.0.2.10
Port [22]: 22
Username [root]: root
LUKS UUID (blank = done): aaaa-bbbb-cccc-dddd
Fallback device path (optional): /dev/sda2
Mapper name [cryptroot]: cryptroot
Order [0]: 0
  target added, 64-byte keyfile generated.
LUKS UUID (blank = done): 

Client public key (deploy to initramfs authorized_keys):
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... ltv:myserver
```

## 3. Deploy to Target

```bash
ltv-admin> server-setup myserver --out ./deploy-myserver
Generated deployment in: ./deploy-myserver

# Copy to target
scp -r ./deploy-myserver root@192.0.2.10:/root/

# On target (as root):
cd /root/deploy-myserver
./deploy.sh

# Update bootloader (syslinux example)
# Edit /etc/syslinux.conf:
#   INITRD /boot/initramfs-ltv-6.18.59-0-virt
#   APPEND ltv_mappers=cryptroot root=UUID=... modules=...

reboot
```

## 4. Pin Host Key

Wait for server to reboot into initramfs (Dropbear on port 22):

```bash
ltv-admin> hostkey fetch myserver
ssh-ed25519 SHA256:abc123...
Pin this key? [y/N]: y
```

## 5. Enroll Keyfile

Boot target normally (into OS), then:

```bash
ltv-admin> enroll myserver
OS SSH user [root]: root
Auth: (p)assword / (k)ey file [k]: k
Key file [/home/user/.ssh/id_ed25519]: 
Do all targets use the same LUKS passphrase? [Y/n]: y
Existing LUKS passphrase (for all targets): ********

  ✓ TargetStart("aaaa-bbbb-cccc-dddd")
  ✓ SlotChosen("aaaa-bbbb-cccc-dddd", 1)
  ✓ SlotAdded("aaaa-bbbb-cccc-dddd", 1)
  ✓ Verified("aaaa-bbbb-cccc-dddd")
enrolled 1 target(s); keyslots recorded. Remember to 'save'.
```

```bash
ltv-admin> save
ltv-admin> quit
```

## 6. Test Unlock

Reboot target → initramfs → from admin:

```bash
ltv-admin> unlock myserver
 ✓ UnlockEvent::Connecting { host: "192.0.2.10", port: 22 }
 ✓ UnlockEvent::HostKeyVerified { fingerprint: "SHA256:abc123..." }
 ✓ UnlockEvent::Authenticated
 ✓ UnlockEvent::TargetStarted { target: "cryptroot", uuid: "aaaa-bbbb-cccc-dddd" }
 ✓ UnlockEvent::TargetSuccess { target: "cryptroot", keyslot: 1 }
 ✓ UnlockEvent::ResumeCommand
```

Server boots to login prompt. Done!

## One-Line Cheat Sheet

```bash
# Create
create ~/.ltv/vault.ltv

# Add server
add → name, host, UUID, mapper

# Deploy
server-setup name --out ./deploy
scp -r ./deploy root@host:/root/
# On target: ./deploy.sh → update bootloader → reboot

# Pin key
hostkey fetch name

# Enroll (on booted OS)
enroll name

# Unlock (on initramfs)
unlock name
```

## Files Created

| File | Purpose |
|------|---------|
| `~/.ltv/vault.ltv` | Encrypted vault (backup this!) |
| `deploy-*/deploy.sh` | Run on target to install feature |
| `deploy-*/cmdline.txt` | Kernel cmdline for bootloader |
| `deploy-*/README.md` | Full deployment guide |

## Next Steps

- Add more targets: `target add <profile>`
- Discover volumes: `fetch <profile>`
- Backup vault: `backup ~/.ltv/backup.ltv`
- Read full docs: `docs/WORKFLOWS.md`, `docs/DEPLOYMENT.md`