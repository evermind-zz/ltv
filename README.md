# LUKS Tunnel Vault (LTV)

A Rust library and toolset for securely unlocking remote LUKS2 volumes from a pre-boot environment (Alpine Linux initramfs running Dropbear SSH) by pushing keyfiles directly into `cryptsetup` stdin over a mutually authenticated SSH session.

## Scope

LTV solves the problem of unattended remote boot for encrypted servers. Instead of storing decryption keys on the server disk, the keys are held only on an administrator workstation (or mobile device) and pushed over SSH at boot time.

Key properties:
- **Nothing secret on the server at rest** - no keyfiles, no encrypted blobs, no client IPs stored
- **Single artifact** - all client-side state lives in one encrypted `.ltv` file
- **Laptop-manage, mobile-execute** - the admin tool creates, edits, enrolls, and unlocks; the mobile app only imports and unlocks
- **No hardware binding** - backup is a copy of the `.ltv` file plus the master passphrase
- **Core is a pure library** - every frontend (CLI, Android/UniFFI) uses the same code; nothing security-relevant lives in a frontend

## Architecture

```
ltv-core (library)
  ├── format.rs      # On-disk header, slot table, AAD construction
  ├── crypto.rs      # KDF (Argon2id), AEAD (XChaCha20-Poly1305), HKDF envelope keys
  ├── model.rs       # Data structures (Inventory, Profile, SecretPayload, etc.)
  ├── vault.rs       # Vault open/save, slot management, profile/target CRUD
  ├── net.rs         # SSH client (russh), probe, unlock, enroll, fetch
  ├── enroll.rs      # LUKS key enrollment over booted OS (luksAddKey via tmpfs)
  ├── rotate.rs      # Paranoid key rotation with per-target vault persistence
  └── error.rs       # Error types

ltv-admin (binary)
  └── main.rs        # Interactive shell (sqlite-style) + non-interactive subcommands

ltv-mobile (planned)
  └── Android app via UniFFI (read-only executor)
```

## File Format (.ltv)

- **Magic**: `LTCV` (LUKS Tunnel Core Vault)
- **Version**: 1
- **Cipher suite**: Argon2id + XChaCha20-Poly1305 + HKDF-SHA256
- **Key hierarchy**:
  ```
  master_passphrase -> Argon2id(salt, m, t, p) -> master_key (32 B)
  master_key -> XChaCha20-Poly1305 -> decrypts Inventory
  master_key -> HKDF-SHA256(info="ltv-envelope:v1:" || profile_uuid) -> envelope_key
  envelope_key -> XChaCha20-Poly1305 -> decrypts SecretPayload per profile
  ```
- **Slot-based header** (1-8 slots, LUKS-style) - allows future multi-passphrase support
- **Envelope encryption** - per-profile secrets encrypted separately, JIT decryption only
- **Memory safety** - all secrets use `zeroize::ZeroizeOnDrop`, passphrases in `secrecy::SecretVec`

## Server Requirements

1. Alpine Linux initramfs with Dropbear SSH
2. Persistent Ed25519 host key for Dropbear (copied into initramfs)
3. `authorized_keys` for root in initramfs containing LTV client public key (restricted)
4. `cryptsetup` binary in initramfs
5. `ltv-luks-wrapper.sh` ash script (installed via mkinitfs feature) that:
   - Replaces `nlplug-findfs` call in initramfs-init
   - Starts Dropbear SSH server
   - Runs `nlplug-findfs` for TTY password prompt
   - Background monitor waits for `/run/ltv/resume` signal
   - On signal: kills first `nlplug-findfs`, runs second without crypto options

## Unlock Protocol (Push-to-Stdin)

1. TCP connect to `host:port` (connect timeout)
2. SSH KEX; verify host key against pinned `initramfs_host_key`
3. Public key auth as `username` with `client_private_seed`
4. For each target (ordered by `order`):
   - `exec: cryptsetup luksOpen --key-file=- UUID=<uuid> <mapped_name>`
   - Write 64-byte keyfile to stdin, send EOF
   - Wait for exit status (exec timeout)
5. Execute resume command if configured (`ResumePolicy::Command`)
6. Disconnect; zeroize all secrets

## Admin Tool Commands

Interactive shell (sqlite-style) and non-interactive subcommands:

| Command | Description |
|---------|-------------|
| `create <file>` | New vault, prompts passphrase twice |
| `open <file>` / `close` / `save` / `status` | Vault lifecycle |
| `passwd` | Change master passphrase (re-derive, new salt) |
| `ls` | List profiles: name, host, target count, hostkey status |
| `show <profile>` | Full profile details (public parts) |
| `add` | Wizard: name -> host/port/user -> host key -> targets -> resume policy |
| `edit <profile> [field=value ...]` | Edit scalar fields (name, host, port, user, notes, timeouts, resume) |
| `rm <profile>` | Remove profile (confirm) |
| `target add <profile>` | Add target interactively |
| `target rm <profile> <uuid>` | Remove target |
| `pubkey <profile>` | Print Ed25519 pubkey (restricted authorized_keys line) |
| `rotate-key <profile>` | Generate new Ed25519 keypair |
| `hostkey fetch <profile> [--os]` | TOFU-fetch Dropbear/OS host key, confirm, store |
| `probe <profile>|--all` | State detection (Unreachable / WaitingInInitramfs / BootedOs / UnknownHostKey) |
| `unlock <profile>` | Full push-unlock with live progress |
| `enroll <profile> [--target <uuid>]` | Enroll keyfiles into LUKS headers over booted OS |
| `fetch <profile>` | Discover LUKS volumes on booted OS, offer to add as targets |
| `server-setup <profile>` | Generate deployment artifacts (feature file, wrapper, keys, patch script) |
| `export-keyfile <profile> <uuid> <path>` | Emergency plaintext export (requires re-auth) |
| `backup <path>` | Timestamped encrypted vault copy |
| `import-profile` / `export-profile` | Move profiles between vaults |
| `dump-keys <profile>` | Dump keyfiles for verification (requires passphrase re-entry) |

## Deploying Remote Unlock (server-setup)

The `server-setup` command generates all files needed to deploy LTV remote unlock to an Alpine Linux server. It creates an `mkinitfs` feature that installs Dropbear and the LTV luks-wrapper into the initramfs.

**For the complete deployment guide, see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).**

### Quick Overview

```bash
# 1. Generate deployment artifacts
ltv-admin> server-setup web01 --out ./deploy-web01

# 2. Copy to target Alpine server
scp -r ./deploy-web01 root@target:/root/

# 3. On target server (as root):
cd /root/deploy-web01
./deploy.sh
# Follow the printed manual steps, then reboot
```

### What Happens at Boot

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#boot-process) for the detailed boot sequence.

### Generated Kernel Cmdline

```
ltv=yes ip=dhcp modules=virtio_net
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#kernel-cmdline-parameters) for full parameter reference.

### Security Notes

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#security-notes) for security considerations.

## Dependencies

Core crates:
- `russh`, `russh-keys` - SSH client implementation
- `tokio` - Async runtime
- `chacha20poly1305` (xchacha feature) - AEAD
- `argon2` - KDF
- `hkdf`, `sha2` - Key derivation
- `postcard` - Binary serialization
- `serde` - Serialization framework
- `zeroize`, `secrecy` - Memory safety
- `rand` - Randomness
- `uuid` - Profile UUIDs
- `thiserror` - Error handling
- `rpassword` - Secure password input
- `rustyline` - Interactive shell
- `getopts` - CLI parsing

## Building

```bash
cargo build --workspace
```

## Testing

```bash
cargo test -p ltv-core --features write
```

## License

GPL-3.0-or-later. See [LICENSE](LICENSE) for details.

## Status

Draft 1.1 implementation. Core library and admin tool functional. Mobile executor planned.

Open points tracked in SPEC.md section 9.
