# LTV Architecture

## Overview

LTV (LUKS Tunnel Vault) enables remote unlocking of LUKS2-encrypted volumes during early boot via SSH. The system consists of:

1. **ltv-core** - Rust library with all crypto, vault, and network logic
2. **ltv-admin** - CLI tool for vault management and deployment
3. **Target server** - Alpine Linux initramfs with Dropbear SSH + LTV luks-wrapper

For detailed deployment steps, see [DEPLOYMENT.md](DEPLOYMENT.md). For operational workflows, see [WORKFLOWS.md](WORKFLOWS.md). For the full specification, see [SPEC.md](../SPEC.md).

## Threat Model

- **Server at rest**: Nothing secret on disk (no keyfiles, no encrypted blobs)
- **Admin workstation**: Holds the single `.ltv` vault file + master passphrase
- **Network**: Mutually authenticated SSH (Ed25519 keys + host key pinning)
- **Memory**: Secrets zeroized on drop, JIT decryption only

## Key Hierarchy

```
master_passphrase
    │
    ├─▶ Argon2id(salt, m=64MiB, t=3, p=1) ──▶ master_key (32 B)
    │       │
    │       ├─▶ XChaCha20-Poly1305 ──▶ decrypts Inventory
    │       │
    │       └─▶ HKDF-SHA256(info="ltv-envelope:v1:" || profile_uuid)
    │               │
    │               └─▶ envelope_key ──▶ XChaCha20-Poly1305 ──▶ decrypts SecretPayload
    │
    └─▶ SecretPayload per profile:
            ├─▶ client_private_seed (32 B) - Ed25519 for SSH auth
            └─▶ keyfiles: Vec<TargetKey> - 64-byte keyfiles per LUKS volume
```

## File Format (.ltv)

- **Magic**: `LTCV` (4 bytes)
- **Version**: 1 (2 bytes, little-endian)
- **Slots**: 1-8 (LUKS-style, for future multi-passphrase)
- **Slot structure**: Argon2 params + salt + wrap_nonce + wrapped_master_key
- **Payload**: XChaCha20-Poly1305 encrypted Inventory + per-profile envelopes

## Unlock Protocol (Push-to-Stdin)

```
Admin (ltv-admin)                          Target (initramfs Dropbear)
─────────────────────────────────────────────────────────────────────────
1. TCP connect (timeout)
2. SSH KEX
3. Verify host key (pinned initramfs_host_key)
4. Ed25519 pubkey auth (client_private_seed)
5. For each target (ordered by 'order'):
   a. exec: cryptsetup luksOpen --key-file=- UUID=<uuid> <mapped_name>
   b. Write 64-byte keyfile to stdin
   c. Send EOF
   d. Wait for exit code (timeout)
6. Execute resume command (if configured)
7. Disconnect, zeroize all secrets
```

## ltv-core Module Structure

```
ltv-core/
├── format.rs      # On-disk header, slot table, AAD construction
├── crypto.rs      # KDF (Argon2id), AEAD (XChaCha20-Poly1305), HKDF envelope keys
├── model.rs       # Data structures (Inventory, Profile, SecretPayload, etc.)
├── vault.rs       # Vault open/save, slot management, profile/target CRUD
├── net.rs         # SSH client (russh), probe, unlock, enroll, fetch
├── enroll.rs      # LUKS key enrollment over booted OS (luksAddKey via tmpfs)
├── rotate.rs      # Paranoid key rotation with per-target vault persistence
├── luks.rs        # Shared LUKS utilities (parse_used_slots, find_existing_slot, etc.)
├── scripts.rs     # Embedded deployment scripts (include_str!)
├── constants.rs   # Centralized constants (no magic numbers)
└── error.rs       # Error types (VaultError, NetError, UnlockError)
```

## Crypto Primitives

| Purpose | Algorithm | Parameters |
|---------|-----------|------------|
| KDF | Argon2id | m=64MiB, t=3, p=1 (configurable) |
| AEAD | XChaCha20-Poly1305 | 24-byte nonce, 16-byte tag |
| Key Derivation | HKDF-SHA256 | info="ltv-envelope:v1:" \|\| profile_uuid |
| SSH Auth | Ed25519 | RFC 8032 |
| Hash | SHA-256 | For fingerprints |
| Random | OS CSPRNG | getrandom(2) / urandom |

## Memory Safety

- All secret material uses `zeroize::ZeroizeOnDrop`
- Passphrases read into `secrecy::SecretVec`/`SecretString`
- `SecretPayload` lifetime = single `unlock()`/`enroll()` call
- Optional `mlock` on secret buffers (Linux: yes; Android: best-effort)