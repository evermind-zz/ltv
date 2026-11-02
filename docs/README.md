# LTV Documentation

| Document | Description |
|----------|-------------|
| [QUICKSTART.md](QUICKSTART.md) | 5-minute setup guide |
| [WORKFLOWS.md](WORKFLOWS.md) | Complete workflows (onboarding, unlock, management) |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Server deployment details (mkinitfs, bootloader, hook) |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System architecture, crypto, protocols |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Common issues and fixes |

## Command Reference

```
ltv-admin> help
Commands:
  create <file>                  Create new vault file
  open <file>                    Open existing vault
  save                           Save changes (atomic)
  close                          Close vault
  status                         Show vault status
  ls                             List profiles
  show <profile>                 Show profile details
  add                            Add profile (wizard)
  rm <profile>                   Remove profile
  edit <profile> [field=val]     Edit profile fields
  target add <profile>           Add target interactively
  target rm <profile> <uuid>     Remove target
  pubkey <profile>               Print restricted pubkey
  rotate-key <profile>           Generate new keypair (stub)
  hostkey fetch <profile> [--os] TOFU pin host key
  probe <profile>|--all          Check server state
  unlock <profile>               Remote unlock via SSH
  enroll <profile> [--target]    Enroll keyfile via booted OS
  fetch <profile>                Discover LUKS volumes
  server-setup <profile> [--out] Generate mkinitfs deployment
  passwd                         Change master passphrase
  backup <path>                  Create timestamped backup
  import-profile                 Import profile (stub)
  export-profile <p> <dir>       Export profile (stub)
  quit | exit                    Exit
```

## Key Files

| File | Description |
|------|-------------|
| `*.ltv` | Encrypted vault (single artifact) |
| `ltv-admin` | CLI binary |
| `ltv-core` | Rust library |

## Links

- [SPEC.md](../SPEC.md) - Full specification
- [LICENSE](../LICENSE) - GPL-3.0
