# LUKS Tunnel Vault (LTV) — Specification

**Components:** `ltv-core` (library) · `ltv-admin` (full-featured CLI/shell) · `ltv-mobile` (Android, read-only executor)

**Status:** Draft 1.1 — decisions from the step-by-step review are locked in; remaining open points are listed in §9.

---

## 0. Scope & Goals

LTV unlocks one or more remote LUKS2 volumes from a pre-boot environment (Alpine Linux initramfs running Dropbear) by pushing keyfiles directly into `cryptsetup`'s stdin over a single, mutually authenticated SSH session.

Design principles:

1. **Nothing secret on the server at rest.** No keyfile, no encrypted blob, no client IP.
2. **Single artifact.** All client-side state lives in one encrypted file (`*.ltv`).
3. **Laptop-manage, mobile-execute.** The admin tool creates, edits, enrolls and can also unlock. The mobile app only imports and unlocks.
4. **No hardware binding.** Backup = copy of the `.ltv` file + the master passphrase.
5. **Core is a pure library.** Every frontend (CLI, Android/UniFFI) uses the same code; nothing security-relevant lives in a frontend.

---

## 1. Vault File Format (Data-at-Rest)

File extension: `.ltv` (*LUKS Tunnel Vault*). Magic: `LTCV` (*LUKS Tunnel Core Vault*).

### 1.1 Header

| Offset | Size | Field | AAD |
|---|---|---|---|
| 0 | 4 | Magic `"LTCV"` | ✓ |
| 4 | 1 | Format version = `1` | ✓ |
| 5 | 1 | Cipher suite = `1` (Argon2id + XChaCha20-Poly1305) | ✓ |
| 6 | 1 | slot_count (1..=8) | ✓ |
| 7 | 1 | flags (bit0: token-import default) | ✓ |
| 8 | 24 | payload_nonce | ✓ |
| 32 | 97*N | Slot table, N = slot_count | ✓ |
| 32+97N | n | payload ciphertext ‖ 16 B tag | — |

**Slot (97 B):**
- 0   4   argon2 memory KiB (LE)
- 4   4   argon2 iterations (LE)
- 8   1   argon2 parallelism
- 9   16  salt
- 25  24  wrap_nonce
- 49  48  wrapped master key (32 B key ‖ 16 B tag)

- `KEK_i = Argon2id(passphrase, salt_i, params_i)`
- `master_key = XChaCha20-Poly1305.open(KEK_i, wrap_nonce_i, wrapped_i, aad = header[0..32] ‖ i)`
- `payload = XChaCha20-Poly1305.open(master_key, payload_nonce, ct, aad = header[0..32+97N])`
- Open tries slots in order; first success wins (constant work isn't attempted — slot count is tiny).
- The full header (0..32+97N) is passed as **Associated Data** to the AEAD. Any tampering (e.g. lowering Argon2 cost) fails authentication.
- **Every save** generates a fresh random nonce. Salt stays constant unless the passphrase is changed (then salt + nonce are regenerated).
- Minimum accepted Argon2 parameters on load: m ≥ 16 MiB, t ≥ 2. Lower values are rejected even if authenticated (defense against the admin's own misconfiguration).

### 1.2 Key Hierarchy

```
master_passphrase ──Argon2id(salt, m, t, p)──▶ master_key (32 B)
master_key ─── XChaCha20-Poly1305 ──────────▶ decrypts Inventory (outer payload)
master_key ─── HKDF-SHA256(info="ltv-envelope:v1:"‖profile_uuid) ─▶ envelope_key (32 B, per profile)
envelope_key ─ XChaCha20-Poly1305 ──────────▶ decrypts SecretPayload of that profile
```

No per-profile key material is stored; envelope keys are derived just-in-time and zeroized after use.

### 1.3 Atomic Writes

Save = write to `<file>.ltv.tmp` → fsync → rename over original. The admin tool additionally keeps `<file>.ltv.bak` (previous version) unless disabled.

---

## 2. Data Model (Inside the Ciphertext)

Serialization: **postcard** (serde). First field is always `schema_version`.

```rust
#[derive(Serialize, Deserialize)]
pub struct Inventory {
    pub schema_version: u16,           // = 1
    pub created_at: u64,               // unix seconds
    pub modified_at: u64,
    pub profiles: Vec<Profile>,
}

#[derive(Serialize, Deserialize)]
pub struct Profile {
    pub uuid: [u8; 16],                // v4, immutable, HKDF info
    pub name: String,                  // display name, mutable
    pub notes: String,

    // --- connection to pre-boot environment ---
    pub host: String,                  // IP or DNS
    pub port: u16,                     // default 22
    pub username: String,              // default "root"
    pub initramfs_host_key: Option<HostKey>,   // Dropbear key, strict match
    pub os_host_key: Option<HostKey>,  // optional: key of booted OS (OpenSSH),
                                       // used for state detection + enroll
    pub host_key_pinned_at: u64,
    pub client_public_key: Vec<u8>,    // Ed25519, OpenSSH wire format (for distribution)

    // --- unlock behaviour ---
    pub targets_meta: Vec<TargetMeta>, // non-secret part of targets, for display
    pub resume: ResumePolicy,
    pub connect_timeout_s: u16,        // default 10
    pub exec_timeout_s: u16,           // default 30 per target

    // --- envelope ---
    pub envelope_nonce: [u8; 24],
    pub envelope_ciphertext: Vec<u8>,  // XChaCha20-Poly1305(SecretPayload)
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct HostKey {
    pub key_type: String,              // "ssh-ed25519"
    pub key_bytes: Vec<u8>,            // raw public key blob
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TargetMeta {
    pub luks_uuid: String,             // preferred addressing: cryptsetup "UUID=..."
    pub fallback_path: Option<String>, // "/dev/sda2"
    pub mapped_name: String,           // "cryptroot"
    pub order: u8,                     // unlock sequence
    pub keyslot: Option<u8>,
    pub token_id: Option<u32>,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum ResumePolicy {
    /// initramfs hook polls /dev/mapper/<name>; nothing to send.
    DeviceMapperPoll,
    /// run explicit command after all targets succeeded
    Command(String),                   // default: "touch /run/ltv/resume"
}

// ---------- JIT-decrypted, zeroized ----------
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretPayload {
    pub client_private_seed: [u8; 32],      // Ed25519 seed
    pub keyfiles: Vec<TargetKey>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct TargetKey { pub luks_uuid: String, pub keyfile: Vec<u8> }
```

Invariant: `targets_meta[i].luks_uuid` has exactly one matching `TargetKey`. Validated on save and on JIT decrypt.

---

## 3. Memory Safety

- `master_key`, `envelope_key`, `SecretPayload`, every SSH stdin buffer: `zeroize` on drop, plus explicit `zeroize()` at the end of each unlock, including on error paths.
- Passphrase input is read into `SecretString`/`SecretVec`; never `String` concatenation, never logged.
- `Inventory` (non-secret) may live as long as the vault is "open" in the frontend.
- `SecretPayload` lifetime = duration of one `unlock()`/`enroll()` call. Frontends never receive it; they receive opaque handles or results.
- Optional `mlock` on secret buffers where the platform allows (Linux: yes; Android: best-effort).
- No swap-out guarantee is claimed; documented as residual risk.

---

## 4. Server-Side Contract (Alpine initramfs)

LTV does **not** use `cryptsetup-ssh`. The server needs:

1. **Dropbear in initramfs** with its own persistent Ed25519 host key (generated once, stored in `/etc/dropbear/` and copied into the initramfs by a custom `mkinitfs` feature `ltv`).
2. `authorized_keys` for `root` inside the initramfs containing the LTV client public key (restricted: `no-port-forwarding,no-agent-forwarding,no-X11-forwarding`).
3. `cryptsetup` binary in initramfs (already provided by the `cryptsetup` mkinitfs feature).
4. **`ltv-hook`**, a tiny ash script run by `init` before the normal root-unlock step:

```sh
#!/bin/sh
# /usr/share/mkinitfs/features.d/ltv  → installs this hook
mkdir -p /run/ltv
dropbear -R -s -j -k -p 22 -r /etc/dropbear/dropbear_ed25519_host_key
# wait until all configured mappers exist OR explicit resume flag
while :; do
    ready=1
    for n in $LTV_MAPPERS; do [ -e /dev/mapper/$n ] || ready=0; done
    [ $ready = 1 ] && break
    [ -e /run/ltv/resume ] && break
    sleep 1
done
killall dropbear 2>/dev/null
```

`LTV_MAPPERS` comes from a kernel cmdline parameter (`ltv_mappers=cryptroot,cryptdata`) written by the admin's `server-setup` output.

5. The LUKS keyfile (64 B) must be **enrolled** into a dedicated keyslot per volume (`cryptsetup luksAddKey <dev> -`), performed by `ltv-admin enroll` over the normal booted OS SSH, or manually.

The admin tool generates all of the above (feature file, hook, `authorized_keys` line, kernel cmdline snippet) via `server-setup`; the admin deploys them manually (as decided).

---

## 5. Unlock Protocol (Push-to-Stdin)

```
Client                                             Server (initramfs, Dropbear)
  │ 1. TCP connect host:port (timeout connect_timeout_s)
  │ 2. SSH KEX; receive host key
  │    ├─ == initramfs_host_key  → continue
  │    ├─ == os_host_key         → abort: StateBootedOs
  │    └─ else                   → abort: HostKeyMismatch (no auth attempted)
  │ 3. publickey auth as `username` with client_private_key
  │ 4. for target in targets_meta ordered by `order`:
  │      exec: cryptsetup luksOpen --key-file=- UUID=<uuid> <mapped_name>
  │            (fallback: <fallback_path> if cryptsetup reports "device not found")
  │      write keyfile → stdin, send EOF
  │      wait exit status (timeout exec_timeout_s)
  │        0            → ok
  │        2 (no key)   → abort: KeyRejected{target}
  │        5 (busy)     → treat as AlreadyUnlocked{target}, continue
  │        other        → abort: CryptsetupFailed{target, code, stderr}
  │ 5. ResumePolicy::Command → exec command, require exit 0
  │ 6. optional verify: exec `test -e /dev/mapper/<name>` for each target
  │ 7. disconnect; zeroize everything
```

Rules:

- One SSH session, one channel per `exec`. No shell, no PTY.
- `cryptsetup` stderr is captured and returned in the error, never the stdin.
- Idempotency: re-running on an already unlocked server yields `AlreadyUnlocked` per target and still issues the resume command.
- All timeouts are hard; on timeout the session is dropped and memory zeroized.

### 5.1 Probe (state detection without secrets)

`probe(profile)` performs steps 1–2 only (no authentication, no secrets decrypted) and returns:

`Unreachable | WaitingInInitramfs | BootedOs | UnknownHostKey(HostKey)`.

Used by both frontends to show server state in lists.

### 5.2 Enroll (over booted OS)

- Enroll runs **always over the booted OS**, never over the initramfs (there is no passphrase prompt and no guaranteed `/run` there).
- The existing LUKS passphrase is staged for the duration of one `luksAddKey` under `/run/ltv/pass` (tmpfs, mode 0600) and removed immediately afterwards — also on errors. Residual risk: RAM of the already booted server; that server is fully trusted at this point (it has the master key mounted).
- Slot choice: `TargetMeta.keyslot` if set and free, else first free slot from `luksDump`. Result persisted in the vault.
- Verification via `cryptsetup open --test-passphrase --key-slot N --key-file=-` with the new key.
- Exit code 2 on `luksAddKey` = existing passphrase wrong → `KeyRejected`.
- `luksDump` parser covers LUKS1 (`Key Slot N: ENABLED`) and LUKS2 (`N: luks2`).

---

## 6. `ltv-core` API

```rust
pub mod ltv_core {
    // ---- vault ----
    pub struct Vault;                       // opaque, holds Inventory + master_key (zeroized)
    impl Vault {
        pub fn create(params: Argon2Params) -> Vault;
        pub fn open(bytes: &[u8], passphrase: &SecretVec<u8>) -> Result<Vault, VaultError>;
        pub fn save(&self) -> Result<Vec<u8>, VaultError>;          // new nonce every call
        pub fn change_passphrase(&mut self, new: &SecretVec<u8>, params: Argon2Params);
        pub fn profiles(&self) -> &[Profile];
        pub fn add_profile(&mut self, draft: ProfileDraft) -> Result<Uuid, VaultError>;
        pub fn update_profile(&mut self, uuid: Uuid, patch: ProfilePatch) -> Result<(), VaultError>;
        pub fn remove_profile(&mut self, uuid: Uuid) -> Result<(), VaultError>;
        pub fn add_target(&mut self, uuid: Uuid, meta: TargetMeta, key: KeySource) -> Result<(), VaultError>;
        pub fn remove_target(&mut self, uuid: Uuid, luks_uuid: &str) -> Result<(), VaultError>;
        pub fn rotate_client_key(&mut self, uuid: Uuid) -> Result<Vec<u8>, VaultError>; // returns new pubkey
        pub fn export_public_key(&self, uuid: Uuid) -> String;      // "ssh-ed25519 AAAA... ltv:<name>"
        pub fn export_keyfile(&self, uuid: Uuid, luks_uuid: &str, passphrase_confirm: &SecretVec<u8>)
            -> Result<SecretVec<u8>, VaultError>;                   // explicit, re-auth required
    }

    pub enum KeySource { Generate, Import(SecretVec<u8>) }

    // ---- booted OS access ----
    pub struct BootedAccess {
        pub username: String,
        pub auth: BootedAuth,
        pub use_sudo: bool,
        pub connect_timeout_s: u16,
    }
    pub enum BootedAuth {
        Password(SecretString),
        Ed25519Seed([u8; 32]),
    }

    // ---- network ----
    pub struct Unlocker;
    impl Unlocker {
        pub async fn probe(profile: &Profile) -> ProbeResult;
        pub async fn fetch_host_key(host: &str, port: u16) -> Result<HostKey, NetError>; // TOFU helper
        pub async fn unlock(vault: &Vault, uuid: Uuid, progress: impl FnMut(UnlockEvent))
            -> Result<UnlockReport, UnlockError>;
        pub async fn enroll(vault: &Vault, uuid: Uuid, booted: &BootedAccess, progress: impl FnMut(UnlockEvent))
            -> Result<(), UnlockError>;     // luksAddKey over normal OS SSH
        pub async fn fetch_luks_info(vault: &Vault, uuid: &[u8; 16], booted: &BootedAccess, only_mapped: Option<&str>)
            -> Result<Vec<FetchedLuksInfo>, UnlockError>; // discover LUKS volumes on booted OS
    }

    pub struct FetchedLuksInfo {
        pub luks_uuid: String,
        pub device_path: String,
        pub cipher: String,
        pub key_size: u32,
        pub header_version: String,
    }

    pub enum UnlockEvent { Connecting, HostKeyVerified, Authenticated,
                           TargetStart(String), TargetDone(String), ResumeSent, Disconnected }

    // ---- ffi ----
    // uniffi scaffolding exposes: open/save/profiles/probe/unlock (read-only subset) for Android.
}
```

Crates: `russh`, `russh-keys`, `tokio`, `chacha20poly1305` (xchacha feature), `argon2`, `hkdf`, `sha2`, `postcard`, `serde`, `zeroize`, `secrecy`, `rand`, `uuid`, `thiserror`, `uniffi`.

Feature flags: `write` (vault mutation, enroll — enabled for admin, disabled for mobile build), `ffi`.

---

## 7. `ltv-admin` — Full-Featured Admin Tool

### 7.1 Modes

- **Interactive shell** (`ltv-admin` or `ltv-admin shell`): `rustyline`, history (commands only, never arguments containing secrets), tab completion. Passphrase asked once at `open`, cached in memory until `close`/exit/idle-lock.
- **Non-interactive subcommands** (`ltv-admin unlock --vault x.ltv --profile web01`) for scripting. Passphrase via prompt, `--passphrase-fd`, or `LTV_PASSPHRASE_FILE`. Never via argument.

### 7.2 Command Set

| Command | Description |
|---|---|
| `create <file> [--argon-mem --argon-time]` | New vault, prompts passphrase twice |
| `open <file>` / `close` / `save` / `status` | Vault lifecycle; `status` shows file, dirty flag, profile count |
| `passwd` | Change master passphrase (re-derive, new salt) |
| `params` | Show/adjust Argon2 params (re-encrypt) |
| `ls` | List profiles: name, host, #targets, last probe state |
| `show <profile>` | Full profile details (public parts only) |
| `add` | **Wizard**: name → host/port/user → host key (fetch & confirm fingerprint / paste / skip) → targets loop (UUID, fallback path, mapper name, generate/import key) → resume policy → summary → confirm |
| `edit <profile> [field]` | Edit scalar fields |
| `rm <profile>` | Remove (confirm) |
| `target add/rm <profile>` | Manage targets |
| `pubkey <profile> [--authorized-keys]` | Print Ed25519 pubkey, optionally as restricted `authorized_keys` line |
| `rotate-key <profile>` | New Ed25519 pair; prints new pubkey, reminds to redeploy |
| `hostkey fetch <profile> [--os]` | TOFU-fetch Dropbear (or OS) host key, show fingerprint, confirm, store |
| `probe [<profile>|--all]` | State detection |
| `unlock <profile>` | Perform full push-unlock with live progress |
| `enroll <profile> [--target <uuid>]` | Connect to **booted OS** (asks for OS SSH credentials/key + existing LUKS passphrase), runs `luksAddKey` per target, verifies with `luksDump`, optionally detects LUKS UUIDs from `blkid` to fill targets |
| `fetch <profile>` | Connect to **booted OS** (asks for OS SSH credentials/key), runs `blkid` + `cryptsetup luksDump` to discover LUKS volumes, displays cipher/key size/version, offers to add all as targets with generated keyfiles |
| `server-setup <profile>` | Generates mkinitfs feature file, `ltv-hook`, `authorized_keys` line, kernel cmdline snippet, step-by-step deployment checklist; writes to `./ltv-server-<name>/` |
| `export-keyfile <profile> <uuid> <path>` | Emergency plaintext export; requires passphrase re-entry and typed `YES` |
| `backup <path>` | Copy vault (already encrypted) with timestamp |
| `import-profile` / `export-profile` | Move single profile between vaults (re-encrypted under target vault) |
| `lock-timeout <sec>` | Auto-close vault on idle |
| `help`, `quit` | — |

### 7.3 Shell Session Example

```
$ ltv-admin
ltv-admin> open ~/servers.ltv
Passphrase: ********
Opened: 3 profiles.
ltv-admin(servers)> probe --all
 web01     192.0.2.10   WaitingInInitramfs
 storage   192.0.2.20   BootedOs
 backup    203.0.113.5  Unreachable
ltv-admin(servers)> unlock web01
 ✓ connected, host key ok (SHA256:Qm3…)
 ✓ authenticated as root
 ✓ cryptroot  (UUID 6f2a…)  unlocked
 ✓ cryptdata  (UUID 91cc…)  unlocked
 ✓ resume sent, disconnected, memory zeroized
ltv-admin(servers)> quit
```

---

## 8. `ltv-mobile` (Android) — Read-Only Executor

Kotlin/Compose UI over `ltv-core` via UniFFI (`write` feature off). No profile editing on the phone.

### 8.1 Screens

1. **Onboarding / Import** — pick `.ltv` via SAF, copied into app-private storage; shows file header info (version, Argon2 cost) before asking passphrase.
2. **Unlock Vault** — passphrase field; optional "Remember with biometrics" (passphrase wrapped by Android Keystore key, biometric-gated, invalidated on enrollment change). Fallback always passphrase.
3. **Server List** — cards with name, host, state badge (grey Unreachable / amber Waiting / green BootedOs / red UnknownKey), pull-to-refresh runs `probe`. Primary action per card: **Unlock** (enabled only when Waiting).
4. **Server Detail** — read-only: host, user, fingerprints, targets (mapper + UUID), resume policy, client pubkey (copy/share for distribution).
5. **Unlock Progress** — step list mirroring `UnlockEvent`, cancel button (drops session), final report; errors show `cryptsetup` stderr.
6. **Settings** — re-import vault, forget biometrics, idle lock timeout, "wipe vault from device".
7. **About / Log** — last N unlock reports (no secrets), app & schema versions.

### 8.2 Mobile Constraints

- Vault file and passphrase cache cleared on app uninstall; nothing synced to cloud.
- Unlock runs in a foreground service so the OS doesn't kill the SSH session mid-stream.
- Screenshots disabled on secret-adjacent screens (`FLAG_SECURE`).
- Network only during `probe`/`unlock`; no background polling.

---

## 9. Open Points / Unclear Items

1. **Alpine integration depth.** Alpine's stock `init` uses `nlplug-findfs` to prompt for the root passphrase. The `ltv-hook` must run *before* that step and either satisfy it (mapper already exists → `nlplug-findfs` skips the prompt — to be verified) or replace it. Needs a test on a real mkinitfs version.
2. **Dropbear in Alpine initramfs** is not a stock mkinitfs feature; the `ltv` feature file must list the Dropbear binary + libs correctly (musl static build preferred to avoid lib-path issues).
3. **`UUID=` device syntax** is documented for cryptsetup but relies on `blkid`-style scanning inside initramfs; confirm it works without udev under `mdev`. Fallback path is specified for this reason.
4. **Exit code mapping** of `cryptsetup` (2 = no key, 5 = device busy) must be verified against the Alpine-shipped version.
5. **Network in initramfs** (DHCP vs. static IP via `ip=` cmdline) is out of LTV scope but a prerequisite; `server-setup` will emit a template.
6. **Host key change on reinstall.** Decided: strict mismatch aborts. Workflow for intentional changes = `hostkey fetch` on admin, re-export vault to phone. Acceptable? Consider an admin-side "expected change" flag.
7. **Multiple admins / shared vault.** Not addressed; single-passphrase model. Could be extended later via per-user key slots in the header (format version 2).
8. **Android `mlock`** is unreliable; residual risk documented, not solved.
9. **Keyslot hygiene.** `enroll` should record which keyslot it used (returned by `luksAddKey` output) so `rotate-key`/revocation can `luksKillSlot` precisely. Field `keyslot: Option<u8>` in `TargetMeta` — add in schema v1 or defer?
10. **Naming.** Extension `.ltv`, magic `LTCV`, crate names `ltv-core` / `ltv-admin`.

---

## A. Resolution of Open Points

### 1) Alpine init integration → stays open, now with test plan
Added §9.1: a reproducible QEMU test (Alpine ISO → `setup-disk -e` → inspect `/usr/share/mkinitfs/initramfs-init` to find where `nlplug-findfs` prompts). Acceptance criterion: if `/dev/mapper/<name>` exists before `nlplug-findfs` runs, no prompt appears. If it does prompt anyway, the hook must `kill` the prompt or we patch `init` via feature overlay.

### 2) Own SSH server in the initramfs → specified as **`ltv-agent`, Phase 2**
Two options, both kept in the spec:

| | A: Dropbear (Phase 1) | B: `ltv-agent` (Rust, russh server, static musl) |
|---|---|---|
| Dependencies | Alpine package, well-audited | Our code; ~2 MB static binary |
| Protocol | Full SSH, `exec` channels | SSH, but **only** our verbs: `probe`, `unlock`, `resume` – no shell at all |
| Resume logic | Shell hook polling `/dev/mapper` | Agent itself runs `cryptsetup`, writes resume flag, exits |
| Attack surface | Generic SSH server, root login | Minimal, no exec of arbitrary commands, pubkey-only, single client key compiled from config |
| Risk | mkinitfs packaging (libs) | We maintain a pre-boot network daemon |

Decision: Phase 1 ships Dropbear + hook. `ltv-core` abstracts the remote side as a `Transport` trait so `ltv-agent` can be dropped in later without changing vault format or UI. The agent is explicitly out of scope for the first code drop.

### 6) Host key changes → admin-only, mobile read-only
- `hostkey fetch` exists only with the `write` feature.
- Mobile on `UnknownHostKey`: shows new fingerprint, status "needs admin", no override possible. Vault must be re-exported from the admin.
- Added a per-profile `host_key_pinned_at: u64` so the admin sees how old the pin is.

### 7) Multiple admins → header is now **slot-based** (LUKS-style)
Instead of Argon2 → master key directly, v1 now uses: Argon2 → KEK → unwraps a random 32-byte master key. Header holds a slot table (1–8 slots). v1 writes exactly one slot; `ltv-admin` gets `slot add/rm` later with zero format change. Bonus: `passwd` no longer re-encrypts the payload, only rewraps one slot.

### 8) Android memory → documented solution
- Android has **no disk swap**; `zram` compresses pages *into RAM*, so secrets never hit flash via swapping. The classic `mlock` motivation is therefore mostly moot.
- Real threats: root/debugger memory dumps, and the passphrase cache. Mitigations: `zeroize` + minimal lifetime (secrets live only inside `unlock()`), passphrase cache only via Keystore-wrapped blob (biometric-gated, `setInvalidatedByBiometricEnrollment(true)`), `FLAG_SECURE`, `android:debuggable=false`, `android:allowBackup=false`.
- `mlock` remains best-effort via `memsec`; failure is logged, not fatal.
- Conclusion: residual risk = rooted device, same as Aegis. Accepted.

### 9) Keyslot hygiene → options and ramifications

| Option | How | Pros | Cons |
|---|---|---|---|
| **A** Remove-by-key | Revocation via `cryptsetup luksRemoveKey <dev> --key-file=-` with the *old* key | No slot number needed, works LUKS1/2, trivial | Requires the old key to still be in the vault at rotation time (it is); if the old key was already lost, you can't target the slot |
| **B** Explicit slot | `luksAddKey --key-slot N` (admin picks N, default: first free from `luksDump`), store `keyslot: Option<u8>` | Deterministic, `luksKillSlot N` works even without the key, visible in `luksDump` | Must parse `luksDump`; slot may be reused by others later → stale number |
| **C** LUKS2 token | `cryptsetup token import` JSON `{"type":"ltv","keyslots":["N"],"ltv_profile":"<uuid>"}` | Header itself documents which slot is LTV's; discoverable from the server side; survives vault loss | LUKS2 only; writes a (non-secret) identifier onto the server disk – the profile UUID reveals "this disk belongs to LTV profile X" |

**Decision:** B as primary (record `keyslot`), A as the revocation path during `rotate-key` (works even if the recorded slot is stale), C as opt-in flag `--token` for admins who want server-side discoverability. `TargetMeta.keyslot: Option<u8>` is in schema v1.

### 10) `.ltv` confirmed.

---

## B. Spec Deltas (replace the relevant sections of Draft 1.0)

### §1.1 Header (v1, slot-based)

```
Offset  Size   Field
0       4      Magic "LTCV"
4       1      Format version = 1
5       1      Cipher suite = 1 (Argon2id + XChaCha20-Poly1305 + HKDF-SHA256)
6       1      slot_count (1..=8)
7       1      flags (bit0: token-import default) 
8       24     payload_nonce
32      97*N   Slot table, N = slot_count
32+97N  n      payload ciphertext ‖ 16 B tag

Slot (97 B):
  0   4   argon2 memory KiB (LE)
  4   4   argon2 iterations (LE)
  8   1   argon2 parallelism
  9   16  salt
  25  24  wrap_nonce
  49  48  wrapped master key (32 B key ‖ 16 B tag)
```

### §2 Data model additions
- `Profile.host_key_pinned_at: u64`
- `TargetMeta.keyslot: Option<u8>`
- `TargetMeta.token_id: Option<u32>` (only if option C used)

### §4 Server contract
- Phase 1: Dropbear + `ltv-hook` (unchanged).
- Phase 2: `ltv-agent` (russh server, verbs `probe|unlock|resume`), same host key file, same `authorized_keys`.
- `ltv-core` talks to both via `trait RemoteBoot { probe; open_target; resume }`; Dropbear implementation = `exec` channels.

### §9.1 Test plan (Alpine)
QEMU, Alpine 3.20 ISO, `setup-disk -e`, add `ltv` mkinitfs feature, verify (a) Dropbear reachable, (b) `cryptsetup luksOpen UUID=… --key-file=-` under `mdev`, (c) no passphrase prompt after mapper exists, (d) cryptsetup exit codes 2/5.