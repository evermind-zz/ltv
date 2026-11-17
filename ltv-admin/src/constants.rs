// LTV (LUKS Tunnel Vault) - Remote LUKS unlock over SSH
// Copyright (C) 2024 LTV Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Centralized constants for the admin tool.

/// Prompt for OS SSH username
pub const PROMPT_OS_SSH_USER: &str = "OS SSH user";

/// Default OS SSH username
pub const DEFAULT_OS_SSH_USER: &str = "root";

/// Prompt for auth method
pub const PROMPT_AUTH_METHOD: &str = "Auth: (p)assword / (k)ey file";

/// Default auth method
pub const DEFAULT_AUTH_METHOD: &str = "k";

/// Prompt for OS password
pub const PROMPT_OS_PASSWORD: &str = "OS password: ";

/// Prompt for SSH key file
pub const PROMPT_KEY_FILE: &str = "Key file";

/// Prompt for key passphrase
pub const PROMPT_KEY_PASSPHRASE: &str = "Key passphrase: ";

/// Prompt: Do all targets use the same LUKS passphrase?
pub const PROMPT_SAME_LUKS_PASSPHRASE: &str = "Do all targets use the same LUKS passphrase? [Y/n]: ";

/// Prompt for shared LUKS passphrase
pub const PROMPT_LUKS_PASSPHRASE_ALL: &str = "Existing LUKS passphrase (for all targets): ";

/// Prompt for per-target LUKS passphrase
pub const PROMPT_LUKS_PASSPHRASE_TARGET: &str = "Existing LUKS passphrase for {} ({}): ";

/// Warning for target without keyslot
pub const WARN_TARGET_NO_KEYSLOT: &str = "Warning: target {} ({}) has no keyslot recorded. Run 'enroll' first.";

/// Error: vault has unsaved changes
pub const ERR_VAULT_DIRTY: &str = "vault has unsaved changes; run 'save' first";

/// Error: no vault path
pub const ERR_NO_VAULT_PATH: &str = "no vault path";

/// Confirmation for overwriting existing file
pub const CONFIRM_OVERWRITE: &str = "File '{}' already exists. Overwrite? [y/N]: ";

/// Confirmation for pinning host key
pub const CONFIRM_PIN_HOST_KEY: &str = "Pin this key? [y/N]: ";

/// Confirmation for repinning unlock host key
pub const CONFIRM_REPIN_UNLOCK_HOST_KEY: &str = "Replace pinned unlock SSH host key? [y/N]: ";

/// Confirmation for removing profile
pub const CONFIRM_REMOVE_PROFILE: &str = "Remove '{}'? type YES: ";

/// Prompt for vault passphrase
pub const PROMPT_VAULT_PASSPHRASE: &str = "Passphrase: ";

/// Prompt for new vault passphrase
pub const PROMPT_NEW_PASSPHRASE: &str = "New passphrase: ";

/// Prompt for repeat vault passphrase
pub const PROMPT_REPEAT_PASSPHRASE: &str = "Repeat: ";

/// Prompt for old vault passphrase
pub const PROMPT_OLD_PASSPHRASE: &str = "Old passphrase: ";

/// Prompt for source vault passphrase
pub const PROMPT_SRC_VAULT_PASSPHRASE: &str = "Source vault passphrase: ";

/// Prompt for new profile name
pub const PROMPT_NEW_PROFILE_NAME: &str = "New profile name: ";

/// Prompt for LUKS UUID
pub const PROMPT_LUKS_UUID: &str = "LUKS UUID: ";

/// Prompt for fallback device path
pub const PROMPT_FALLBACK_DEVICE: &str = "Fallback device path (optional): ";

/// Prompt for mapper name
pub const PROMPT_MAPPER_NAME: &str = "Mapper name";

/// Default mapper name
pub const DEFAULT_MAPPER_NAME: &str = "cryptroot";

/// Prompt for target order
pub const PROMPT_TARGET_ORDER: &str = "Order";

/// Default target order
pub const DEFAULT_TARGET_ORDER: &str = "0";

/// Confirmation for pinning OS host key
pub const CONFIRM_PIN_OS_HOST_KEY: &str = "Pin as OS host key? [y/N]: ";

/// Message: no OS host key pinned
pub const MSG_NO_OS_HOST_KEY: &str = "No OS host key pinned. Fetching from {}:{} ...";

/// Message: no unlock host key pinned
pub const MSG_NO_UNLOCK_HOST_KEY: &str = "No unlock SSH host key pinned. Fetching from {}:{} ...";

/// Message: created backup
pub const MSG_CREATED_BACKUP: &str = "Created backup: {}";

/// Message: backup removed
pub const MSG_BACKUP_REMOVED: &str = "Backup removed: {}";

/// Message: rotated targets
pub const MSG_ROTATED: &str = "rotated {} target(s); vault saved after each target.";

/// Message: enrolled targets
pub const MSG_ENROLLED: &str = "enrolled {} target(s); keyslots recorded. Remember to 'save'.";

/// Message: unsaved changes on exit
pub const CONFIRM_SAVE_ON_EXIT: &str = "Unsaved changes. Save? [Y/n]: ";

/// Confirmation for saving on close
pub const CONFIRM_SAVE_ON_CLOSE: &str = "Unsaved changes. Save before closing? [Y/n/d]: ";

/// Confirmation for dumping keys
pub const CONFIRM_DUMP_KEYS: &str = "Dump {} keyfile(s) to '{}'? type YES: ";

/// Warning for overwriting key files
pub const WARN_KEYFILES_EXIST: &str = "{} key file(s) already exist there. Overwrite? [y/N]: ";

/// Message: passphrase verified
pub const MSG_PASSPHRASE_VERIFIED: &str = "✓ Passphrase verified.";

/// Message: passphrase changed
pub const MSG_PASSPHRASE_CHANGED: &str = "Passphrase changed successfully.";

/// Message: profile updated
pub const MSG_PROFILE_UPDATED: &str = "profile updated";

/// Message: no changes
pub const MSG_NO_CHANGES: &str = "no changes";

/// Message: target added
pub const MSG_TARGET_ADDED: &str = "  target added, 64-byte keyfile generated.";

/// Message: target removed
pub const MSG_TARGET_REMOVED: &str = "target removed";

/// Message: vault closed
pub const MSG_VAULT_CLOSED: &str = "Vault closed.";

/// Message: verbose toggled
pub const MSG_VERBOSE: &str = "Verbose: {}";

/// Prompt for unsaved changes discard
pub const CONFIRM_DISCARD: &str = "d";

/// Target selection prompt
pub const PROMPT_TARGET_SELECTION: &str = "\nTargets to add or refresh? [all/none/numbers, e.g. 0,2]: ";

/// Confirmation for updating changed targets
pub const CONFIRM_UPDATE_TARGETS: &str = "Update these {} target(s)? [y/N]: ";

/// Note about mapper name changes
pub const NOTE_MAPPER_CHANGED: &str = "note: mapper names changed; re-run 'server-setup' and redeploy so the initramfs cmdline matches.";

/// Message: targets added
pub const MSG_TARGETS_ADDED: &str = "targets added.";

/// Message: kept existing metadata
pub const MSG_KEPT_EXISTING: &str = "kept existing target metadata unchanged.";

/// Message: remember to save
pub const MSG_REMEMBER_SAVE: &str = "Remember to 'save'.";

/// Message: no LUKS volumes found
pub const MSG_NO_LUKS_VOLUMES: &str = "No LUKS volumes found.";

/// Message: profile copied (kept)
pub const MSG_PROFILE_COPIED_KEPT: &str = "Profile '{}' copied to '{}' in current vault (kept client key + host keys).";

/// Message: profile copied (new key)
pub const MSG_PROFILE_COPIED_NEW: &str = "Profile '{}' copied to '{}' in current vault.";

/// Note: same authorized_keys
pub const NOTE_SAME_AUTH_KEYS: &str = "Same authorized_keys applies. Remember to 'save'.";

/// Note: new keypair generated
pub const NOTE_NEW_KEYPAIR: &str = "New client keypair generated. Remember to 'save' and deploy new authorized_keys.";

/// Error: profile already exists
pub const ERR_PROFILE_EXISTS: &str = "profile '{}' already exists in destination vault";

/// Error: mapper name already used
pub const ERR_MAPPER_EXISTS: &str = "mapper name '{}' is already used by another target; rename that target first";

/// Error: invalid port
pub const ERR_INVALID_PORT: &str = "bad port";

/// Error: invalid OS port
pub const ERR_INVALID_OS_PORT: &str = "bad OS port";

/// Error: invalid timeout
pub const ERR_INVALID_TIMEOUT: &str = "bad timeout";

/// Error: only Ed25519 keys supported
pub const ERR_ONLY_ED25519: &str = "only Ed25519 keys supported";

/// Error: load key failed
pub const ERR_LOAD_KEY: &str = "load key: {}";

/// Error: no target matches
pub const ERR_NO_TARGET_MATCHES: &str = "no target matches filter '{}'";

/// Error: two targets map to same output
pub const ERR_OUTPUT_COLLISION: &str = "two targets map to the same output file: {}";

/// Error: unsupported operation
pub const ERR_UNSUPPORTED: &str = "unsupported operation: {}";

/// Error: invalid argument
pub const ERR_INVALID_ARGUMENT: &str = "invalid argument: {}";

/// Error: operation aborted
pub const ERR_ABORTED: &str = "operation aborted";

/// Error: incorrect passphrase
pub const ERR_INCORRECT_PASSPHRASE: &str = "incorrect passphrase";

/// Error: old passphrase incorrect
pub const ERR_OLD_PASSPHRASE_INCORRECT: &str = "old passphrase incorrect";

/// Error: passphrases differ
pub const ERR_PASSPHRASES_DIFFER: &str = "passphrases differ";

/// Error: passphrase cannot be empty
pub const ERR_EMPTY_PASSPHRASE: &str = "passphrase cannot be empty";

/// Host key status: pinned
pub const HOSTKEY_PINNED: &str = "pinned";

/// Host key status: missing
pub const HOSTKEY_MISSING: &str = "MISSING";

/// Empty notes placeholder
pub const NOTES_NONE: &str = "(none)";

/// Same as unlock SSH note
pub const SAME_AS_UNLOCK_SSH: &str = " (same as unlock SSH)";