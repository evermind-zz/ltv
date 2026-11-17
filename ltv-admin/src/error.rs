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

//! Admin tool error types.
use std::path::PathBuf;
use thiserror::Error;
use ltv_core::error::{VaultError, NetError, UnlockError};

#[derive(Debug, Error)]
pub enum AdminError {
    #[error("no vault open")]
    NoVaultOpen,

    #[error("no vault path")]
    NoVaultPath,

    #[error("profile '{0}' not found")]
    ProfileNotFound(String),

    #[error("target '{0}' not found")]
    TargetNotFound(String),

    #[error("incorrect passphrase")]
    IncorrectPassphrase,

    #[error("old passphrase incorrect")]
    OldPassphraseIncorrect,

    #[error("passphrase cannot be empty")]
    EmptyPassphrase,

    #[error("passphrases differ")]
    PassphrasesDiffer,

    #[error("vault error: {0}")]
    Vault(#[from] VaultError),

    #[error("network error: {0}")]
    Net(#[from] NetError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("unlock error: {0}")]
    Unlock(#[from] UnlockError),

    #[error("serialization error: {0}")]
    Serde(String),

    #[error("invalid selection: {0}")]
    InvalidSelection(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("operation aborted")]
    Aborted,

    #[error("file already exists: {0}")]
    FileExists(PathBuf),

    #[error("no target matches filter '{0}'")]
    NoTargetMatches(String),

    #[error("two targets map to the same output file: {0}")]
    OutputCollision(PathBuf),

    #[error("unsupported operation: {0}")]
    Unsupported(String),
}

impl From<getopts::Fail> for AdminError {
    fn from(e: getopts::Fail) -> Self {
        AdminError::InvalidArgument(e.to_string())
    }
}

impl From<String> for AdminError {
    fn from(s: String) -> Self {
        AdminError::InvalidArgument(s)
    }
}

impl From<&str> for AdminError {
    fn from(s: &str) -> Self {
        AdminError::InvalidArgument(s.to_string())
    }
}

pub type AdminResult<T> = Result<T, AdminError>;

/// Extension trait for converting common errors to AdminError with context.
pub(crate) trait ToAdminResult<T, E> {
    fn admin_ctx(self, msg: &str) -> AdminResult<T>
    where
        E: std::error::Error + Send + Sync + 'static;
}

impl<T, E> ToAdminResult<T, E> for Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn admin_ctx(self, msg: &str) -> AdminResult<T> {
        self.map_err(|e| AdminError::InvalidArgument(format!("{msg}: {e}")))
    }
}