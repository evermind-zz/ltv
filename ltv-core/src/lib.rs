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

pub mod error;
pub mod constants;
pub mod format;
pub mod crypto;
pub mod model;
pub mod vault;
pub mod net;
pub mod scripts;
pub mod luks;

#[cfg(feature = "write")]
pub mod enroll;
#[cfg(feature = "write")]
pub mod rotate;

pub use error::{VaultError, NetError, UnlockError};
pub use model::{*, BootedAccess, BootedAuth};
pub use vault::Vault;
pub use net::{probe, unlock, fetch_host_key, fetch_luks_info, ProbeResult, UnlockEvent, FetchedLuksInfo};
pub use enroll::{enroll, EnrollEvent, EnrollResult};
pub use rotate::{rotate_key, RotateEvent, RotateResult};
pub use scripts::{render_deploy_sh, render_deploy_nopatch_sh, LTV_FILES, LTV_MODULES, LTV_PACKAGES, LTV_LUKS_WRAPPER, LTV_PATCH_INIT, DEPLOY_SH, DEPLOY_NOPATCH_SH};