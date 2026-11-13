pub mod error;
pub mod constants;
pub mod format;
pub mod crypto;
pub mod model;
pub mod vault;
pub mod net;
pub mod scripts;

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