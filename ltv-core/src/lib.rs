pub mod error;
pub mod format;
pub mod crypto;
pub mod model;
pub mod vault;
pub mod net;

#[cfg(feature = "write")]
pub mod enroll;

pub use error::{VaultError, NetError, UnlockError};
pub use model::*;
pub use vault::Vault;
pub use net::{probe, unlock, fetch_host_key, ProbeResult, UnlockEvent};

#[cfg(feature = "write")]
pub use enroll::{enroll, BootedAccess, BootedAuth, EnrollEvent, EnrollResult};