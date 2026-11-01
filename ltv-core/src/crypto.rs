use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use secrecy::{ExposeSecret, SecretVec};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{error::VaultError, format::Argon2Params};

pub type Key32 = Zeroizing<[u8; 32]>;

pub fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N]; OsRng.fill_bytes(&mut b); b
}

pub fn kdf(pass: &SecretVec<u8>, salt: &[u8; 16], p: Argon2Params) -> Result<Key32, VaultError> {
    let params = Params::new(p.mem_kib, p.time, p.par as u32, Some(32)).map_err(|_| VaultError::Crypto)?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(pass.expose_secret(), salt, out.as_mut()).map_err(|_| VaultError::Crypto)?;
    Ok(out)
}

pub fn seal(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, VaultError> {
    XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(nonce), Payload { msg: pt, aad })
        .map_err(|_| VaultError::Crypto)
}

pub fn open(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| VaultError::AuthFailed)
}

pub fn envelope_key(master: &[u8; 32], profile_uuid: &[u8; 16]) -> Key32 {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut info = b"ltv-envelope:v1:".to_vec();
    info.extend_from_slice(profile_uuid);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(&info, out.as_mut()).expect("hkdf 32 bytes");
    out
}