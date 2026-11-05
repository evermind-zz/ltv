use ltv_core::{Vault, fetch_host_key};
use secrecy::SecretVec;
use std::fs;

#[tokio::test]
async fn check_initramfs_content() {
    let bytes = fs::read("../myTestVault.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let mut vault = Vault::open(&bytes, &pass).unwrap();
    
    let profile = vault.inventory.profiles[0].clone();
    let uuid = profile.uuid;
    
    // Pin initramfs host key from the server
    let hk = fetch_host_key(&profile.host, profile.port, profile.connect_timeout_s).await.unwrap();
    println!("Server OS host key: {} ({} bytes)", hk.key_type, hk.key_bytes.len());
    vault.set_host_key(&uuid, hk, false).unwrap();
}
