use ltv_core::{Vault, unlock, fetch_host_key};
use secrecy::SecretVec;
use std::fs;

#[tokio::test]
async fn test_unlock_now() {
    let bytes = fs::read("/home/opencode/repos/ltcv/myTestVault.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let mut vault = Vault::open(&bytes, &pass).unwrap();

    let profile = vault.inventory.profiles[0].clone();
    let uuid = profile.uuid;

    // Pin initramfs host key (fetch from server)
    let hk = fetch_host_key(&profile.host, profile.port, profile.connect_timeout_s).await.unwrap();
    vault.set_host_key(&uuid, hk, false).unwrap();
    let saved = vault.save().unwrap();
    fs::write("/home/opencode/repos/ltcv/myTestVault.ltv", saved).unwrap();

    // Unlock with verbose
    println!("=== UNLOCK ===");
    let result = unlock(&vault, &uuid, |e| println!("Event: {:?}", e), Some(Box::new(|cmd: &str| {
        println!("  [unlock] $ {}", cmd);
    }))).await;
    println!("Unlock: {:?}", result);
}
