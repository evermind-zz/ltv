use ltv_core::{Vault, fetch_host_key};
use secrecy::SecretVec;
use std::fs;

#[tokio::test]
async fn test_hostkey_fetch() {
    let bytes = fs::read("../test_full.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let mut vault = Vault::open(&bytes, &pass).unwrap();

    let profile = vault.inventory.profiles[0].clone();

    // Fetch initramfs host key
    let hk = fetch_host_key(&profile.host, profile.port, profile.connect_timeout_s).await.unwrap();
    println!("Fetched initramfs host key: {}", hk.key_type);
    vault.set_host_key(&profile.uuid, hk, false).unwrap();
    println!("Pinned as initramfs host key");

    // Save to a new vault file
    let bytes = vault.save().unwrap();
    std::fs::write("../test_full2.ltv", bytes).unwrap();
    println!("Vault with initramfs key saved to test_full2.ltv");
}
