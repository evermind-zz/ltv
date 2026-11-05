use ltv_core::{Vault, unlock};
use secrecy::SecretVec;
use std::fs;

#[tokio::test]
async fn test_unlock_verbose2() {
    let bytes = fs::read("../myTestVault.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let vault = Vault::open(&bytes, &pass).unwrap();

    let profile = vault.inventory.profiles[0].clone();
    let uuid = profile.uuid;

    println!("Attempting unlock against initramfs at {}", profile.host);
    let result = unlock(&vault, &uuid, |e| println!("Event: {:?}", e), Some(Box::new(|cmd: &str| {
        println!("  [unlock] $ {}", cmd);
    }))).await;

    match result {
        Ok(()) => println!("Unlock SUCCESS!"),
        Err(e) => println!("Unlock failed: {}", e),
    }
}
