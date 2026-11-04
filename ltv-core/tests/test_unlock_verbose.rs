use ltv_core::{Vault, unlock, UnlockEvent};
use secrecy::SecretVec;
use std::fs;

#[tokio::test]
async fn test_unlock_verbose() {
    let bytes = fs::read("../test_full2.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let vault = Vault::open(&bytes, &pass).unwrap();

    let uuid = vault.inventory.profiles[0].uuid;

    let result = unlock(&vault, &uuid, |e: UnlockEvent| {
        println!("  [event] {:?}", e);
    }, Some(Box::new(|cmd: &str| {
        println!("  [verbose] {}", cmd);
    }))).await;

    match result {
        Ok(_) => println!("  Unlock succeeded"),
        Err(e) => println!("  Unlock error: {}", e),
    }
}
