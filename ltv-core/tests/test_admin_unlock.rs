use ltv_core::{Vault, unlock, format::Argon2Params, TargetMeta};
use secrecy::SecretVec;
use std::fs;

#[tokio::test]
async fn test_admin_unlock() {
    let bytes = fs::read("../test_full.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let vault = Vault::open(&bytes, &pass).unwrap();

    let uuid = vault.inventory.profiles[0].uuid;
    println!("Testing unlock with uuid: {:?}", uuid);

    let result = unlock(&vault, &uuid, |e| {
        println!("Unlock event: {:?}", e);
    }, Some(Box::new(|cmd: &str| println!("  [unlock] $ {cmd}")))).await;

    match result {
        Ok(_) => println!("Unlock succeeded"),
        Err(e) => println!("Unlock error: {}", e),
    }
}
