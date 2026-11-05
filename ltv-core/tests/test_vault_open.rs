use ltv_core::Vault;
use secrecy::SecretVec;
use std::fs;

#[test]
fn test_vault_open() {
    let bytes = fs::read("../myTestVault.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let vault = Vault::open(&bytes, &pass).unwrap();
    println!("Vault opened successfully!");
    println!("Profile: {}", vault.inventory.profiles[0].name);
    println!("Host: {}", vault.inventory.profiles[0].host);
}
