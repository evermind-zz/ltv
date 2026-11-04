use ltv_core::Vault;
use secrecy::SecretVec;
use std::fs;

#[test]
fn test_pubkey() {
    let bytes = fs::read("../test_full.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let vault = Vault::open(&bytes, &pass).unwrap();

    let profile = &vault.inventory.profiles[0];
    println!("Profile: {}", profile.name);
    println!("Client public key: {}", vault.export_public_key(profile));
    println!("Authorized keys line: {}", vault.authorized_keys_line(profile));
}
