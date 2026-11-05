use ltv_core::Vault;
use secrecy::SecretVec;
use std::fs;

#[test]
fn check_vault() {
    let bytes = fs::read("../myTestVault.ltv").unwrap();
    println!("Vault file size: {} bytes", bytes.len());
    
    // Try with "abc"
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    match Vault::open(&bytes, &pass) {
        Ok(v) => println!("Opened with 'abc': {} profiles", v.inventory.profiles.len()),
        Err(e) => println!("Failed with 'abc': {}", e),
    }
    
    // Try with "xyz"
    let pass = SecretVec::new("xyz".as_bytes().to_vec());
    match Vault::open(&bytes, &pass) {
        Ok(v) => println!("Opened with 'xyz': {} profiles", v.inventory.profiles.len()),
        Err(e) => println!("Failed with 'xyz': {}", e),
    }
}
