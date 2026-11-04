use ltv_core::Vault;
use secrecy::SecretVec;
use std::fs;

#[test]
fn test_open() {
    let bytes = fs::read("../test2.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let vault = Vault::open(&bytes, &pass).unwrap();
    println!("Opened: {} profiles", vault.inventory.profiles.len());
    for p in &vault.inventory.profiles {
        println!("  Profile: {}", p.name);
        println!("  Host: {:?}", p.host);
        println!("  Targets meta: {}", p.targets_meta.len());
    }
}
