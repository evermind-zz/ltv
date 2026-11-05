use ltv_core::Vault;
use secrecy::SecretVec;
use std::fs;

#[test]
fn test_open_passphrase() {
    let bytes = fs::read("../myTestVault.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let vault = Vault::open(&bytes, &pass).unwrap();
    println!("Opened successfully with passphrase 'abc'");
}
