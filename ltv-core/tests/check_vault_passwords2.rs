use ltv_core::Vault;
use secrecy::SecretVec;
use std::fs;

#[test]
fn check_vault_passwords() {
    let vaults = ["../myTestVault.ltv", "../test.ltv", "../test2.ltv", "../test_full.ltv", "../test_full2.ltv"];
    let passwords = ["abc", "testpass", "newtestpass", "createpass", "abc123", "xyz", "password", "secret", "pass", "newpass", "test", "test123", "123456", "admin", "root"];
    
    for vault_path in &vaults {
        println!("\n=== {} ===", vault_path);
        let bytes = fs::read(vault_path).unwrap();
        let mut found = false;
        for pass in &passwords {
            let p = SecretVec::new(pass.as_bytes().to_vec());
            if Vault::open(&bytes, &p).is_ok() {
                println!("  PASSWORD: '{}'", pass);
                found = true;
                break;
            }
        }
        if !found {
            println!("  PASSWORD: NOT FOUND (tried common ones)");
        }
    }
}
