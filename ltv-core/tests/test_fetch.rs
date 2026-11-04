use ltv_core::{Vault, fetch_luks_info, BootedAccess, BootedAuth};
use secrecy::{SecretVec, SecretString};
use std::fs;

#[tokio::test]
async fn test_fetch() {
    let bytes = fs::read("../test2.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let vault = Vault::open(&bytes, &pass).unwrap();
    
    let profile = &vault.inventory.profiles[0];
    
    // Test with password auth
    let access = BootedAccess {
        username: "root".to_string(),
        auth: BootedAuth::Password(SecretString::new("abc".into())),
        use_sudo: false,
        connect_timeout_s: 10,
    };
    
    let results = fetch_luks_info(&vault, &profile.uuid, &access, None, Some(Box::new(|cmd: &str| println!("  [fetch] $ {cmd}")))).await;
    
    match results {
        Ok(infos) => {
            println!("Found {} LUKS volumes", infos.len());
            for info in infos {
                println!("  UUID: {}", info.luks_uuid);
                println!("  Device: {}", info.device_path);
                println!("  Cipher: {}", info.cipher);
                println!("  Key size: {}", info.key_size);
            }
        }
        Err(e) => {
            println!("Fetch error: {}", e);
        }
    }
}
