use ltv_core::{Vault, fetch_luks_info, fetch_host_key, BootedAccess, BootedAuth};
use secrecy::{SecretVec, SecretString};
use std::fs;

#[tokio::test]
async fn test_fetch_debug() {
    let bytes = fs::read("../test2.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let mut vault = Vault::open(&bytes, &pass).unwrap();
    
    let profile = vault.inventory.profiles[0].clone();
    
    // Fetch and pin the host key
    let hk = fetch_host_key(&profile.host, profile.port, profile.connect_timeout_s).await.unwrap();
    println!("Fetched host key: {}", hk.key_type);
    vault.set_host_key(&profile.uuid, hk, true).unwrap();
    
    // Test with password auth
    let access = BootedAccess {
        username: "root".to_string(),
        auth: BootedAuth::Password(SecretString::new("abc".into())),
        use_sudo: false,
        connect_timeout_s: 10,
    };
    
    // Try different blkid commands
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
