use ltv_core::{Vault, fetch_luks_info, fetch_host_key, BootedAccess, BootedAuth};
use secrecy::{SecretVec, SecretString};
use std::fs;

#[tokio::test]
async fn test_server_setup2() {
    let bytes = fs::read("../myTestVault.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let mut vault = Vault::open(&bytes, &pass).unwrap();

    let profile = vault.inventory.profiles[0].clone();
    let uuid = profile.uuid;

    // Pin BOTH initramfs and OS host keys (server is in initramfs state, same key for both)
    let hk = fetch_host_key(&profile.host, profile.port, profile.connect_timeout_s).await.unwrap();
    vault.set_host_key(&uuid, hk.clone(), false).unwrap();  // initramfs
    vault.set_host_key(&uuid, hk, true).unwrap();            // OS

    // Now test fetch_luks_info
    let fetch = fetch_luks_info(&vault, &uuid, &BootedAccess {
        username: "root".to_string(),
        auth: BootedAuth::Password(SecretString::new("abc".into())),
        use_sudo: false,
        connect_timeout_s: 10,
    }, None, Some(Box::new(|cmd: &str| {
        println!("  [fetch] $ {cmd}");
    }))).await;

    match fetch {
        Ok(infos) => {
            println!("SUCCESS: Found {} LUKS volumes:", infos.len());
            for info in &infos {
                println!("  UUID: {} Device: {} Cipher: {} KeySize: {} Version: {}", 
                    info.luks_uuid, info.device_path, info.cipher, info.key_size, info.header_version);
            }
        }
        Err(e) => println!("Error: {}", e),
    }
}
