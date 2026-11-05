use ltv_core::{Vault, fetch_luks_info, fetch_host_key, BootedAccess, BootedAuth};
use secrecy::{SecretVec, SecretString};
use std::fs;

#[tokio::test]
async fn test_check_luks2() {
    let bytes = fs::read("../myTestVault.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let mut vault = Vault::open(&bytes, &pass).unwrap();

    let profile = vault.inventory.profiles[0].clone();
    let uuid = profile.uuid;

    // Fetch and pin initramfs host key
    let hk = fetch_host_key(&profile.host, profile.port, profile.connect_timeout_s).await.unwrap();
    println!("Fetched key: {} {}", hk.key_type, hk.key_bytes.len());
    vault.set_host_key(&uuid, hk, true).unwrap();  // pin as OS key

    let access = BootedAccess {
        username: "root".to_string(),
        auth: BootedAuth::Password(SecretString::new("abc".into())),
        use_sudo: false,
        connect_timeout_s: 10,
    };

    let result = fetch_luks_info(&vault, &uuid, &access, None, Some(Box::new(|cmd: &str| {
        println!("  [fetch] $ {cmd}");
    }))).await;

    match result {
        Ok(infos) => {
            println!("SUCCESS: Found {} LUKS volumes:", infos.len());
            for info in &infos {
                println!("  UUID: {} Device: {} Cipher: {} KeySize: {}", info.luks_uuid, info.device_path, info.cipher, info.key_size);
            }
        }
        Err(e) => println!("Fetch error: {}", e),
    }
}
