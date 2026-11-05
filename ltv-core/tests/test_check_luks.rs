use ltv_core::{Vault, fetch_luks_info, fetch_host_key, BootedAccess, BootedAuth};
use secrecy::{SecretVec, SecretString};
use std::fs;

#[tokio::test]
async fn test_check_luks() {
    let bytes = fs::read("../myTestVault.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let mut vault = Vault::open(&bytes, &pass).unwrap();

    let profile = vault.inventory.profiles[0].clone();
    let uuid = profile.uuid;

    let hk = fetch_host_key(&profile.host, profile.port, profile.connect_timeout_s).await.unwrap();
    vault.set_host_key(&uuid, hk, true).unwrap();

    let access = BootedAccess {
        username: "root".to_string(),
        auth: BootedAuth::Password(SecretString::new("abc".into())),
        use_sudo: false,
        connect_timeout_s: 10,
    };

    // Run blkid directly to see all LUKS volumes
    let result = fetch_luks_info(&vault, &uuid, &access, None, Some(Box::new(|cmd: &str| {
        println!("  [cmd] $ {cmd}");
    }))).await;

    match result {
        Ok(infos) => {
            println!("Found {} LUKS volumes:", infos.len());
            for info in &infos {
                println!("  UUID: {} Device: {} Cipher: {}", info.luks_uuid, info.device_path, info.cipher);
            }
        }
        Err(e) => println!("Error: {}", e),
    }
}
