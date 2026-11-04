use ltv_core::{Vault, fetch_luks_info, fetch_host_key, BootedAccess, BootedAuth};
use secrecy::{SecretVec, SecretString};
use std::fs;

#[tokio::test]
async fn test_fetch_verbose() {
    let bytes = fs::read("../test_full2.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let mut vault = Vault::open(&bytes, &pass).unwrap();

    let profile = vault.inventory.profiles[0].clone();
    let uuid = profile.uuid;

    // Fetch OS host key first
    if profile.os_host_key.is_none() {
        let hk = fetch_host_key(&profile.host, profile.port, profile.connect_timeout_s).await.unwrap();
        println!("  [verbose] Fetching OS host key: {} {}", hk.key_type, hk.key_bytes.len());
        vault.set_host_key(&uuid, hk, true).unwrap();
        println!("  [verbose] OS host key pinned");
    }

    let access = BootedAccess {
        username: profile.username.clone(),
        auth: BootedAuth::Password(SecretString::new("abc".into())),
        use_sudo: false,
        connect_timeout_s: 10,
    };

    let results = fetch_luks_info(&vault, &uuid, &access, None, Some(Box::new(|cmd: &str| {
        println!("  [fetch] $ {}", cmd);
    }))).await;

    match results {
        Ok(infos) => {
            println!("  [verbose] Found {} LUKS volumes", infos.len());
            for info in &infos {
                println!("    UUID: {} Device: {}", info.luks_uuid, info.device_path);
            }
        }
        Err(e) => println!("  [verbose] Fetch error: {}", e),
    }
}
