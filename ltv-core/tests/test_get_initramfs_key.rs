use ltv_core::{Vault, unlock, probe, format::Argon2Params, TargetMeta};
use secrecy::SecretVec;

#[tokio::test]
async fn test_get_initramfs_key() {
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let mut vault = Vault::create(&pass, Argon2Params::default()).unwrap();

    let uuid = vault.add_profile("test", "192.0.2.100", 22, "root").unwrap();

    let meta = TargetMeta {
        luks_uuid: "40b886d1-3f5c-4527-913f-b6ff3d1b2fca".to_string(),
        fallback_path: Some("/dev/vda2".to_string()),
        mapped_name: "cryptroot".to_string(),
        order: 0,
        keyslot: Some(0),
        token_id: None,
    };
    vault.add_target(&uuid, meta, Some("abc".as_bytes().to_vec())).unwrap();

    let meta2 = TargetMeta {
        luks_uuid: "dc0a28b7-06ac-4198-b974-8fa3191cab28".to_string(),
        fallback_path: Some("/dev/vda3".to_string()),
        mapped_name: "cryptdata".to_string(),
        order: 1,
        keyslot: Some(0),
        token_id: None,
    };
    vault.add_target(&uuid, meta2, Some("xyz".as_bytes().to_vec())).unwrap();

    // Probe to get the initramfs host key
    let profile = vault.inventory.profiles[0].clone();
    let probe_result = probe(&profile, Some(Box::new(|cmd: &str| println!("  [probe] $ {cmd}")))).await;

    match probe_result {
        ltv_core::ProbeResult::WaitingInInitramfs => {
            println!("Server is in initramfs - but this requires pinned key");
        }
        ltv_core::ProbeResult::BootedOs => {
            println!("Server is booted OS");
        }
        ltv_core::ProbeResult::UnknownHostKey(k) => {
            println!("Unknown host key (initramfs?): {} {} bytes", k.key_type, k.key_bytes.len());
            // Pin as initramfs host key
            vault.set_host_key(&uuid, k, false).unwrap();
            println!("Pinned as initramfs host key");
        }
        ltv_core::ProbeResult::Unreachable(e) => {
            println!("Unreachable: {}", e);
        }
    }

    // Now try unlock
    let result = unlock(&vault, &uuid, |e| {
        println!("Unlock event: {:?}", e);
    }, Some(Box::new(|cmd: &str| println!("  [unlock] $ {cmd}")))).await;

    match result {
        Ok(_) => println!("Unlock succeeded"),
        Err(e) => println!("Unlock error: {}", e),
    }
}
