use ltv_core::{Vault, unlock, format::Argon2Params, TargetMeta};
use secrecy::SecretVec;
use std::fs;

#[tokio::test]
async fn test_unlock_with_key() {
    let bytes = fs::read("../test_full.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let mut vault = Vault::open(&bytes, &pass).unwrap();

    let profile = vault.inventory.profiles[0].clone();
    let uuid = profile.uuid;

    // First probe to get and pin the initramfs host key
    let probe_result = ltv_core::probe(&profile, Some(Box::new(|cmd: &str| println!("  [probe] $ {cmd}")))).await;
    match probe_result {
        ltv_core::ProbeResult::UnknownHostKey(k) => {
            println!("Unknown host key (initramfs?): {} {} bytes", k.key_type, k.key_bytes.len());
            vault.set_host_key(&uuid, k, false).unwrap();
            println!("Pinned as initramfs host key");
        }
        ltv_core::ProbeResult::WaitingInInitramfs => println!("Already have initramfs key"),
        ltv_core::ProbeResult::BootedOs => println!("Server is booted OS"),
        ltv_core::ProbeResult::Unreachable(e) => println!("Unreachable: {}", e),
    }

    // Now try unlock with the pinned key
    let result = unlock(&vault, &uuid, |e| {
        println!("Unlock event: {:?}", e);
    }, Some(Box::new(|cmd: &str| println!("  [unlock] $ {cmd}")))).await;

    match result {
        Ok(_) => println!("Unlock succeeded"),
        Err(e) => println!("Unlock error: {}", e),
    }
}
