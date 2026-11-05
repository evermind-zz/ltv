use ltv_core::{Vault, unlock, probe, Profile};
use secrecy::SecretVec;
use std::fs;

#[tokio::test]
async fn debug_unlock() {
    let bytes = fs::read("../myTestVault.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let vault = Vault::open(&bytes, &pass).unwrap();

    let profile = vault.inventory.profiles[0].clone();
    let uuid = profile.uuid;

    println!("=== DEBUG UNLOCK ===");
    println!("Profile: {} at {}:{}", profile.name, profile.host, profile.port);
    println!("Has initramfs key: {}", profile.initramfs_host_key.is_some());
    println!("Has OS key: {}", profile.os_host_key.is_some());
    
    if let Some(k) = &profile.initramfs_host_key {
        println!("Initramfs key: {} ({} bytes)", k.key_type, k.key_bytes.len());
    }
    if let Some(k) = &profile.os_host_key {
        println!("OS key: {} ({} bytes)", k.key_type, k.key_bytes.len());
    }
    println!("Targets: {}", profile.targets_meta.len());
    for t in &profile.targets_meta {
        println!("  {} UUID={} fallback={:?} slot={:?}", t.mapped_name, t.luks_uuid, t.fallback_path, t.keyslot);
    }

    // Test probe first
    println!("\n=== PROBE ===");
    let p_ref: &Profile = &profile;
    let probe_result = probe(p_ref, Some(Box::new(|cmd: &str| {
        println!("  [probe] $ {}", cmd);
    }))).await;
    println!("Probe: {:?}", probe_result);

    // Now unlock with more verbose
    println!("\n=== UNLOCK ===");
    let unlock_result = unlock(&vault, &uuid, |e| println!("Event: {:?}", e), Some(Box::new(|cmd: &str| {
        println!("  [unlock] $ {}", cmd);
    }))).await;
    println!("Unlock: {:?}", unlock_result);
}
