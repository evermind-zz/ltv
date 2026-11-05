use ltv_core::{Vault, unlock, probe, fetch_luks_info, BootedAccess, BootedAuth, Profile};
use secrecy::{SecretVec, SecretString};
use std::fs;

#[tokio::test]
async fn test_all_commands() {
    let bytes = fs::read("../myTestVault.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let vault = Vault::open(&bytes, &pass).unwrap();

    let profile = vault.inventory.profiles[0].clone();
    let uuid = profile.uuid;

    println!("=== VAULT OPEN SUCCESS ===");
    println!("Profile: {} at {}", profile.name, profile.host);

    // Test 1: probe (should show initramfs state)
    println!("\n=== PROBE TEST ===");
    let p_ref: &Profile = &profile;
    let probe_result = probe(p_ref, Some(Box::new(|cmd: &str| {
        println!("  [probe] $ {}", cmd);
    }))).await;
    println!("Probe result: {:?}", probe_result);

    // Test 2: unlock (against initramfs)
    println!("\n=== UNLOCK TEST ===");
    let unlock_result = unlock(&vault, &uuid, |e| println!("Event: {:?}", e), Some(Box::new(|cmd: &str| {
        println!("  [unlock] $ {}", cmd);
    }))).await;
    println!("Unlock result: {:?}", unlock_result);

    // Test 3: fetch_luks_info (should fail - server not booted)
    println!("\n=== FETCH LUKS INFO TEST ===");
    let access = BootedAccess {
        username: "root".to_string(),
        auth: BootedAuth::Password(SecretString::new("abc".into())),
        use_sudo: false,
        connect_timeout_s: 10,
    };
    let fetch_result = fetch_luks_info(&vault, &uuid, &access, None, Some(Box::new(|cmd: &str| {
        println!("  [fetch] $ {}", cmd);
    }))).await;
    println!("Fetch result: {:?}", fetch_result);
}
