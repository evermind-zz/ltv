use ltv_core::{Vault, unlock, probe, fetch_luks_info, fetch_host_key, BootedAccess, BootedAuth};
use secrecy::{SecretVec, SecretString};
use std::fs;

/// Test all read-only admin commands against the live server
#[tokio::test]
async fn test_all_commands() {
    let bytes = fs::read("../test_full2.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let mut vault = Vault::open(&bytes, &pass).unwrap();

    let profile = vault.inventory.profiles[0].clone();
    let uuid = profile.uuid;

    println!("=== 1. STATUS ===");
    println!("Vault: {} profiles, {}", vault.inventory.profiles.len(), 
             if vault.is_dirty() { "dirty" } else { "clean" });
    for p in &vault.inventory.profiles {
        println!("  Profile: {} ({}:{})", p.name, p.host, p.port);
        println!("    initramfs_host_key: {}", if p.initramfs_host_key.is_some() { "pinned" } else { "none" });
        println!("    os_host_key: {}", if p.os_host_key.is_some() { "pinned" } else { "none" });
        println!("    targets: {}", p.targets_meta.len());
    }

    println!("\n=== 2. PROBE ===");
    let probe_result = probe(&profile, Some(Box::new(|cmd: &str| println!("  [probe] $ {cmd}")))).await;
    match probe_result {
        ltv_core::ProbeResult::WaitingInInitramfs => println!("  Result: WaitingInInitramfs"),
        ltv_core::ProbeResult::BootedOs => println!("  Result: BootedOs"),
        ltv_core::ProbeResult::UnknownHostKey(k) => println!("  Result: UnknownHostKey({} {} bytes)", k.key_type, k.key_bytes.len()),
        ltv_core::ProbeResult::Unreachable(e) => println!("  Result: Unreachable({})", e),
    }

    println!("\n=== 3. HOSTKEY FETCH ===");
    let hk = fetch_host_key(&profile.host, profile.port, profile.connect_timeout_s).await;
    match hk {
        Ok(k) => println!("  Result: {} {}", k.key_type, k.key_bytes.len()),
        Err(e) => println!("  Result: Error: {}", e),
    }

    println!("\n=== 4. PUBKEY ===");
    println!("  Public key: {}", vault.export_public_key(&profile));
    println!("  Authorized keys line: {}", vault.authorized_keys_line(&profile));

    println!("\n=== 5. UNLOCK (expected to fail without authorized key on server) ===");
    let result = unlock(&vault, &uuid, |e| {
        println!("  Unlock event: {:?}", e);
    }, Some(Box::new(|cmd: &str| println!("  [unlock] $ {cmd}")))).await;
    match result {
        Ok(_) => println!("  Result: SUCCESS"),
        Err(e) => println!("  Result: Error: {}", e),
    }

    println!("\n=== 6. FETCH (booted OS only) ===");
    let access = BootedAccess {
        username: profile.username.clone(),
        auth: BootedAuth::Password(SecretString::new("abc".into())),
        use_sudo: false,
        connect_timeout_s: 10,
    };
    let results = fetch_luks_info(&vault, &uuid, &access, None, Some(Box::new(|cmd: &str| println!("  [fetch] $ {cmd}")))).await;
    match results {
        Ok(infos) => {
            println!("  Found {} LUKS volumes", infos.len());
            for info in &infos {
                println!("    UUID: {}", info.luks_uuid);
            }
        }
        Err(e) => println!("  Result: Error: {}", e),
    }

    println!("\n=== 7. ENROLL (booted OS only, expected to fail) ===");
    // Enroll requires booted OS - should fail when in initramfs
}
