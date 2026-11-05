use ltv_core::{Vault, probe, fetch_host_key};
use secrecy::SecretVec;
use std::fs;

#[tokio::test]
async fn test_current_state() {
    let bytes = fs::read("../myTestVault.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let vault = Vault::open(&bytes, &pass).unwrap();

    let profile = vault.inventory.profiles[0].clone();
    
    println!("=== PROBE ===");
    let result = probe(&profile, Some(Box::new(|cmd: &str| println!("  [probe] $ {cmd}")))).await;
    match result {
        ltv_core::ProbeResult::WaitingInInitramfs => println!("  State: WaitingInInitramfs"),
        ltv_core::ProbeResult::BootedOs => println!("  State: BootedOs"),
        ltv_core::ProbeResult::UnknownHostKey(k) => println!("  State: UnknownHostKey ({} {} bytes)", k.key_type, k.key_bytes.len()),
        ltv_core::ProbeResult::Unreachable(e) => println!("  State: Unreachable ({})", e),
    }

    println!("\n=== FETCH HOST KEY ===");
    let hk = fetch_host_key(&profile.host, profile.port, profile.connect_timeout_s).await.unwrap();
    println!("  Host key: {} {}", hk.key_type, hk.key_bytes.len());
}
