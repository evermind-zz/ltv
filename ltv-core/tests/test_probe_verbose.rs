use ltv_core::{Vault, probe, ProbeResult};
use secrecy::SecretVec;
use std::fs;

#[tokio::test]
async fn test_probe_verbose() {
    let bytes = fs::read("../test_full2.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let vault = Vault::open(&bytes, &pass).unwrap();

    let profile = vault.inventory.profiles[0].clone();

    let result = probe(&profile, Some(Box::new(|cmd: &str| {
        println!("  [verbose] {}", cmd);
    }))).await;

    println!("\nProbe result: {:?}", result);

    // Server is in initramfs - should get a host key
    match result {
        ProbeResult::WaitingInInitramfs => println!("  OK: waiting in initramfs"),
        ProbeResult::BootedOs => println!("  OK: booted OS"),
        ProbeResult::UnknownHostKey(k) => println!("  Unknown host key: {} {} bytes", k.key_type, k.key_bytes.len()),
        ProbeResult::Unreachable(e) => println!("  Unreachable: {}", e),
    }
}
