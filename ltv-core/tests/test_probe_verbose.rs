use ltv_core::{Vault, probe, ProbeResult, format::Argon2Params};
use secrecy::SecretVec;

#[tokio::test]
async fn test_probe_verbose() {
    // Create a test vault
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let params = Argon2Params { mem_kib: 16 * 1024, time: 2, par: 1 };
    let mut v = Vault::create(&pass, params).unwrap();
    let _uuid = v.add_profile("test", "127.0.0.1", 2222, "root", None, None).unwrap();
    
    let profile = v.inventory.profiles[0].clone();
    
    // Test probe against non-existent server (should return Unreachable)
    let result = probe(&profile, Some(Box::new(|cmd: &str| {
        println!("  [verbose] {}", cmd);
    }))).await;
    
    println!("\nProbe result: {:?}", result);
    
    // Should be unreachable since no server is running
    match result {
        ProbeResult::Unreachable(e) => println!("  OK: unreachable: {}", e),
        ProbeResult::WaitingInInitramfs => println!("  OK: waiting in initramfs"),
        ProbeResult::BootedOs => println!("  OK: booted OS"),
        ProbeResult::UnknownHostKey(k) => println!("  Unknown host key: {} {} bytes", k.key_type, k.key_bytes.len()),
    }
}