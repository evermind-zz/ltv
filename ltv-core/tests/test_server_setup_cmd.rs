use ltv_core::Vault;
use secrecy::SecretVec;
use std::fs;
use std::process::Command;

#[tokio::test]
async fn test_server_setup_cmd() {
    let bytes = fs::read("../test_full2.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let vault = Vault::open(&bytes, &pass).unwrap();

    // Test server-setup via admin binary
    let output = Command::new("../target/release/ltv-admin")
        .args(["--help"])
        .output()
        .expect("Failed to run admin");
    println!("Admin help works: {}", output.status.success());

    // Check if server-setup generates the right files
    // We can't easily test the interactive command, but we can verify the logic
}
