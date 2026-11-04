use ltv_core::Vault;
use secrecy::SecretVec;
use std::fs;

#[tokio::test]
async fn test_server_setup() {
    let bytes = fs::read("../test_full2.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let vault = Vault::open(&bytes, &pass).unwrap();

    // We can't easily call the admin command from here, but we can check the artifacts
    let profile = &vault.inventory.profiles[0];
    println!("Profile: {}", profile.name);
    println!("Initramfs host key: {:?}", profile.initramfs_host_key.is_some());
    println!("Client public key: {}", vault.export_public_key(profile));
    println!("Authorized keys line: {}", vault.authorized_keys_line(profile));
}
