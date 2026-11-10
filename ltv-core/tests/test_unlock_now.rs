use ltv_core::{Vault, unlock, model::ExecutionMode, format::Argon2Params};
use secrecy::SecretVec;

#[tokio::test]
async fn test_unlock_now() {
    // Create a test vault with a fake server
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let params = Argon2Params { mem_kib: 16 * 1024, time: 2, par: 1 };
    let mut vault = Vault::create(&pass, params).unwrap();
    let uuid = vault.add_profile("test", "127.0.0.1", 2222, "root", None, None).unwrap();

    let _profile = vault.inventory.profiles[0].clone();
    
    // No host key pinned, so unlock should fail with HostKeyNotPinned
    let result = unlock(&vault, &uuid, ExecutionMode::Sequential, |e| println!("Event: {:?}", e), None).await;
    println!("Unlock result: {:?}", result);
    
    // Expect HostKeyNotPinned since we didn't pin a key
    assert!(matches!(result, Err(ltv_core::UnlockError::HostKeyNotPinned)));
}
