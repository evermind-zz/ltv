use ltv_core::{Vault, enroll, BootedAccess, BootedAuth, EnrollEvent};
use secrecy::{SecretVec, SecretString};
use std::fs;

#[tokio::test]
async fn test_enroll_verbose() {
    let bytes = fs::read("../test_full2.ltv").unwrap();
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let mut vault = Vault::open(&bytes, &pass).unwrap();

    let profile = vault.inventory.profiles[0].clone();
    let uuid = profile.uuid;

    // Need OS host key for enroll (connects to booted OS)
    if profile.os_host_key.is_none() {
        println!("  [verbose] No OS host key - enroll requires booted OS");
        return;
    }

    let access = BootedAccess {
        username: profile.username.clone(),
        auth: BootedAuth::Password(SecretString::new("abc".into())),
        use_sudo: false,
        connect_timeout_s: 10,
    };

    // Use existing LUKS passphrase "abc" for root, "xyz" for data
    // In real usage, this would be provided by user
    let luks_pass = SecretString::new("abc".into());

    let results = enroll(&vault, &uuid, &access, &luks_pass, None, |e: EnrollEvent| {
        println!("  [event] {:?}", e);
    }, Some(Box::new(|cmd: &str| {
        println!("  [enroll] $ {}", cmd);
    }))).await;

    match results {
        Ok(res) => {
            for r in res {
                println!("  Enrolled {} into slot {}", r.luks_uuid, r.keyslot);
            }
        }
        Err(e) => println!("  Enroll error: {}", e),
    }
}
