use ltv_core::{Vault, format::Argon2Params, TargetMeta};
use secrecy::SecretVec;

#[test]
fn test_create_vault() {
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let mut vault = Vault::create(&pass, Argon2Params::default()).unwrap();
    
    let uuid = vault.add_profile("test", "192.0.2.100", 22, "root").unwrap();
    
    let meta = TargetMeta {
        luks_uuid: "40b886d1-3f5c-4527-913f-b6ff3d1b2fca".to_string(),
        fallback_path: Some("/dev/vda2".to_string()),
        mapped_name: "cryptroot".to_string(),
        order: 0,
        keyslot: Some(0),
        token_id: None,
    };
    vault.add_target(&uuid, meta, None).unwrap();
    
    let bytes = vault.save().unwrap();
    std::fs::write("../test.ltv", bytes).unwrap();
    println!("Vault created successfully");
}
