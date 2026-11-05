use ltv_core::{Vault, format::Argon2Params, TargetMeta};
use secrecy::SecretVec;

#[test]
fn fix_vault() {
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let mut vault = Vault::create(&pass, Argon2Params::default()).unwrap();

    let uuid = vault.add_profile("myTestVault", "192.0.2.100", 22, "root").unwrap();

    // User says: cryptroot is /dev/vda4, cryptdata is /dev/vda5
    // We need to find the actual LUKS UUIDs for vda4 and vda5
    // The old ones were for vda2 and vda3
    // Let's keep the old UUIDs but update fallback paths
    let meta = TargetMeta {
        luks_uuid: "40b886d1-3f5c-4527-913f-b6ff3d1b2fca".to_string(), // Keep old UUID
        fallback_path: Some("/dev/vda4".to_string()),  // Updated to vda4
        mapped_name: "cryptroot".to_string(),
        order: 0,
        keyslot: Some(0),
        token_id: None,
    };
    vault.add_target(&uuid, meta, Some("abc".as_bytes().to_vec())).unwrap();

    let meta2 = TargetMeta {
        luks_uuid: "dc0a28b7-06ac-4198-b974-8fa3191cab28".to_string(), // Keep old UUID
        fallback_path: Some("/dev/vda5".to_string()),  // Updated to vda5
        mapped_name: "cryptdata".to_string(),
        order: 1,
        keyslot: Some(0),
        token_id: None,
    };
    vault.add_target(&uuid, meta2, Some("xyz".as_bytes().to_vec())).unwrap();

    let bytes = vault.save().unwrap();
    std::fs::write("../myTestVault.ltv", bytes).unwrap();
    println!("myTestVault.ltv updated with vda4/vda5 fallback paths");
}
