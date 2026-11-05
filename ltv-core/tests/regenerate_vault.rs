use ltv_core::{Vault, format::Argon2Params, TargetMeta};
use secrecy::SecretVec;

#[test]
fn regenerate_vault() {
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let mut vault = Vault::create(&pass, Argon2Params::default()).unwrap();

    let uuid = vault.add_profile("myTestVault", "192.0.2.100", 22, "root").unwrap();

    // Correct UUIDs from blkid on server
    let meta = TargetMeta {
        luks_uuid: "111832b4-5029-4439-8713-d5b928f44412".to_string(), // vda4 root
        fallback_path: Some("/dev/vda4".to_string()),
        mapped_name: "cryptroot".to_string(),
        order: 0,
        keyslot: Some(0),
        token_id: None,
    };
    vault.add_target(&uuid, meta, Some("abc".as_bytes().to_vec())).unwrap();

    let meta2 = TargetMeta {
        luks_uuid: "ac302374-1b08-4511-944b-ef1658dd909b".to_string(), // vda5 data
        fallback_path: Some("/dev/vda5".to_string()),
        mapped_name: "cryptdata".to_string(),
        order: 1,
        keyslot: Some(0),
        token_id: None,
    };
    vault.add_target(&uuid, meta2, Some("xyz".as_bytes().to_vec())).unwrap();

    let bytes = vault.save().unwrap();
    std::fs::write("../myTestVault.ltv", bytes).unwrap();
    println!("myTestVault.ltv REGENERATED with CORRECT UUIDs");
}
