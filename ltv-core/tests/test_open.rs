use ltv_core::Vault;
use ltv_core::format::Argon2Params;
use secrecy::SecretVec;

#[test]
fn test_open() {
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let params = Argon2Params { mem_kib: 16 * 1024, time: 2, par: 1 };
    let mut v = Vault::create(&pass, params).unwrap();
    let _uuid = v.add_profile("test", "192.168.1.10", 22, "root", None, None).unwrap();

    let bytes = v.save().unwrap();
    let v2 = Vault::open(&bytes, &pass).unwrap();
    println!("Opened: {} profiles", v2.inventory.profiles.len());
    for p in &v2.inventory.profiles {
        println!("  Profile: {}", p.name);
        println!("  Host: {:?}", p.host);
        println!("  OS host: {:?}", p.os_host);
        println!("  OS port: {:?}", p.os_port);
        println!("  Targets meta: {}", p.targets_meta.len());
    }
}
