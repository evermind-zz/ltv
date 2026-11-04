use ltv_core::{Vault, Argon2Params, Profile, Target};

fn main() {
    let pass = "abc";
    let vault = Vault::create(pass, Argon2Params::default()).unwrap();
    
    let mut profile = Profile::new("test".to_string());
    profile.host = Some("192.0.2.100".to_string());
    profile.port = 22;
    profile.user = Some("root".to_string());
    profile.connect_timeout_s = 10;
    profile.exec_timeout_s = 300;
    profile.resume = true;
    
    let target = Target::new(
        "cryptroot".to_string(),
        "40b886d1-3f5c-4527-913f-b6ff3d1b2fca".to_string(),
    );
    profile.targets.push(target);
    
    vault.add_profile(profile).unwrap();
    vault.save_to_file("test.ltv").unwrap();
    println!("Vault created successfully");
}
