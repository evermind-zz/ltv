use ltv_core::{Vault, Argon2Params, Profile, Target};

fn main() {
    let mut vault = Vault::new();
    vault.create("test".to_string(), "abc", Argon2Params::default()).unwrap();
    let mut profile = Profile::new("test".to_string());
    profile.host = Some("192.0.2.100".to_string());
    profile.targets.push(Target::new(
        "cryptroot".to_string(),
        "40b886d1-3f5c-4527-913f-b6ff3d1b2fca".to_string(),
    ));
    vault.add_profile(profile).unwrap();
    vault.save_to_file("test.ltv").unwrap();
}
