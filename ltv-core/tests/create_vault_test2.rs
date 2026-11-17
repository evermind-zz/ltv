// LTV (LUKS Tunnel Vault) - Remote LUKS unlock over SSH
// Copyright (C) 2024 LTV Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use ltv_core::{Vault, format::Argon2Params, TargetMeta};
use secrecy::SecretVec;
use tempfile::tempdir;

#[test]
fn test_create_vault2() {
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let mut vault = Vault::create(&pass, Argon2Params::default()).unwrap();
    
    let uuid = vault.add_profile("test", "192.0.2.100", 22, "root", None, None).unwrap();
    
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
    let dir = tempdir().unwrap();
    let path = dir.path().join("test2.ltv");
    std::fs::write(&path, bytes).unwrap();
    println!("Vault created successfully at {}", path.display());
}
