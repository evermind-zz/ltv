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

use ltv_core::format::Argon2Params;
use ltv_core::Vault;
use secrecy::SecretVec;

#[test]
fn test_open() {
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let params = Argon2Params {
        mem_kib: 16 * 1024,
        time: 2,
        par: 1,
    };
    let mut v = Vault::create(&pass, params).unwrap();
    let _uuid = v
        .add_profile("test", "192.168.1.10", 22, "root", None, None)
        .unwrap();

    let bytes = v.save().unwrap();
    let v2 = Vault::open(&bytes, &pass).unwrap();
    println!("Opened: {} profiles", v2.inventory.profiles.len());
    for p in &v2.inventory.profiles {
        println!("  Profile: {}", p.name);
        println!("  Unlock SSH: {}:{}", p.unlock_host, p.unlock_port);
        println!("  OS SSH: {:?}:{:?}", p.os_host, p.os_port);
        println!("  Targets meta: {}", p.targets_meta.len());
    }
}
