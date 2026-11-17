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

use ltv_core::{format::Argon2Params, model::ExecutionMode, unlock, Vault};
use secrecy::SecretVec;

#[tokio::test]
async fn test_unlock_now() {
    // Create a test vault with a fake server
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let params = Argon2Params {
        mem_kib: 16 * 1024,
        time: 2,
        par: 1,
    };
    let mut vault = Vault::create(&pass, params).unwrap();
    let uuid = vault
        .add_profile("test", "127.0.0.1", 2222, "root", None, None)
        .unwrap();

    let _profile = vault.inventory.profiles[0].clone();

    // No host key pinned, so unlock should fail with HostKeyNotPinned
    let result = unlock(
        &vault,
        &uuid,
        ExecutionMode::Sequential,
        |e| println!("Event: {:?}", e),
        None,
    )
    .await;
    println!("Unlock result: {:?}", result);

    // Expect HostKeyNotPinned since we didn't pin a key
    assert!(matches!(
        result,
        Err(ltv_core::UnlockError::HostKeyNotPinned)
    ));
}
