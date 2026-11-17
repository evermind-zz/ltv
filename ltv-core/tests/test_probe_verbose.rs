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

use ltv_core::{format::Argon2Params, probe, ProbeResult, Vault};
use secrecy::SecretVec;

#[tokio::test]
async fn test_probe_verbose() {
    // Create a test vault
    let pass = SecretVec::new("abc".as_bytes().to_vec());
    let params = Argon2Params {
        mem_kib: 16 * 1024,
        time: 2,
        par: 1,
    };
    let mut v = Vault::create(&pass, params).unwrap();
    let _uuid = v
        .add_profile("test", "127.0.0.1", 2222, "root", None, None)
        .unwrap();

    let profile = v.inventory.profiles[0].clone();

    // Test probe against non-existent server (should return Unreachable)
    let result = probe(
        &profile,
        Some(Box::new(|cmd: &str| {
            println!("  [verbose] {}", cmd);
        })),
    )
    .await;

    println!("\nProbe result: {:?}", result);

    // Should be unreachable since no server is running
    match result {
        ProbeResult::Unreachable(e) => println!("  OK: unreachable: {}", e),
        ProbeResult::WaitingInInitramfs => println!("  OK: waiting in initramfs"),
        ProbeResult::BootedOs => println!("  OK: booted OS"),
        ProbeResult::UnknownHostKey(k) => println!(
            "  Unknown host key: {} {} bytes",
            k.key_type,
            k.key_bytes.len()
        ),
    }
}
