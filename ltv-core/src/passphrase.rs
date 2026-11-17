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

//! Shared passphrase handling utilities for enroll and rotate operations.

use crate::error::UnlockError;
use crate::model::TargetMeta;
use secrecy::SecretString;
use std::collections::HashMap;

/// Creates a sequential passphrase provider that caches results per UUID.
/// Each unique LUKS UUID is only prompted once, even across multiple targets.
pub fn make_sequential_passphrase_provider(
    mut provider: impl FnMut(&str) -> Result<SecretString, String> + Send,
) -> impl FnMut(&str) -> Result<SecretString, String> + Send {
    let mut cache: HashMap<String, SecretString> = HashMap::new();
    move |uuid: &str| {
        if let Some(cached) = cache.get(uuid) {
            Ok(cached.clone())
        } else {
            let p = provider(uuid)?;
            cache.insert(uuid.to_string(), p.clone());
            Ok(p)
        }
    }
}

/// Creates a parallel passphrase map by calling provider for each unique UUID upfront.
/// Returns a map of luks_uuid -> passphrase, or an error if any provider call fails.
pub fn make_parallel_passphrase_map(
    targets: &[(usize, TargetMeta)],
    mut provider: impl FnMut(&str) -> Result<SecretString, String>,
) -> Result<HashMap<String, SecretString>, UnlockError> {
    let mut pass_map = HashMap::new();
    for (_, tm) in targets {
        if !pass_map.contains_key(&tm.luks_uuid) {
            let p = provider(&tm.luks_uuid).map_err(|e| UnlockError::CryptsetupFailed {
                target: tm.mapped_name.clone(),
                code: 0,
                stderr: e,
            })?;
            pass_map.insert(tm.luks_uuid.clone(), p);
        }
    }
    Ok(pass_map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::TargetMeta;
    use secrecy::{ExposeSecret, SecretString};

    #[test]
    fn test_make_sequential_passphrase_provider() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let call_count = AtomicUsize::new(0);
        let mut provider = make_sequential_passphrase_provider(|uuid: &str| {
            call_count.fetch_add(1, Ordering::SeqCst);
            Ok(SecretString::from(format!("pass-{}", uuid)))
        });

        let r1 = provider("uuid-1").unwrap();
        let r2 = provider("uuid-1").unwrap();
        let r3 = provider("uuid-2").unwrap();

        assert_eq!(call_count.load(Ordering::SeqCst), 2); // uuid-1 called once, uuid-2 called once
        assert_eq!(r1.expose_secret(), "pass-uuid-1");
        assert_eq!(r2.expose_secret(), "pass-uuid-1");
        assert_eq!(r3.expose_secret(), "pass-uuid-2");
    }

    #[test]
    fn test_make_parallel_passphrase_map() {
        let targets = vec![
            (
                0,
                TargetMeta {
                    luks_uuid: "uuid-1".into(),
                    mapped_name: "t1".into(),
                    ..Default::default()
                },
            ),
            (
                1,
                TargetMeta {
                    luks_uuid: "uuid-2".into(),
                    mapped_name: "t2".into(),
                    ..Default::default()
                },
            ),
            (
                2,
                TargetMeta {
                    luks_uuid: "uuid-1".into(),
                    mapped_name: "t3".into(),
                    ..Default::default()
                },
            ),
        ];

        let mut call_count = 0;
        let pass_map = make_parallel_passphrase_map(&targets, |uuid: &str| {
            call_count += 1;
            Ok(SecretString::from(format!("pass-{}", uuid)))
        })
        .unwrap();

        assert_eq!(call_count, 2); // Only called for unique UUIDs
        assert_eq!(pass_map.len(), 2);
        assert_eq!(
            pass_map.get("uuid-1").unwrap().expose_secret(),
            "pass-uuid-1"
        );
        assert_eq!(
            pass_map.get("uuid-2").unwrap().expose_secret(),
            "pass-uuid-2"
        );
    }

    #[test]
    fn test_make_parallel_passphrase_map_error() {
        let targets = vec![(
            0,
            TargetMeta {
                luks_uuid: "uuid-1".into(),
                mapped_name: "t1".into(),
                ..Default::default()
            },
        )];

        let result = make_parallel_passphrase_map(&targets, |_| Err("provider error".into()));
        assert!(result.is_err());
        match result.unwrap_err() {
            UnlockError::CryptsetupFailed {
                target,
                code: 0,
                stderr,
            } => {
                assert_eq!(target, "t1");
                assert_eq!(stderr, "provider error");
            }
            _ => panic!("wrong error type"),
        }
    }
}
