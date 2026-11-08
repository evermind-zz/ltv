use base64::Engine;
use secrecy::SecretVec;
use zeroize::Zeroizing;

use crate::{constants::*, crypto::*, error::VaultError, format::*, model::*};


pub struct Vault {
    header: Header,
    master: Key32,
    pub inventory: Inventory,
    dirty: bool,
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Vault {
    pub fn open(bytes: &[u8], pass: &SecretVec<u8>) -> Result<Vault, VaultError> {
        let (header, hlen) = Header::decode(bytes)?;
        let ct = &bytes[hlen..];
        let mut master: Option<Key32> = None;
        for (i, slot) in header.slots.iter().enumerate() {
            let kek = kdf(pass, &slot.salt, slot.params)?;
            if let Ok(mk) = open(&kek, &slot.wrap_nonce, &header.slot_aad(i), &slot.wrapped) {
                let mut k = Zeroizing::new([0u8; KEY_LEN]);
                k.copy_from_slice(&mk);
                master = Some(k);
                break;
            }
        }
        let master = master.ok_or(VaultError::AuthFailed)?;
        let pt = open(&master, &header.payload_nonce, &bytes[..hlen], ct)?;
        let inventory: Inventory = postcard::from_bytes(&pt).map_err(|e| VaultError::Serde(e.to_string()))?;
        Ok(Vault { header, master, inventory, dirty: false })
    }

    pub fn is_dirty(&self) -> bool { self.dirty }

    pub fn profile(&self, uuid: &[u8; 16]) -> Result<&Profile, VaultError> {
        self.inventory.profiles.iter().find(|p| &p.uuid == uuid).ok_or(VaultError::NoProfile)
    }

    pub fn find_by_name(&self, name: &str) -> Option<&Profile> {
        self.inventory.profiles.iter().find(|p| p.name == name)
    }

    /// JIT decryption of one profile's secrets. Caller must drop ASAP.
    pub fn open_secrets(&self, p: &Profile) -> Result<SecretPayload, VaultError> {
        let ek = envelope_key(&self.master, &p.uuid);
        let pt = open(&ek, &p.envelope_nonce, &p.uuid, &p.envelope_ciphertext)?;
        let s: SecretPayload = postcard::from_bytes(&pt).map_err(|e| VaultError::Serde(e.to_string()))?;
        for t in &p.targets_meta {
            if !s.keyfiles.iter().any(|k| k.luks_uuid == t.luks_uuid) {
                return Err(VaultError::Invariant("target without keyfile"));
            }
        }
        Ok(s)
    }
}

#[cfg(feature = "write")]
impl Vault {
    pub fn create(pass: &SecretVec<u8>, params: Argon2Params) -> Result<Vault, VaultError> {
        let master: Key32 = Zeroizing::new(random::<32>());
        let mut header = Header { flags: 0, payload_nonce: random(), slots: vec![] };
        let slot = Self::make_slot(&header, 0, &master, pass, params)?;
        header.slots.push(slot);
        let t = now();
        Ok(Vault {
            header, master, dirty: true,
            inventory: Inventory { schema_version: 1, created_at: t, modified_at: t, profiles: vec![] },
        })
    }

    fn make_slot(header: &Header, idx: usize, master: &[u8; 32], pass: &SecretVec<u8>, params: Argon2Params)
        -> Result<Slot, VaultError> {
        let salt = random::<16>();
        let wrap_nonce = random::<24>();
        let kek = kdf(pass, &salt, params)?;
        let ct = seal(&kek, &wrap_nonce, &header.slot_aad(idx), master)?;
        let mut wrapped = [0u8; WRAPPED_LEN]; wrapped.copy_from_slice(&ct);
        Ok(Slot { params, salt, wrap_nonce, wrapped })
    }

    pub fn save(&mut self) -> Result<Vec<u8>, VaultError> {
        self.inventory.modified_at = now();
        self.header.payload_nonce = random();
        let hb = self.header.encode();
        let pt = Zeroizing::new(postcard::to_allocvec(&self.inventory).map_err(|e| VaultError::Serde(e.to_string()))?);
        let ct = seal(&self.master, &self.header.payload_nonce, &hb, &pt)?;
        let mut out = hb; out.extend_from_slice(&ct);
        self.dirty = false;
        Ok(out)
    }

    pub fn change_passphrase(&mut self, slot_idx: usize, new: &SecretVec<u8>, params: Argon2Params) -> Result<(), VaultError> {
        if slot_idx >= self.header.slots.len() { return Err(VaultError::SlotsFull); }
        let s = Self::make_slot(&self.header, slot_idx, &self.master, new, params)?;
        self.header.slots[slot_idx] = s;
        self.dirty = true;
        Ok(())
    }

    pub fn add_slot(&mut self, pass: &SecretVec<u8>, params: Argon2Params) -> Result<usize, VaultError> {
        let idx = self.header.slots.len();
        if idx >= MAX_SLOTS { return Err(VaultError::SlotsFull); }
        let s = Self::make_slot(&self.header, idx, &self.master, pass, params)?;
        self.header.slots.push(s);
        self.dirty = true;
        Ok(idx)
    }

    pub fn add_profile(&mut self, name: &str, host: &str, port: u16, username: &str) -> Result<[u8; 16], VaultError> {
        let uuid = *uuid::Uuid::new_v4().as_bytes();
        let signing = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let pubblob = ssh_ed25519_blob(signing.verifying_key().as_bytes());
        let secrets = SecretPayload { client_private_seed: signing.to_bytes(), keyfiles: vec![] };
        let mut p = Profile {
            uuid, name: name.into(), notes: String::new(), host: host.into(), port, username: username.into(),
            initramfs_host_key: None, os_host_key: None, host_key_pinned_at: 0,
            client_public_key: pubblob, targets_meta: vec![], resume: ResumePolicy::default(),
            connect_timeout_s: DEFAULT_CONNECT_TIMEOUT, exec_timeout_s: DEFAULT_EXEC_TIMEOUT, envelope_nonce: [0; NONCE_LEN], envelope_ciphertext: vec![],
        };
        self.seal_secrets(&mut p, &secrets)?;
        self.inventory.profiles.push(p);
        self.dirty = true;
        Ok(uuid)
    }

    fn seal_secrets(&self, p: &mut Profile, s: &SecretPayload) -> Result<(), VaultError> {
        let ek = envelope_key(&self.master, &p.uuid);
        p.envelope_nonce = random();
        let pt = Zeroizing::new(postcard::to_allocvec(s).map_err(|e| VaultError::Serde(e.to_string()))?);
        p.envelope_ciphertext = seal(&ek, &p.envelope_nonce, &p.uuid, &pt)?;
        Ok(())
    }

    fn profile_mut(&mut self, uuid: &[u8; 16]) -> Result<&mut Profile, VaultError> {
        self.inventory.profiles.iter_mut().find(|p| &p.uuid == uuid).ok_or(VaultError::NoProfile)
    }

    pub fn add_target(&mut self, uuid: &[u8; 16], meta: TargetMeta, key: Option<Vec<u8>>) -> Result<(), VaultError> {
        let p = self.profile(uuid)?.clone();
        let mut s = self.open_secrets(&p)?;
        if p.targets_meta.iter().any(|t| t.luks_uuid == meta.luks_uuid) {
            return Err(VaultError::Invariant("duplicate luks_uuid"));
        }
        let keyfile = key.unwrap_or_else(|| random::<64>().to_vec());
        s.keyfiles.push(TargetKey { luks_uuid: meta.luks_uuid.clone(), keyfile });
        let mut p2 = p;
        p2.targets_meta.push(meta);
        self.seal_secrets(&mut p2, &s)?;
        *self.profile_mut(uuid)? = p2;
        self.dirty = true;
        Ok(())
    }

    pub fn remove_target(&mut self, uuid: &[u8; 16], luks_uuid: &str) -> Result<(), VaultError> {
        let p = self.profile(uuid)?.clone();
        let mut s = self.open_secrets(&p)?;
        if !p.targets_meta.iter().any(|t| t.luks_uuid == luks_uuid) {
            return Err(VaultError::NoTarget);
        }
        s.keyfiles.retain(|k| k.luks_uuid != luks_uuid);
        let mut p2 = p;
        p2.targets_meta.retain(|t| t.luks_uuid != luks_uuid);
        self.seal_secrets(&mut p2, &s)?;
        *self.profile_mut(uuid)? = p2;
        self.dirty = true;
        Ok(())
    }

    pub fn set_host_key(&mut self, uuid: &[u8; 16], key: HostKey, os: bool) -> Result<(), VaultError> {
        let p = self.profile_mut(uuid)?;
        if os { p.os_host_key = Some(key) } else { p.initramfs_host_key = Some(key); p.host_key_pinned_at = now(); }
        self.dirty = true;
        Ok(())
    }

    pub fn set_keyslot(&mut self, uuid: &[u8; 16], luks_uuid: &str, slot: u8) -> Result<(), VaultError> {
        let p = self.profile_mut(uuid)?;
        let t = p.targets_meta.iter_mut().find(|t| t.luks_uuid == luks_uuid).ok_or(VaultError::NoTarget)?;
        t.keyslot = Some(slot);
        self.dirty = true;
        Ok(())
    }

    pub fn remove_profile(&mut self, uuid: &[u8; 16]) -> Result<(), VaultError> {
        let n = self.inventory.profiles.len();
        self.inventory.profiles.retain(|p| &p.uuid != uuid);
        if n == self.inventory.profiles.len() { return Err(VaultError::NoProfile); }
        self.dirty = true;
        Ok(())
    }

    pub fn update_profile(&mut self, uuid: &[u8; 16], f: impl FnOnce(&mut Profile)) -> Result<(), VaultError> {
        let p = self.profile_mut(uuid)?;
        f(p);
        self.dirty = true;
        Ok(())
    }

    pub fn export_public_key(&self, p: &Profile) -> String {
        format!("ssh-ed25519 {} ltv:{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(&p.client_public_key), p.name)
    }

    pub fn authorized_keys_line(&self, p: &Profile) -> String {
        // Client pubkey only (no forced commands) - current unlock uses full shell
        self.export_public_key(p)
    }
}

pub fn ssh_ed25519_blob(pk: &[u8; 32]) -> Vec<u8> {
    let mut b = Vec::new();
    for part in [SSH_KEY_TYPE.as_bytes(), pk.as_slice()] {
        b.extend_from_slice(&(part.len() as u32).to_be_bytes());
        b.extend_from_slice(part);
    }
    b
}


#[cfg(all(test, feature = "write"))]
mod tests {
    use super::*;
    use crate::format::{FIXED_LEN, SLOT_LEN};

    fn fast() -> Argon2Params { Argon2Params { mem_kib: 16 * 1024, time: 2, par: 1 } }
    fn pw(s: &str) -> SecretVec<u8> { SecretVec::new(s.as_bytes().to_vec()) }

    fn sample() -> (Vault, [u8; 16]) {
        let mut v = Vault::create(&pw("hunter2"), fast()).unwrap();
        let u = v.add_profile("web01", "192.0.2.10", 22, "root").unwrap();
        v.add_target(&u, TargetMeta { luks_uuid: "aaaa-1".into(), fallback_path: Some("/dev/sda2".into()),
            mapped_name: "cryptroot".into(), order: 0, keyslot: None, token_id: None }, None).unwrap();
        (v, u)
    }

    #[test]
    fn header_roundtrip() {
        let (mut v, _) = sample();
        let bytes = v.save().unwrap();
        let (h, len) = Header::decode(&bytes).unwrap();
        assert_eq!(len, FIXED_LEN + SLOT_LEN);
        assert_eq!(h.slots.len(), 1);
        assert_eq!(h.encode(), bytes[..len]);
    }

    #[test]
    fn save_open_roundtrip_and_secrets() {
        let (mut v, u) = sample();
        let bytes = v.save().unwrap();
        let v2 = Vault::open(&bytes, &pw("hunter2")).unwrap();
        let p = v2.profile(&u).unwrap();
        assert_eq!(p.name, "web01");
        let s = v2.open_secrets(p).unwrap();
        assert_eq!(s.keyfiles.len(), 1);
        assert_eq!(s.keyfiles[0].keyfile.len(), 64);
        assert_eq!(p.client_public_key.len(), 4 + 11 + 4 + 32);
    }

    #[test]
    fn wrong_passphrase() {
        let (mut v, _) = sample();
        let bytes = v.save().unwrap();
        assert!(matches!(Vault::open(&bytes, &pw("nope")), Err(VaultError::AuthFailed)));
    }

    #[test]
    fn tamper_header_fails_auth() {
        let (mut v, _) = sample();
        let mut bytes = v.save().unwrap();
        bytes[7] ^= 0x01;                       // flags byte → in AAD of both slot and payload
        assert!(matches!(Vault::open(&bytes, &pw("hunter2")), Err(VaultError::AuthFailed)));
    }

    #[test]
    fn tamper_ciphertext_fails_auth() {
        let (mut v, _) = sample();
        let mut bytes = v.save().unwrap();
        let last = bytes.len() - 1; bytes[last] ^= 0xff;
        assert!(matches!(Vault::open(&bytes, &pw("hunter2")), Err(VaultError::AuthFailed)));
    }

    #[test]
    fn weak_params_rejected_before_kdf() {
        let (mut v, _) = sample();
        let mut bytes = v.save().unwrap();
        bytes[FIXED_LEN..FIXED_LEN + 4].copy_from_slice(&1024u32.to_le_bytes()); // 1 MiB
        assert!(matches!(Vault::open(&bytes, &pw("hunter2")), Err(VaultError::WeakParams)));
    }

    #[test]
    fn bad_magic_and_truncated() {
        let (mut v, _) = sample();
        let mut bytes = v.save().unwrap();
        assert!(matches!(Vault::open(&bytes[..40], &pw("x")), Err(VaultError::Truncated)));
        bytes[0] = b'X';
        assert!(matches!(Vault::open(&bytes, &pw("x")), Err(VaultError::BadMagic)));
    }

    #[test]
    fn second_slot_opens_same_payload() {
        let (mut v, u) = sample();
        v.add_slot(&pw("second-admin"), fast()).unwrap();
        let bytes = v.save().unwrap();
        assert_eq!(bytes[6], 2);
        let a = Vault::open(&bytes, &pw("hunter2")).unwrap();
        let b = Vault::open(&bytes, &pw("second-admin")).unwrap();
        assert_eq!(a.profile(&u).unwrap().envelope_ciphertext, b.profile(&u).unwrap().envelope_ciphertext);
        assert!(b.open_secrets(b.profile(&u).unwrap()).is_ok());
    }

    #[test]
    fn change_passphrase_keeps_profiles() {
        let (mut v, u) = sample();
        v.change_passphrase(0, &pw("new"), fast()).unwrap();
        let bytes = v.save().unwrap();
        assert!(Vault::open(&bytes, &pw("hunter2")).is_err());
        let v2 = Vault::open(&bytes, &pw("new")).unwrap();
        assert!(v2.open_secrets(v2.profile(&u).unwrap()).is_ok());
    }

    #[test]
    fn nonce_rotates_every_save() {
        let (mut v, _) = sample();
        let a = v.save().unwrap(); let b = v.save().unwrap();
        assert_ne!(a[8..32], b[8..32]);
    }

    #[test]
    fn duplicate_target_rejected_and_keyslot_persists() {
        let (mut v, u) = sample();
        let dup = TargetMeta { luks_uuid: "aaaa-1".into(), fallback_path: None, mapped_name: "x".into(),
                               order: 1, keyslot: None, token_id: None };
        assert!(matches!(v.add_target(&u, dup, None), Err(VaultError::Invariant(_))));
        v.set_keyslot(&u, "aaaa-1", 3).unwrap();
        assert!(matches!(v.set_keyslot(&u, "zzz", 3), Err(VaultError::NoTarget)));
        let bytes = v.save().unwrap();
        let v2 = Vault::open(&bytes, &pw("hunter2")).unwrap();
        assert_eq!(v2.profile(&u).unwrap().targets_meta[0].keyslot, Some(3));
    }

    #[test]
    fn envelope_invariant_detects_missing_key() {
        let (mut v, u) = sample();
        // add meta without key by poking the profile directly (simulates corruption)
        let p = v.profile_mut(&u).unwrap();
        p.targets_meta.push(TargetMeta { luks_uuid: "orphan".into(), fallback_path: None, mapped_name: "o".into(),
                                         order: 9, keyslot: None, token_id: None });
        let p = v.profile(&u).unwrap().clone();
        assert!(matches!(v.open_secrets(&p), Err(VaultError::Invariant(_))));
    }
}