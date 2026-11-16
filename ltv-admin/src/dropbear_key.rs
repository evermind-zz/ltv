use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::io::{self, Read, Write};

/// Dropbear Ed25519 private key format (matches dropbear's buf_put_ed25519_priv_key):
/// - 4 bytes: length of "ssh-ed25519" (11, big-endian)
/// - 11 bytes: "ssh-ed25519" (NO null terminator)
/// - 4 bytes: length of private key data (64, big-endian)
/// - 64 bytes: private key data (32 bytes seed + 32 bytes public key)
/// Total: 83 bytes

const DROPBEAR_KEY_TYPE: &str = "ssh-ed25519";
const DROPBEAR_KEY_TYPE_LEN: u32 = 11;
const DROPBEAR_PRIVKEY_DATA_LEN: u32 = 64;

/// Generate a new Ed25519 keypair and return the SigningKey
pub fn generate_ed25519_keypair() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Generate a deterministic Ed25519 keypair from a 32-byte seed (for testing)
pub fn generate_ed25519_keypair_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

/// Write a Dropbear-format Ed25519 private key to a writer
pub fn write_dropbear_ed25519_private_key<W: Write>(writer: &mut W, signing_key: &SigningKey) -> io::Result<()> {
    let verifying_key = signing_key.verifying_key();
    let seed = signing_key.to_bytes();
    let pubkey = verifying_key.as_bytes();

    // 1. Write key type length (4 bytes, big-endian)
    writer.write_all(&DROPBEAR_KEY_TYPE_LEN.to_be_bytes())?;
    // 2. Write key type string (NO null terminator)
    writer.write_all(DROPBEAR_KEY_TYPE.as_bytes())?;
    // 3. Write private key data length (4 bytes, big-endian)
    writer.write_all(&DROPBEAR_PRIVKEY_DATA_LEN.to_be_bytes())?;
    // 4. Write private key data: seed (32 bytes) + public key (32 bytes)
    writer.write_all(&seed)?;
    writer.write_all(pubkey)?;

    Ok(())
}

/// Read a Dropbear-format Ed25519 private key from a reader
pub fn read_dropbear_ed25519_private_key<R: io::Read>(reader: &mut R) -> io::Result<SigningKey> {
    // Read key type length (4 bytes)
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let key_type_len = u32::from_be_bytes(len_buf) as usize;

    // Read key type string
    let mut key_type_buf = vec![0u8; key_type_len];
    reader.read_exact(&mut key_type_buf)?;
    let key_type = String::from_utf8(key_type_buf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key type utf-8"))?;

    if key_type != DROPBEAR_KEY_TYPE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unsupported key type: {}", key_type)));
    }

    // Read private key data length (4 bytes)
    reader.read_exact(&mut len_buf)?;
    let privkey_data_len = u32::from_be_bytes(len_buf) as usize;

    if privkey_data_len != DROPBEAR_PRIVKEY_DATA_LEN as usize {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unexpected private key data length: {}", privkey_data_len)));
    }

    // Read private key data (64 bytes = 32 seed + 32 public key)
    let mut privkey_data = vec![0u8; privkey_data_len];
    reader.read_exact(&mut privkey_data)?;

    // Extract seed (first 32 bytes)
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&privkey_data[0..32]);

    // Verify public key matches (bytes 32..64)
    let stored_pubkey = &privkey_data[32..64];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    if verifying_key.as_bytes() != stored_pubkey {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "public key in private key file does not match seed"));
    }

    Ok(signing_key)
}

/// Generate the SSH wire format public key blob (matches ssh_ed25519_blob in ltv-core)
pub fn ssh_ed25519_public_key_blob(verifying_key: &VerifyingKey) -> Vec<u8> {
    let pk = verifying_key.as_bytes();
    let mut b = Vec::new();
    for part in [DROPBEAR_KEY_TYPE.as_bytes(), pk] {
        b.extend_from_slice(&(part.len() as u32).to_be_bytes());
        b.extend_from_slice(part);
    }
    b
}

/// Compute SHA256 fingerprint of SSH public key blob (matches fingerprint_sha256 in ltv-core)
pub fn fingerprint_sha256(blob: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    use base64::Engine;
    let hash = Sha256::digest(blob);
    format!("SHA256:{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_write_read_dropbear_key_roundtrip() {
        // Generate a keypair
        let signing_key = generate_ed25519_keypair();

        // Write to buffer
        let mut buf = Vec::new();
        write_dropbear_ed25519_private_key(&mut buf, &signing_key).unwrap();

        // Read back
        let mut cursor = Cursor::new(&buf);
        let read_key = read_dropbear_ed25519_private_key(&mut cursor).unwrap();

        // Verify keys match
        assert_eq!(signing_key.to_bytes(), read_key.to_bytes());
        assert_eq!(signing_key.verifying_key().as_bytes(), read_key.verifying_key().as_bytes());
    }

    #[test]
    fn test_deterministic_key_generation() {
        // Use a fixed seed for deterministic testing
        let seed = [42u8; 32];
        let signing_key = generate_ed25519_keypair_from_seed(&seed);

        // Write to buffer
        let mut buf = Vec::new();
        write_dropbear_ed25519_private_key(&mut buf, &signing_key).unwrap();

        // Read back
        let mut cursor = Cursor::new(&buf);
        let read_key = read_dropbear_ed25519_private_key(&mut cursor).unwrap();

        // Verify keys match
        assert_eq!(signing_key.to_bytes(), read_key.to_bytes());
        assert_eq!(signing_key.verifying_key().as_bytes(), read_key.verifying_key().as_bytes());
    }

    #[test]
    fn test_public_key_blob_format() {
        let seed = [42u8; 32];
        let signing_key = generate_ed25519_keypair_from_seed(&seed);
        let verifying_key = signing_key.verifying_key();

        let blob = ssh_ed25519_public_key_blob(&verifying_key);

        // Should be 51 bytes: 4 + 11 + 4 + 32
        assert_eq!(blob.len(), 51);

        // Verify structure
        assert_eq!(&blob[0..4], &11u32.to_be_bytes()); // length of "ssh-ed25519"
        assert_eq!(&blob[4..15], b"ssh-ed25519");
        assert_eq!(&blob[15..19], &32u32.to_be_bytes()); // length of public key
        assert_eq!(&blob[19..51], verifying_key.as_bytes());
    }

    #[test]
    fn test_fingerprint_format() {
        let seed = [42u8; 32];
        let signing_key = generate_ed25519_keypair_from_seed(&seed);
        let verifying_key = signing_key.verifying_key();

        let blob = ssh_ed25519_public_key_blob(&verifying_key);
        let fp = fingerprint_sha256(&blob);

        // Should start with "SHA256:"
        assert!(fp.starts_with("SHA256:"));
        // Base64 without padding
        assert!(!fp.contains("="));
    }

    #[test]
    fn test_dropbear_key_format_structure() {
        let seed = [42u8; 32];
        let signing_key = generate_ed25519_keypair_from_seed(&seed);

        let mut buf = Vec::new();
        write_dropbear_ed25519_private_key(&mut buf, &signing_key).unwrap();

        // Total size: 4 + 11 + 4 + 64 = 83 bytes (no null terminator)
        assert_eq!(buf.len(), 83);

        // Verify structure
        assert_eq!(&buf[0..4], &11u32.to_be_bytes());
        assert_eq!(&buf[4..15], b"ssh-ed25519");
        assert_eq!(&buf[15..19], &64u32.to_be_bytes()); // private key data length
        
        // Private key data
        assert_eq!(&buf[19..51], &signing_key.to_bytes()); // seed
        assert_eq!(&buf[51..83], signing_key.verifying_key().as_bytes()); // public key
    }

    #[test]
    #[ignore] // Requires dropbearkey binary in PATH
    fn test_dropbearkey_compatibility() {
        use std::fs::File;
        use std::io::Write;
        use std::process::Command;
        use base64::Engine;

        // Use a fixed seed for reproducible testing
        let seed = [42u8; 32];
        let signing_key = generate_ed25519_keypair_from_seed(&seed);
        let verifying_key = signing_key.verifying_key();

        // Write to temp file
        let key_path = "/tmp/test_dropbear_compat_key";
        let mut file = File::create(key_path).unwrap();
        write_dropbear_ed25519_private_key(&mut file, &signing_key).unwrap();
        file.flush().unwrap();

        // Compute expected public key and fingerprint
        let expected_blob = ssh_ed25519_public_key_blob(&verifying_key);
        let expected_fp = fingerprint_sha256(&expected_blob);

        // Run dropbearkey -y to extract public key
        let output = Command::new("dropbearkey")
            .args(["-y", "-f", key_path])
            .output()
            .expect("dropbearkey not found in PATH");

        assert!(output.status.success(), "dropbearkey failed: {}", String::from_utf8_lossy(&output.stderr));

        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("dropbearkey output: {}", stdout);

        // Parse the public key line
        let pub_key_line = stdout.lines()
            .find(|l| l.starts_with("ssh-ed25519 "))
            .expect("no public key in dropbearkey output");

        let pub_key_parts: Vec<&str> = pub_key_line.split_whitespace().collect();
        let pub_b64 = pub_key_parts.get(1).expect("invalid public key format");
        let actual_pubkey = base64::engine::general_purpose::STANDARD.decode(pub_b64)
            .expect("invalid base64 in public key");

        // Verify the public key matches (should be the full 51-byte SSH wire format)
        assert_eq!(actual_pubkey, expected_blob, "public key mismatch");

        // Parse the fingerprint line
        let fp_line = stdout.lines()
            .find(|l| l.starts_with("Fingerprint: "))
            .expect("no fingerprint in dropbearkey output");
        
        let actual_fp = fp_line.strip_prefix("Fingerprint: ").unwrap().trim();
        assert_eq!(actual_fp, expected_fp, "fingerprint mismatch");

        // Clean up
        std::fs::remove_file(key_path).ok();
    }
}