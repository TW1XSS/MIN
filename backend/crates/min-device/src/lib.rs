//! Device revoke: отзыв устройства с инкрементом epoch на relay.
//!
//! Отозванное устройство не может молча вернуться (README security invariant №6).
//! Механизм: владелец генерирует RevokeCertificate (подпись identity-ключом),
//! relay при получении валидирует подпись и инкрементирует epoch mailbox'а.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub const REVOKE_VERSION: u8 = 1;
pub const DEVICE_ID_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("invalid certificate: {0}")]
    Invalid(String),
    #[error("signature verification failed")]
    BadSignature,
}

#[derive(Debug, Clone)]
pub struct RevokeCertificate {
    pub version: u8,
    pub device_id: [u8; DEVICE_ID_LEN],
    pub revoked_at: u64,
    pub signature: Signature,
}

pub fn device_id_from_key(public_key: &VerifyingKey) -> [u8; DEVICE_ID_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(public_key.as_bytes());
    let result = hasher.finalize();
    let mut id = [0u8; DEVICE_ID_LEN];
    id.copy_from_slice(&result[..DEVICE_ID_LEN]);
    id
}

pub fn create_revoke_certificate(
    identity_key: &SigningKey,
    device_id: &[u8; DEVICE_ID_LEN],
    revoked_at: u64,
) -> RevokeCertificate {
    let mut msg = Vec::with_capacity(DEVICE_ID_LEN + 8);
    msg.extend_from_slice(device_id);
    msg.extend_from_slice(&revoked_at.to_be_bytes());
    let signature = identity_key.sign(&msg);

    RevokeCertificate {
        version: REVOKE_VERSION,
        device_id: *device_id,
        revoked_at,
        signature,
    }
}

pub fn verify_revoke_certificate(
    cert: &RevokeCertificate,
    owner_public_key: &VerifyingKey,
) -> Result<(), DeviceError> {
    if cert.version != REVOKE_VERSION {
        return Err(DeviceError::Invalid(format!(
            "unsupported revoke version: {}",
            cert.version
        )));
    }

    let mut msg = Vec::with_capacity(DEVICE_ID_LEN + 8);
    msg.extend_from_slice(&cert.device_id);
    msg.extend_from_slice(&cert.revoked_at.to_be_bytes());

    owner_public_key
        .verify(&msg, &cert.signature)
        .map_err(|_| DeviceError::BadSignature)
}

pub fn serialize_revoke_certificate(cert: &RevokeCertificate) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + DEVICE_ID_LEN + 8 + 64);
    out.push(cert.version);
    out.extend_from_slice(&cert.device_id);
    out.extend_from_slice(&cert.revoked_at.to_be_bytes());
    out.extend_from_slice(&cert.signature.to_bytes());
    out
}

pub fn deserialize_revoke_certificate(bytes: &[u8]) -> Result<RevokeCertificate, DeviceError> {
    let min_len = 1 + DEVICE_ID_LEN + 8 + 64;
    if bytes.len() < min_len {
        return Err(DeviceError::Invalid("certificate too short".into()));
    }

    let version = bytes[0];
    let mut device_id = [0u8; DEVICE_ID_LEN];
    device_id.copy_from_slice(&bytes[1..1 + DEVICE_ID_LEN]);

    let mut revoked_at_bytes = [0u8; 8];
    revoked_at_bytes.copy_from_slice(&bytes[1 + DEVICE_ID_LEN..1 + DEVICE_ID_LEN + 8]);
    let revoked_at = u64::from_be_bytes(revoked_at_bytes);

    let sig_bytes: [u8; 64] = bytes[1 + DEVICE_ID_LEN + 8..min_len]
        .try_into()
        .map_err(|_| DeviceError::Invalid("signature decode".into()))?;
    let signature = Signature::from_bytes(&sig_bytes);

    Ok(RevokeCertificate {
        version,
        device_id,
        revoked_at,
        signature,
    })
}

pub fn is_device_revoked(
    revoked_list: &[[u8; DEVICE_ID_LEN]],
    device_id: &[u8; DEVICE_ID_LEN],
) -> bool {
    revoked_list.iter().any(|id| id == device_id)
}

pub fn generate_test_keypair() -> (SigningKey, VerifyingKey) {
    let signing = SigningKey::generate(&mut rand_core::OsRng);
    let verifying = VerifyingKey::from(&signing);
    (signing, verifying)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_id_from_key() {
        let (_signing, verifying) = generate_test_keypair();
        let id1 = device_id_from_key(&verifying);
        let id2 = device_id_from_key(&verifying);
        assert_eq!(id1, id2);
        assert_ne!(id1, [0u8; DEVICE_ID_LEN]);
    }

    #[test]
    fn test_create_and_verify_revoke_cert() {
        let (owner_signing, owner_verifying) = generate_test_keypair();
        let (_device_signing, device_verifying) = generate_test_keypair();
        let device_id = device_id_from_key(&device_verifying);

        let cert = create_revoke_certificate(&owner_signing, &device_id, 1234567890);
        verify_revoke_certificate(&cert, &owner_verifying).unwrap();
    }

    #[test]
    fn test_revoke_cert_wrong_key_fails() {
        let (owner_signing, _owner_verifying) = generate_test_keypair();
        let (_attacker_signing, attacker_verifying) = generate_test_keypair();
        let (_device_signing, device_verifying) = generate_test_keypair();
        let device_id = device_id_from_key(&device_verifying);

        let cert = create_revoke_certificate(&owner_signing, &device_id, 1234567890);

        match verify_revoke_certificate(&cert, &attacker_verifying) {
            Err(DeviceError::BadSignature) => {}
            other => panic!("expected BadSignature, got {other:?}"),
        }
    }

    #[test]
    fn test_serialize_roundtrip() {
        let (owner_signing, owner_verifying) = generate_test_keypair();
        let (_device_signing, device_verifying) = generate_test_keypair();
        let device_id = device_id_from_key(&device_verifying);

        let cert = create_revoke_certificate(&owner_signing, &device_id, 9999999999);
        let bytes = serialize_revoke_certificate(&cert);
        let restored = deserialize_revoke_certificate(&bytes).unwrap();

        assert_eq!(restored.version, cert.version);
        assert_eq!(restored.device_id, cert.device_id);
        assert_eq!(restored.revoked_at, cert.revoked_at);
        verify_revoke_certificate(&restored, &owner_verifying).unwrap();
    }

    #[test]
    fn test_is_device_revoked() {
        let (_signing1, verifying1) = generate_test_keypair();
        let (_signing2, verifying2) = generate_test_keypair();
        let id1 = device_id_from_key(&verifying1);
        let id2 = device_id_from_key(&verifying2);

        let revoked = vec![id1];
        assert!(is_device_revoked(&revoked, &id1));
        assert!(!is_device_revoked(&revoked, &id2));
    }

    #[test]
    fn test_too_short_certificate() {
        match deserialize_revoke_certificate(&[1u8; 10]) {
            Err(DeviceError::Invalid(_)) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn test_wrong_version() {
        let (owner_signing, owner_verifying) = generate_test_keypair();
        let (_device_signing, device_verifying) = generate_test_keypair();
        let device_id = device_id_from_key(&device_verifying);

        let mut cert = create_revoke_certificate(&owner_signing, &device_id, 1);
        cert.version = 99;

        match verify_revoke_certificate(&cert, &owner_verifying) {
            Err(DeviceError::Invalid(_)) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn test_signature_over_device_and_timestamp() {
        let (owner_signing, _owner_verifying) = generate_test_keypair();
        let (_device_signing, device_verifying) = generate_test_keypair();
        let device_id = device_id_from_key(&device_verifying);

        let cert1 = create_revoke_certificate(&owner_signing, &device_id, 1000);
        let cert2 = create_revoke_certificate(&owner_signing, &device_id, 2000);

        assert_ne!(cert1.signature.to_bytes(), cert2.signature.to_bytes());
    }
}
