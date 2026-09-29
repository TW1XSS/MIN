//! Офлайн бэкап и восстановление (Argon2id + XChaCha20-Poly1305).
//!
//! Бэкап — это зашифрованный блоб: пароль пользователя → Argon2id → 32-байтный ключ →
//! XChaCha20-Poly1305(plaintext). Сервер не участвует, не валидирует, не хранит.
//!
//! Формат бэкапа (binary, little-endian):
//! ```text
//! [1 byte]  version = 1
//! [16 bytes] salt (Argon2id)
//! [24 bytes] nonce (XChaCha20)
//! [rest]     ciphertext (AEAD tag включён)
//! ```

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead as AeadOps, NewAead, Payload},
    Key, XChaCha20Poly1305 as Aead, XNonce,
};
use rand_core::RngCore;

/// AUDIT MIN-04: AAD домен бэкапа — шифротекст привязан к назначению
/// (offline backup v1), подмена между структурами блокируется AEAD.
const BACKUP_AAD: &[u8] = b"min-recovery/v1";

pub const BACKUP_VERSION: u8 = 1;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;

/// Argon2id параметры: m=64 MiB, t=3, p=1 (OWASP рекомендация для interactive).
const ARGON2_M_COST: u32 = 64 * 1024;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("invalid backup: {0}")]
    Invalid(String),
    #[error("wrong password")]
    WrongPassword,
}

/// Генерирует случайную соль для бэкапа.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand_core::OsRng.fill_bytes(&mut salt);
    salt
}

/// Деривация ключа из пароля через Argon2id.
fn derive_key(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; KEY_LEN], RecoveryError> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_LEN))
        .map_err(|e| RecoveryError::Crypto(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| RecoveryError::Crypto(e.to_string()))?;
    Ok(key)
}

/// Шифрует plaintext с паролем, возвращает готовый бэкап-блоб.
pub fn create_backup(plaintext: &[u8], password: &[u8]) -> Result<Vec<u8>, RecoveryError> {
    let salt = generate_salt();
    let key = derive_key(password, &salt)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);

    let key = Key::from_slice(&key);
    let cipher = Aead::new(key);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = AeadOps::encrypt(
        &cipher,
        nonce,
        Payload {
            msg: plaintext,
            aad: BACKUP_AAD,
        },
    )
    .map_err(|e| RecoveryError::Crypto(e.to_string()))?;

    let mut backup = Vec::with_capacity(1 + SALT_LEN + NONCE_LEN + ciphertext.len());
    backup.push(BACKUP_VERSION);
    backup.extend_from_slice(&salt);
    backup.extend_from_slice(&nonce_bytes);
    backup.extend_from_slice(&ciphertext);

    Ok(backup)
}

/// Расшифровывает бэкап-блоб. Возвращает plaintext или WrongPassword.
pub fn restore_backup(backup: &[u8], password: &[u8]) -> Result<Vec<u8>, RecoveryError> {
    let min_len = 1 + SALT_LEN + NONCE_LEN + 16;
    if backup.len() < min_len {
        return Err(RecoveryError::Invalid("backup too short".into()));
    }

    let version = backup[0];
    if version != BACKUP_VERSION {
        return Err(RecoveryError::Invalid(format!(
            "unsupported backup version: {version}"
        )));
    }

    let salt: [u8; SALT_LEN] = backup[1..1 + SALT_LEN]
        .try_into()
        .map_err(|_| RecoveryError::Invalid("salt decode".into()))?;
    let nonce_bytes: [u8; NONCE_LEN] = backup[1 + SALT_LEN..1 + SALT_LEN + NONCE_LEN]
        .try_into()
        .map_err(|_| RecoveryError::Invalid("nonce decode".into()))?;
    let ciphertext = &backup[1 + SALT_LEN + NONCE_LEN..];

    let key = derive_key(password, &salt)?;
    let key = Key::from_slice(&key);
    let cipher = Aead::new(key);
    let nonce = XNonce::from_slice(&nonce_bytes);

    AeadOps::decrypt(
        &cipher,
        nonce,
        Payload {
            msg: ciphertext,
            aad: BACKUP_AAD,
        },
    )
    .map_err(|_| RecoveryError::WrongPassword)
}

/// Информация о бэкапе (без plaintext).
pub fn backup_info(backup: &[u8]) -> Result<(u8, usize), RecoveryError> {
    if backup.len() < 1 + SALT_LEN + NONCE_LEN {
        return Err(RecoveryError::Invalid("backup too short".into()));
    }
    let version = backup[0];
    let total_size = backup.len();
    Ok((version, total_size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_restore() {
        let secret = b"my secret identity data";
        let password = b"correct horse battery staple";
        let backup = create_backup(secret, password).unwrap();
        let restored = restore_backup(&backup, password).unwrap();
        assert_eq!(restored, secret.to_vec());
    }

    #[test]
    fn test_wrong_password_fails() {
        let backup = create_backup(b"sensitive data", b"right password").unwrap();
        match restore_backup(&backup, b"wrong password") {
            Err(RecoveryError::WrongPassword) => {}
            other => panic!("expected WrongPassword, got {other:?}"),
        }
    }

    #[test]
    fn test_backup_has_salt_and_nonce() {
        let backup = create_backup(b"data", b"pass").unwrap();
        assert!(backup.len() > 1 + SALT_LEN + NONCE_LEN);
        assert_eq!(backup[0], BACKUP_VERSION);
    }

    #[test]
    fn test_empty_plaintext() {
        let backup = create_backup(b"", b"pass").unwrap();
        let restored = restore_backup(&backup, b"pass").unwrap();
        assert_eq!(restored, b"");
    }

    #[test]
    fn test_large_plaintext() {
        let big = vec![0xCDu8; 1024 * 1024];
        let backup = create_backup(&big, b"pass").unwrap();
        let restored = restore_backup(&backup, b"pass").unwrap();
        assert_eq!(restored, big);
    }

    #[test]
    fn test_corrupted_backup_fails() {
        let mut backup = create_backup(b"data", b"pass").unwrap();
        if backup.len() > 40 {
            backup[40] ^= 0xFF;
        }
        match restore_backup(&backup, b"pass") {
            Err(RecoveryError::WrongPassword) => {}
            other => panic!("expected WrongPassword, got {other:?}"),
        }
    }

    #[test]
    fn test_too_short_backup() {
        match restore_backup(&[1u8; 10], b"pass") {
            Err(RecoveryError::Invalid(_)) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn test_wrong_version() {
        let mut backup = create_backup(b"data", b"pass").unwrap();
        backup[0] = 99;
        match restore_backup(&backup, b"pass") {
            Err(RecoveryError::Invalid(_)) => {}
            other => panic!("expected Invalid version, got {other:?}"),
        }
    }

    #[test]
    fn test_backup_info() {
        let backup = create_backup(b"test", b"pass").unwrap();
        let (version, size) = backup_info(&backup).unwrap();
        assert_eq!(version, BACKUP_VERSION);
        assert_eq!(size, backup.len());
    }

    #[test]
    fn test_unique_salt_per_backup() {
        let backup1 = create_backup(b"data", b"pass").unwrap();
        let backup2 = create_backup(b"data", b"pass").unwrap();
        assert_ne!(backup1[1..17], backup2[1..17]);
    }
}
