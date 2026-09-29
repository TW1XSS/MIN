//! Локальная криптографическая идентичность MIN (ТЗ §5, §6).
//!
//! Все приватные материалы генерируются на устройстве (OsRng) и никогда
//! не покидают его; на relay публикуются только публичные ключи.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};

/// Долгоживущая идентичность аккаунта: Ed25519.
pub struct IdentityKeypair {
    signing: SigningKey,
}

impl IdentityKeypair {
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    /// Из сырых 32 байт секрета (для будущего восстановления из backup).
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(bytes),
        }
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn public(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    pub fn verify(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(public) else {
            return false;
        };
        let s = ed25519_dalek::Signature::from_bytes(sig);
        vk.verify(msg, &s).is_ok()
    }
}

/// Подписанный prekey устройства: X25519 (MVP, без PQ-части — абстракция под PQXDH).
pub struct SignedPrekey {
    secret: XSecret,
}

impl SignedPrekey {
    pub fn generate() -> Self {
        Self {
            secret: XSecret::random_from_rng(&mut OsRng),
        }
    }

    pub fn public(&self) -> [u8; 32] {
        *XPublic::from(&self.secret).as_bytes()
    }
}

/// Начальная эпоха адреса (MIN-26): epoch < 1 не существует. Единственный
/// источник правды по правилу (реэкспорт в min-protocol).
pub const EPOCH_INITIAL: u64 = 1;

/// Opaque mailbox id эпохи: HKDF-SHA256(ikm = identity_pk ++ LE64(epoch),
/// salt = "MIN-MAILBOX-SALT-v1", info = "mailbox-id-v1", L = 16) — PROTOCOL.md §5.
///
/// AUDIT MIN-26 / O-5: раньше адрес выводился только из identity, т.е. был
/// стабилен навсегда: relay мог связывать всю активность аккаунта одним
/// идентификатором. Теперь epoch участвует в деривации: ротация (epoch + 1)
/// даёт независимый mailbox, нелинейно несвязуемый с прежним, при той же
/// долгоживущей identity. Инвариант MIN-25 сохранён: адрес — чистая функция
/// от (identity, epoch), поэтому подписанный чужой mailbox по-прежнему
/// невыразим.
/// Relay видит только эти 16 байт — не username, не телефон (ТЗ §12.2).
pub fn mailbox_id(identity_public: &[u8; 32], epoch: u64) -> [u8; 16] {
    let mut ikm = [0u8; 40];
    ikm[..32].copy_from_slice(identity_public);
    ikm[32..].copy_from_slice(&epoch.to_le_bytes());
    let hk = Hkdf::<Sha256>::new(Some(b"MIN-MAILBOX-SALT-v1"), &ikm);
    let mut out = [0u8; 16];
    hk.expand(b"mailbox-id-v1", &mut out)
        .expect("16 <= 255*32 bytes");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let id = IdentityKeypair::generate();
        let msg = b"MIN test payload";
        let sig = id.sign(msg);
        assert!(IdentityKeypair::verify(&id.public(), msg, &sig));
        // подмена сообщения → подпись невалидна
        assert!(!IdentityKeypair::verify(&id.public(), b"tampered", &sig));
    }

    #[test]
    fn distinct_identities_have_distinct_mailboxes() {
        let a = IdentityKeypair::generate();
        let b = IdentityKeypair::generate();
        let mb_a = mailbox_id(&a.public(), EPOCH_INITIAL);
        let mb_b = mailbox_id(&b.public(), EPOCH_INITIAL);
        assert_ne!(mb_a, mb_b);
        // детерминизм: та же identity → тот же mailbox
        assert_eq!(mb_a, mailbox_id(&a.public(), EPOCH_INITIAL));
    }

    #[test]
    fn prekey_public_is_deterministic_from_secret() {
        let pk = SignedPrekey::generate();
        assert_eq!(pk.public().len(), 32);
    }

    /// RT-26.9 / MIN-26: ротация эпохи даёт независимый адрес (unlinkability)
    /// при сохранении инварианта адрес = f(identity, epoch).
    #[test]
    fn epoch_rotation_yields_unlinkable_deterministic_mailbox() {
        let a = IdentityKeypair::generate();
        let b = IdentityKeypair::generate();
        let e1 = mailbox_id(&a.public(), EPOCH_INITIAL);
        let e2 = mailbox_id(&a.public(), EPOCH_INITIAL + 1);
        let e3 = mailbox_id(&a.public(), EPOCH_INITIAL + 2);
        assert_ne!(e1, e2);
        assert_ne!(e2, e3);
        assert_ne!(e1, e3);
        assert_ne!(e1, mailbox_id(&b.public(), EPOCH_INITIAL));
        assert_eq!(e2, mailbox_id(&a.public(), EPOCH_INITIAL + 1));
        assert_ne!(
            mailbox_id(&a.public(), u64::MAX),
            mailbox_id(&a.public(), u64::MAX - 1)
        );
    }
}
