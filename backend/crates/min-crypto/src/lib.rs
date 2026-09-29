//! MIN Crypto — настоящая криптография для этапа 9 (§44 ТЗ).
//!
//! Схема заморожена в PROTOCOL.md:
//!   - key agreement: X25519 (x25519-dalek)
//!   - AEAD:          XChaCha20-Poly1305, nonce 24 байта (chacha20poly1305)
//!   - KDF:           HKDF-SHA256 с domain separation
//!
//! libsignal (PQXDH + Double Ratchet) остаётся целью для post-MVP:
//! здесь реализован минимальный безопасный обмен, достаточный для
//! «сервера-глухого-почтальона» (relay видит только nonce+ciphertext).

use chacha20poly1305::aead::{Aead as AeadOps, NewAead, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305 as Aead, XNonce};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};

/// 24 байта — nonce XChaCha20-Poly1305 (PROTOCOL.md §5).
const NONCE_LEN: usize = 24;
/// 16 байт — тег Poly1305.
const TAG_LEN: usize = 16;

/// AUDIT FIX-1 (красная команда): домен-строка Associated Data примитивного
/// слоя (FFI min_encrypt/min_decrypt, min-e2e). Пустой AAD позволял
/// контекстную подмену: шифротекст примитивного слоя принимался бы без
/// привязки к контексту использования. Ciphertext, зашифрованный с этим
/// доменом, не расшифровывается с пустым AAD и наоборот (AEAD-тег не сходится).
pub const PRIMITIVE_AAD: &[u8] = b"min-primitive/v1";

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    KeyGenerationFailed,
    SessionInitFailed,
    EncryptionFailed,
    DecryptionFailed,
    InvalidCiphertext,
    SessionNotFound,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyGenerationFailed => write!(f, "key generation failed"),
            Self::SessionInitFailed => write!(f, "session initialization failed"),
            Self::EncryptionFailed => write!(f, "encryption failed"),
            Self::DecryptionFailed => write!(f, "decryption failed"),
            Self::InvalidCiphertext => write!(f, "invalid ciphertext"),
            Self::SessionNotFound => write!(f, "session not found"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Result type for crypto operations.
pub type Result<T> = std::result::Result<T, CryptoError>;

/// A 256-bit secret key derived from a KDF.
///
/// AUDIT MIN-03: при drop память под ключом затирается (zeroize), чтобы копии
/// секрета не оставались в свободной куче для форензики/дампов.
#[derive(Debug, Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SecretKey(pub [u8; 32]);

/// A 256-bit public key for key agreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(pub [u8; 32]);

/// A shared secret derived from key agreement.
/// AUDIT MIN-03: zeroize при drop (см. SecretKey).
#[derive(Debug, Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SharedSecret(pub [u8; 32]);

/// Общий секрет по X25519 + HKDF-SHA256 (domain-separated, PROTOCOL.md §0/§5).
pub fn derive_shared_secret(private: &SecretKey, public_key: &PublicKey) -> Result<SharedSecret> {
    let secret = XSecret::from(private.0);
    let peer = XPublic::from(public_key.0);
    let raw = secret.diffie_hellman(&peer).to_bytes();

    let hk = Hkdf::<Sha256>::new(Some(b"MIN-KDF-v1"), &raw);
    let mut okm = [0u8; 32];
    hk.expand(b"min-e2e-v1", &mut okm)
        .map_err(|_| CryptoError::KeyGenerationFailed)?;
    Ok(SharedSecret(okm))
}

/// Шифрует plaintext в XChaCha20-Poly1305 с Associated Data.
///
/// AAD аутентифицируется вместе с plaintext (PROTOCOL.md §3: associated
/// data = канонический header envelope). Пустой AAD допустим только для
/// примитивного слоя; на уровне EnvelopeV1 всегда должен подаваться
/// канонический заголовок.
///
/// Возвращает `nonce(24) || ciphertext(||tag)`.
pub fn encrypt(shared_secret: &SharedSecret, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let key = Key::from_slice(&shared_secret.0);
    let aead = Aead::new(&key);

    let mut nonce_raw = [0u8; NONCE_LEN];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut nonce_raw);
    let nonce = XNonce::from_slice(&nonce_raw);

    let sealed = AeadOps::encrypt(
        &aead,
        &nonce,
        Payload {
            msg: plaintext,
            aad,
        },
    )
    .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut out = Vec::with_capacity(NONCE_LEN + sealed.len());
    out.extend_from_slice(&nonce_raw);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Расшифровывает `nonce(24) || ciphertext` с теми же Associated Data.
pub fn decrypt(shared_secret: &SharedSecret, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::InvalidCiphertext);
    }

    let key = Key::from_slice(&shared_secret.0);
    let aead = Aead::new(&key);

    let nonce = XNonce::from_slice(&ciphertext[..NONCE_LEN]);
    let payload = &ciphertext[NONCE_LEN..];

    AeadOps::decrypt(&aead, &nonce, Payload { msg: payload, aad })
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Производит доменно-отделённый подключ из 32-байтного IKM (HKDF-SHA256).
///
/// `info` обязан быть уникальной строкой для каждого применения: подключ для
/// подписи снапшота сессий и подключ для recovery-блоба — РАЗНЫЕ ключи, хотя
/// от одного IKM. Иначе компрометация одного использования раскрывает другое
/// (ключевое разделение, PROTOCOL.md §0 «domain-separated»).
pub fn derive_subkey(ikm: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"MIN-KDF-v1"), ikm);
    let mut out = [0u8; 32];
    // info передаётся нами и всегда короче 255 байт (HKDF-SHA256 max 255*32).
    hk.expand(info, &mut out)
        .expect("HKDF-SHA256 expand with 32-byte output always fits");
    out
}

/// Генерирует новую X25519-пару.
pub fn generate_keypair() -> Result<(SecretKey, PublicKey)> {
    let secret = XSecret::random_from_rng(&mut OsRng);
    let private = secret.to_bytes();
    let public = XPublic::from(&secret).to_bytes();
    Ok((SecretKey(private), PublicKey(public)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (sk, pk) = generate_keypair().unwrap();
        assert_eq!(sk.0.len(), 32);
        assert_eq!(pk.0.len(), 32);
    }

    #[test]
    fn test_shared_secret_symmetric() {
        // Алиса и Боб получают ОДИН общий секрет (X25519 DH симметричен).
        let (alice_sk, alice_pk) = generate_keypair().unwrap();
        let (bob_sk, bob_pk) = generate_keypair().unwrap();

        let s_alice = derive_shared_secret(&alice_sk, &bob_pk).unwrap();
        let s_bob = derive_shared_secret(&bob_sk, &alice_pk).unwrap();
        assert_eq!(s_alice.0.to_vec(), s_bob.0.to_vec());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (alice_sk, alice_pk) = generate_keypair().unwrap();
        let (bob_sk, bob_pk) = generate_keypair().unwrap();

        let s_alice = derive_shared_secret(&alice_sk, &bob_pk).unwrap();
        let s_bob = derive_shared_secret(&bob_sk, &alice_pk).unwrap();

        let plaintext = b"Hello from MIN, encrypted end-to-end!";
        let sealed = encrypt(&s_alice, plaintext, b"header-aad").unwrap();
        // nonce(24) + ciphertext + tag(16)
        assert_eq!(sealed.len(), 24 + plaintext.len() + 16);

        let opened = decrypt(&s_bob, &sealed, b"header-aad").unwrap();
        assert_eq!(plaintext.to_vec(), opened);
    }

    #[test]
    fn test_aad_is_bound() {
        let (alice_sk, alice_pk) = generate_keypair().unwrap();
        let (bob_sk, bob_pk) = generate_keypair().unwrap();

        let s_alice = derive_shared_secret(&alice_sk, &bob_pk).unwrap();
        let s_bob = derive_shared_secret(&bob_sk, &alice_pk).unwrap();

        // Правильный AAD сходится.
        let sealed = encrypt(&s_alice, b"bound", b"canonical-header").unwrap();
        assert_eq!(
            decrypt(&s_bob, &sealed, b"canonical-header").unwrap(),
            b"bound".to_vec()
        );
        // Подмена AAD на стороне получателя обязана провалиться (PROTOCOL.md §3).
        assert!(matches!(
            decrypt(&s_bob, &sealed, b"tampered-header"),
            Err(CryptoError::DecryptionFailed)
        ));
        // И подмена AAD у отправителя даёт шифротекст, который легитимный AAD не откроет.
        let sealed2 = encrypt(&s_alice, b"bound", b"other-header").unwrap();
        assert!(matches!(
            decrypt(&s_bob, &sealed2, b"canonical-header"),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn test_tamper_detection() {
        let (alice_sk, alice_pk) = generate_keypair().unwrap();
        let (bob_sk, bob_pk) = generate_keypair().unwrap();

        let s_alice = derive_shared_secret(&alice_sk, &bob_pk).unwrap();
        let s_bob = derive_shared_secret(&bob_sk, &alice_pk).unwrap();

        let mut sealed = encrypt(&s_alice, b"important", b"").unwrap();
        // Портим один байт шифротекста — расшифровка должна провалиться.
        sealed[30] ^= 0x01;
        assert!(matches!(
            decrypt(&s_bob, &sealed, b""),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    /// Замороженный KAT всего криптопути X25519 → HKDF-SHA256.
    /// Сгенерирован и сверен с нативным X25519 (Python `cryptography`, openssl):
    ///   salt = b"MIN-KDF-v1", info = b"min-e2e-v1", L = 32, KDF = HKDF-SHA256.
    /// Смена домен-параметров или хэша/алгоритма сломает этот тест.
    #[test]
    fn test_kdf_kat_frozen() {
        let alice_priv =
            hex::decode("de28ad9b4643c23ec748579c29ef93b88fdc27787473c987116d166a5a79cd94")
                .unwrap()
                .try_into()
                .unwrap();
        let bob_pub =
            hex::decode("4ed91aaafb76fd025ae6914d863f16cb72f4c3aadbb544cd4e8ffecf2ebcec78")
                .unwrap()
                .try_into()
                .unwrap();
        let shared = derive_shared_secret(&SecretKey(alice_priv), &PublicKey(bob_pub)).unwrap();
        assert_eq!(
            hex::encode(&shared.0),
            "bd675d88246969aacccd1b377a8dffa9fbfe6db469e83a53c016f3c71f28c649"
        );
    }

    #[test]
    fn test_invalid_ciphertext_too_short() {
        let (sk, _) = generate_keypair().unwrap();
        let (_, pk) = generate_keypair().unwrap();
        let secret = derive_shared_secret(&sk, &pk).unwrap();

        let result = decrypt(&secret, &[1, 2, 3], b"");
        assert!(matches!(result, Err(CryptoError::InvalidCiphertext)));
    }
}
