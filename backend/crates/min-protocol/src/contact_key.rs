//! MIN Contact Key v3 (ТЗ §5.2): подписанный криптографический адрес.
//!
//! Строковая форма: `MIN3:<base58btc(canonical CBOR)>`.
//! AUDIT MIN-17: версия протокола 1 → 2 (Envelope: ключевой MAC).
//! AUDIT MIN-26 / O-5: версия 2 → 3 — добавлено обязательно поле `epoch`
//! (ротация адреса, unlinkability для relay):
//! mailbox_id = HKDF(identity ++ LE64(epoch)), см. PROTOCOL.md §5.
//! Голый public key — не маршрут доставки.

use crate::{
    canonical_map, expect_bstr, expect_u64, map_get, ProtocolError, ProtocolResult,
    CONTACT_KEY_VERSION, EPOCH_INITIAL,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use min_wire::canonical_decode_strict;

/// CBOR-ключи полей Contact Key v3 (PROTOCOL.md §2).
mod field {
    pub const VERSION: u64 = 1;
    pub const IDENTITY_PUB: u64 = 2;
    pub const MAILBOX_ID: u64 = 3;
    pub const SIGNED_PREKEY_PUB: u64 = 4;
    pub const EXPIRY: u64 = 5;
    /// MIN-26: эпоха адреса (ротация mailbox_id).
    pub const EPOCH: u64 = 6;
    /// Ed25519-подпись над каноническими полями 1..=6 (включая epoch).
    pub const SIGNATURE: u64 = 7;
}

pub const STRING_PREFIX: &str = "MIN3:";

/// Строгий набор полей: ключи ровно 1..=FIELD_COUNT (ТЗ §42).
const FIELD_COUNT: u64 = 7;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactKeyV3 {
    pub identity_public_key: [u8; 32],
    pub mailbox_id: [u8; 16],
    pub signed_prekey_public: [u8; 32],
    /// Unix-секунды; 0 = без срока действия.
    pub expiry: u64,
    /// MIN-26: эпоха адреса (>= EPOCH_INITIAL); ротация = epoch + 1.
    pub epoch: u64,
    /// Ed25519 подпись identity-ключа над каноническими полями 1..=6.
    pub signature: [u8; 64],
}

fn field_map(
    identity_public_key: &[u8; 32],
    mailbox_id: &[u8; 16],
    signed_prekey_public: &[u8; 32],
    expiry: u64,
    epoch: u64,
    with_signature: Option<&[u8; 64]>,
) -> ciborium::value::Value {
    let mut pairs = vec![
        (
            field::VERSION,
            ciborium::value::Value::Integer(CONTACT_KEY_VERSION.into()),
        ),
        (
            field::IDENTITY_PUB,
            ciborium::value::Value::Bytes(identity_public_key.to_vec()),
        ),
        (
            field::MAILBOX_ID,
            ciborium::value::Value::Bytes(mailbox_id.to_vec()),
        ),
        (
            field::SIGNED_PREKEY_PUB,
            ciborium::value::Value::Bytes(signed_prekey_public.to_vec()),
        ),
        (
            field::EXPIRY,
            ciborium::value::Value::Integer(expiry.into()),
        ),
        (field::EPOCH, ciborium::value::Value::Integer(epoch.into())),
    ];
    if let Some(sig) = with_signature {
        pairs.push((
            field::SIGNATURE,
            ciborium::value::Value::Bytes(sig.to_vec()),
        ));
    }
    canonical_map(&pairs)
}

impl ContactKeyV3 {
    /// Канонические CBOR-байты полей 1..5 — ровно то, что подписывается.
    pub fn canonical_payload(&self) -> Vec<u8> {
        min_wire::canonical_encode(&field_map(
            &self.identity_public_key,
            &self.mailbox_id,
            &self.signed_prekey_public,
            self.expiry,
            self.epoch,
            None,
        ))
        .expect("canonical encode of fixed map")
    }

    /// Строгая проверка: подпись и (если задан) срок действия.
    pub fn verify(&self) -> ProtocolResult<()> {
        if self.epoch < EPOCH_INITIAL {
            // MIN-26: epoch 0 не существует; отсекаем и здесь, чтобы
            // самодельный ключ не проходил только на уровне парсера.
            return Err(ProtocolError::Malformed);
        }
        if self.expiry != 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if now >= self.expiry {
                return Err(ProtocolError::Malformed);
            }
        }
        let vk = VerifyingKey::from_bytes(&self.identity_public_key)
            .map_err(|_| ProtocolError::Malformed)?;
        let sig = Signature::from_bytes(&self.signature);
        vk.verify(&self.canonical_payload(), &sig)
            .map_err(|_| ProtocolError::BadSignature)
    }

    /// Строковая форма `MIN3:<base58btc(canonical CBOR)>`.
    pub fn to_string_form(&self) -> String {
        let full = min_wire::canonical_encode(&field_map(
            &self.identity_public_key,
            &self.mailbox_id,
            &self.signed_prekey_public,
            self.expiry,
            self.epoch,
            Some(&self.signature),
        ))
        .expect("canonical encode of fixed map");
        format!("{STRING_PREFIX}{}", bs58::encode(full).into_string())
    }
}

impl ContactKeyV3 {
    /// Строгий парс строковой формы. Неизвестная версия → UnsupportedVersion.
    pub fn parse_string_form(s: &str) -> ProtocolResult<Self> {
        let b58 = s
            .strip_prefix(STRING_PREFIX)
            .ok_or(ProtocolError::BadContactKeyString)?;
        if b58.is_empty() {
            return Err(ProtocolError::BadContactKeyString);
        }
        let bytes = bs58::decode(b58)
            .into_vec()
            .map_err(|_| ProtocolError::BadContactKeyString)?;
        let root = canonical_decode_strict::<ciborium::value::Value>(&bytes)
            .map_err(|_| ProtocolError::Malformed)?;

        // Строгий набор полей: ровно 1..=FIELD_COUNT, никаких лишних ключей (ТЗ §42).
        let pairs = match &root {
            ciborium::value::Value::Map(p) => p,
            _ => return Err(ProtocolError::Malformed),
        };
        let keys: Vec<u64> = pairs
            .iter()
            .map(|(k, _)| expect_u64(k).ok_or(ProtocolError::Malformed))
            .collect::<Result<_, _>>()?;
        // Ключи обязаны идти строго по возрастанию — канонический CBOR (PROTOCOL §0).
        // Проверяем и набор, и порядок: keys == expected исключает дубликаты и
        // перестановки в одном сравнении.
        let expected: Vec<u64> = (1..=FIELD_COUNT).collect();
        if keys != expected {
            return Err(ProtocolError::Malformed);
        }

        let version = expect_u64(map_get(&root, field::VERSION).ok_or(ProtocolError::Malformed)?)
            .ok_or(ProtocolError::Malformed)?;
        if version != CONTACT_KEY_VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }

        let identity_public_key: [u8; 32] = expect_bstr(
            map_get(&root, field::IDENTITY_PUB).ok_or(ProtocolError::Malformed)?,
            32,
        )
        .ok_or(ProtocolError::Malformed)?
        .try_into()
        .unwrap();
        let mailbox_id: [u8; 16] = expect_bstr(
            map_get(&root, field::MAILBOX_ID).ok_or(ProtocolError::Malformed)?,
            16,
        )
        .ok_or(ProtocolError::Malformed)?
        .try_into()
        .unwrap();
        let signed_prekey_public: [u8; 32] = expect_bstr(
            map_get(&root, field::SIGNED_PREKEY_PUB).ok_or(ProtocolError::Malformed)?,
            32,
        )
        .ok_or(ProtocolError::Malformed)?
        .try_into()
        .unwrap();
        let expiry = expect_u64(map_get(&root, field::EXPIRY).ok_or(ProtocolError::Malformed)?)
            .ok_or(ProtocolError::Malformed)?;
        let epoch = expect_u64(map_get(&root, field::EPOCH).ok_or(ProtocolError::Malformed)?)
            .ok_or(ProtocolError::Malformed)?;
        if epoch < EPOCH_INITIAL {
            return Err(ProtocolError::Malformed);
        }
        let signature: [u8; 64] = expect_bstr(
            map_get(&root, field::SIGNATURE).ok_or(ProtocolError::Malformed)?,
            64,
        )
        .ok_or(ProtocolError::Malformed)?
        .try_into()
        .unwrap();

        Ok(ContactKeyV3 {
            identity_public_key,
            mailbox_id,
            signed_prekey_public,
            expiry,
            epoch,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Фикстура: подпись здесь невалидна; тесты, которым нужна настоящая
    /// подпись, строят ключ через min_identity (signed_key_binds_epoch_to_mailbox).
    fn sample() -> ContactKeyV3 {
        ContactKeyV3 {
            identity_public_key: [1u8; 32],
            mailbox_id: [2u8; 16],
            signed_prekey_public: [3u8; 32],
            expiry: 0,
            epoch: EPOCH_INITIAL,
            signature: [4u8; 64],
        }
    }

    #[test]
    fn string_roundtrip() {
        let ck = sample();
        let s = ck.to_string_form();
        assert!(s.starts_with("MIN3:"));
        let back = ContactKeyV3::parse_string_form(&s).unwrap();
        assert_eq!(back, ck);
    }

    #[test]
    fn unknown_version_rejected() {
        let ck = sample();
        let b58 = &ck.to_string_form()[STRING_PREFIX.len()..];
        let mut bytes = bs58::decode(b58).into_vec().unwrap();
        // Канонический CBOR map из 7 пар начинается с 0xa7, затем пара
        // «ключ поля version (0x01), значение версии». Подставляем заведомо
        // неподдерживаемую версию (PROTOCOL_VERSION + 1), чтобы тест не
        // протухал при каждом bump'е протокола (MIN-17: 1 → 2).
        assert_eq!(bytes[0], 0xa7);
        assert_eq!(bytes[1], 0x01); // ключ поля version
        bytes[2] = (CONTACT_KEY_VERSION + 1) as u8;
        let forged = format!("{STRING_PREFIX}{}", bs58::encode(&bytes).into_string());
        let err = ContactKeyV3::parse_string_form(&forged).unwrap_err();
        assert_eq!(err, ProtocolError::UnsupportedVersion);
    }

    #[test]
    fn missing_fields_rejected() {
        let ck = sample();
        let b58 = &ck.to_string_form()[STRING_PREFIX.len()..];
        let mut bytes = bs58::decode(b58).into_vec().unwrap();
        bytes.truncate(bytes.len() - 65); // срезали подпись — набор полей неполный
        let s = format!("{STRING_PREFIX}{}", bs58::encode(&bytes).into_string());
        assert_eq!(
            ContactKeyV3::parse_string_form(&s).unwrap_err(),
            ProtocolError::Malformed
        );
    }

    #[test]
    fn garbage_string_rejected() {
        assert_eq!(
            ContactKeyV3::parse_string_form("hello").unwrap_err(),
            ProtocolError::BadContactKeyString
        );
        // 0, O, I, l не входят в алфавит base58btc
        assert_eq!(
            ContactKeyV3::parse_string_form("MIN3:0OIl").unwrap_err(),
            ProtocolError::BadContactKeyString
        );
    }

    /// MIN-26: epoch входит в подписываемые поля — подмена эпохи (то есть
    /// молчаливая перепривязка адреса) ломает подпись identity.
    #[test]
    fn epoch_is_bound_by_signature() {
        use min_identity::IdentityKeypair;
        let ident = IdentityKeypair::generate();
        let mut ck = sample();
        ck.identity_public_key = ident.public();
        ck.mailbox_id = min_identity::mailbox_id(&ident.public(), EPOCH_INITIAL);
        ck.signature = ident.sign(&ck.canonical_payload());
        ck.verify().expect("canonical key must verify");
        let mut forged = ck.clone();
        forged.epoch = EPOCH_INITIAL + 1;
        assert_eq!(forged.verify().unwrap_err(), ProtocolError::BadSignature);
        let mut stale = ck.clone();
        stale.mailbox_id = min_identity::mailbox_id(&ident.public(), EPOCH_INITIAL + 1);
        assert_eq!(stale.verify().unwrap_err(), ProtocolError::BadSignature);
    }

    /// MIN-26: ротация даёт новый адрес, обе эпохи самодостаточны
    /// (строковая форма хранит epoch и восстанавливается без потерь).
    #[test]
    fn rotation_round_trip_keeps_epoch_and_new_mailbox() {
        use min_identity::IdentityKeypair;
        let ident = IdentityKeypair::generate();
        let build = |epoch: u64| {
            let mut ck = ContactKeyV3 {
                identity_public_key: ident.public(),
                mailbox_id: min_identity::mailbox_id(&ident.public(), epoch),
                signed_prekey_public: [9u8; 32],
                expiry: 0,
                epoch,
                signature: [0u8; 64],
            };
            ck.signature = ident.sign(&ck.canonical_payload());
            ck
        };
        let k1 = build(EPOCH_INITIAL);
        let k2 = build(EPOCH_INITIAL + 1);
        assert_ne!(k1.mailbox_id, k2.mailbox_id);
        assert_eq!(k1.epoch, EPOCH_INITIAL);
        assert_eq!(k2.epoch, EPOCH_INITIAL + 1);
        assert_eq!(
            ContactKeyV3::parse_string_form(&k2.to_string_form()).unwrap(),
            k2
        );
        assert!(k2.to_string_form().starts_with(STRING_PREFIX));
    }

    /// MIN-26: epoch < EPOCH_INITIAL — недопустимая семантика, fail-closed
    /// даже когда подпись корректна ровно над этим значением.
    #[test]
    fn epoch_zero_is_rejected_fail_closed() {
        use min_identity::IdentityKeypair;
        let ident = IdentityKeypair::generate();
        let mut ck = ContactKeyV3 {
            identity_public_key: ident.public(),
            mailbox_id: [0u8; 16],
            signed_prekey_public: [9u8; 32],
            expiry: 0,
            epoch: 0,
            signature: [0u8; 64],
        };
        ck.signature = ident.sign(&ck.canonical_payload());
        assert_eq!(ck.verify().unwrap_err(), ProtocolError::Malformed);
        let s = ck.to_string_form();
        assert_eq!(
            ContactKeyV3::parse_string_form(&s).unwrap_err(),
            ProtocolError::Malformed
        );
    }

    /// MIN-26: wire v2 (префикс MIN2) не принимается как MIN3 —
    /// downgrade-пути нет, расхождение версий явное (UnsupportedVersion на
    /// уровне поля version, BadContactKeyString на уровне префикса).
    #[test]
    fn legacy_v2_prefix_is_rejected() {
        let s = format!("MIN2:{}", bs58::encode([1u8, 2, 3]).into_string());
        assert_eq!(
            ContactKeyV3::parse_string_form(&s).unwrap_err(),
            ProtocolError::BadContactKeyString
        );
    }
}
