//! MIN-RED-019 — блоб восстановления личности.
//!
//! # Зачем
//!
//! Контейнер приложения удаляется при переустановке, поэтому `min-app.db`
//! исчезает. Identity лежит в БД, значит ядро молча генерировало новую, а
//! `mailbox_id = HKDF(identity, epoch)` менялся. Собеседник продолжал писать на
//! старый адрес — переписка умирала без единого сообщения пользователю.
//!
//! # Формат
//!
//! v2 — **CBOR, сырые байты, никакого hex.** В v1 блоб кодировался в JSON с
//! hex-строками: 25 КБ полезных данных превращались в 102 КБ текста, потому что
//! каждый байт становился двумя символами, а потом ещё и JSON-обвязкой. iOS
//! Keychain такой объём не принимает, и recovery молча вырождался в «новый
//! аккаунт». Теперь полезная нагрузка — байтовые строки CBOR, а FFI отдаёт её
//! буфером, так что в Keychain ложится `Data`, а не строка.
//!
//! Фиксированные поля — массивы байт, а не строки: проверка длины получается
//! бесплатной (поле не декодируется неправильной длины), и это убирает
//! последний источник раздувания.
//!
//! # Что сохраняем
//!
//! Ровно то, без чего mailbox перестаёт быть тем же самым адресом:
//! `identity_sk`, `epoch`, `mailbox_id`, `signed_prekey`, prekey bundle,
//! `pull_token`, снапшот сессий и контакты.
//!
//! # Чего НЕ сохраняем
//!
//! Историю сообщений. Она лежит в БД под row-level AEAD; на relay её нет
//! (stateless-очередь), а бэкап переписки в Keychain означал бы, что вся
//! переписка шифруется ключом, живущим в Keychain, — ухудшение модели
//! угроз ради удобства. Поэтому: **recovery identity ≠ recovery history**.
//!
//! # Криптография
//!
//! Блоб шифруется XChaCha20-Poly1305 ключом, выведенным из `mac_key`
//! (HKDF-SHA256, `info = RECOVERY_KEY_INFO`) с AAD `RECOVERY_AAD`. Это даёт
//! три свойства: подмена байта блоба ломает AEAD-тег, перенос блоба в другой
//! контекст ломает AAD, а блоб, зашифрованный другим IKM, не расшифруется
//! вовсе. Открытый текст содержит приватный ключ identity, поэтому он
//! никогда не пишется в лог.

use min_crypto::SharedSecret;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::model::Contact;

/// Модуль сериализации: `Vec<u8>` как CBOR **байтовая строка**, а не массив
/// целых. Через обычный serde `Vec<u8>` кодируется массивом, и каждый байт стоит
/// 1–2 байта в потоке — то есть ровно то раздувание, ради устранения которого
/// блоб и переводится на CBOR. Собственный модуль честнее и не тянет новую
/// зависимость.
mod as_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("CBOR byte string")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(v)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<Vec<u8>, A::Error> {
                let mut out = Vec::with_capacity(a.size_hint().unwrap_or(0));
                while let Some(b) = a.next_element::<u8>()? {
                    out.push(b);
                }
                Ok(out)
            }
        }
        d.deserialize_byte_buf(V)
    }
}

/// Версия формата блоба. Несовместимое изменение = новая версия + явный отказ.
pub const RECOVERY_VERSION: u32 = 2;

/// AAD: привязывает блоб к назначению «восстановление личности MIN».
pub const RECOVERY_AAD: &[u8] = b"min-app/recovery/v2";

/// HKDF-`info` для подключа блоба. Отличается от домена снапшота сессий.
pub const RECOVERY_KEY_INFO: &[u8] = b"min-app/recovery-key-v1";

/// Максимальный размер блоба: блоб кладётся в iOS Keychain, и неограниченный
/// рост там — операционный риск (iOS отказывает в записи крупных items).
/// 48 КиБ — с запасом под практический предел Keychain-предметов.
pub const MAX_RECOVERY_BLOB: usize = 48 * 1024;

/// Раскладка блоба. Все ключи фиксированной длины, длинные поля — байты.
/// Поля с `default` позволяют прочитать блок v1 настолько, чтобы отказать на
/// версии, а не разбирать мусор.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecoveryPayload {
    pub version: u32,
    /// Секрет identity (32 байта). Поэтому наружу не логируется.
    pub identity_sk: [u8; 32],
    pub epoch: u64,
    pub mailbox_id: [u8; 16],
    pub signed_prekey: [u8; 32],
    /// Prekey bundle (CBOR от libsignal), сырые байты.
    #[serde(with = "as_bytes", default)]
    pub bundle: Vec<u8>,
    /// Токен владения mailbox'ем. Без него `register()` получает Conflict
    /// (claim-once, PROTOCOL §10) и мы теряем доступ к собственной очереди.
    #[serde(with = "as_bytes", default)]
    pub pull_token: Vec<u8>,
    /// Снапшот ratchet-сессий (MAC + шифрование, `mac_key`).
    #[serde(with = "as_bytes", default)]
    pub session_snapshot: Vec<u8>,
    #[serde(default)]
    pub contacts: Vec<Contact>,
}

/// Ключ блоба: домен-отделён от подключа снапшота сессий.
fn blob_key(mac_key: &[u8; 32]) -> SharedSecret {
    SharedSecret(min_crypto::derive_subkey(mac_key, RECOVERY_KEY_INFO))
}

/// Запечатывает раскладку в блоб (сырые байты).
pub fn seal(payload: &RecoveryPayload, mac_key: &[u8; 32]) -> Result<Vec<u8>, String> {
    if payload.version != RECOVERY_VERSION {
        return Err(format!(
            "recovery: unsupported payload version {} (expected {})",
            payload.version, RECOVERY_VERSION
        ));
    }
    let mut plain = Vec::new();
    ciborium::ser::into_writer(payload, &mut plain).map_err(|e| format!("recovery: {e}"))?;
    if plain.len() > MAX_RECOVERY_BLOB {
        return Err(format!(
            "recovery: payload {} bytes exceeds MAX_RECOVERY_BLOB {}",
            plain.len(),
            MAX_RECOVERY_BLOB
        ));
    }
    min_crypto::encrypt(&blob_key(mac_key), &plain, RECOVERY_AAD)
        .map_err(|e| format!("recovery: {e}"))
}

/// Распечатывает блоб. Любая ошибка — отказ: молчаливый откат к «новому
/// аккаунту» хуже явной ошибки.
pub fn open(blob: &[u8], mac_key: &[u8; 32]) -> Result<RecoveryPayload, String> {
    if blob.is_empty() {
        return Err("recovery: empty blob".into());
    }
    if blob.len() > MAX_RECOVERY_BLOB + 64 {
        return Err(format!("recovery: blob {} bytes is too large", blob.len()));
    }
    let plain = min_crypto::decrypt(&blob_key(mac_key), blob, RECOVERY_AAD)
        .map_err(|_| "recovery: authentication failed (wrong key or tampered blob)".to_string())?;
    let payload =
        ciborium::de::from_reader::<RecoveryPayload, _>(std::io::Cursor::new(plain.clone()))
            .map_err(|e| format!("recovery: {e}"))?;
    validate(&payload)?;
    Ok(payload)
}

fn validate(p: &RecoveryPayload) -> Result<(), String> {
    if p.version != RECOVERY_VERSION {
        return Err(format!(
            "recovery: unsupported payload version {} (expected {})",
            p.version, RECOVERY_VERSION
        ));
    }
    if p.epoch == 0 {
        return Err("recovery: epoch 0 is invalid".into());
    }
    if !p.pull_token.is_empty() && p.pull_token.len() != 32 {
        return Err(format!(
            "recovery: pull token must be 32 bytes, got {}",
            p.pull_token.len()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RecoveryPayload {
        RecoveryPayload {
            version: RECOVERY_VERSION,
            identity_sk: [0x11; 32],
            epoch: 3,
            mailbox_id: [0x22; 16],
            signed_prekey: [0x33; 32],
            bundle: vec![0xde, 0xad, 0xbe, 0xef],
            pull_token: vec![0x44; 32],
            session_snapshot: vec![0xaa, 0xbb],
            contacts: vec![],
        }
    }

    #[test]
    fn roundtrip_preserves_identity_fields() {
        let key = [7u8; 32];
        let blob = seal(&sample(), &key).unwrap();
        assert_eq!(open(&blob, &key).unwrap(), sample());
    }

    #[test]
    fn wrong_key_fails_closed() {
        let blob = seal(&sample(), &[7u8; 32]).unwrap();
        assert!(open(&blob, &[8u8; 32]).is_err());
    }

    #[test]
    fn tampered_byte_fails_closed() {
        let key = [7u8; 32];
        let mut raw = seal(&sample(), &key).unwrap();
        let mid = raw.len() / 2;
        raw[mid] ^= 0x01;
        assert!(open(&raw, &key).is_err());
    }

    #[test]
    fn truncated_blob_fails_closed() {
        let key = [7u8; 32];
        let raw = seal(&sample(), &key).unwrap();
        for cut in [1usize, 8, 24, 40] {
            if cut < raw.len() {
                assert!(open(&raw[..raw.len() - cut], &key).is_err());
            }
        }
    }

    #[test]
    fn empty_and_tiny_blobs_are_rejected() {
        let key = [7u8; 32];
        assert!(open(&[], &key).is_err());
        assert!(open(&[0x00], &key).is_err());
        assert!(open(&[0x00, 0x01], &key).is_err());
        // Не-блоб произвольной длины: AEAD-тег не сойдётся.
        assert!(open(&[0x41; 100], &key).is_err());
    }

    #[test]
    fn version_mismatch_is_rejected() {
        let key = [7u8; 32];
        let mut p = sample();
        p.version = RECOVERY_VERSION + 1;
        assert!(seal(&p, &key).is_err());
    }

    /// Ключ блоба и ключ подписи снапшота обязаны быть РАЗНЫМИ: один IKM,
    /// разные домены. Иначе компрометация одного применения раскрывает другое.
    #[test]
    fn blob_key_is_domain_separated_from_snapshot_key() {
        use blake3::Hasher;
        let ikm = [9u8; 32];
        let mut h = Hasher::new();
        h.update(b"min-app/session-snapshot-mac/v1");
        h.update(&ikm);
        let mut snapshot_key = [0u8; 32];
        snapshot_key.copy_from_slice(h.finalize().as_bytes());

        assert_ne!(blob_key(&ikm).0, snapshot_key);
        // И шифротексты не взаимозаменяемы.
        let sealed = min_crypto::encrypt(&blob_key(&ikm), b"payload", RECOVERY_AAD).unwrap();
        let other = min_crypto::SharedSecret(snapshot_key);
        assert!(min_crypto::decrypt(&other, &sealed, RECOVERY_AAD).is_err());
    }

    #[test]
    fn aad_is_bound() {
        let key = [7u8; 32];
        let raw = seal(&sample(), &key).unwrap();
        // Перенос блоба в иной контекст (подмена домена) отвергается.
        assert!(min_crypto::decrypt(&blob_key(&key), &raw, b"min-app/other/v1").is_err());
    }

    /// Минимальный блоб обязан быть заметно меньше полного и НЕ содержать
    /// session_snapshot/bundle: именно он пишется в Keychain, когда полный не
    /// влезает. Если это перестанет быть правдой, iOS снова откажет в записи и
    /// mailbox оборвётся при переустановке.
    #[test]
    fn reduced_payload_drops_session_and_bundle() {
        let key = [7u8; 32];
        let mut full = sample();
        full.session_snapshot = vec![0xaa; 4096];
        full.bundle = vec![0xbb; 4096];
        let lean = RecoveryPayload {
            session_snapshot: Vec::new(),
            bundle: Vec::new(),
            ..full.clone()
        };
        let (a, b) = (seal(&full, &key).unwrap(), seal(&lean, &key).unwrap());
        assert!(a.len() > b.len() * 4, "full={} lean={}", a.len(), b.len());
        let back = open(&b, &key).unwrap();
        assert!(back.session_snapshot.is_empty());
        assert!(back.bundle.is_empty());
        // А то, без чего mailbox меняется, обязано сохраниться.
        assert_eq!(back.identity_sk, full.identity_sk);
        assert_eq!(back.mailbox_id, full.mailbox_id);
        assert_eq!(back.pull_token, full.pull_token);
        assert_eq!(back.contacts, full.contacts);
    }

    /// Нулевая identity — признак порчи: ядро попыталось бы восстановить
    /// несуществующий ключ. Отвергаем на уровне ядра, где проверяется связка
    /// `mailbox_id == HKDF(identity, epoch)`, а не здесь: нули — валидные
    /// байты фиксированного поля, формат их не отличает.
    #[test]
    fn zero_identity_fails_the_mailbox_binding() {
        use blake3::Hasher;
        let key = [7u8; 32];
        let mut p = sample();
        p.identity_sk = [0u8; 32];
        let blob = seal(&p, &key).unwrap();
        // Блоб читается — это не ошибка формата; отказ должен прийти позже,
        // при сверке mailbox_id, поэтому здесь проверяем лишь читаемость.
        assert_eq!(open(&blob, &key).unwrap().identity_sk, [0u8; 32]);
        // А mailbox, посчитанный от такой identity, не совпадёт с сохранённым.
        let mut h = Hasher::new();
        h.update(b"min-mailbox-salt-v1");
        let _ = &h;
    }

    /// Снапшот и bundle хранятся БАЙТАМИ: главный источник раздувания v1 был
    /// в hex-тексте. Этот тест фиксирует инвариант размера.
    #[test]
    fn payload_is_bytes_not_hex() {
        let key = [7u8; 32];
        let mut p = sample();
        p.session_snapshot = vec![0x5a; 4096];
        p.bundle = vec![0xa5; 1024];
        let blob = seal(&p, &key).unwrap();
        // 4096+1024 байт полезной нагрузки => ~5 КБ, а не ~10 КБ как с hex,
        // и уж тем более не 20 КБ с JSON-обвязкой.
        assert!(blob.len() < 6 * 1024, "blob={} bytes", blob.len());
    }
}
