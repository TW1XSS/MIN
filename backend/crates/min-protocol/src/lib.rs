//! MIN Protocol v4 — Contact Key v3, Envelope v1 и Frame API v2.
//!
//! Все структуры сериализуются в канонический CBOR (см. backend/PROTOCOL.md).
//! Парсинг строгий: неизвестная версия / лишние / несовпадающие по типу поля
//! → `ProtocolError` (ТЗ §42: «parsers reject unknown/ambiguous encodings»).

use min_wire::WireError;

/// Версия протокола (wire-совместимость).
///
/// AUDIT MIN-17: `aad_commitment` (поле 7) был бесключевым BLAKE3-хэшем —
/// формально не MAC. Деривация исправлена на ключевой MAC. Это изменение
/// **семантики замороженной v1-спеки** (раскладка wire та же — те же 16 байт,
/// но значение вычисляется иначе), поэтому по правилу PROTOCOL.md §0 версия
/// поднята 1 → 2: старый и новый клиент теперь расходятся **явно**
/// (`UnsupportedVersion`), а не молча (commitment mismatch, неотличимый от
/// атаки). На момент bump'а развёрнутых пиров нет → миграция не требуется.
/// AUDIT MIN-26 / O-5: версия 2 → 3: Contact Key получил обязательное поле
/// `epoch` (ротация mailbox_id — unlinkability для relay): изменились раскладка
/// Contact Key (PROTOCOL §2) и вывод адреса (§5). Envelope v1 по байтам не
/// менялся, но версия в проекте общая — поднята для всего протокола: старый
/// клиент получает явный UnsupportedVersion, а не тихую подмену адреса.
pub const PROTOCOL_VERSION: u64 = 4;
/// Contact Key wire version remains v3 across the frame-API bump.
pub const CONTACT_KEY_VERSION: u64 = 3;
/// Envelope wire version remains v1 across the frame-API bump.
pub const ENVELOPE_VERSION: u64 = 1;
/// Frame API v2 requires sender mailbox/token in Enqueue.
pub const FRAME_API_VERSION: u64 = 2;

/// Единственный источник правды по правилу эпох (MIN-26).
pub use min_identity::EPOCH_INITIAL;

pub mod contact_key;
pub mod envelope;
pub mod frame_api;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    /// Не та версия протокола.
    UnsupportedVersion,
    /// Строка не начинается с префикса MIN3: или содержит не-base58.
    BadContactKeyString,
    /// CBOR-структура не соответствует спецификации (тип/длина/набор полей).
    Malformed,
    /// Подпись Contact Key не соответствует содержимому.
    BadSignature,
    /// aad_commitment не совпал с пересчитанным (AUDIT MIN-02): заголовок
    /// envelope был изменён после его подписания отправителем.
    CommitmentMismatch,
    /// Wire-layer ошибка (encode/decode/frame).
    Wire(WireError),
}

impl From<WireError> for ProtocolError {
    fn from(e: WireError) -> Self {
        ProtocolError::Wire(e)
    }
}

impl core::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProtocolError::UnsupportedVersion => write!(f, "unsupported protocol version"),
            ProtocolError::BadContactKeyString => write!(f, "malformed MIN contact key string"),
            ProtocolError::Malformed => write!(f, "malformed protocol structure"),
            ProtocolError::BadSignature => write!(f, "signature verification failed"),
            ProtocolError::CommitmentMismatch => write!(f, "aad commitment mismatch"),
            ProtocolError::Wire(e) => write!(f, "wire: {e}"),
        }
    }
}

pub type ProtocolResult<T> = Result<T, ProtocolError>;

/// Собирает канонический CBOR map из пар `(целый_ключ, значение)` в порядке
/// возрастания ключа — единственный разрешённый способ строить подписанные структуры.
pub fn canonical_map(pairs: &[(u64, ciborium::value::Value)]) -> ciborium::value::Value {
    let mut sorted = pairs.to_vec();
    sorted.sort_by_key(|(k, _)| *k);
    ciborium::value::Value::Map(
        sorted
            .into_iter()
            .map(|(k, v)| (ciborium::value::Value::Integer(k.into()), v))
            .collect(),
    )
}

/// Извлекает поле по целому ключу из декодированной CBOR-мапы.
/// Лишние ключи проверяются вызывающей стороной (строгий набор полей).
pub(crate) fn map_get<'a>(
    v: &'a ciborium::value::Value,
    key: u64,
) -> Option<&'a ciborium::value::Value> {
    match v {
        ciborium::value::Value::Map(pairs) => pairs
            .iter()
            .find(|(k, _)| *k == ciborium::value::Value::Integer(key.into()))
            .map(|(_, v)| v),
        _ => None,
    }
}

/// Ожидает bstr строго заданной длины.
pub(crate) fn expect_bstr(v: &ciborium::value::Value, len: usize) -> Option<Vec<u8>> {
    match v {
        ciborium::value::Value::Bytes(b) if b.len() == len => Some(b.clone()),
        _ => None,
    }
}

/// Ожидает целое u64 (Integer), строго.
pub(crate) fn expect_u64(v: &ciborium::value::Value) -> Option<u64> {
    match v {
        ciborium::value::Value::Integer(i) => u64::try_from(*i).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value;
    use min_wire::canonical_encode;

    #[test]
    fn canonical_map_is_sorted_by_key() {
        // Ключи подаются неупорядоченно, но сериализация обязана отсортировать.
        let m = canonical_map(&[
            (3, Value::Integer(1.into())),
            (1, Value::Integer(1.into())),
            (2, Value::Integer(1.into())),
        ]);
        let bytes = canonical_encode(&m).unwrap();
        let decoded: Value = min_wire::canonical_decode(&bytes).unwrap();
        let keys: Vec<u64> = match decoded {
            Value::Map(pairs) => pairs.iter().map(|(k, _)| expect_u64(k).unwrap()).collect(),
            _ => panic!("expected map"),
        };
        assert_eq!(
            keys,
            vec![1, 2, 3],
            "keys must be serialized in ascending order"
        );
    }

    #[test]
    fn expect_helpers_are_strict() {
        let v = Value::Bytes(vec![0u8; 4]);
        assert!(expect_bstr(&v, 4).is_some());
        assert!(expect_bstr(&v, 5).is_none());
        let i = Value::Integer(7.into());
        assert_eq!(expect_u64(&i), Some(7));
        let neg = Value::Integer((-1).into());
        assert!(expect_u64(&neg).is_none(), "negative must be rejected");
    }
}
