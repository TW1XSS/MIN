//! MIN Envelope v1 (ТЗ §19) — wire-структура доставки. Никаких plaintext-имён,
//! телефонов, email, preview. Строгий набор полей 1..=11 (PROTOCOL.md §3).

use crate::{
    canonical_map, expect_bstr, expect_u64, map_get, ProtocolError, ProtocolResult,
    ENVELOPE_VERSION,
};
use min_wire::{canonical_decode_strict, canonical_encode, WireError, WireResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum MessageType {
    Request = 1,
    Message = 2,
    Control = 3,
    Ack = 4,
}

impl TryFrom<u64> for MessageType {
    type Error = ProtocolError;
    fn try_from(v: u64) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(MessageType::Request),
            2 => Ok(MessageType::Message),
            3 => Ok(MessageType::Control),
            4 => Ok(MessageType::Ack),
            _ => Err(ProtocolError::Malformed),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeV1 {
    pub msg_type: MessageType,
    pub epoch: u32,
    pub seq: u64,
    /// Opaque хинт отправителя (16 байт; нули допустимы) — метаданные минимизированы.
    pub sender_hint: [u8; 16],
    pub mailbox_hint: [u8; 16],
    /// Обязательство по заголовку И шифротексту (16 байт). AUDIT MIN-17:
    /// это КЛЮЧЕВОЙ MAC (BLAKE3-keyed), а не бесключевой хэш — подделать
    /// его без знания `session_id` невозможно, даже зная все поля envelope.
    pub aad_commitment: [u8; 16],
    /// XChaCha20-Poly1305 nonce (24 байта, PROTOCOL.md §0).
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
    pub ttl_sec: u64,
    pub queue_class: u64,
}

fn to_value(env: &EnvelopeV1) -> ciborium::value::Value {
    canonical_map(&[
        (1, ciborium::value::Value::Integer(ENVELOPE_VERSION.into())),
        (
            2,
            ciborium::value::Value::Integer((env.msg_type as u64).into()),
        ),
        (3, ciborium::value::Value::Integer(env.epoch.into())),
        (4, ciborium::value::Value::Integer(env.seq.into())),
        (5, ciborium::value::Value::Bytes(env.sender_hint.to_vec())),
        (6, ciborium::value::Value::Bytes(env.mailbox_hint.to_vec())),
        (
            7,
            ciborium::value::Value::Bytes(env.aad_commitment.to_vec()),
        ),
        (8, ciborium::value::Value::Bytes(env.nonce.to_vec())),
        (9, ciborium::value::Value::Bytes(env.ciphertext.clone())),
        (10, ciborium::value::Value::Integer(env.ttl_sec.into())),
        (11, ciborium::value::Value::Integer(env.queue_class.into())),
    ])
}

impl EnvelopeV1 {
    /// Канонические wire-байты.
    pub fn to_wire(&self) -> WireResult<Vec<u8>> {
        if self.ciphertext.len() > min_wire::MAX_FRAME_SIZE {
            return Err(WireError::PayloadTooLarge);
        }
        canonical_encode(&to_value(self))
    }

    // ---- Header binding (AUDIT MIN-02 → MIN-17, PROTOCOL §3 поле 7) ----
    //
    // aad_commitment = BLAKE3-keyed( KDF(session_id), канонический CBOR
    // заголовка || ciphertext )[..16], где «заголовок» = поля 1..=11 КРОМЕ 7.
    //
    // AUDIT MIN-17: ранее поле считалось бесключевым BLAKE3-хэшем. Формально
    // это не MAC: защита держалась исключительно на неизвестности session_id,
    // а бесключевой хэш не даёт криптографической привязки к секрету. Теперь
    // ключ выводится из session_id через BLAKE3 KDF, и commitment покрывает
    // ciphertext (MIN-19): мутация ЛЮБОГО байта envelope — включая поля
    // PreKey-конверта, не покрытые внутренним MAC libsignal, — детектируется.
    //
    // Отправитель: `seal(session_id)` перед `to_wire`.
    // Получатель: `from_wire_verified(bytes, session_id)` — mismatch →
    // ProtocolError::CommitmentMismatch. Любая модификация заголовка (seq,
    // epoch, hints, nonce, ttl, queue_class) или ciphertext для relay не
    // только «недетектируема» — теперь вообще невозможна незаметно.

    /// Ключ MAC обязательства, выводимый из идентификатора сессии
    /// (BLAKE3 derive_key: домен отделён от любых других производных).
    fn commitment_key(session_id: &[u8]) -> [u8; 32] {
        blake3::derive_key("min-envelope-commitment/v1", session_id)
    }

    /// Байты-вход для обязательства: канонический заголовок (без поля 7)
    /// вместе с ciphertext (поле 9).
    pub fn commitment_input(&self, session_id: &[u8]) -> Vec<u8> {
        let header = canonical_map(&[
            (1, ciborium::value::Value::Integer(ENVELOPE_VERSION.into())),
            (
                2,
                ciborium::value::Value::Integer((self.msg_type as u64).into()),
            ),
            (3, ciborium::value::Value::Integer(self.epoch.into())),
            (4, ciborium::value::Value::Integer(self.seq.into())),
            (5, ciborium::value::Value::Bytes(self.sender_hint.to_vec())),
            (6, ciborium::value::Value::Bytes(self.mailbox_hint.to_vec())),
            (8, ciborium::value::Value::Bytes(self.nonce.to_vec())),
            (9, ciborium::value::Value::Bytes(self.ciphertext.clone())),
            (10, ciborium::value::Value::Integer(self.ttl_sec.into())),
            (11, ciborium::value::Value::Integer(self.queue_class.into())),
        ]);
        let mut buf = canonical_encode(&header).expect("canonical encode of header is infallible");
        // Доменная разметка: вход не должен быть конкатенацией-амбигуазной.
        buf.extend_from_slice(b"min-envelope-commitment/v1");
        buf.extend_from_slice(session_id);
        buf
    }

    /// Вычисляет aad_commitment: ключевой BLAKE3 по session_id, обрезка до 16.
    pub fn compute_aad_commitment(&self, session_id: &[u8]) -> [u8; 16] {
        let key = Self::commitment_key(session_id);
        let digest = blake3::keyed_hash(&key, &self.commitment_input(session_id));
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest.as_bytes()[..16]);
        out
    }

    /// Заполняет поле 7 вычисленным обязательством. Вызывается отправителем
    /// перед `to_wire`.
    pub fn seal(&mut self, session_id: &[u8]) {
        self.aad_commitment = self.compute_aad_commitment(session_id);
    }

    /// Проверяет обязательство: заголовок не был изменён после seal().
    /// Mismatch → `ProtocolError::CommitmentMismatch`.
    pub fn verify_commitment(&self, session_id: &[u8]) -> ProtocolResult<()> {
        if self.aad_commitment == self.compute_aad_commitment(session_id) {
            Ok(())
        } else {
            Err(ProtocolError::CommitmentMismatch)
        }
    }

    /// Строгий парс + проверка обязательства по заголовку. Единый вход приёма.
    pub fn from_wire_verified(bytes: &[u8], session_id: &[u8]) -> ProtocolResult<Self> {
        let env = Self::from_wire(bytes)?;
        env.verify_commitment(session_id)?;
        Ok(env)
    }

    /// Строгий парс: ровно поля 1..=11, типы и длины — по спецификации.
    pub fn from_wire(bytes: &[u8]) -> ProtocolResult<Self> {
        let root = canonical_decode_strict::<ciborium::value::Value>(bytes)
            .map_err(|_| ProtocolError::Malformed)?;
        let pairs = match &root {
            ciborium::value::Value::Map(p) => p,
            _ => return Err(ProtocolError::Malformed),
        };
        let keys: Vec<u64> = pairs
            .iter()
            .map(|(k, _)| expect_u64(k).ok_or(ProtocolError::Malformed))
            .collect::<Result<_, _>>()?;
        let expected: Vec<u64> = (1..=11).collect();
        // Ключи обязаны идти строго по возрастанию — канонический CBOR (PROTOCOL §0).
        // Проверяем и набор (sorted == expected), и порядок (keys == sorted).
        if keys != expected {
            return Err(ProtocolError::Malformed);
        }

        let get_u = |k: u64| -> ProtocolResult<u64> {
            expect_u64(map_get(&root, k).ok_or(ProtocolError::Malformed)?)
                .ok_or(ProtocolError::Malformed)
        };
        let get_b = |k: u64, n: usize| -> ProtocolResult<Vec<u8>> {
            expect_bstr(map_get(&root, k).ok_or(ProtocolError::Malformed)?, n)
                .ok_or(ProtocolError::Malformed)
        };

        let version = get_u(1)?;
        if version != ENVELOPE_VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }
        let msg_type = MessageType::try_from(get_u(2)?)?;
        let epoch = u32::try_from(get_u(3)?).map_err(|_| ProtocolError::Malformed)?;
        let seq = get_u(4)?;
        let sender_hint: [u8; 16] = get_b(5, 16)?.try_into().unwrap();
        let mailbox_hint: [u8; 16] = get_b(6, 16)?.try_into().unwrap();
        let aad_commitment: [u8; 16] = get_b(7, 16)?.try_into().unwrap();
        let nonce: [u8; 24] = get_b(8, 24)?.try_into().unwrap();
        // ciphertext — bstr без фиксированной длины
        let ciphertext = match map_get(&root, 9) {
            Some(ciborium::value::Value::Bytes(b)) if b.len() <= min_wire::MAX_FRAME_SIZE => {
                b.clone()
            }
            Some(_) => return Err(ProtocolError::Wire(WireError::PayloadTooLarge)),
            None => return Err(ProtocolError::Malformed),
        };
        let ttl_sec = get_u(10)?;
        let queue_class = get_u(11)?;

        Ok(EnvelopeV1 {
            msg_type,
            epoch,
            seq,
            sender_hint,
            mailbox_hint,
            aad_commitment,
            nonce,
            ciphertext,
            ttl_sec,
            queue_class,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> EnvelopeV1 {
        EnvelopeV1 {
            msg_type: MessageType::Message,
            epoch: 1,
            seq: 42,
            sender_hint: [0u8; 16],
            mailbox_hint: [7u8; 16],
            aad_commitment: [9u8; 16],
            nonce: [5u8; 24],
            ciphertext: vec![0xEE; 128],
            ttl_sec: 7 * 24 * 3600,
            queue_class: 0,
        }
    }

    #[test]
    fn wire_roundtrip() {
        let e = sample();
        let bytes = e.to_wire().unwrap();
        let back = EnvelopeV1::from_wire(&bytes).unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn wrong_bstr_length_rejected() {
        let e = sample();
        let mut bytes = e.to_wire().unwrap();
        // ломаем длину nonce: заголовок bstr(24) = 0x58 0x18, правим младший байт
        let pos = bytes.iter().position(|&b| b == 0x58).unwrap();
        bytes[pos + 1] = 0x19;
        assert_eq!(
            EnvelopeV1::from_wire(&bytes).unwrap_err(),
            ProtocolError::Malformed
        );
    }

    #[test]
    fn truncated_cbor_rejected() {
        let e = sample();
        let mut bytes = e.to_wire().unwrap();
        bytes.truncate(bytes.len() - 1);
        assert!(EnvelopeV1::from_wire(&bytes).is_err());
    }

    #[test]
    fn map_keys_out_of_order_rejected() {
        // Собираем envelope с ключами map в неканоническом порядке (11..=1).
        // Набор полей тот же, но порядок нарушен → парсер обязан отвергнуть.
        use ciborium::value::Value;
        let pairs: Vec<(Value, Value)> = (1..=11u64)
            .rev()
            .map(|k| (Value::Integer(k.into()), Value::Integer(0.into())))
            .collect();
        let bad = canonical_encode(&Value::Map(pairs)).unwrap();
        assert_eq!(
            EnvelopeV1::from_wire(&bad).unwrap_err(),
            ProtocolError::Malformed
        );
    }

    // ---- Header binding (AUDIT MIN-02) ----

    fn sealed(session_id: &[u8]) -> (EnvelopeV1, Vec<u8>) {
        let mut e = sample();
        e.aad_commitment = [0u8; 16];
        e.seal(session_id);
        let bytes = e.to_wire().unwrap();
        (e, bytes)
    }

    #[test]
    fn commitment_seal_verify_roundtrip() {
        let (e, bytes) = sealed(b"session-alice-bob-1");
        assert_ne!(e.aad_commitment, [0u8; 16], "seal обязан заполнить поле");
        // Честный envelope: from_wire_verified проходит.
        let back = EnvelopeV1::from_wire_verified(&bytes, b"session-alice-bob-1").unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn commitment_binds_to_session_id() {
        let (e, _) = sealed(b"session-alice-bob-1");
        // Тот же envelope, но чужая сессия → mismatch (Signal-2026 #1: cross-session).
        assert_eq!(
            e.verify_commitment(b"session-mallory").unwrap_err(),
            ProtocolError::CommitmentMismatch
        );
    }

    /// AUDIT MIN-17: commitment — КЛЮЧЕВОЙ MAC, а не бесключевой хэш.
    /// Регресс-тест: значение обязано отличаться от простого BLAKE3-хэша
    /// того же входа. Если однажды кто-то вернёт `blake3::hash`, тест упадёт.
    #[test]
    fn commitment_is_keyed_not_plain_hash() {
        let session = b"session-alice-bob-1";
        let (e, _) = sealed(session);
        let plain = blake3::hash(&e.commitment_input(session));
        assert_ne!(
            &plain.as_bytes()[..16],
            &e.aad_commitment[..],
            "MIN-17 regression: commitment must be a KEYED MAC, not plain BLAKE3"
        );
    }

    #[test]
    fn commitment_binds_every_header_field() {
        let session = b"session-alice-bob-1";
        // AUDIT MIN-17: commitment покрывает и ciphertext (поле 9). Ранее
        // целостность шифротекста держалась только на внутреннем AEAD
        // libsignal — этого не хватало для полей PreKey-конверта, которые
        // libsignal не MAC-ает (red-team скан MIN-19).
        let cases: Vec<(&str, Box<dyn Fn(&mut EnvelopeV1)>)> = vec![
            (
                "msg_type",
                Box::new(|e: &mut EnvelopeV1| e.msg_type = MessageType::Request),
            ),
            ("epoch", Box::new(|e: &mut EnvelopeV1| e.epoch = 999)),
            ("seq", Box::new(|e: &mut EnvelopeV1| e.seq += 1)),
            (
                "sender_hint",
                Box::new(|e: &mut EnvelopeV1| e.sender_hint = [1u8; 16]),
            ),
            (
                "mailbox_hint",
                Box::new(|e: &mut EnvelopeV1| e.mailbox_hint = [2u8; 16]),
            ),
            ("nonce", Box::new(|e: &mut EnvelopeV1| e.nonce = [3u8; 24])),
            (
                "ciphertext",
                Box::new(|e: &mut EnvelopeV1| {
                    let last = e.ciphertext.len() - 1;
                    e.ciphertext[last] ^= 0xFF;
                }),
            ),
            ("ttl_sec", Box::new(|e: &mut EnvelopeV1| e.ttl_sec = 1)),
            (
                "queue_class",
                Box::new(|e: &mut EnvelopeV1| e.queue_class = 5),
            ),
        ];
        for (field, mutate) in cases {
            let (e, _) = sealed(session);
            let mut tampered = e;
            mutate(&mut tampered);
            assert_eq!(
                tampered.verify_commitment(session).unwrap_err(),
                ProtocolError::CommitmentMismatch,
                "tampered field '{field}' must be detected"
            );
        }
    }

    /// AUDIT MIN-19: инвариант «каждый байт wire-представления envelope
    /// влияет либо на CBOR-структуру, либо на commitment». Строгий байт-скан:
    /// мутируем по одному байту канонического wire и проверяем, что либо
    /// парсинг отвергает вход, либо `from_wire_verified` даёт mismatch.
    #[test]
    fn every_wire_byte_is_authenticated() {
        let session = b"session-alice-bob-1";
        let (_, bytes) = sealed(session);
        let mut undetected: Vec<usize> = Vec::new();
        for pos in 0..bytes.len() {
            let mut t = bytes.clone();
            t[pos] ^= 0xFF;
            let detected = match EnvelopeV1::from_wire_verified(&t, session) {
                Ok(_) => false,
                Err(_) => true,
            };
            if !detected {
                undetected.push(pos);
            }
        }
        assert!(
            undetected.is_empty(),
            "wire bytes accepted after tampering: {undetected:?}"
        );
    }

    #[test]
    fn from_wire_verified_rejects_tampered_wire() {
        let session = b"session-alice-bob-1";
        let (e, bytes) = sealed(session);
        // Меняем seq на wire: канонический порядок ключей сохраняем — правим
        // байт значения seq в пересобранных байтах через честный decode/encode
        // с подменой, затем шьём «старый» commitment (как это сделал бы
        // атакующий, не зная session_id).
        let mut fake = e.clone();
        fake.seq = e.seq + 1;
        fake.aad_commitment = e.aad_commitment; // старый commitment, seq подменён
        let tampered = fake.to_wire().unwrap();
        assert_eq!(
            EnvelopeV1::from_wire_verified(&tampered, session).unwrap_err(),
            ProtocolError::CommitmentMismatch
        );
        assert!(EnvelopeV1::from_wire_verified(&bytes, session).is_ok());
    }

    #[test]
    fn commitment_is_deterministic_and_bounded() {
        let (e1, _) = sealed(b"sid");
        let (e2, _) = sealed(b"sid");
        assert_eq!(e1.aad_commitment, e2.aad_commitment, "детерминизм KDF");
        // Пересборка input детерминирована: повторный вызов тот же.
        assert_eq!(e1.commitment_input(b"sid"), e1.commitment_input(b"sid"),);
    }

    // ---- AUDIT MIN-17 (ключевой MAC) и MIN-19 (binding ciphertext) ----

    #[test]
    fn commitment_binds_ciphertext() {
        let session = b"session-alice-bob-1";
        let (e, _) = sealed(session);
        // MIN-19: мутация ciphertext (поле 9) обязана детектироваться даже
        // при неизменном заголовке. Это закрывает поля PreKey-конверта,
        // которые внутренний MAC libsignal может не покрывать.
        let mut tampered = e.clone();
        let last = tampered.ciphertext.len() - 1;
        tampered.ciphertext[last] ^= 0xFF;
        assert_eq!(
            tampered.verify_commitment(session).unwrap_err(),
            ProtocolError::CommitmentMismatch,
            "ciphertext mutation must be detected"
        );
    }

    #[test]
    fn commitment_without_session_never_forges() {
        // MIN-17: commitment — ключевой MAC. Атакующий, знающий все поля
        // envelope (relay), но не знающий session_id, не может вычислить
        // совпадающий MAC для подменённого заголовка.
        let session = b"session-alice-bob-1";
        let (e, _) = sealed(session);
        let mut fake = e.clone();
        fake.seq = e.seq + 7;
        assert_ne!(fake.seq, e.seq, "подмена должна менять поле");

        // Попытка №1: пересчитать бесключевым хэшем (старая схема MIN-02) —
        // не проходит: теперь MAC ключевой.
        let legacy_like = blake3::hash(&fake.commitment_input(b""));
        let mut forged = [0u8; 16];
        forged.copy_from_slice(&legacy_like.as_bytes()[..16]);
        fake.aad_commitment = forged;
        assert_eq!(
            fake.verify_commitment(session).unwrap_err(),
            ProtocolError::CommitmentMismatch,
            "keyless hash must not forge a keyed MAC"
        );

        // Попытка №2: сохранить старый MAC при подменённом поле — mismatch.
        fake.aad_commitment = e.aad_commitment;
        assert_eq!(
            fake.verify_commitment(session).unwrap_err(),
            ProtocolError::CommitmentMismatch
        );

        // Контроль: честный seal от отправителя с тем же session_id сходится.
        let mut honest = e.clone();
        honest.seq = e.seq + 7;
        honest.seal(session);
        assert_eq!(honest.seq, fake.seq, "обе ветки — с одинаковым seq");
        assert!(honest.verify_commitment(session).is_ok());
    }

    #[test]
    fn commitment_domain_separation() {
        // Два разных session_id → разные ключи MAC (проверяем, что KDF
        // использует session_id, а не константу).
        let (e, _) = sealed(b"sid-a");
        let other = e.compute_aad_commitment(b"sid-b");
        assert_ne!(e.aad_commitment, other);
    }

    /// RT-26.12: ни два семантически разных заголовка не дают одинаковый
    /// commitment_input (canonical_map + CBOR length-prefix ⇒ коллизий
    /// на уровне структуры нет).
    #[test]
    fn rt26_12_no_commitment_input_collisions() {
        let session = b"rt26-12";
        let (base, _) = sealed(session);
        let mut variants: Vec<EnvelopeV1> = vec![base.clone()];
        let mut m = base.clone();
        m.msg_type = MessageType::Request;
        variants.push(m);
        let mut m = base.clone();
        m.epoch = base.epoch + 1;
        variants.push(m);
        let mut m = base.clone();
        m.seq = base.seq + 1;
        variants.push(m);
        let mut m = base.clone();
        m.sender_hint = [1u8; 16];
        variants.push(m);
        let mut m = base.clone();
        m.mailbox_hint = [2u8; 16];
        variants.push(m);
        let mut m = base.clone();
        m.nonce = [3u8; 24];
        variants.push(m);
        let mut m = base.clone();
        m.ttl_sec = base.ttl_sec + 1;
        variants.push(m);
        let mut m = base.clone();
        m.queue_class = base.queue_class + 1;
        variants.push(m);
        let mut m = base.clone();
        let last = m.ciphertext.len() - 1;
        m.ciphertext[last] ^= 0x01;
        variants.push(m);

        for i in 0..variants.len() {
            for j in (i + 1)..variants.len() {
                assert_ne!(
                    variants[i].commitment_input(session),
                    variants[j].commitment_input(session),
                    "semantic variants {i}/{j} must not share commitment_input"
                );
            }
        }
    }

    /// RT-26.14: обрезка канонического CBOR на ЛЮБОМ префиксе → отказ
    /// (все обязательные поля fail-closed, no implicit defaults).
    #[test]
    fn rt26_14_every_truncation_fails_closed() {
        let session = b"rt26-14";
        let (_, bytes) = sealed(session);
        for cut in 1..bytes.len() {
            let truncated = &bytes[..cut];
            assert!(
                EnvelopeV1::from_wire_verified(truncated, session).is_err(),
                "truncation at {} must fail",
                cut
            );
        }
        // Контроль: полная длина проходит.
        assert!(EnvelopeV1::from_wire_verified(&bytes, session).is_ok());
    }

    /// RT-26.22: парсер и канонизатор имеют одну семантику —
    /// from_wire → to_wire тождественен входу (canonical idempotence).
    #[test]
    fn rt26_22_parse_reencode_is_identity() {
        let session = b"rt26-22";
        let (_, bytes) = sealed(session);
        let back = EnvelopeV1::from_wire_verified(&bytes, session).unwrap();
        let re = back.to_wire().unwrap();
        assert_eq!(bytes, re, "canonical parse→encode must be identity");
    }
}
