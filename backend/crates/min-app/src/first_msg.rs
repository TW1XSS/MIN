//! Заголовок ПЕРВОГО сообщения (E2E, внутри шифротекста).
//!
//! # Зачем
//!
//! Чтобы ответить отправителю, получателю нужен его `mailbox_id` + `epoch`.
//! В конверте (PROTOCOL §3) их нет: `sender_hint`/`mailbox_hint` — opaque
//! 16 байт, и класть туда что-то осмысленное нельзя (relay увидит).
//!
//! Мы кладём их **внутрь расшифрованного plaintext** первого сообщения.
//! Relay перевозит конверт непрозрачным `bstr` и не имеет ключей, поэтому
//! адрес отправителя ему недоступен — то же свойство, что и у содержимого.
//!
//! # Формат (28 байт, строгий)
//!
//! ```text
//! [0..4)   magic  "MINQ"
//! [4..20)  sender_mailbox — 16 байт (PROTOCOL §5)
//! [20..28) sender_epoch   — u64 big-endian
//! ```
//!
//! Остальное — обычный текст пользователя. Никакого CBOR здесь намеренно
//! нет: это не wire-структура, а внутренний префикс E2E-plaintext, и любая
//! переменная длина здесь означала бы, что «заголовок» можно спутать с
//! текстом. Фиксированная длина делает разбор однозначным.
//!
//! # Почему это не меняет wire
//!
//! Ни конверт (§3), ни фрейминг (§7), ни frame API (§10) не меняются.
//! Меняется только содержимое первого сообщения, которое и так
//! полностью определяется приложением-отправителем. `PROTOCOL_VERSION`
//! не бампается; §8 дополняется пометкой о политике MVP.

/// Магическое начало первого сообщения. `MINQ` отличается от `MIN3:`
/// (префикс Contact Key), `MIN1:`/`MIN2:` (старые форматы) и `BND:`
/// (строка bundle в приглашении) — коллизий нет.
pub const MAGIC: [u8; 4] = *b"MINQ";

/// Полная длина заголовка: 4 + 16 + 8.
pub const HEADER_LEN: usize = 28;

/// Максимальная длина тела первого сообщения.
///
/// Заголовок — служебный, он не должен съедать бюджет переписки: текст
/// длиннее этого отвергается (а не обрезается молча).
pub const MAX_BODY_LEN: usize = 16 * 1024;

/// Разобранный заголовок первого сообщения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Адрес отправителя для ответа (16 байт).
    pub sender_mailbox: [u8; 16],
    /// Эпоха отправителя на момент отправки.
    pub sender_epoch: u64,
}

/// Собирает заголовок + тело в один буфер для отправки.
pub fn encode(mailbox: &[u8; 16], epoch: u64, body: &str) -> Option<Vec<u8>> {
    if body.len() > MAX_BODY_LEN {
        return None;
    }
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(mailbox);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(body.as_bytes());
    Some(out)
}

/// Разбирает первое сообщение: возвращает заголовок и тело.
///
/// Строгий разбор: неверная магия, слишком короткий буфер, неверная длина
/// адреса или тело больше лимита — это `None`, а не «примерно разобрали».
/// Иначе злоумышленник, знающий протокол, подсунул бы в поле адреса
/// произвольные байты и увел наш ответ на свой адрес.
pub fn decode(plaintext: &[u8]) -> Option<(Header, &str)> {
    if plaintext.len() < HEADER_LEN {
        return None;
    }
    if plaintext[..4] != MAGIC {
        return None;
    }
    let mut sender_mailbox = [0u8; 16];
    sender_mailbox.copy_from_slice(&plaintext[4..20]);
    let mut epoch_bytes = [0u8; 8];
    epoch_bytes.copy_from_slice(&plaintext[20..28]);
    let epoch = u64::from_be_bytes(epoch_bytes);

    // Эпоха 0 не существует: mailbox_id = HKDF(identity, salt, info, epoch)
    // определён только для epoch >= EPOCH_INITIAL (=1). Заголовок с epoch 0
    // — это либо мусор, либо попытка отправить нас на несуществующий адрес.
    if epoch == 0 {
        return None;
    }

    let body = &plaintext[HEADER_LEN..];
    if body.len() > MAX_BODY_LEN {
        return None;
    }
    let text = std::str::from_utf8(body).ok()?;
    Some((
        Header {
            sender_mailbox,
            sender_epoch: epoch,
        },
        text,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mb = [7u8; 16];
        let enc = encode(&mb, 3, "Привет").expect("fits");
        assert_eq!(enc.len(), HEADER_LEN + "Привет".len());
        let (h, text) = decode(&enc).expect("decodes");
        assert_eq!(h.sender_mailbox, mb);
        assert_eq!(h.sender_epoch, 3);
        assert_eq!(text, "Привет");
    }

    #[test]
    fn empty_body_is_valid() {
        let mb = [1u8; 16];
        let enc = encode(&mb, 1, "").expect("fits");
        let (h, text) = decode(&enc).expect("decodes");
        assert_eq!(h.sender_mailbox, mb);
        assert!(text.is_empty());
    }

    #[test]
    fn wrong_magic_is_rejected() {
        let mut enc = encode(&[2u8; 16], 1, "x").unwrap();
        enc[0] = b'X';
        assert!(decode(&enc).is_none());
    }

    #[test]
    /// «Показатели безопасности» для владельца: мусор в начале сообщения — это
    /// НЕ шифротекст и не ключи. Это 28 байт открытого заголовка первого
    /// сообщения: `MINQ` + публичный mailbox отправителя + его epoch.
    /// Ровно эти же значения relay и так видит в `Enqueue`, поэтому показать их
    /// дополнительно ничего не раскрывает. Настоящий шифротекст находится
    /// ВНЕ этого блока и на устройство не попадает вовсе.
    fn first_msg_header_carries_public_address_only_not_secrets() {
        let mailbox = [7u8; 16];
        let payload = crate::first_msg::encode(&mailbox, 1, "Privet").unwrap();

        assert_eq!(&payload[0..4], b"MINQ");
        assert_eq!(&payload[4..20], &mailbox, "это публичный адрес, он же в Enqueue");
        assert_eq!(&payload[20..28], &1u64.to_be_bytes());
        assert_eq!(&payload[28..], b"Privet", "дальше — ровно текст пользователя");

        // Секретов в заголовке нет by construction: ни identity_sk, ни prekey.
        // Единственное, что видно из «мусора», — адрес, который и так публичен.
        let (header, text) = crate::first_msg::decode(&payload).unwrap();
        assert_eq!(header.sender_mailbox, mailbox);
        assert_eq!(header.sender_epoch, 1);
        assert_eq!(text, "Privet");
    }

    #[test]
    fn zero_epoch_is_rejected() {
        let enc = encode(&[3u8; 16], 0, "x").unwrap();
        assert!(decode(&enc).is_none());
    }

    #[test]
    fn truncated_is_rejected() {
        let enc = encode(&[4u8; 16], 1, "hello").unwrap();
        for cut in 0..HEADER_LEN {
            assert!(decode(&enc[..cut]).is_none(), "cut={cut}");
        }
    }

    #[test]
    fn invalid_utf8_body_is_rejected() {
        let mut enc = encode(&[5u8; 16], 1, "ok").unwrap();
        enc.push(0xff); // непрерывный байт в теле
        assert!(decode(&enc).is_none());
    }

    #[test]
    fn oversized_body_is_rejected() {
        let big = "x".repeat(MAX_BODY_LEN + 1);
        assert!(encode(&[6u8; 16], 1, &big).is_none());
    }

    #[test]
    fn plain_message_is_not_mistaken_for_first() {
        // Обычное сообщение (2-е и далее) начинается с 0x02 — заголовка нет.
        let enc = encode(&[8u8; 16], 1, "второе").unwrap();
        let mut plain = vec![0x02u8];
        plain.extend_from_slice(&enc[HEADER_LEN..]);
        assert!(decode(&plain).is_none());
    }
}
