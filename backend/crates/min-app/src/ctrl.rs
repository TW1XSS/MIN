//! CONTROL-ответы на заявку (E2E, внутри сессии).
//!
//! # Зачем
//!
//! Отправитель должен получить определённость: «отправлено» навсегда —
//! это ложь. Но различать «отклонено» / «заблокировано» / «заявки выключены»
//! **нельзя**: каждый такой ответ раскрывает решение получателя постороннему.
//! Отклонение — это read-receipt (мы доказали, что текст прочитан),
//! блокировка — самый сильный сигнал для спамера, а «заявки выключены»
//! позволяет построить карту интересов перебором invite-кодов.
//!
//! Поэтому на провод уходит **один нейтральный код** без причины, а локально
//! (в своём UI) получатель знает, что именно произошло.
//!
//! # Формат (5 байт, строгий)
//!
//! ```text
//! [0..4) magic "MINC"
//! [4]    код: 1 = accepted, 2 = not delivered
//! ```
//!
//! Никакой CBOR: payload не структурирован, поле-причина сознательно
//! отсутствует. Фиксированная длина исключает «хвост с подсказкой».

/// Магическое начало CONTROL-ответа.
pub const MAGIC: [u8; 4] = *b"MINC";

/// Полная длина CONTROL-ответа.
pub const LEN: usize = 5;

/// Код ответа получателя.
///
/// На провод уходят только эти два значения. Локально вызывающая сторона
/// знает больше (причина хранится в своей очереди заявок), но наружу не
/// отдаёт.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Заявка принята, чат открыт, отправитель может писать дальше.
    Accepted,
    /// Нейтральный отказ: отклонено, заблокировано или заявки выключены.
    /// Отправитель обязан показать одинаковый текст во всех трёх случаях.
    NotDelivered,
}

impl Outcome {
    fn code(self) -> u8 {
        match self {
            Outcome::Accepted => 1,
            Outcome::NotDelivered => 2,
        }
    }
}

/// Кодирует ответ получателя.
pub fn encode(outcome: Outcome) -> Vec<u8> {
    let mut out = Vec::with_capacity(LEN);
    out.extend_from_slice(&MAGIC);
    out.push(outcome.code());
    out
}

/// Разбирает ответ. Строго: неверная магия, длина, неизвестный код — `None`.
pub fn decode(plaintext: &[u8]) -> Option<Outcome> {
    if plaintext.len() != LEN {
        return None;
    }
    if plaintext[..4] != MAGIC {
        return None;
    }
    match plaintext[4] {
        1 => Some(Outcome::Accepted),
        2 => Some(Outcome::NotDelivered),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_accepted() {
        let enc = encode(Outcome::Accepted);
        assert_eq!(enc.len(), LEN);
        assert_eq!(decode(&enc), Some(Outcome::Accepted));
    }

    #[test]
    fn round_trip_not_delivered() {
        let enc = encode(Outcome::NotDelivered);
        assert_eq!(decode(&enc), Some(Outcome::NotDelivered));
    }

    #[test]
    fn all_codes_are_distinct_and_neutral() {
        // Ключевой инвариант: ровно ДВА кода на проводе. Реальная причина
        // (отклонено/заблокировано/выключено) наружу не уходит никогда.
        assert_ne!(encode(Outcome::Accepted), encode(Outcome::NotDelivered));
    }

    #[test]
    fn wrong_length_is_rejected() {
        let enc = encode(Outcome::Accepted);
        assert!(decode(&enc[..LEN - 1]).is_none());
        let mut longer = enc.clone();
        longer.push(0);
        assert!(decode(&longer).is_none());
    }

    #[test]
    fn wrong_magic_is_rejected() {
        let mut enc = encode(Outcome::Accepted);
        enc[0] = b'Z';
        assert!(decode(&enc).is_none());
    }

    #[test]
    fn unknown_code_is_rejected() {
        let mut enc = encode(Outcome::Accepted);
        enc[4] = 9;
        assert!(decode(&enc).is_none());
    }

    #[test]
    fn ordinary_chat_text_is_not_a_control() {
        // Обычный текст пользователя не должен разбираться как CONTROL.
        assert!(decode(b"ok").is_none());
        assert!(decode(b"MINC").is_none());
    }
}
