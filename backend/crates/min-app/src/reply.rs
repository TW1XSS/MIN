//! Цитата ответа внутри зашифрованного payload.
//!
//! Почему так, а не отдельным полем в записи: полем в записи цитата осталась
//! бы только на этом устройстве (запись создаётся при расшифровке), а нам
//! нужно, чтобы вторая сторона её увидела. Значит цитата обязана ехать по
//! проводу — внутри E2E-plaintext, который relay не читает.
//!
//! Формат: `\u{2}reply\u{2}<автор>\u{2}<превью>\n<текст>`.
//! - Префикс `\u{2}reply\u{2}` не может встретиться в обычном тексте: автор
//!   и превью sanit'ятся (убираются `\u{2}` и переводы строк), поэтому даже
//!   злонамеренный текст не выдаст себя за ответ.
//! - Старые сообщения (без префикса) читаются как обычный текст — совместимость
//!   в обе стороны, формат §11, версию протокола не трогает.
//! - Превью обрезается: плашка в пузыре не должна раздувать payload.

use crate::model::ReplyRef;

/// Максимальная длина превью цитаты в байтах.
const PREVIEW_MAX: usize = 160;
const MARK: &str = "\u{2}reply\u{2}";

fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| *c != '\u{2}' && *c != '\n' && *c != '\r')
        .collect()
}

fn truncate(s: &str) -> String {
    if s.len() <= PREVIEW_MAX {
        s.to_string()
    } else {
        let mut end = PREVIEW_MAX;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}

/// Кодирует ответ. `text` — то, что человек набрал.
pub fn encode(reply: Option<&ReplyRef>, text: &str) -> String {
    match reply {
        None => text.to_string(),
        Some(r) => format!(
            "{MARK}{}\u{2}{}\n{text}",
            sanitize(&r.author),
            truncate(&sanitize(&r.preview))
        ),
    }
}

/// Разбирает payload: возвращает цитату (если есть) и сам текст.
pub fn decode(payload: &str) -> (Option<ReplyRef>, String) {
    let Some(rest) = payload.strip_prefix(MARK) else {
        return (None, payload.to_string());
    };
    let mut parts = rest.splitn(3, '\u{2}');
    let (Some(author), Some(preview_tail)) = (parts.next(), parts.next()) else {
        // Некорректный заголовок — не теряем текст, показываем как есть.
        return (None, payload.to_string());
    };
    // Заголовок без перевода строки — это не цитата, а битый payload: раньше
    // здесь возвращалась `(Some(цитата), "")` и ТЕКСТ СООБЩЕНИЯ ИСЧЕЗАЛ, то
    // есть отправитель мог заставить получателя увидеть пустое сообщение с
    // чужой подписью. Показываем payload как есть — потеря данных недопустима.
    let (preview, text) = match preview_tail.split_once('\n') {
        Some((p, t)) => (p.to_string(), t.to_string()),
        None => return (None, payload.to_string()),
    };
    (
        Some(ReplyRef {
            author: author.to_string(),
            preview,
        }),
        text,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let r = ReplyRef {
            author: "Алиса".into(),
            preview: "привет".into(),
        };
        let wire = encode(Some(&r), "ответ");
        let (got, text) = decode(&wire);
        assert_eq!(got, Some(r));
        assert_eq!(text, "ответ");
    }

    #[test]
    fn plain_text_has_no_reply() {
        let (r, t) = decode("обычное сообщение");
        assert!(r.is_none());
        assert_eq!(t, "обычное сообщение");
    }

    /// Настоящее свойство: цитата не может ПОДДЕЛАТЬСЯ внутри текста.
    /// Отправитель в принципе может прислать любую цитату — это его право.
    /// Но текст, который лишь СОДЕРИТ маркер, не должен разбираться как ответ
    /// (маркер распознаётся только в начале), а автор/превью санитайзятся, так
    /// что вложенный маркер вырезается и заголовок не собирается заново.
    #[test]
    fn text_cannot_forge_a_reply() {
        let (r, t) = decode("смотри \u{2}reply\u{2}вот\u{2}тут");
        assert!(r.is_none(), "маркер в середине не делает сообщение ответом");
        assert!(t.contains("смотри"));

        let evil = ReplyRef {
            author: "A\u{2}reply\u{2}B\u{2}C".into(),
            preview: "p".into(),
        };
        let (got, text) = decode(&encode(Some(&evil), "тело"));
        let got = got.expect("цитата разбирается");
        assert_eq!(got.author, "AreplyBC", "вложенные маркеры вырезаны");
        assert_eq!(text, "тело", "текст не разъехался");
    }

    /// Перевод строки в авторe/превью ломает разбор — sanit'им при кодировании.
    #[test]
    fn newlines_in_author_are_sanitized() {
        let r = ReplyRef {
            author: "А\nБ".into(),
            preview: "п\nр".into(),
        };
        let (got, text) = decode(&encode(Some(&r), "тело"));
        let got = got.expect("цитата должна разобраться");
        assert_eq!(got.author, "АБ");
        assert_eq!(got.preview, "пр");
        assert_eq!(text, "тело");
    }

    #[test]
    fn preview_is_truncated() {
        let r = ReplyRef {
            author: "A".into(),
            preview: "я".repeat(1000),
        };
        let (got, _) = decode(&encode(Some(&r), "t"));
        assert!(got.unwrap().preview.len() <= PREVIEW_MAX + 4);
    }

    /// Неполный заголовок цитаты (нет перевода строки) НЕ должен молча
    /// превращать сообщение в пустое: получатель обязан увидеть текст как есть.
    ///
    /// Найдено на аудите: `decode` при `preview_tail` без `\n` возвращал
    /// `(Some(цитата), "")` — текст исчезал, а цитата показывалась с пустым
    /// телом. Для отправителя это выглядит как «сообщение пропало».
    #[test]
    fn truncated_reply_header_does_not_blank_the_message() {
        // Заголовок без перевода строки — обычный текст, разбор не должен
        // «съесть» содержимое.
        let forged = "\u{2}reply\u{2}Алиса\u{2}как дела?";
        let (r, t) = decode(forged);
        assert!(r.is_none(), "битый заголовок не цитата");
        assert_eq!(t, forged, "текст показан как есть, ничего не потеряно");

        // Совсем пустой хвост тоже безопасен.
        let (r, t) = decode("\u{2}reply\u{2}");
        assert!(r.is_none());
        assert_eq!(t, "\u{2}reply\u{2}");
    }

    /// Автор цитаты не аутентифицирован: любой отправитель может подписать
    /// чужое имя. Это заложено в формат, но должно быть осознанно — иначе
    /// получится подделка атрибуции в интерфейсе.
    #[test]
    fn quote_author_is_claimed_not_verified() {
        let r = ReplyRef {
            author: "Алиса".into(),
            preview: "я никогда этого не писала".into(),
        };
        let (got, text) = decode(&encode(Some(&r), "согласен"));
        assert_eq!(got.unwrap().author, "Алиса");
        assert_eq!(text, "согласен");
        // Значит защиты на уровне формата нет и быть не может: цитата —
        // это утверждение отправителя. Проверка здесь фиксирует намерение,
        // чтобы его не «закрыли» наивным доверием полю author.
    }
}
