//! Формат логов relay: маскирование идентификаторов.
//!
//! Логи — это метаданные, и они остаются на диске узла. Поэтому по умолчанию в
//! лог попадает не `mailbox_id`, а его короткий хэш (`mb=3f9a1c02`): по нему
//! видно, что события относятся к одной сессии, и можно коррелировать, но на
//! диске не оседает список адресов, к которым обращались.
//!
//! Полные идентификаторы включаются переменной `MIN_LOG_FULL_IDS=1` — на время
//! конкретной отладки (`RUST_LOG`/relay.env), а не постоянно.
//!
//! Payload/envelope/pull_token/plaintext в логи не попадают **никогда** —
//! только размеры, счётчики и коды ошибок.
//!
//! Хэш — FNV-1a 64 (берём старшие 32 бита → 8 hex): детерминирован между
//! запусками и версиями Rust, нулевые зависимости. Криптостойкость тут не
//! нужна: `mailbox_id` — не секрет (выводится из публичного identity-ключа,
//! PROTOCOL §5), задача маски — не превратить лог в список адресов.

use std::sync::OnceLock;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a, 64 бита.
pub fn hash64(bytes: &[u8]) -> u64 {
    let mut h = FNV_OFFSET;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Включены ли полные идентификаторы в логах (`MIN_LOG_FULL_IDS=1`).
///
/// Читается один раз за процесс: переменная влияет только на формат логов,
/// а не на логику, поэтому менять её на ходу не нужно.
pub fn full_ids() -> bool {
    static FULL: OnceLock<bool> = OnceLock::new();
    *FULL.get_or_init(|| match std::env::var("MIN_LOG_FULL_IDS") {
        Ok(v) => matches!(v.trim(), "1" | "true" | "yes" | "on"),
        Err(_) => false,
    })
}

/// Маскирует идентификатор: 8 hex от FNV-1a либо как есть при `full = true`.
///
/// Пустая строка остаётся пустой — в логе это видно как «нет идентификатора».
pub fn mask_with(id: &str, full: bool) -> String {
    if full || id.is_empty() {
        return id.to_string();
    }
    let h = hash64(id.as_bytes());
    format!("{:08x}", (h >> 32) as u32)
}

/// Маскированный идентификатор для логов (с учётом `MIN_LOG_FULL_IDS`).
pub fn mask(id: &str) -> String {
    mask_with(id, full_ids())
}

/// Огрубляет размер сообщения до порядкового диапазона.
///
/// MIN-RED-014: точная длина каждого конверта в логе — это метаданные
/// (наблюдатель диск/оператор реле узнаёт длину каждого сообщения и может
/// строить профиль активности). Для диагностики достаточно знать класс
/// размера, поэтому в логи идут только границы диапазона.
///
/// Границы выбраны по типичным размерам: control-кадры (<512 B),
/// короткий текст, длинный текст, медиа-конверты (пока не реализованы).
pub fn size_class(len: usize) -> &'static str {
    match len {
        0..=255 => "<=255",
        256..=1023 => "256-1k",
        1024..=4095 => "1k-4k",
        4096..=16383 => "4k-16k",
        16384..=65535 => "16k-64k",
        _ => ">64k",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv_is_stable_and_known() {
        // Контрольные значения FNV-1a 64: ломается только осознанным изменением
        // алгоритма (иначе поехала бы корреляция логов между версиями).
        assert_eq!(hash64(b""), FNV_OFFSET);
        assert_eq!(hash64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(hash64(b"foobar"), 0x85944171f73967e8);
    }

    #[test]
    fn mask_is_short_hex_and_hides_input() {
        let id = "a3f19c0b7d2e4f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c";
        let m = mask_with(id, false);
        assert_eq!(m.len(), 8, "маска — 8 hex: {m}");
        assert!(m.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!m.contains(id), "маска не должна содержать оригинал");
        assert_ne!(m, id);
    }

    #[test]
    fn mask_is_deterministic_and_distinguishes_ids() {
        let a = mask_with("mailbox-alice", false);
        let b = mask_with("mailbox-alice", false);
        let c = mask_with("mailbox-bob", false);
        assert_eq!(a, b, "один id → одна маска (корреляция логов)");
        assert_ne!(a, c, "разные id → разные маски");
    }

    #[test]
    fn full_mode_returns_id_as_is() {
        assert_eq!(mask_with("mailbox-alice", true), "mailbox-alice");
    }

    #[test]
    fn empty_id_stays_empty() {
        assert_eq!(mask_with("", false), "");
        assert_eq!(mask_with("", true), "");
    }

    #[test]
    fn hash_handles_binary_and_utf8() {
        // item_id/hex-подобные строки и произвольный UTF-8 не должны паниковать.
        let _ = mask_with("\u{1F512}-ключ", false);
        let _ = hash64(&[0u8, 255, 128, 7]);
    }

    /// MIN-RED-014: `size_class` не должен выдавать точную длину — иначе
    /// оператор реле по логу восстанавливает длину каждого сообщения.
    #[test]
    fn size_class_never_reveals_exact_length() {
        // Границы диапазонов: соседние значения обязаны попадать в один класс,
        // а строка класса не должна содержать само число.
        let cases: &[(usize, &str)] = &[
            (0, "<=255"),
            (1, "<=255"),
            (255, "<=255"),
            (256, "256-1k"),
            (1023, "256-1k"),
            (1024, "1k-4k"),
            (4095, "1k-4k"),
            (4096, "4k-16k"),
            (16383, "4k-16k"),
            (16384, "16k-64k"),
            (65535, "16k-64k"),
            (65536, ">64k"),
            (256 * 1024, ">64k"),
        ];
        for (len, expected) in cases {
            assert_eq!(size_class(*len), *expected, "len={len}");
        }
    }

    /// Ключевой инвариант: длины ВНУТРИ одного класса неразличимы, иначе
    /// наблюдатель сузил бы длину сообщения подбором по границе диапазона.
    /// Границы классов (255/256, 1023/1024, …) намеренно различают — это цена
    /// огрубления, а не утечка: точная длина всё равно недоступна.
    #[test]
    fn size_class_is_coarse_enough_to_hide_length() {
        // Длины заведомо НЕ на границах диапазонов.
        for len in [
            1usize, 100, 200, 300, 500, 1000, 2000, 5000, 10000, 30000, 100_000,
        ] {
            let here = size_class(len);
            assert_eq!(size_class(len + 1), here, "len={len}: сосед смешан");
            assert_eq!(size_class(len - 1), here, "len={len}: пред. смешан");
        }
    }

    /// Границы диапазонов — единственные точки смены класса; их ровно четыре,
    /// и они раскрывают лишь факт перехода порога, но не длину.
    #[test]
    fn size_class_boundaries_are_limited_and_known() {
        let boundaries: Vec<usize> = (1..=20_000)
            .filter(|&len| size_class(len) != size_class(len - 1))
            .collect();
        assert_eq!(
            boundaries,
            vec![256, 1024, 4096, 16384],
            "лишних границ быть не должно"
        );
    }
}
