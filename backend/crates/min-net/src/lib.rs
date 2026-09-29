//! MIN networking layer: transport abstraction, size-class padding and
//! batch constants.
//!
//! Purpose (README: минимализация метаданных):
//! - relay must not learn exact message sizes from frame lengths;
//! - batch pull hides message frequency;
//! - Transport trait lets us inject Tor (prod) vs direct TCP (tests)
//!   without touching protocol logic.

use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

/// Upper bound from PROTOCOL §3 (max envelope 256 KiB).
const MAX_ENVELOPE: usize = 256 * 1024;

/// Size classes for padding. Every real envelope is padded UP to a class
/// boundary so relay cannot infer content size from frame length.
pub const PADDING_CLASSES: &[usize] =
    &[256, 512, 1024, 2048, 4096, 8192, 16384, 65536, MAX_ENVELOPE];

/// Default batch size for pull (README: batching / no per-message round-trips).
pub const DEFAULT_BATCH_SIZE: usize = 16;

/// Errors returned by the net layer.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum NetError {
    #[error("payload exceeds max envelope size")]
    PayloadTooLarge,
    #[error("invalid padding header")]
    InvalidPadding,
    #[error("transport error: {0}")]
    Transport(String),
}

pub type NetResult<T> = Result<T, NetError>;

/// Pads `payload` up to a size class boundary (metadata minimization).
///
/// Format: `[u16be real_len][payload][random padding]`. Randomness within
/// the class window hides the exact content length.
pub fn pad_payload<R: RngCore + CryptoRng>(payload: &[u8], rng: &mut R) -> NetResult<Vec<u8>> {
    let total = payload.len() + 2; // length header
    if total > MAX_ENVELOPE {
        return Err(NetError::PayloadTooLarge);
    }
    let target = PADDING_CLASSES
        .iter()
        .copied()
        .find(|c| *c >= total)
        .ok_or(NetError::PayloadTooLarge)?;

    // MIN-RED-011: равномерный выбор длины окна padding'а через rejection
    // sampling (см. `uniform_span`/`accept_threshold`). Смещение остатков не
    // давало утечки длины payload, но делало заявленное свойство «равномерное
    // окно» неверным, поэтому исправлено и теперь проверяется точным тестом.
    let extra = if target > total {
        uniform_span(rng, (target - total) as u32)
    } else {
        0
    };
    let mut buf = Vec::with_capacity(target);
    let payload_len = u16::try_from(payload.len()).map_err(|_| NetError::PayloadTooLarge)?;
    buf.extend_from_slice(&payload_len.to_be_bytes());
    buf.extend_from_slice(payload);
    buf.resize(target, 0);
    let tail_start = total;
    let tail_end = (total + extra).min(target);
    for byte in &mut buf[tail_start..tail_end] {
        *byte = (rng.next_u32() & 0xFF) as u8;
    }
    Ok(buf)
}

/// Uniform value in `[0, span)` without modulo bias.
///
/// MIN-RED-011. Происхождение дефекта: изначально здесь было
/// `rng.next_u32() % span` — это смещение для любого `span`, не делящего
/// `2^32`. Затем границу отбрасывания вывели от `u32::MAX`, но неверно:
/// см. доказательство в `accept_threshold` ниже.
///
/// Оценка влияния (важно не преувеличивать): само смещение `1/2^32`
/// **не является** эксплуатируемой утечкой длины payload — наблюдатель и так
/// видит длину конверта из CBOR-заголовка. Ценность правки в том, что код
/// теперь действительно обеспечивает заявленное свойство «равномерное окно»,
/// а доказательство на это свойство не эвристическое, а точное. Регрессия
/// защищена тестами, которые падают на прежней формуле для любого `span`,
/// где `2^32 mod span != 1`.
fn uniform_span<R: RngCore + CryptoRng>(rng: &mut R, span: u32) -> usize {
    if span <= 1 {
        return 0;
    }
    let accept = accept_threshold(span);
    loop {
        let v = rng.next_u32() as u64;
        if v < accept {
            return (v % span as u64) as usize;
        }
    }
}

/// Верхняя граница (exclusive) принятых значений `next_u32()` для `span`.
///
/// Множество значений `next_u32()` — ровно `[0, 2^32)`, то есть `TOTAL`
/// элементов. Чтобы `v % span` был равномерен, число принятых значений должно
/// быть КРАТНО `span`. Берём наибольшее кратное `span`, не превосходящее
/// `TOTAL`, и отбрасываем всё, что не меньше него:
///
/// ```text
/// accept = (TOTAL / span) * span
/// приняты ровно значения [0, accept)
/// ```
///
/// MIN-RED-011: прежняя граница считалась от `u32::MAX` как
/// `u32::MAX - (u32::MAX % span)`, то есть принимала
/// `u32::MAX - (u32::MAX % span) + 1` значений. Эта величина кратна `span`
/// только когда `2^32 ≡ 1 (mod span)`. Для `span = 3`, например,
/// `u32::MAX % 3 == 0`, значит принимались все `2^32` значений, а
/// `2^32 mod 3 == 1` — остаток `0` оказывался строго вероятнее остальных.
/// Смещение величиной `1/2^32` статистически не наблюдаемо, но доказуемо
/// точно, поэтому граница выводится из `2^32`, а не из `u32::MAX`.
const fn accept_threshold(span: u32) -> u64 {
    let total = 1u64 << 32;
    (total / span as u64) * span as u64
}

/// Removes padding, returning the original payload.
pub fn unpad_payload(padded: &[u8]) -> NetResult<Vec<u8>> {
    if padded.len() < 2 {
        return Err(NetError::InvalidPadding);
    }
    // Strict transport shape: a padded frame length must be one of the
    // published size classes. Without this, `[0,0]` and arbitrary short/long
    // frames pass unpadding and violate the fail-closed parser contract.
    if !PADDING_CLASSES.contains(&padded.len()) {
        return Err(NetError::InvalidPadding);
    }
    let len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if len > padded.len() - 2 {
        return Err(NetError::InvalidPadding);
    }
    Ok(padded[2..2 + len].to_vec())
}

/// Transport abstraction. Implementations:
/// - tests: in-memory pipe;
/// - MVP: direct TCP only for localhost integration tests (dev tooling);
/// - prod: Tor circuit (C Tor/IPtProxy on iOS; Arti-compatible SOCKS link) —
pub trait Transport {
    fn send(&mut self, payload: &[u8]) -> NetResult<()>;
    fn recv(&mut self) -> NetResult<Option<Vec<u8>>>;
    fn is_open(&self) -> bool;
}

/// Convenience: writes `payload` as `u32be(len)||payload` (PROTOCOL §7).
pub fn write_frame<W: std::io::Write>(w: &mut W, payload: &[u8]) -> NetResult<()> {
    let len = u32::try_from(payload.len()).map_err(|_| NetError::PayloadTooLarge)?;
    w.write_all(&len.to_be_bytes())
        .map_err(|e| NetError::Transport(e.to_string()))?;
    w.write_all(payload)
        .map_err(|e| NetError::Transport(e.to_string()))?;
    Ok(())
}

/// Reads one frame from `r`, enforcing the framing rule (PROTOCOL §7).
pub fn read_frame(r: &mut impl std::io::Read) -> NetResult<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(NetError::Transport(e.to_string())),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_ENVELOPE {
        return Err(NetError::PayloadTooLarge);
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)
        .map_err(|e| NetError::Transport(e.to_string()))?;
    Ok(Some(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn padding_roundtrip() {
        let mut rng = OsRng;
        for len in [0usize, 1, 2, 100, 255, 256, 512, 1000] {
            let payload = vec![0xAB; len];
            let padded = pad_payload(&payload, &mut rng).unwrap();
            assert!(padded.len() >= 256, "len={} padded={}", len, padded.len());
            assert!(padded.len() <= MAX_ENVELOPE);
            let back = unpad_payload(&padded).unwrap();
            assert_eq!(back, payload, "roundtrip failed for len {len}");
        }
    }

    #[test]
    fn padding_hides_length_variability() {
        // Everything ≤ 254 bytes pads to ≥ 256, so exact length is not
        // inferable from frame size.
        let mut rng = OsRng;
        for len in 0..=254 {
            let payload = vec![0u8; len];
            let padded = pad_payload(&payload, &mut rng).unwrap();
            assert!(padded.len() >= 256);
        }
    }

    #[test]
    fn padding_rejects_oversize() {
        let mut rng = OsRng;
        let big = vec![0u8; MAX_ENVELOPE];
        assert_eq!(
            pad_payload(&big, &mut rng).unwrap_err(),
            NetError::PayloadTooLarge
        );
    }

    #[test]
    fn unpad_rejects_garbage() {
        // Length claims more than available.
        let bad = vec![0xFF, 0xFF, 1, 2, 3];
        assert_eq!(unpad_payload(&bad).unwrap_err(), NetError::InvalidPadding);
        // Too short / non-class frame, including the previously accepted `[0,0]`.
        for frame in [vec![], vec![0], vec![0, 0], vec![7; 255], vec![7; 257]] {
            assert_eq!(unpad_payload(&frame).unwrap_err(), NetError::InvalidPadding);
        }
    }

    #[test]
    fn padding_roundtrip_output_always_uses_published_class() {
        let mut rng = OsRng;
        for len in [0usize, 1, 2, 100, 254, 255, 256, 512, 65_535] {
            let padded = pad_payload(&vec![0x5A; len], &mut rng).unwrap();
            assert!(PADDING_CLASSES.contains(&padded.len()));
        }
    }

    /// Детерминированный RNG: выдаёт заданную последовательность u32 по кругу.
    ///
    /// Нужен, чтобы проверять `uniform_span` на **конкретных** значениях
    /// диапазона, включая границу отбрасывания. При `OsRng` смещение величиной
    /// `1/2^32` принципиально не наблюдаемо за разумное число сэмплов, поэтому
    /// статистика здесь бессильна и доказательство обязано быть точным.
    struct SeqRng {
        values: Vec<u32>,
        pos: usize,
        /// Сколько u32 запросила функция — этим видно отбрасывание.
        drawn: usize,
    }

    impl rand_core::RngCore for SeqRng {
        fn next_u32(&mut self) -> u32 {
            let v = self.values[self.pos % self.values.len()];
            self.pos += 1;
            self.drawn += 1;
            v
        }
        fn next_u64(&mut self) -> u64 {
            u64::from(self.next_u32()) << 32 | u64::from(self.next_u32())
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for b in dest {
                *b = self.next_u32() as u8;
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    // Тесты доверяют заранее заданной последовательности.
    impl rand_core::CryptoRng for SeqRng {}

    /// MIN-RED-011: безусловная проверка двух свойств границы отбрасывания.
    ///
    /// Свойство 1 (корректность): число принятых значений кратно `span`.
    /// Тогда на каждый остаток приходится ровно `accept / span` значений, то
    /// есть `v % span` равномерен. Старая граница считалась от `u32::MAX`:
    /// при `span = 3` получалось `accept = 2^32`, а `2^32 mod 3 == 1`, то есть
    /// остаток `0` был строго вероятнее любого другого.
    ///
    /// Свойство 2 (максимальность): `accept + span > 2^32` — отбрасывается
    /// минимально возможный хвост, иначе rejection sampling теряет скорость.
    ///
    /// Проверка безусловна: смещение `1/2^32` не нужно наблюдать
    /// статистически, достаточно посчитать точное число принятых значений.
    #[test]
    fn accept_threshold_is_largest_span_multiple_below_2_32() {
        const TOTAL: u64 = 1 << 32;
        let mut spans: Vec<u32> = (2u32..=512).collect();
        // Границы из опыта: делители 2^32-1 и соседние значения.
        spans.extend([513u32, 1_000, 1_024, 65_535, 65_537, 0xFFFF_FFFF]);
        for span in spans {
            let accept = accept_threshold(span);
            assert_eq!(
                accept % span as u64,
                0,
                "span={span}: принятых значений {accept} не кратно span — остатки неравномерны"
            );
            assert!(
                accept + span as u64 > TOTAL,
                "span={span}: граница {accept} не максимальна — отбрасывается лишний хвост"
            );
            assert!(
                accept <= TOTAL,
                "span={span}: граница {accept} вне диапазона next_u32()"
            );
        }
    }

    /// MIN-RED-011: поведение на границе. Хвост из `2^32 mod span` значений
    /// обязан отбрасываться: первое из них требует ровно одной повторной
    /// выборки, последнее принятое — ни одной. Неверная граница (от
    /// `u32::MAX`) принимала часть хвоста и возвращала смещённый остаток с
    /// первой попытки.
    #[test]
    fn uniform_span_rejects_the_remainder_tail() {
        const TOTAL: u64 = 1 << 32;
        for span in [3u32, 5, 6, 7, 100, 1_000, 65_535] {
            // Ожидание считается из первых принципов, а НЕ из production-функции:
            // иначе тест был бы циклическим и проходил бы на багованном коде.
            let required_accept = (TOTAL / span as u64) * span as u64;
            if TOTAL - required_accept == 0 {
                // span делит 2^32 — отбрасывать нечего, это корректный случай.
                continue;
            }
            let first_rejected = required_accept as u32;
            let mut rng = SeqRng {
                values: vec![first_rejected, 0],
                pos: 0,
                drawn: 0,
            };
            let got = uniform_span(&mut rng, span);
            assert_eq!(
                rng.drawn, 2,
                "span={span}: значение {first_rejected} обязано быть отброшено \
                 (принятые значения обязаны быть кратны span)"
            );
            assert_eq!(got, 0, "span={span}: после отбрасывания берётся 0");

            let last_accepted = (required_accept - 1) as u32;
            let mut rng = SeqRng {
                values: vec![last_accepted],
                pos: 0,
                drawn: 0,
            };
            let got = uniform_span(&mut rng, span);
            assert_eq!(
                rng.drawn, 1,
                "span={span}: значение {last_accepted} обязано приниматься сразу"
            );
            assert_eq!(got as u64, last_accepted as u64 % span as u64);
        }
    }

    /// Дымовая проверка «не совсем сломано». Это НЕ доказательство отсутствия
    /// смещения: при `span = 3` абсолютная разница — один исход на 2^32
    /// значений, поэтому такой тест проходит и на заведомо смещённом коде.
    /// Корректность обеспечивают два теста выше.
    #[test]
    fn uniform_span_smoke_is_not_fully_broken() {
        use rand_core::RngCore as _;
        let mut rng = OsRng;
        let n = 30_000u32;
        let mut counts = [0u32; 3];
        for _ in 0..n {
            counts[uniform_span(&mut rng, 3)] += 1;
        }
        let expected = n as f64 / 3.0;
        for c in counts {
            let rel = (c as f64 - expected).abs() / expected;
            assert!(rel < 0.05, "uniform_span grossly broken: counts={counts:?}");
        }
        assert!(
            counts.iter().all(|&c| c > 0),
            "every bucket must be reachable"
        );
        let _ = std::hint::black_box(&mut rng.next_u32());
    }

    /// MIN-RED-011: кадры одного класса должны давать разный объём padding'а,
    /// иначе длина выдаёт границы payload.
    #[test]
    fn padding_window_varies_within_class() {
        let mut rng = OsRng;
        let mut widths = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let padded = pad_payload(&vec![0x11; 300], &mut rng).unwrap();
            // Первые два байта — заголовок, далее payload, далее хвост.
            widths.insert(padded.len());
        }
        assert_eq!(widths.len(), 1, "frame size must stay in one size class");
        // Отдельно: объём заполненного нулями хвоста обязан варьировать.
        let mut tails = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let padded = pad_payload(&vec![0x11; 300], &mut rng).unwrap();
            let zeros = padded[302..].iter().filter(|&&b| b == 0).count();
            tails.insert(zeros);
        }
        assert!(
            tails.len() > 1,
            "padding window must vary, otherwise payload size leaks"
        );
    }

    #[test]
    fn padding_length_header_rejects_above_u16() {
        let mut rng = OsRng;
        assert_eq!(
            pad_payload(&vec![0u8; 65_536], &mut rng).unwrap_err(),
            NetError::PayloadTooLarge
        );
    }

    #[test]
    fn frame_roundtrip() {
        let payload = b"hello min";
        let mut buf = Vec::new();
        write_frame(&mut buf, payload).unwrap();
        let mut cur = std::io::Cursor::new(&buf);
        let got = read_frame(&mut cur).unwrap();
        assert_eq!(got, Some(payload.to_vec()));
        assert_eq!(read_frame(&mut cur).unwrap(), None, "clean EOF");
    }

    #[test]
    fn frame_rejects_huge_length() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut cur = std::io::Cursor::new(&buf);
        assert_eq!(read_frame(&mut cur).unwrap_err(), NetError::PayloadTooLarge);
    }
}
