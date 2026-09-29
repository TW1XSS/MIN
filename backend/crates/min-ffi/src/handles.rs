//! Реестр живых FFI-handle (`min-ffi`).
//!
//! MIN-RED-007: `extern "C"`-функции освобождения получали «сырой» указатель от
//! вызывающей стороны и без проверок делали `Box::from_raw`. Двойной free = UB,
//! использование после free = UB (PoC: SIGSEGV на double free).
//!
//! Реестр даёт определённое поведение вместо UB:
//! - повторный `free` — тихий no-op + диагностика в `last_error`;
//! - вызов после `free` — `NULL`, а не чтение освобождённой памяти.
//!
//! Указатели берутся из сырой памяти только после успешной проверки по адресу,
//! поэтому само чтение/освобождение вызывается лишь для зарегистрированного
//! handle. Ограничение (осознанное): если freed-адрес немедленно переиспользован
//! новым handle, «старый» указатель станет валидным — это неотличимо от корректного
//! доступа и для целей FFI-дисциплины безвредно.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

fn registry() -> &'static Mutex<HashSet<usize>> {
    static REGISTRY: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Mutex может быть отравлен, если паника случилась внутри critical section;
/// данные здесь всегда валидны, поэтому восстанавливаем владение, а не паникуем.
fn with_registry<R>(f: impl FnOnce(&mut HashSet<usize>) -> R) -> R {
    let mut guard = registry().lock().unwrap_or_else(|e| e.into_inner());
    f(&mut guard)
}

/// Регистрирует новый handle, выделенный вызывающей стороне.
pub fn insert(ptr: usize) {
    with_registry(|set| {
        set.insert(ptr);
    });
}

/// Снимает handle с учёта. `true` — handle был живой (и его нужно освободить),
/// `false` — уже освобождён/неизвестен (освобождать НЕЛЬЗЯ).
pub fn remove(ptr: usize) -> bool {
    with_registry(|set| set.remove(&ptr))
}

/// Жив ли handle. Все `extern "C"` входные точки проверяют это до `&mut *ptr`.
pub fn is_live(ptr: usize) -> bool {
    with_registry(|set| set.contains(&ptr))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Адреса-«ручки» в тесте не разыменовываются: проверяется только логика
    /// реестра (insert/remove/is_live).
    #[test]
    fn double_remove_reports_second_as_not_live() {
        let handle = 0x1000_0000usize;
        insert(handle);
        assert!(is_live(handle));
        assert!(remove(handle), "первый remove обязан снять handle");
        assert!(!is_live(handle), "после free handle не жив");
        assert!(
            !remove(handle),
            "второй remove обязан вернуть false (no-op)"
        );
    }

    #[test]
    fn unknown_handle_is_not_live() {
        assert!(!is_live(0xDEAD_BEEF));
        assert!(!remove(0xDEAD_BEEF));
    }

    #[test]
    fn reallocated_address_is_registered_again() {
        let handle = 0x2000_0000usize;
        insert(handle);
        assert!(remove(handle));
        // Новый handle может получить тот же адрес — реестр обязан его принять.
        insert(handle);
        assert!(is_live(handle));
        assert!(remove(handle));
    }
}
