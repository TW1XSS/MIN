//! Ограниченное чтение C-строк на границе FFI (`min-ffi`).
//!
//! MIN-RED-011: `CStr::from_ptr` сканирует память до NUL **без ограничения**.
//! Это контракт вызывающей стороны (Swift `withCString` всегда NUL-терминирует),
//! но на границе FFI это неконтролируемое чтение и неконтролируемая аллокация:
//! при ошибочном (висящем) указателе процесс будет читать память до
//! «случайного» нуля.
//!
//! Здесь строка читается **побайтово** с жёстким потолком. Срез
//! `from_raw_parts(ptr, N)` не используется намеренно: такой срез создал бы
//! ссылку за пределы фактического выделения, что само по себе UB.
//!
//! Потолок намеренно намного выше любой легитимной нагрузки (invite ≈ 8 КиБ,
//! PROTOCOL §3 ограничивает envelope 256 КиБ), поэтому функционально ничего не
//! ломает, но делает поведение определённым при ошибочном указателе.
use std::os::raw::c_char;

/// Потолок длины входной C-строки (1 МиБ).
pub const MAX_CSTR_BYTES: usize = 1024 * 1024;

/// Побайтовое чтение C-строки с потолком длины.
/// `None` для NULL, не-терминированной или слишком длинной строки.
///
/// # Safety
/// `ptr` должен быть либо NULL, либо указывать на NUL-терминированную строку
/// (или на буфер, где NUL гарантированно встретится до `MAX_CSTR_BYTES`).
pub unsafe fn cstr_bytes(ptr: *const c_char) -> Option<Vec<u8>> {
    if ptr.is_null() {
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    let mut cursor = ptr.cast::<u8>();
    for _ in 0..MAX_CSTR_BYTES {
        let byte = *cursor;
        if byte == 0 {
            return Some(out);
        }
        out.push(byte);
        cursor = cursor.add(1);
    }
    // NUL не найден в пределах потолка — строка не терминирована или слишком
    // длинная. Отвергаем, не читая дальше.
    None
}

/// То же, что [`cstr_bytes`], но с проверкой UTF-8.
///
/// # Safety
/// См. [`cstr_bytes`].
pub unsafe fn cstr_str(ptr: *const c_char) -> Option<String> {
    String::from_utf8(cstr_bytes(ptr)?).ok()
}

/// Ограниченная замена `CStr` с тем же API вызовов.
///
/// Введена, чтобы перевести существующие точки FFI на ограниченное чтение
/// без переписывания каждой: сигнатуры `to_str()` / `to_bytes()` совпадают, меняется
/// только конструктор ([`BoundedCStr::from_ptr`]) и добавляется `.ok()?` на
/// отвержение не-терминированной/слишком длинной строки.
pub struct BoundedCStr {
    bytes: Vec<u8>,
}

impl BoundedCStr {
    /// Ограниченное чтение C-строки. `None` для NULL или отсутствия NUL в
    /// пределах потолка.
    ///
    /// # Safety
    /// `ptr` должен быть либо NULL, либо указывать на буфер, где NUL
    /// гарантированно встретится до [`MAX_CSTR_BYTES`].
    pub unsafe fn from_ptr(ptr: *const c_char) -> Option<Self> {
        cstr_bytes(ptr).map(|bytes| Self { bytes })
    }

    /// Байты без завершающего NUL (как `CStr::to_bytes`).
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// UTF-8-view (как `CStr::to_str`).
    pub fn to_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.bytes)
    }
}
