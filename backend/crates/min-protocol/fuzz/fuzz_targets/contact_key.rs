#![no_main]
use libfuzzer_sys::fuzz_target;
use min_protocol::contact_key::ContactKeyV3;

/// Fuzzing для production ContactKey v3.
///
/// Вход: произвольные UTF-8 строки.
/// Ожидание: никаких паников, только ошибки парсинга.
fuzz_target!(|data: &[u8]| {
    // Попытаться распарсить произвольные байты как ContactKey
    if let Ok(s) = std::str::from_utf8(data) {
        let _: Result<ContactKeyV3, _> = ContactKeyV3::parse_string_form(s);
    }
});