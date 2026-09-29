//! FFI высокоуровневого API приложения (`min-app`) для UI (Swift).
//!
//! Наружу — только JSON-строки и opaque-handle; ключи/сессии/снапшоты
//! остаются внутри Rust. Контракт UI ↔ core описан в CONTRIBUTING.md.
//!
//! NULL = ошибка (как в остальном FFI). Блокирующие вызовы (open/register/
//! poll — сеть) звать из worker-потока, не из UI-потока.

use crate::{DeliveryLink, LinkKind};
use min_app::AppCore;
use min_delivery::{DeliveryError, MailboxClient};
use min_tor::{TorTransport, TorTransportConfig};
use std::ffi::CString;
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use zeroize::Zeroize;

/// Handle приложения: identity + сессии (PQXDH) + relay + локальная история.
pub struct AppHandle {
    inner: AppCore<DeliveryLink>,
}

/// Потолок длины входной C-строки.
///
/// MIN-RED-007: `CStr::from_ptr` сканирует память до NUL без ограничения. Это
/// контракт вызывающей стороны (Swift `withCString` всегда NUL-терминирует),
/// но на границе FFI это неконтролируемое чтение и неконтролируемая аллокация.
/// Потолок намеренно намного выше любой легитимной нагрузки (invite ≈ 8 КиБ,
/// PROTOCOL §3 ограничивает envelope 256 КиБ), поэтому функционально ничего
/// не ломает, но делает поведение определённым при ошибочном указателе.
const MAX_CSTR_BYTES: usize = 1024 * 1024;

/// Безопасное чтение C-строки с потолком длины (None для NULL, не-UTF-8 или
/// слишком длинной строки).
///
/// ВАЖНО: строка читается ПОБАЙТОВО, а не через срез `from_raw_parts(.., N)`:
/// срез длиной N создал бы ссылку за пределы фактического выделения, что само
/// по себе UB. Побайтовый скан ограничивает худший случай (over-read) потолком
/// байт вместо сканирования до «случайного» NUL где-то в памяти.
unsafe fn cstr(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    let mut cursor = ptr.cast::<u8>();
    for _ in 0..MAX_CSTR_BYTES {
        let byte = *cursor;
        if byte == 0 {
            return String::from_utf8(out).ok();
        }
        out.push(byte);
        cursor = cursor.add(1);
    }
    // NUL не найден в пределах потолка — строка не терминирована или слишком
    // длинная. Отвергаем, не читая дальше.
    None
}

/// Собирает транспорт по (kind, addr) — тот же набор, что в min_delivery_open.
fn build_link(
    kind: &str,
    addr: &str,
    state_dir: Option<String>,
    cache_dir: Option<String>,
) -> Result<DeliveryLink, DeliveryError> {
    if addr.is_empty() {
        return Err(DeliveryError::Net(min_net::NetError::Transport(
            "bad value".into(),
        )));
    }
    let (host, port) = crate::split_host_port(addr)?;
    match LinkKind::resolve(kind) {
        #[cfg(any(test, feature = "dev-tcp-link"))]
        Some(LinkKind::DirectTcp) => Ok(DeliveryLink::Tcp(min_delivery::tcp_link::TcpLink::new(
            addr,
        ))),
        // В SOCKS5-режиме Swift поднимает C Tor/IPtProxy и передаёт onion endpoint;
        // этот слой отвечает только за открытие SOCKS-ссылки.
        // Адрес SOCKS: env MIN_SOCKS_ADDR (dev/тесты) или 127.0.0.1:9050.
        Some(LinkKind::Socks) => {
            let socks = std::env::var("MIN_SOCKS_ADDR")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "127.0.0.1:9050".to_string());
            Ok(DeliveryLink::Socks(
                min_delivery::socks_link::SocksLink::new(addr, socks),
            ))
        }
        Some(LinkKind::Tor) => {
            let cfg = TorTransportConfig {
                relay_host: host,
                relay_port: port,
                state_dir: state_dir.map(std::path::PathBuf::from),
                cache_dir: cache_dir.map(std::path::PathBuf::from),
                ..Default::default()
            };
            let transport = TorTransport::connect(cfg)
                .map_err(|e| DeliveryError::Net(min_net::NetError::Transport(e.to_string())))?;
            Ok(DeliveryLink::Tor(transport))
        }
        _ => Err(DeliveryError::Net(min_net::NetError::Transport(
            "bad value".into(),
        ))),
    }
}

// Последняя ошибка текущего FFI-вызова. UI получает NULL как сигнал ошибки
// (совместимость с остальным FFI), а подробный диагноз забирает отдельным
// `min_app_last_error`. Хранится thread-local: вызовы Swift сериализованы.
thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

fn set_last_error(message: impl Into<String>) {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(message.into()));
}

fn into_c_string(value: String) -> *mut c_char {
    match CString::new(value) {
        Ok(value) => value.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Забирает и очищает последнюю ошибку вызова с текущего потока.
#[no_mangle]
pub extern "C" fn min_app_last_error() -> *mut c_char {
    let message = LAST_ERROR.with(|slot| slot.borrow_mut().take());
    message.map(into_c_string).unwrap_or(std::ptr::null_mut())
}

/// Обёртка: вызывает метод ядра и возвращает JSON-строку (или NULL).
fn call_app<F>(handle: *mut AppHandle, f: F) -> *mut c_char
where
    F: FnOnce(&mut AppCore<DeliveryLink>) -> Result<String, min_app::AppError>,
{
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
    if handle.is_null() {
        set_last_error("min_app: NULL handle");
        return std::ptr::null_mut();
    }
    // MIN-RED-007: не разыменовываем указатель, пока он не подтверждён
    // живым в реестре — иначе вызов после `free` читал бы UAF-память.
    if !crate::handles::is_live(handle as usize) {
        set_last_error("min_app: handle уже освобождён или не наш");
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &mut *handle };
        f(&mut h.inner)
    })) {
        Ok(Ok(json)) => into_c_string(json),
        Ok(Err(error)) => {
            set_last_error(error.to_string());
            std::ptr::null_mut()
        }
        Err(_) => {
            set_last_error("min_app: внутренняя ошибка ядра");
            std::ptr::null_mut()
        }
    }
}

/// Открывает приложение. Возвращает handle или NULL.
///
/// - `storage_path` — файл зашифрованной БД (создаётся при отсутствии);
/// - `storage_key_hex` — 64 hex-символа (32 байта) из iOS Keychain;
/// - `link_kind` — `"tor"` (прод) или `"tcp-dev-harness"` (dev-сборка);
/// - `addr` — `onion_host:port` / `host:port`;
/// - `state_dir`/`cache_dir` — каталоги Tor (iOS обязана передать реальные).
///
/// Блокирующий (Tor bootstrap при первом вызове) — звать из worker-потока.
#[no_mangle]
pub extern "C" fn min_app_open(
    storage_path: *const c_char,
    storage_key_hex: *const c_char,
    link_kind: *const c_char,
    addr: *const c_char,
    state_dir: *const c_char,
    cache_dir: *const c_char,
) -> *mut AppHandle {
    let (Some(path), Some(key), Some(kind), Some(addr)) = (unsafe {
        (
            cstr(storage_path),
            cstr(storage_key_hex),
            cstr(link_kind),
            cstr(addr),
        )
    }) else {
        set_last_error("min_app_open: отсутствует обязательный аргумент");
        return std::ptr::null_mut();
    };
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
    let (state, cache) = unsafe { (cstr(state_dir), cstr(cache_dir)) };
    let built = catch_unwind(AssertUnwindSafe(|| {
        let link = build_link(&kind, &addr, state, cache)?;
        AppCore::open(&path, &key, MailboxClient::new(link))
            .map_err(|e| DeliveryError::Net(min_net::NetError::Transport(e.to_string())))
    }));
    match built {
        Ok(Ok(core)) => {
            // MIN-RED-007: регистрируем handle, чтобы `min_app_free` знал,
            // какой указатель можно безопасно разыменовать/освободить.
            let raw = Box::into_raw(Box::new(AppHandle { inner: core }));
            crate::handles::insert(raw as usize);
            raw
        }
        Ok(Err(error)) => {
            set_last_error(error.to_string());
            std::ptr::null_mut()
        }
        Err(_) => {
            set_last_error("min_app_open: внутренняя ошибка ядра");
            std::ptr::null_mut()
        }
    }
}

/// MIN-RED-019: открытие ядра с recovery-блобом из Keychain.
///
/// Отличие от `min_app_open`: если БД отсутствует (переустановка приложения),
/// а блоб расшифровывается, identity ВОССТАНАВЛИВАЕТСЯ, а не генерируется заново —
/// mailbox_id остаётся прежним, и собеседник не перестаёт нам писать.
///
/// `recovery_blob_hex` может быть NULL/пустым: тогда поведение совпадает с
/// `min_app_open`. Битый блоб — явная ошибка (NULL), а НЕ «новый аккаунт»:
/// молчаливая подмена identity хуже явного отказа.
///
/// Отдельная функция, а не новый аргумент в `min_app_open`, чтобы не ломать
/// существующий ABI xcframework.
#[no_mangle]
pub extern "C" fn min_app_open_with_recovery(
    storage_path: *const c_char,
    storage_key_hex: *const c_char,
    link_kind: *const c_char,
    addr: *const c_char,
    state_dir: *const c_char,
    cache_dir: *const c_char,
    recovery_blob: *const u8,
    recovery_blob_len: usize,
) -> *mut AppHandle {
    let (Some(path), Some(key), Some(kind), Some(addr)) = (unsafe {
        (
            cstr(storage_path),
            cstr(storage_key_hex),
            cstr(link_kind),
            cstr(addr),
        )
    }) else {
        set_last_error("min_app_open_with_recovery: отсутствует обязательный аргумент");
        return std::ptr::null_mut();
    };
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
    let (state, cache) = unsafe { (cstr(state_dir), cstr(cache_dir)) };
    // NULL и нулевая длина трактуются одинаково: блоба нет. Размер сверяется с
    // потолком модуля ещё здесь, чтобы чужой указатель не читался целиком.
    let recovery = if recovery_blob.is_null() || recovery_blob_len == 0 {
        None
    } else if recovery_blob_len > min_app::recovery::MAX_RECOVERY_BLOB + 64 {
        set_last_error("min_app_open_with_recovery: блоб неприемлемого размера");
        return std::ptr::null_mut();
    } else {
        Some(unsafe { std::slice::from_raw_parts(recovery_blob, recovery_blob_len) })
    };
    let built = catch_unwind(AssertUnwindSafe(|| {
        let link = build_link(&kind, &addr, state, cache)?;
        AppCore::open_with_recovery(&path, &key, recovery, MailboxClient::new(link))
            .map_err(|e| DeliveryError::Net(min_net::NetError::Transport(e.to_string())))
    }));
    match built {
        Ok(Ok(core)) => {
            let raw = Box::into_raw(Box::new(AppHandle { inner: core }));
            crate::handles::insert(raw as usize);
            raw
        }
        Ok(Err(error)) => {
            set_last_error(error.to_string());
            std::ptr::null_mut()
        }
        Err(_) => {
            set_last_error("min_app_open_with_recovery: внутренняя ошибка ядра");
            std::ptr::null_mut()
        }
    }
}

/// Освобождает handle приложения.
///
/// MIN-RED-007: три защиты — (1) `free(NULL)` = no-op; (2) handle снимается с
/// учёта атомарно-до освобождения, поэтому повторный free и вызов после free
/// являются no-op/`NULL`, а не double free / use-after-free (PoC: SIGSEGV);
/// (3) `Drop` выполняется под panic-barrier — разворачивание паники через
/// `extern "C"` в Rust является UB.
#[no_mangle]
pub extern "C" fn min_app_free(handle: *mut AppHandle) {
    if handle.is_null() {
        return;
    }
    if !crate::handles::remove(handle as usize) {
        set_last_error("min_app_free: handle уже освобождён или не наш");
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(handle));
    }));
}

/// Публичные данные аккаунта (JSON): identity_hex, mailbox_id_hex, epoch.
#[no_mangle]
pub extern "C" fn min_app_self(handle: *mut AppHandle) -> *mut c_char {
    call_app(handle, |core| core.self_public())
}

/// MIN-RED-019: recovery-блоб личности для iOS Keychain.
///
/// Внутри блоба — приватный ключ identity, поэтому содержимое НЕ должно попадать
/// в лог, в `NSLog` или в crash-дамп. Вызывающая сторона кладёт его в Keychain
/// (`ThisDeviceOnly`) и обязана стереть буфер через `min_free_bytes`.
///
/// Отдаётся **сырым буфером**, а не hex-строкой: блоб — это шифротекст, и
/// hex-текст удвоил бы его ровно настолько, насколько iOS Keychain не готов
/// принять крупный item. Строка потребовала бы вдвое больше памяти и вдвое
/// дольше грузилась в Keychain.
///
/// `with_session != 0` — полный блоб (со снапшотом ratchet и prekey bundle).
/// `with_session == 0` — сокращённый: только то, без чего mailbox перестаёт быть
/// тем же адресом (identity, эпоха, mailbox, pull_token, контакты). Вызывающая
/// сторона обязана использовать сокращённый вариант, если полный не влезает в
/// Keychain: iOS отказывает на крупных items, а отказ записи означает, что
/// следующая переустановка оборвёт mailbox.
///
/// `out_len` получает длину; на ошибке возвращается NULL, а `out_len` = 0.
#[no_mangle]
pub extern "C" fn min_app_recovery_export_bin(
    handle: *mut AppHandle,
    with_session: i32,
    out_len: *mut usize,
) -> *mut u8 {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
    if out_len.is_null() || handle.is_null() {
        set_last_error("min_app_recovery_export_bin: NULL аргумент");
        return std::ptr::null_mut();
    }
    unsafe { *out_len = 0 };
    if !crate::handles::is_live(handle as usize) {
        set_last_error("min_app_recovery_export_bin: handle уже освобождён или не наш");
        return std::ptr::null_mut();
    }
    let res = catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &mut *handle };
        h.inner.recovery_export(with_session != 0)
    }));
    let blob = match res {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            set_last_error(&format!("min_app_recovery_export_bin: {e}"));
            return std::ptr::null_mut();
        }
        Err(_) => {
            set_last_error("min_app_recovery_export_bin: внутренняя ошибка ядра");
            return std::ptr::null_mut();
        }
    };
    if blob.is_empty() || blob.len() > min_app::recovery::MAX_RECOVERY_BLOB + 64 {
        set_last_error("min_app_recovery_export_bin: блоб неприемлемого размера");
        return std::ptr::null_mut();
    }
    let len = blob.len();
    let boxed = blob.into_boxed_slice();
    unsafe {
        *out_len = len;
        Box::into_raw(boxed) as *mut u8
    }
}

/// Освобождает буфер, выданный `min_app_recovery_export_bin`, с затиранием.
///
/// `ptr`/`len` обязаны быть теми же, что вернул экспорт: длина участвует в
/// восстановлении среза, и подмена одного из двух — чтение чужой памяти.
#[no_mangle]
pub extern "C" fn min_free_bytes(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    unsafe {
        let slice = std::slice::from_raw_parts_mut(ptr, len);
        slice.zeroize();
        // from_raw_parts_mut на срезе Box<[u8]> и drop — возвращают аллокатору
        // ровно ту же память, что была выделена в min_app_recovery_export_bin.
        drop(Box::from_raw(slice));
    }
}

/// Мой Contact Key (`MIN3:...`) — «визитка» для обмена контактом.
#[no_mangle]
pub extern "C" fn min_app_contact_key(handle: *mut AppHandle) -> *mut c_char {
    call_app(handle, |core| core.my_contact_key())
}

/// Мой prekey bundle (hex CBOR) — передаётся вместе с Contact Key.
#[no_mangle]
pub extern "C" fn min_app_bundle(handle: *mut AppHandle) -> *mut c_char {
    call_app(handle, |core| core.my_bundle_hex())
}

/// Регистрирует mailbox на relay (идемпотентно). Возвращает "ok" или NULL.
#[no_mangle]
pub extern "C" fn min_app_register(handle: *mut AppHandle) -> *mut c_char {
    call_app(handle, |core| {
        core.register()?;
        Ok("ok".to_string())
    })
}

/// Моё приглашение (Contact Key + bundle одним текстом, MVP-альфа).
#[no_mangle]
pub extern "C" fn min_app_invite(handle: *mut AppHandle) -> *mut c_char {
    call_app(handle, |core| core.my_invite())
}

/// Добавляет контакт по тексту приглашения. Возвращает JSON контакта.
#[no_mangle]
pub extern "C" fn min_app_add_contact(
    handle: *mut AppHandle,
    name: *const c_char,
    invite: *const c_char,
) -> *mut c_char {
    let (Some(name), Some(invite)) = (unsafe { (cstr(name), cstr(invite)) }) else {
        set_last_error("min_app_add_contact: невалидные C-строки");
        return std::ptr::null_mut();
    };
    call_app(handle, |core| {
        let contact = core.add_contact_by_invite(&name, &invite)?;
        serde_json::to_string(&contact).map_err(|e| min_app::AppError::Json(e.to_string()))
    })
}

/// Отправляет текст контакту. Возвращает JSON отправленного сообщения.
#[no_mangle]
pub extern "C" fn min_app_send_text(
    handle: *mut AppHandle,
    peer: *const c_char,
    text: *const c_char,
) -> *mut c_char {
    let (Some(peer), Some(text)) = (unsafe { (cstr(peer), cstr(text)) }) else {
        set_last_error("min_app_send_text: невалидные C-строки");
        return std::ptr::null_mut();
    };
    call_app(handle, |core| {
        let msg = core.send_text(&peer, &text)?;
        serde_json::to_string(&msg).map_err(|e| min_app::AppError::Json(e.to_string()))
    })
}

/// Отправка ОТВЕТА: цитата уезжает в зашифрованный payload, поэтому её видит
/// вторая сторона и она переживает перезапуск (в UI-только цитата исчезала).
#[no_mangle]
pub extern "C" fn min_app_send_reply(
    handle: *mut AppHandle,
    peer: *const c_char,
    text: *const c_char,
    author: *const c_char,
    preview: *const c_char,
) -> *mut c_char {
    let (Some(peer), Some(text), Some(author), Some(preview)) = (
        unsafe { cstr(peer) },
        unsafe { cstr(text) },
        unsafe { cstr(author) },
        unsafe { cstr(preview) },
    ) else {
        set_last_error("min_app_send_reply: невалидные C-строки");
        return std::ptr::null_mut();
    };
    call_app(handle, |core| {
        let msg = core.send_reply(&peer, &text, &author, &preview)?;
        serde_json::to_string(&msg).map_err(|e| min_app::AppError::Json(e.to_string()))
    })
}

/// Отправка сообщения: ядро само выбирает путь (сессия или invite) и несёт
/// цитату в обоих путях. `author`/`preview`/`invite` — NULL, если не применимо.
#[no_mangle]
pub extern "C" fn min_app_send_message(
    handle: *mut AppHandle,
    peer: *const c_char,
    text: *const c_char,
    author: *const c_char,
    preview: *const c_char,
    invite: *const c_char,
) -> *mut c_char {
    let (Some(peer), Some(text)) = (unsafe { cstr(peer) }, unsafe { cstr(text) }) else {
        set_last_error("min_app_send_message: невалидные C-строки");
        return std::ptr::null_mut();
    };
    let author = unsafe { cstr(author) };
    let preview = unsafe { cstr(preview) };
    let invite = unsafe { cstr(invite) };
    call_app(handle, |core| {
        let reply = match (author, preview) {
            (Some(a), Some(p)) => Some(min_app::model::ReplyRef {
                author: a,
                preview: p,
            }),
            _ => None,
        };
        let msg = core.send_message(&peer, &text, reply.as_ref(), invite.as_deref())?;
        serde_json::to_string(&msg).map_err(|e| min_app::AppError::Json(e.to_string()))
    })
}

/// Забирает очередь с relay: JSON-массив новых входящих сообщений.
/// Блокирующий (сеть) — worker-поток. Повторный вызов ничего не дублирует.
#[no_mangle]
pub extern "C" fn min_app_poll(handle: *mut AppHandle) -> *mut c_char {
    call_app(handle, |core| {
        let msgs = core.poll()?;
        serde_json::to_string(&msgs).map_err(|e| min_app::AppError::Json(e.to_string()))
    })
}

// ================= MIN-RED-022: сообщения от незнакомцев =================
//
// Тумблер «кто угодно с моим invite может написать» (дефолт ВКЛ) + очередь
// заявок Accept/Reject/Block. Текст заявки не отдаётся ДО решения.

// Отправляет ПЕРВОЕ сообщение незнакомцу по его invite: сессия заводится сразу,
// получателю придёт заявка (не чат). Ручное добавление контакта не требуется.
#[no_mangle]
pub extern "C" fn min_app_send_text_to_invite(
    handle: *mut AppHandle,
    invite: *const c_char,
    text: *const c_char,
) -> *mut c_char {
    let (Some(invite), Some(text)) = (unsafe { (cstr(invite), cstr(text)) }) else {
        set_last_error("min_app_send_text_to_invite: невалидные C-строки");
        return std::ptr::null_mut();
    };
    call_app(handle, |core| {
        let msg = core.send_text_to_invite(&invite, &text)?;
        serde_json::to_string(&msg).map_err(|e| min_app::AppError::Json(e.to_string()))
    })
}

/// Заявки от незнакомцев (JSON-массив) + «1» / «0» — разрешены ли они сейчас.
#[no_mangle]
pub extern "C" fn min_app_requests(handle: *mut AppHandle) -> *mut c_char {
    call_app(handle, |core| {
        let list = core.requests()?;
        let allowed = core.discoverability()?;
        let items: serde_json::Value =
            serde_json::from_str(&list).map_err(|e| min_app::AppError::Json(e.to_string()))?;
        Ok(serde_json::json!({ "discoverable": allowed, "requests": items }).to_string())
    })
}

/// Помечает чат прочитанным и возвращает все отметки «прочитано».
///
/// Отметки живут в зашифрованном хранилище ядра, а не в контейнере приложения:
/// Swift-кэш удаляется при переустановке, и прочитанное снова выглядело бы
/// непрочитанным.
#[no_mangle]
pub extern "C" fn min_app_mark_chat_read(handle: *mut AppHandle, peer: *const c_char) -> *mut c_char {
    let Some(peer) = (unsafe { cstr(peer) }) else {
        set_last_error("min_app_mark_chat_read: невалидная C-строка");
        return std::ptr::null_mut();
    };
    call_app(handle, |core| {
        core.mark_chat_read(&peer)?;
        let map = core.read_markers()?;
        serde_json::to_string(&map).map_err(|e| min_app::AppError::Json(e.to_string()))
    })
}

/// Отметка «прочитано» с явным временем — только для миграции старых отметок
/// из Swift-кэша. Обычная отметка всегда ставит «сейчас».
#[no_mangle]
pub extern "C" fn min_app_mark_chat_read_at(
    handle: *mut AppHandle,
    peer: *const c_char,
    at: u64,
) -> *mut c_char {
    let Some(peer) = (unsafe { cstr(peer) }) else {
        set_last_error("min_app_mark_chat_read_at: невалидная C-строка");
        return std::ptr::null_mut();
    };
    call_app(handle, |core| {
        core.mark_chat_read_at(&peer, at)?;
        let map = core.read_markers()?;
        serde_json::to_string(&map).map_err(|e| min_app::AppError::Json(e.to_string()))
    })
}

/// Отметки «прочитано» без изменения состояния.
#[no_mangle]
pub extern "C" fn min_app_read_markers(handle: *mut AppHandle) -> *mut c_char {
    call_app(handle, |core| {
        let map = core.read_markers()?;
        serde_json::to_string(&map).map_err(|e| min_app::AppError::Json(e.to_string()))
    })
}

/// Ответ незнакомцу, у которого ещё нет сессии: и запрос, и цитата едут
/// одним зашифрованным first-contact сообщением.
#[no_mangle]
pub extern "C" fn min_app_send_text_to_invite_reply(
    handle: *mut AppHandle,
    invite: *const c_char,
    text: *const c_char,
    author: *const c_char,
    preview: *const c_char,
) -> *mut c_char {
    let (Some(invite), Some(text), Some(author), Some(preview)) = (
        unsafe { cstr(invite) },
        unsafe { cstr(text) },
        unsafe { cstr(author) },
        unsafe { cstr(preview) },
    ) else {
        set_last_error("min_app_send_text_to_invite_reply: невалидные C-строки");
        return std::ptr::null_mut();
    };
    call_app(handle, |core| {
        let msg = core.send_text_to_invite_reply(&invite, &text, &author, &preview)?;
        serde_json::to_string(&msg).map_err(|e| min_app::AppError::Json(e.to_string()))
    })
}

/// Принимает заявку: чат открывается, текст заявки становится первым сообщением.
/// Возвращает JSON контакта.
#[no_mangle]
pub extern "C" fn min_app_accept_request(
    handle: *mut AppHandle,
    request_id: *const c_char,
) -> *mut c_char {
    let Some(request_id) = (unsafe { cstr(request_id) }) else {
        set_last_error("min_app_accept_request: невалидная C-строка");
        return std::ptr::null_mut();
    };
    call_app(handle, |core| {
        let contact = core.accept_request(&request_id)?;
        serde_json::to_string(&contact).map_err(|e| min_app::AppError::Json(e.to_string()))
    })
}

/// Отклоняет заявку. Отправитель получает нейтральный отказ.
#[no_mangle]
pub extern "C" fn min_app_reject_request(
    handle: *mut AppHandle,
    request_id: *const c_char,
) -> *mut c_char {
    let Some(request_id) = (unsafe { cstr(request_id) }) else {
        set_last_error("min_app_reject_request: невалидная C-строка");
        return std::ptr::null_mut();
    };
    call_app(handle, |core| {
        core.reject_request(&request_id)?;
        Ok("ok".to_string())
    })
}

/// Блокирует отправителя. Ответа на провод НЕ уходит (см. ctrl.rs).
#[no_mangle]
pub extern "C" fn min_app_block_request(
    handle: *mut AppHandle,
    request_id: *const c_char,
) -> *mut c_char {
    let Some(request_id) = (unsafe { cstr(request_id) }) else {
        set_last_error("min_app_block_request: невалидная C-строка");
        return std::ptr::null_mut();
    };
    call_app(handle, |core| {
        core.block_request(&request_id)?;
        Ok("ok".to_string())
    })
}

/// Тумблер «кто может мне писать» (только локально, в сеть не уходит).
#[no_mangle]
pub extern "C" fn min_app_set_discoverable(handle: *mut AppHandle, allowed: bool) -> *mut c_char {
    call_app(handle, |core| {
        core.set_discoverability(allowed)?;
        Ok("ok".to_string())
    })
}

/// Список чатов (JSON-массив агрегатов) для списка чатов в UI.
#[no_mangle]
pub extern "C" fn min_app_chats(handle: *mut AppHandle) -> *mut c_char {
    call_app(handle, |core| core.list_chats())
}

/// История переписки с контактом (JSON-массив, хронологический порядок).
#[no_mangle]
pub extern "C" fn min_app_messages(handle: *mut AppHandle, peer: *const c_char) -> *mut c_char {
    let Some(peer) = (unsafe { cstr(peer) }) else {
        set_last_error("min_app_messages: невалидная C-строка");
        return std::ptr::null_mut();
    };
    call_app(handle, |core| core.messages(&peer))
}

/// Список контактов (JSON-массив).
#[no_mangle]
pub extern "C" fn min_app_contacts(handle: *mut AppHandle) -> *mut c_char {
    call_app(handle, |core| core.contacts())
}

#[cfg(test)]
mod red_011_cstr_tests {
    use super::*;
    use crate::cstr_bound::{self, BoundedCStr, MAX_CSTR_BYTES};
    use std::ffi::CString;

    // Локальный алиас: в этом модуле уже есть одноимённая функция `cstr`,
    // поэтому путь к bounded-хелперу указываем явно.
    use cstr_bound::cstr_str;
    // Эталон для сверки поведения: сам `CStr` (сырой, неограниченный).
    use std::ffi::CStr;

    /// Обычная строка читается точно.
    #[test]
    fn reads_normal_c_string() {
        let s = CString::new("MIN3:hello").unwrap();
        assert_eq!(
            unsafe { cstr_str(s.as_ptr()) }.as_deref(),
            Some("MIN3:hello")
        );
    }

    /// NULL → None (не паника, не чтение по адресу 0).
    #[test]
    fn null_pointer_is_rejected() {
        assert!(unsafe { cstr_str(std::ptr::null()) }.is_none());
        assert!(unsafe { BoundedCStr::from_ptr(std::ptr::null()) }.is_none());
    }

    /// Пустая строка — валидный вход (не путать с NULL).
    #[test]
    fn empty_string_is_valid() {
        let s = CString::new("").unwrap();
        assert_eq!(unsafe { cstr_str(s.as_ptr()) }.as_deref(), Some(""));
    }

    /// MIN-RED-012: буфер БЕЗ завершающего NUL отвергается на потолке,
    /// вместо того чтобы читать память дальше.
    ///
    /// Тест обязан быть sound: `cstr_bytes` читает ровно `MAX_CSTR_BYTES`
    /// байт, поэтому «нетерминированный» буфер обязан иметь длину РОВНО
    /// `MAX_CSTR_BYTES` (иначе проверка сама читала бы за пределы
    /// аллокации, а это UB в тесте, а не защита в проде).
    #[test]
    fn unterminated_buffer_is_rejected_at_cap() {
        // Ровно потолок байт без NUL: скан исчерпывает лимит и возвращает None.
        let big = vec![b'A'; MAX_CSTR_BYTES];
        assert_eq!(big.len(), MAX_CSTR_BYTES);
        assert!(unsafe { BoundedCStr::from_ptr(big.as_ptr() as *const _) }.is_none());
        // Граница приёма: NUL ровно на последнем читаемом байте — строка
        // максимальной длины MAX-1 принимается целиком.
        let mut longest = vec![b'A'; MAX_CSTR_BYTES];
        longest[MAX_CSTR_BYTES - 1] = 0;
        let bounded = unsafe { BoundedCStr::from_ptr(longest.as_ptr() as *const _) }.unwrap();
        assert_eq!(bounded.to_bytes().len(), MAX_CSTR_BYTES - 1);
    }

    /// Не-UTF8 отвергается, а не паникует.
    #[test]
    fn non_utf8_is_rejected() {
        let raw = vec![0xFFu8, 0xFE, 0x00];
        assert!(unsafe { cstr_str(raw.as_ptr() as *const _) }.is_none());
        // При этом байты доступны через to_bytes (нужны для hex-входов).
        let bytes = unsafe { BoundedCStr::from_ptr(raw.as_ptr() as *const _) }.unwrap();
        assert_eq!(bytes.to_bytes(), &[0xFF, 0xFE]);
    }

    /// Точное поведение `BoundedCStr` совпадает с `CStr` на валидном входе.
    #[test]
    fn bounded_matches_cstr_on_valid_input() {
        let s = CString::new("payload").unwrap();
        let bounded = unsafe { BoundedCStr::from_ptr(s.as_ptr()) }.unwrap();
        let plain = unsafe { CStr::from_ptr(s.as_ptr()) };
        assert_eq!(bounded.to_bytes(), plain.to_bytes());
        assert_eq!(bounded.to_str().unwrap(), plain.to_str().unwrap());
    }
}

#[cfg(test)]
mod red_007_boundary_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static UNIQ: AtomicU64 = AtomicU64::new(0);

    /// Открывает handle, не касаясь сети (socks на закрытый порт не подключается).
    fn open_handle(tag: &str) -> *mut AppHandle {
        let n = UNIQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("min-ffi-red007-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = CString::new(dir.join("store.db").to_string_lossy().as_ref()).unwrap();
        let key = CString::new("00".repeat(32)).unwrap();
        let kind = CString::new("socks").unwrap();
        let addr = CString::new("127.0.0.1:1").unwrap();
        let handle = min_app_open(
            path.as_ptr(),
            key.as_ptr(),
            kind.as_ptr(),
            addr.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
        );
        assert!(!handle.is_null(), "min_app_open must return a handle");
        handle
    }

    /// MIN-RED-007 (1): повторный `min_app_free` = double free (UB).
    /// Pre-fix: авария процесса/heap corruption. Post-fix: определённый no-op.
    #[test]
    fn double_free_is_rejected_instead_of_corrupting_heap() {
        let handle = open_handle("double-free");
        min_app_free(handle);
        // Второй вызов. Post-fix это тихий no-op; pre-fix — double free.
        min_app_free(handle);
    }

    /// MIN-RED-007 (2): вызов после free = use-after-free.
    /// Post-fix обязан вернуть NULL, не читая освобождённую память.
    #[test]
    fn use_after_free_returns_null_instead_of_touching_freed_memory() {
        let handle = open_handle("uaf");
        min_app_free(handle);
        let raw = min_app_self(handle);
        assert!(
            raw.is_null(),
            "вызов после free обязан быть отвергнут, а не читать UAF-память"
        );
        if !raw.is_null() {
            unsafe { crate::min_free_string(raw) };
        }
    }

    /// Базовый гигиен-инвариант: free(NULL) — no-op на любой реализации.
    #[test]
    fn free_null_handle_is_noop() {
        unsafe { min_app_free(std::ptr::null_mut()) };
    }

    /// MIN-RED-007 (3): освобождение не должно пропускать panic через
    /// `extern "C"` (unwind через FFI = UB). Завершение без abort доказывает

    /// наличие panic-barrier.
    #[test]
    fn free_is_panic_contained() {
        let handle = open_handle("panic-barrier");
        unsafe { min_app_free(handle) };
    }
    /// MIN-RED-007 (4): тот же use-after-free на легаси-границе
    /// (`min_session_*`), где раньше был прямой `&mut *handle`.
    /// Post-fix обязан вернуть NULL, не читая освобождённую память.
    #[test]
    fn legacy_session_use_after_free_returns_null() {
        let handle = crate::min_session_create();
        assert!(!handle.is_null());
        unsafe { crate::min_session_free(handle) };
        let raw = unsafe { crate::min_session_identity_public(handle) };
        assert!(
            raw.is_null(),
            "вызов после free обязан быть отвергнут (легаси session-handle)"
        );
        if !raw.is_null() {
            unsafe { crate::min_free_string(raw) };
        }
    }

    /// MIN-RED-007 (5): double free на легаси-границе — no-op, не UB.
    #[test]
    fn legacy_session_double_free_is_noop() {
        let handle = crate::min_session_create();
        assert!(!handle.is_null());
        unsafe { crate::min_session_free(handle) };
        unsafe { crate::min_session_free(handle) };
    }

    /// MIN-RED-007 (6): живой handle продолжает работать — guard не ломает
    /// нормальный путь (регрессия против «лечим always-NULL»).
    #[test]
    fn live_legacy_session_handle_still_works() {
        let handle = crate::min_session_create();
        let raw = unsafe { crate::min_session_identity_public(handle) };
        assert!(!raw.is_null(), "живой handle обязан работать");
        unsafe { crate::min_free_string(raw) };
        unsafe { crate::min_session_free(handle) };
    }

    /// MIN-RED-007 (7): чтение C-строки ограничено потолком.
    ///
    /// Что именно доказывает тест: скан НЕ продолжает читать за пределы
    /// `MAX_CSTR_BYTES`. Реальная память выделена целиком (буфер длиннее
    /// потолка и без NUL), поэтому отсутствие терминатора в этих байтах
    /// обязано привести к `None` — иначе скан ушёл бы дальше выделения.
    ///
    /// Чего тест НЕ утверждает (осознанно): что короткая строка без
    /// терминатора всегда отвергается. Побайтовый скан в пределах потолка
    /// вправе встретить нулевой байт в соседней памяти — это свойство
    /// границы FFI, а не парсера; потолок ограничивает худший случай.
    #[test]
    fn c_string_read_stops_at_cap() {
        let cap = MAX_CSTR_BYTES;
        // Больше потолка, ни одного нулевого байта.
        let buf = vec![b'A'; cap + 4096];
        let ptr = buf.as_ptr() as *const std::os::raw::c_char;
        assert!(
            unsafe { cstr(ptr) }.is_none(),
            "сканирование обязано прекратиться на потолке, а не читать дальше"
        );
    }

    /// MIN-RED-007 (7b): строка, помещающаяся в потолок, читается целиком —
    /// граница не ломает легитимный вход (например, большой invite).
    #[test]
    fn c_string_within_cap_is_read_fully() {
        let payload = "x".repeat(4096);
        let ok = std::ffi::CString::new(payload.clone()).unwrap();
        assert_eq!(
            unsafe { cstr(ok.as_ptr()) }.as_deref(),
            Some(payload.as_str())
        );
    }

    /// MIN-RED-007 (8): NULL → None; короткая корректная строка читается.
    #[test]
    fn cstr_rejects_null_and_accepts_valid() {
        assert!(unsafe { cstr(std::ptr::null()) }.is_none());
        let ok = std::ffi::CString::new("hello").unwrap();
        assert_eq!(unsafe { cstr(ok.as_ptr()) }.as_deref(), Some("hello"));
    }
}
