//! MIN FFI - C-ABI bindings for Swift.
//!
//! All functions are panic-guarded: a Rust panic across the FFI boundary
//! is undefined behavior (abort). We catch_unwind and return NULL instead.
//! This is critical for iOS stability - malformed input must never crash.
//!
//! String-based API: all inputs/outputs are hex-encoded C strings. Raw
//! secret bytes never cross the FFI boundary as binary - keeping the
//! Swift heap free of raw key material.

// iOS does not provide ___chkstk_darwin (stack-probing helper required by
// the Kyber C reference code used via libsignal on arm64). Emit a stub
// directly into the compiled object so the iOS linker resolves it.
#[cfg(target_os = "ios")]
core::arch::global_asm!(".global ___chkstk_darwin", "___chkstk_darwin:", "ret");

use min_crypto::{decrypt, derive_shared_secret, encrypt, generate_keypair};
use min_crypto::{PublicKey, SecretKey, SharedSecret};
#[cfg(test)]
use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use zeroize::Zeroize;

/// Generates a new random keypair.
/// Returns a string in format "secret:public" (hex-encoded), or NULL on error.
#[no_mangle]
pub extern "C" fn min_create_keypair() -> *mut c_char {
    match catch_unwind(AssertUnwindSafe(|| {
        let (sk, pk) = generate_keypair().expect("keypair generation is infallible");
        let secret_hex = hex::encode(sk.0);
        let public_hex = hex::encode(pk.0);
        format!("{}:{}", secret_hex, public_hex)
    })) {
        Ok(result) => CString::new(result).unwrap().into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Derives a shared secret from secret key and public key (hex-encoded).
/// Returns hex-encoded shared secret, or NULL on error.
#[no_mangle]
pub extern "C" fn min_derive_shared_secret(
    secret_key_hex: *const c_char,
    public_key_hex: *const c_char,
) -> *mut c_char {
    match catch_unwind(AssertUnwindSafe(|| {
        if secret_key_hex.is_null() || public_key_hex.is_null() {
            return None;
        }
        let secret_hex = unsafe { cstr_bound::BoundedCStr::from_ptr(secret_key_hex) }?;
        let public_hex = unsafe { cstr_bound::BoundedCStr::from_ptr(public_key_hex) }?;
        let secret_bytes = hex::decode(secret_hex.to_bytes()).ok()?;
        let public_bytes = hex::decode(public_hex.to_bytes()).ok()?;
        let sk: [u8; 32] = secret_bytes.try_into().ok()?;
        let pk: [u8; 32] = public_bytes.try_into().ok()?;
        let shared = derive_shared_secret(&SecretKey(sk), &PublicKey(pk)).ok()?;
        Some(hex::encode(shared.0))
    })) {
        Ok(Some(result)) => CString::new(result).unwrap().into_raw(),
        Ok(None) | Err(_) => std::ptr::null_mut(),
    }
}

/// Encrypts plaintext using a shared secret (hex-encoded).
/// Returns hex-encoded ciphertext, or NULL on error.
#[no_mangle]
pub extern "C" fn min_encrypt(
    shared_secret_hex: *const c_char,
    plaintext: *const c_char,
) -> *mut c_char {
    match catch_unwind(AssertUnwindSafe(|| {
        if shared_secret_hex.is_null() || plaintext.is_null() {
            return None;
        }
        let secret_hex = unsafe { cstr_bound::BoundedCStr::from_ptr(shared_secret_hex) }?;
        let plaintext_str = unsafe { cstr_bound::BoundedCStr::from_ptr(plaintext) }?;
        let secret_bytes = hex::decode(secret_hex.to_bytes()).ok()?;
        let secret: [u8; 32] = secret_bytes.try_into().ok()?;
        // AUDIT FIX-1: домен примитивного слоя вместо пустого AAD.
        let ciphertext = encrypt(
            &SharedSecret(secret),
            plaintext_str.to_bytes(),
            min_crypto::PRIMITIVE_AAD,
        )
        .ok()?;
        Some(hex::encode(ciphertext))
    })) {
        Ok(Some(result)) => CString::new(result).unwrap().into_raw(),
        Ok(None) | Err(_) => std::ptr::null_mut(),
    }
}

/// Decrypts hex-encoded ciphertext using a shared secret (hex-encoded).
/// Returns plaintext as UTF-8 string, or NULL on error.
#[no_mangle]
pub extern "C" fn min_decrypt(
    shared_secret_hex: *const c_char,
    ciphertext_hex: *const c_char,
) -> *mut c_char {
    match catch_unwind(AssertUnwindSafe(|| {
        if shared_secret_hex.is_null() || ciphertext_hex.is_null() {
            return None;
        }
        let secret_hex = unsafe { cstr_bound::BoundedCStr::from_ptr(shared_secret_hex) }?;
        let ct_hex = unsafe { cstr_bound::BoundedCStr::from_ptr(ciphertext_hex) }?;
        let secret_bytes = hex::decode(secret_hex.to_bytes()).ok()?;
        let ct_bytes = hex::decode(ct_hex.to_bytes()).ok()?;
        let secret: [u8; 32] = secret_bytes.try_into().ok()?;
        // AUDIT FIX-1: домен примитивного слоя вместо пустого AAD.
        let plaintext =
            decrypt(&SharedSecret(secret), &ct_bytes, min_crypto::PRIMITIVE_AAD).ok()?;
        String::from_utf8(plaintext).ok()
    })) {
        Ok(Some(result)) => CString::new(result).unwrap().into_raw(),
        Ok(None) | Err(_) => std::ptr::null_mut(),
    }
}

/// Frees a C string allocated by Rust (keypair, shared secret, ciphertext, etc.).
///
/// AUDIT MIN-03: перед освобождением буфер ЗАТИРАЕТСЯ (zeroize). Все строки,
/// приходящие сюда от Swift, содержат hex-секреты (ключи, токены, seed) —
/// обычный free оставлял бы их копии в свободной куче для форензики.
#[no_mangle]
pub extern "C" fn min_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let c = CString::from_raw(ptr);
            let mut bytes = c.into_bytes(); // moves buffer — без копии
            bytes.zeroize();
            // drop(bytes) — уже затёртый буфер возвращается аллокатору.
        }
    }
}

/// Creates a new identity (placeholder - real impl in min-identity).
/// Returns a status string, or NULL on error.
#[no_mangle]
pub extern "C" fn min_create_identity() -> *mut c_char {
    match catch_unwind(AssertUnwindSafe(|| String::from("identity_created"))) {
        Ok(result) => CString::new(result).unwrap().into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Общая fail-closed валидация Contact Key (MIN-05/MIN-15/MIN-25).
///
/// Строгая цепочка (любой шаг → ошибка):
/// 1) разбор `MIN3:<base58btc(canonical CBOR)>` (строгий набор полей 1..=7,
///    канонический порядок, длина полей);
/// 2) Ed25519-подпись identity-ключа над каноническими полями 1..5;
/// 3) инвариант привязки к relay (PROTOCOL §5): mailbox_id == HKDF(identity_pk) —
///    нельзя издать Contact Key, «смотрящий» на чужой mailbox.
///
/// AUDIT MIN-25: вынесено в общий хелпер, чтобы `min_parse_contact_key`
/// (отдаёт mailbox_id) и `min_format_contact_key` (отдаёт каноническую строку)
/// не могли разойтись в правилах валидации.
fn validate_contact_key(
    key_str: &str,
) -> Result<min_protocol::contact_key::ContactKeyV3, min_protocol::ProtocolError> {
    let ck = min_protocol::contact_key::ContactKeyV3::parse_string_form(key_str)?;
    ck.verify()?;
    if min_identity::mailbox_id(&ck.identity_public_key, ck.epoch) != ck.mailbox_id {
        // Contact Key подписан, но mailbox не выведен из identity —
        // валиден криптографически, недопустим семантически.
        return Err(min_protocol::ProtocolError::Malformed);
    }
    Ok(ck)
}

/// AUDIT MIN-05/MIN-15: реальная проверка Contact Key строковой формы.
///
/// Возвращает hex(mailbox_id) (32 символа — адрес маршрутизации) или NULL
/// при любой ошибке валидации (мусорная строка, BadSignature, UnsupportedVersion).
#[no_mangle]
pub extern "C" fn min_parse_contact_key(key: *const c_char) -> *mut c_char {
    if key.is_null() {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let key_str = unsafe { cstr_bound::cstr_str(key) }
            .ok_or(min_protocol::ProtocolError::BadContactKeyString)?;
        let ck = validate_contact_key(&key_str)?;
        Ok::<_, min_protocol::ProtocolError>(hex::encode(ck.mailbox_id))
    })) {
        Ok(Ok(mb_hex)) => CString::new(mb_hex).unwrap().into_raw(),
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// AUDIT MIN-25: канонизация Contact Key для шаринга (был placeholder).
///
/// Раньше возвращал Rust-`Debug`-представление входа с устаревшим префиксом
/// (`MIN1:"..."`) и **без валидации** (fail-open): в UI можно было «отформатировать»
/// и показать к отправке произвольную мусорную строку. Теперь — тот же
/// fail-closed валидатор, что у `min_parse_contact_key`, а на выходе
/// каноническая строковая форма `MIN3:<base58btc>` (нормализованный base58,
/// канонический порядок полей).
///
/// Возвращает каноническую MIN3-строку или NULL при любой ошибке валидации.
#[no_mangle]
pub extern "C" fn min_format_contact_key(key: *const c_char) -> *mut c_char {
    if key.is_null() {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let key_str = unsafe { cstr_bound::cstr_str(key) }
            .ok_or(min_protocol::ProtocolError::BadContactKeyString)?;
        let ck = validate_contact_key(&key_str)?;
        Ok::<_, min_protocol::ProtocolError>(ck.to_string_form())
    })) {
        Ok(Ok(canonical)) => CString::new(canonical).unwrap().into_raw(),
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// AUDIT MIN-26 / O-5: создание Contact Key, в том числе ротация эпохи.
///
/// identity_secret_hex — 32-байтовый Ed25519-секрет identity (64 hex);
/// signed_prekey_hex — 32-байтовый X25519 signed prekey (64 hex);
/// epoch — эпоха адреса (>= EPOCH_INITIAL; ротация = текущая + 1);
/// expiry — unix-секунды (0 = без срока).
///
/// mailbox_id выводится ВНУТРИ как HKDF(identity_pk || LE64(epoch)): подставить
/// чужой адрес или сохранить старую эпоху нельзя. Возвращает каноническую
/// MIN3-строку или NULL (fail-closed).
#[no_mangle]
pub extern "C" fn min_contact_key_create(
    identity_secret_hex: *const c_char,
    signed_prekey_hex: *const c_char,
    epoch: u64,
    expiry: u64,
) -> *mut c_char {
    if identity_secret_hex.is_null() || signed_prekey_hex.is_null() {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let sk_str = unsafe { cstr_bound::cstr_str(identity_secret_hex) }
            .ok_or(min_protocol::ProtocolError::BadContactKeyString)?;
        let spk_str = unsafe { cstr_bound::cstr_str(signed_prekey_hex) }
            .ok_or(min_protocol::ProtocolError::BadContactKeyString)?;
        let sk: [u8; 32] = hex::decode(sk_str)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(min_protocol::ProtocolError::Malformed)?;
        let spk: [u8; 32] = hex::decode(spk_str)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(min_protocol::ProtocolError::Malformed)?;
        if epoch < min_protocol::EPOCH_INITIAL {
            return Err(min_protocol::ProtocolError::Malformed);
        }
        let identity = min_identity::IdentityKeypair::from_secret_bytes(&sk);
        let mut ck = min_protocol::contact_key::ContactKeyV3 {
            identity_public_key: identity.public(),
            mailbox_id: min_identity::mailbox_id(&identity.public(), epoch),
            signed_prekey_public: spk,
            expiry,
            epoch,
            signature: [0u8; 64],
        };
        ck.signature = identity.sign(&ck.canonical_payload());
        ck.verify()?;
        Ok::<_, min_protocol::ProtocolError>(ck.to_string_form())
    })) {
        Ok(Ok(s)) => CString::new(s).unwrap().into_raw(),
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// AUDIT MIN-26: эпоха валидного Contact Key (десятичная строка) или NULL.
/// Валидация та же, что у min_parse_contact_key (fail-closed).
#[no_mangle]
pub extern "C" fn min_contact_key_epoch(key: *const c_char) -> *mut c_char {
    if key.is_null() {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let key_str = unsafe { cstr_bound::cstr_str(key) }
            .ok_or(min_protocol::ProtocolError::BadContactKeyString)?;
        let ck = validate_contact_key(&key_str)?;
        Ok::<_, min_protocol::ProtocolError>(ck.epoch.to_string())
    })) {
        Ok(Ok(e)) => CString::new(e).unwrap().into_raw(),
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

// ---- Session manager FFI (PQXDH + Double Ratchet, via libsignal) ----

/// Opaque handle to a min-session SessionManager.
///
/// One handle per local identity. Created via min_session_create, freed via
/// min_session_free. NOT thread-safe: a single handle must be accessed from
/// a single thread (Swift: dedicate a serial queue).
pub struct SessionHandle {
    inner: min_session::SessionManager,
}

/// Creates a new session manager with a fresh X25519 identity.
/// Returns an opaque handle, or NULL on error.
#[no_mangle]
pub extern "C" fn min_session_create() -> *mut SessionHandle {
    match catch_unwind(AssertUnwindSafe(|| {
        let sm = min_session::SessionManager::new("local")?;
        let raw = Box::into_raw(Box::new(SessionHandle { inner: sm }));
        // MIN-RED-007: регистрация handle (иначе `min_session_free` = no-op).
        handles::insert(raw as usize);
        Ok::<_, min_session::SessionError>(raw)
    })) {
        Ok(Ok(ptr)) => ptr,
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// Frees a session manager handle (all sessions/secrets dropped).
///
/// MIN-RED-007: panic-barrier (unwind через `extern "C"` = UB) + no-op на
/// повторный/чуждый free вместо double free.
#[no_mangle]
pub extern "C" fn min_session_free(handle: *mut SessionHandle) {
    if handle.is_null() || !handles::is_live(handle as usize) {
        return;
    }
    if !handles::remove(handle as usize) {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(handle));
    }));
}

/// Returns the public identity key (hex-encoded) for this manager.
/// Caller frees via min_free_string. Returns NULL on error.
#[no_mangle]
pub extern "C" fn min_session_identity_public(handle: *mut SessionHandle) -> *mut c_char {
    if handle.is_null() || !handles::is_live(handle as usize) {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &mut *handle };
        Ok::<_, min_session::SessionError>(hex::encode(h.inner.identity_key_public()))
    })) {
        Ok(Ok(hex_str)) => CString::new(hex_str).unwrap().into_raw(),
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// Generates a fresh prekey bundle. Returns hex-encoded CBOR of PreKeyBundleData.
/// Caller frees via min_free_string. Returns NULL on error.
#[no_mangle]
pub extern "C" fn min_session_generate_bundle(handle: *mut SessionHandle) -> *mut c_char {
    if handle.is_null() || !handles::is_live(handle as usize) {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &mut *handle };
        let bundle = h.inner.generate_prekey_bundle()?;
        let cbor = bundle.to_cbor()?;
        Ok::<_, min_session::SessionError>(hex::encode(cbor))
    })) {
        Ok(Ok(hex_str)) => CString::new(hex_str).unwrap().into_raw(),
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// AUDIT MIN-05: session init, привязанный к верифицированному Contact Key.
///
/// Цепочка доверия (Signal-2026 класс атак: relay подменяет prekey bundle
/// или мешает mailbox'ы — приёмник обязан сверять bundle с каналом):
/// 1) Contact Key парсится и верифицируется (подпись + mailbox==HKDF(identity)),
///    fail-closed;
/// 2) адрес сессии выводится ИЗ Contact Key (hex(mailbox_id)), а не принимается
///    от вызывающего — подменить адрес без подмены подписанного Contact Key нельзя;
/// 3) bundle.signed_pre_key_public (libsignal, `0x05||32B`) == Contact Key
///    signed_prekey_public (raw 32B): relay не может подставить bundle другого
///    участника/другой сессии, тот же signed prekey фиксирует Contact Key.
///
/// `contact_key_str` — строковая форма `MIN3:...`; `bundle_cbor_hex` — hex CBOR
/// PreKeyBundleData (от min_session_generate_bundle). Возвращает "ok" или NULL.
#[no_mangle]
pub extern "C" fn min_session_init_bound(
    handle: *mut SessionHandle,
    contact_key_str: *const c_char,
    bundle_cbor_hex: *const c_char,
) -> *mut c_char {
    if handle.is_null()
        || !handles::is_live(handle as usize)
        || contact_key_str.is_null()
        || bundle_cbor_hex.is_null()
    {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &mut *handle };
        let ck_s = unsafe { cstr_bound::cstr_str(contact_key_str) }.ok_or(
            min_session::SessionError::Crypto("invalid contact key utf8".into()),
        )?;
        let ck = min_protocol::contact_key::ContactKeyV3::parse_string_form(&ck_s)
            .map_err(|e| min_session::SessionError::Crypto(format!("contact key: {e}")))?;
        ck.verify()
            .map_err(|e| min_session::SessionError::Crypto(format!("contact key: {e}")))?;
        if min_identity::mailbox_id(&ck.identity_public_key, ck.epoch) != ck.mailbox_id {
            return Err(min_session::SessionError::Crypto(
                "contact key: mailbox_id not derived from identity".into(),
            ));
        }
        let bundle_hex = unsafe { cstr_bound::cstr_str(bundle_cbor_hex) }.ok_or(
            min_session::SessionError::Crypto("invalid bundle hex".into()),
        )?;
        if bundle_hex.len() > min_session::MAX_PREKEY_BUNDLE_HEX {
            return Err(min_session::SessionError::InvalidPrekeyBundle);
        }
        let cbor = hex::decode(bundle_hex)
            .map_err(|_| min_session::SessionError::Crypto("invalid bundle hex".into()))?;
        let bundle = min_session::PreKeyBundleData::from_cbor(&cbor)?;
        if !bundle.verify_contact_key_binding(&ck.identity_public_key) {
            return Err(min_session::SessionError::InvalidPrekeyBundle);
        }
        // Привязка bundle ↔ Contact Key: signed prekey тот же, что в подписанном
        // Contact Key (libsignal-сериализация = 0x05-префикс + raw 32 байта).
        let spk: [u8; 32] = bundle
            .signed_pre_key_public
            .get(1..33)
            .and_then(|s| s.try_into().ok())
            .ok_or(min_session::SessionError::InvalidPrekeyBundle)?;
        if spk != ck.signed_prekey_public {
            return Err(min_session::SessionError::InvalidPrekeyBundle);
        }
        let peer = hex::encode(ck.mailbox_id);
        // AUDIT MIN-26 / RT-26.9: адрес привязывается к (identity, epoch) —
        // ротация закрывает прежний маршрут, rollback эпохи отвергается.
        h.inner.init_session_with_contact_key(
            &hex::encode(ck.identity_public_key),
            &peer,
            ck.epoch,
            &bundle,
        )?;
        Ok::<_, min_session::SessionError>("ok")
    })) {
        Ok(Ok(msg)) => CString::new(msg).unwrap().into_raw(),
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// Persistence (v6, RT-26.1): экспорт аутентифицированного snapshot'а сессий.
///
/// `storage_key_hex` — hex storage key (FFI-корень секрета); MAC-ключ выводится
/// внутри через BLAKE3-derive ("min-session-snapshot-key/v1"), сам storage key
/// в MAC-вход не попадает. Возвращает hex(`CBOR || tag[32]`) или NULL.
///
/// SECURITY: блоб содержит identity private key и session keys — вызывающий
/// ОБЯЗАН хранить его зашифрованным (min_storage под storage key).
#[no_mangle]
pub extern "C" fn min_session_export(
    handle: *mut SessionHandle,
    storage_key_hex: *const c_char,
) -> *mut c_char {
    if handle.is_null() || !handles::is_live(handle as usize) || storage_key_hex.is_null() {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &mut *handle };
        let sk_hex = unsafe { cstr_bound::cstr_str(storage_key_hex) }.ok_or(
            min_session::SessionError::Crypto("invalid storage key utf8".into()),
        )?;
        let sk = hex::decode(sk_hex)
            .map_err(|_| min_session::SessionError::Crypto("invalid storage key hex".into()))?;
        let mac_key: [u8; 32] = blake3::derive_key("min-session-snapshot-key/v1", &sk);
        let blob = h.inner.snapshot(&mac_key)?;
        Ok::<_, min_session::SessionError>(hex::encode(blob))
    })) {
        Ok(Ok(s)) => CString::new(s).unwrap().into_raw(),
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// Persistence (v6, RT-26.1): восстановление менеджера из snapshot'а
/// (hex `CBOR || tag[32]`, снятого `min_session_export`). MAC проверяется
/// constant-time ДО десериализации; tamper/чужой ключ/мусор → NULL.
/// `local_name` обязан совпадать с тем, под которым сессии были созданы.
#[no_mangle]
pub extern "C" fn min_session_restore(
    local_name: *const c_char,
    blob_hex: *const c_char,
    storage_key_hex: *const c_char,
) -> *mut SessionHandle {
    if local_name.is_null() || blob_hex.is_null() || storage_key_hex.is_null() {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let name = unsafe { cstr_bound::cstr_str(local_name) }.ok_or(
            min_session::SessionError::Crypto("invalid local_name utf8".into()),
        )?;
        let sk_hex = unsafe { cstr_bound::cstr_str(storage_key_hex) }.ok_or(
            min_session::SessionError::Crypto("invalid storage key utf8".into()),
        )?;
        let sk = hex::decode(sk_hex)
            .map_err(|_| min_session::SessionError::Crypto("invalid storage key hex".into()))?;
        let mac_key: [u8; 32] = blake3::derive_key("min-session-snapshot-key/v1", &sk);
        let blob_hex = unsafe { cstr_bound::cstr_str(blob_hex) }.ok_or(
            min_session::SessionError::Crypto("invalid blob utf8".into()),
        )?;
        let blob = hex::decode(blob_hex)
            .map_err(|_| min_session::SessionError::Crypto("invalid blob hex".into()))?;
        let sm = min_session::SessionManager::restore(&name, &blob, &mac_key)?;
        let raw = Box::into_raw(Box::new(SessionHandle { inner: sm }));
        // MIN-RED-007: handle обязан быть в реестре, иначе `min_session_free`
        // не снимет его с учёта и освобождение станет no-op (утечка памяти).
        handles::insert(raw as usize);
        Ok::<_, min_session::SessionError>(raw)
    })) {
        Ok(Ok(ptr)) => ptr,
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// Encrypts `plaintext` for `peer_name`. Returns hex-encoded ciphertext
/// (1-byte type prefix: 0x01=prekey, 0x02=whisper), or NULL on error.
#[no_mangle]
pub extern "C" fn min_session_encrypt(
    handle: *mut SessionHandle,
    peer_name: *const c_char,
    plaintext: *const c_char,
) -> *mut c_char {
    if handle.is_null()
        || !handles::is_live(handle as usize)
        || peer_name.is_null()
        || plaintext.is_null()
    {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &mut *handle };
        let peer = unsafe { cstr_bound::cstr_str(peer_name) }.ok_or(
            min_session::SessionError::Crypto("invalid peer_name utf8".into()),
        )?;
        let pt = unsafe { cstr_bound::cstr_str(plaintext) }.ok_or(
            min_session::SessionError::Crypto("invalid plaintext utf8".into()),
        )?;
        let ct = h.inner.encrypt(&peer, pt.as_bytes())?;
        Ok::<_, min_session::SessionError>(hex::encode(ct))
    })) {
        Ok(Ok(hex_str)) => CString::new(hex_str).unwrap().into_raw(),
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// Decrypts hex-encoded `ciphertext_hex` from `peer_name`.
/// Returns the plaintext string, or NULL on error.
#[no_mangle]
pub extern "C" fn min_session_decrypt(
    handle: *mut SessionHandle,
    peer_name: *const c_char,
    ciphertext_hex: *const c_char,
) -> *mut c_char {
    if handle.is_null()
        || !handles::is_live(handle as usize)
        || peer_name.is_null()
        || ciphertext_hex.is_null()
    {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &mut *handle };
        let peer = unsafe { cstr_bound::cstr_str(peer_name) }.ok_or(
            min_session::SessionError::Crypto("invalid peer_name utf8".into()),
        )?;
        let ct_hex = unsafe { cstr_bound::cstr_str(ciphertext_hex) }.ok_or(
            min_session::SessionError::Crypto("invalid ciphertext hex".into()),
        )?;
        let ct = hex::decode(ct_hex)
            .map_err(|_| min_session::SessionError::Crypto("invalid ciphertext hex".into()))?;
        let pt = h.inner.decrypt(&peer, &ct)?;
        String::from_utf8(pt)
            .map_err(|_| min_session::SessionError::Crypto("plaintext not utf8".into()))
    })) {
        Ok(Ok(s)) => CString::new(s).unwrap().into_raw(),
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

// =====================================================================
// Delivery FFI (MailboxClient) — register / enqueue / pull / ack.
// Policy (PROTOCOL §7): prod link is Tor; TCP is dev/test harness only.
// No automatic fallback (README: «прямой fallback запрещён»).
// =====================================================================

use min_delivery::{DeliveryError, FrameExchange, MailboxClient};
use min_tor::TorTransport;
use min_tor::TorTransportConfig;

/// Transport selected for a delivery link.
///
/// RT-26.19 / PROTOCOL §7: production transport is Tor ONLY. The direct TCP
/// link exists solely as a dev/test harness and is compiled out of release
/// builds (the `DirectTcp` variant, its token and the `DeliveryLink::Tcp`
/// variant are behind `cfg(any(test, feature = "dev-tcp-link"))`), so a
/// shipped binary contains no direct transport path at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkKind {
    Tor,
    /// В SOCKS5-режиме клиент подключается к локальному C Tor/IPtProxy
    /// и затем к onion relay; адрес и состояние Tor живут в Swift-слое.
    Socks,
    #[cfg(any(test, feature = "dev-tcp-link"))]
    DirectTcp,
}

impl LinkKind {
    /// Strict lexical resolution — no trimming, no case folding, no fuzzy
    /// matching: a typo must never silently select a transport. Unknown kinds
    /// (including the retired bare `"tcp"` token) resolve to `None`, and the
    /// caller fails closed (NULL).
    pub(crate) fn resolve(kind: &str) -> Option<Self> {
        match kind {
            "tor" => Some(LinkKind::Tor),
            "socks" => Some(LinkKind::Socks),
            #[cfg(any(test, feature = "dev-tcp-link"))]
            "tcp-dev-harness" => Some(LinkKind::DirectTcp),
            _ => None,
        }
    }
}

/// Link dispatch (all transports implement `FrameExchange`).
pub(crate) enum DeliveryLink {
    #[cfg(any(test, feature = "dev-tcp-link"))]
    Tcp(min_delivery::tcp_link::TcpLink),
    Socks(min_delivery::socks_link::SocksLink),
    Tor(TorTransport),
}

impl FrameExchange for DeliveryLink {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, DeliveryError> {
        match self {
            #[cfg(any(test, feature = "dev-tcp-link"))]
            DeliveryLink::Tcp(link) => link.exchange(request),
            DeliveryLink::Socks(link) => link.exchange(request),
            DeliveryLink::Tor(link) => link.exchange(request),
        }
    }
}

/// Opaque handle owning the link + client.
pub struct DeliveryHandle {
    inner: MailboxClient<DeliveryLink>,
}

/// Splits `host:port`; returns 443 when no explicit port.
pub(crate) fn split_host_port(addr: &str) -> Result<(String, u16), DeliveryError> {
    let idx = addr.rfind(':');
    if idx.is_none() {
        return Ok((addr.into(), 443));
    }
    let Some(i) = idx else {
        return Err(DeliveryError::Net(min_net::NetError::Transport(
            "no colon".into(),
        )));
    };
    let host = addr[..i].into();
    let mut port = 0u16;
    for ch in addr[i + 1..].chars() {
        if !ch.is_ascii_digit() {
            return Err(DeliveryError::Net(min_net::NetError::Transport(
                "bad value".into(),
            )));
        }
        let d = (ch as u16) - ('0' as u16);
        port = port * 10 + d;
    }
    Ok((host, port))
}

/// Opens a delivery link.
///
/// - `link_kind`: `"tcp-dev-harness"` (dev/test only) or `"tor"` (prod).
/// - `addr`: tcp — `host:port`; tor — `onion_host:port`.
/// - `state_dir_opt`/`cache_dir_opt`: writable dirs for Tor state; pass `""`
///   to use defaults (host only; iOS callers MUST pass real directories).
///
/// Returns an opaque handle, or NULL on error. Blocking (Tor bootstrap on
/// first run) — call from a worker thread, never the UI thread.
#[no_mangle]
pub extern "C" fn min_delivery_open(
    link_kind: *const c_char,
    addr: *const c_char,
    state_dir_opt: *const c_char,
    cache_dir_opt: *const c_char,
) -> *mut DeliveryHandle {
    if link_kind.is_null() || addr.is_null() {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let kind = unsafe { cstr_bound::cstr_str(link_kind) }.unwrap_or_default();
        let addr = unsafe { cstr_bound::cstr_str(addr) }.unwrap_or_default();
        if addr.is_empty() {
            return Err::<_, DeliveryError>(DeliveryError::Net(min_net::NetError::Transport(
                "bad value".into(),
            )));
        }
        let (host, port) = split_host_port(&addr)?;

        let link: DeliveryLink = match LinkKind::resolve(&kind) {
            #[cfg(any(test, feature = "dev-tcp-link"))]
            Some(LinkKind::DirectTcp) => {
                DeliveryLink::Tcp(min_delivery::tcp_link::TcpLink::new(addr))
            }
            Some(LinkKind::Tor) => {
                let cfg = TorTransportConfig {
                    relay_host: host,
                    relay_port: port,
                    state_dir: if state_dir_opt.is_null() {
                        None
                    } else {
                        let s = unsafe { cstr_bound::cstr_str(state_dir_opt) }.unwrap_or_default();
                        if s.is_empty() {
                            None
                        } else {
                            Some(std::path::PathBuf::from(s))
                        }
                    },
                    cache_dir: if cache_dir_opt.is_null() {
                        None
                    } else {
                        let s = unsafe { cstr_bound::cstr_str(cache_dir_opt) }.unwrap_or_default();
                        if s.is_empty() {
                            None
                        } else {
                            Some(std::path::PathBuf::from(s))
                        }
                    },
                    ..Default::default()
                };
                let transport = min_tor::TorTransport::connect(cfg)
                    .map_err(|e| DeliveryError::Net(min_net::NetError::Transport(e.to_string())))?;
                DeliveryLink::Tor(transport)
            }
            _ => {
                return Err::<_, DeliveryError>(DeliveryError::Net(min_net::NetError::Transport(
                    "bad value".into(),
                )))
            }
        };

        let client = MailboxClient::new(link);
        let raw = Box::into_raw(Box::new(DeliveryHandle { inner: client }));
        // MIN-RED-007: регистрация handle (иначе `min_delivery_close` = no-op).
        handles::insert(raw as usize);
        Ok::<_, min_delivery::DeliveryError>(raw)
    })) {
        Ok(Ok(ptr)) => ptr,
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// Frees a delivery handle (link closed, buffers dropped).
///
/// MIN-RED-007: panic не должен разворачиваться через `extern "C"` (UB), а
/// повторный/чуждой вызов обязан быть no-op, а не double free.
#[no_mangle]
pub extern "C" fn min_delivery_close(handle: *mut DeliveryHandle) {
    if handle.is_null() || !handles::is_live(handle as usize) {
        return;
    }
    if !handles::remove(handle as usize) {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(handle));
    }));
}

/// Registers this mailbox (claim-once) and returns `epoch:token_hex`.
/// Caller frees via min_free_string. Returns NULL on error.
#[no_mangle]
pub extern "C" fn min_delivery_register(
    handle: *mut DeliveryHandle,
    mailbox_id: *const c_char,
) -> *mut c_char {
    if handle.is_null() || !handles::is_live(handle as usize) || mailbox_id.is_null() {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &mut *handle };
        let mb = unsafe { cstr_bound::cstr_str(mailbox_id) }.ok_or(DeliveryError::Net(
            min_net::NetError::Transport("utf8".into()),
        ))?;
        let (epoch, token) = h.inner.register(&mb)?;
        Ok::<_, min_delivery::DeliveryError>(format!("{}:{}", epoch, hex::encode(token)))
    })) {
        Ok(Ok(s)) => CString::new(s).unwrap().into_raw(),
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// Enqueues an item to `target_mailbox`. Returns the relay-assigned item_id,
/// or NULL on error (unknown mailbox, queue full, rate limited…).
/// `envelope_hex`: opaque ciphertext, hex-encoded (never plaintext —
/// PROTOCOL invariant №1). `item_type`: 1=REQUEST, 2=MESSAGE, 3=CONTROL.
#[no_mangle]
pub extern "C" fn min_delivery_enqueue(
    handle: *mut DeliveryHandle,
    target_mailbox: *const c_char,
    envelope_hex: *const c_char,
    item_type: u64,
) -> *mut c_char {
    if handle.is_null()
        || !handles::is_live(handle as usize)
        || target_mailbox.is_null()
        || envelope_hex.is_null()
    {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &mut *handle };
        let tgt = unsafe { cstr_bound::cstr_str(target_mailbox) }.ok_or(DeliveryError::Net(
            min_net::NetError::Transport("utf8".into()),
        ))?;
        let env_hex = unsafe { cstr_bound::cstr_str(envelope_hex) }.ok_or(DeliveryError::Net(
            min_net::NetError::Transport("utf8".into()),
        ))?;
        let env =
            hex::decode(env_hex)
                .ok()
                .ok_or(DeliveryError::Net(min_net::NetError::Transport(
                    "bad hex".into(),
                )))?;
        let item_type = match item_type {
            1 => min_protocol::frame_api::QueueItemType::Request,
            2 => min_protocol::frame_api::QueueItemType::Message,
            3 => min_protocol::frame_api::QueueItemType::Control,
            _ => {
                return Err::<_, min_delivery::DeliveryError>(DeliveryError::Protocol(
                    min_protocol::ProtocolError::Malformed,
                ))
            }
        };
        let (item_id, _exp) = h.inner.enqueue(&tgt, &env, item_type)?;
        Ok::<_, min_delivery::DeliveryError>(item_id)
    })) {
        Ok(Ok(s)) => CString::new(s).unwrap().into_raw(),
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// Pulls the queue. One line per item (`\n`-separated):
/// `item_id|type|envelope_hex|arrived_at|expires_at`
/// type ∈ {1,2,3}. Empty string when the queue is empty; NULL on error.
#[no_mangle]
pub extern "C" fn min_delivery_pull(
    handle: *mut DeliveryHandle,
    mailbox_id: *const c_char,
    token_hex: *const c_char,
) -> *mut c_char {
    if handle.is_null()
        || !handles::is_live(handle as usize)
        || mailbox_id.is_null()
        || token_hex.is_null()
    {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &mut *handle };
        let mb = unsafe { cstr_bound::cstr_str(mailbox_id) }.ok_or(DeliveryError::Net(
            min_net::NetError::Transport("utf8".into()),
        ))?;
        let tok_hex = unsafe { cstr_bound::cstr_str(token_hex) }.ok_or(DeliveryError::Net(
            min_net::NetError::Transport("utf8".into()),
        ))?;
        let tok =
            hex::decode(tok_hex)
                .ok()
                .ok_or(DeliveryError::Net(min_net::NetError::Transport(
                    "bad token hex".into(),
                )))?;
        if tok.len() != 32 {
            return Err::<_, min_delivery::DeliveryError>(DeliveryError::Protocol(
                min_protocol::ProtocolError::Malformed,
            ));
        }
        let mut token = [0u8; 32];
        token.copy_from_slice(&tok);
        let items = h.inner.pull(&mb, &token)?;
        let out = items
            .iter()
            .map(|it| {
                format!(
                    "{}|{}|{}|{}|{}",
                    it.item_id,
                    match it.item_type {
                        min_protocol::frame_api::QueueItemType::Request => 1,
                        min_protocol::frame_api::QueueItemType::Message => 2,
                        min_protocol::frame_api::QueueItemType::Control => 3,
                    },
                    hex::encode(&it.envelope),
                    it.arrived_at,
                    it.expires_at,
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        Ok::<_, min_delivery::DeliveryError>(out)
    })) {
        Ok(Ok(s)) => CString::new(s).unwrap().into_raw(),
        Ok(Err(e)) => {
            let msg = format!("ERR:{}", e);
            CString::new(msg).unwrap().into_raw()
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// NULL on error.
#[no_mangle]
pub extern "C" fn min_delivery_ack(
    handle: *mut DeliveryHandle,
    mailbox_id: *const c_char,
    token_hex: *const c_char,
    item_ids: *const c_char,
) -> *mut c_char {
    if handle.is_null()
        || !handles::is_live(handle as usize)
        || mailbox_id.is_null()
        || token_hex.is_null()
        || item_ids.is_null()
    {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &mut *handle };
        let mb = unsafe { cstr_bound::cstr_str(mailbox_id) }.ok_or(DeliveryError::Net(
            min_net::NetError::Transport("utf8".into()),
        ))?;
        let tok_hex = unsafe { cstr_bound::cstr_str(token_hex) }.ok_or(DeliveryError::Net(
            min_net::NetError::Transport("utf8".into()),
        ))?;
        let tok =
            hex::decode(tok_hex)
                .ok()
                .ok_or(DeliveryError::Net(min_net::NetError::Transport(
                    "bad token hex".into(),
                )))?;
        if tok.len() != 32 {
            return Err::<_, min_delivery::DeliveryError>(DeliveryError::Protocol(
                min_protocol::ProtocolError::Malformed,
            ));
        }
        let mut token = [0u8; 32];
        token.copy_from_slice(&tok);
        let ids_raw = unsafe { cstr_bound::cstr_str(item_ids) }.ok_or(DeliveryError::Net(
            min_net::NetError::Transport("utf8".into()),
        ))?;
        let ids: Vec<String> = ids_raw
            .split('\n')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_owned())
            .collect::<Vec<_>>();
        let acked = h.inner.ack(&mb, &token, &ids)?;
        Ok::<_, min_delivery::DeliveryError>(format!("{}", acked))
    })) {
        Ok(Ok(s)) => CString::new(s).unwrap().into_raw(),
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}
// ---------------------------------------------------------------------------
// Storage (min-storage): зашифрованное KV-хранилище (SQLite + XChaCha20).
// ---------------------------------------------------------------------------

/// Opaque handle to an opened encrypted storage.
pub struct StorageHandle {
    inner: min_storage::Storage,
}

/// Generates a fresh random storage key (hex-encoded, 64 chars).
/// The caller MUST wrap it in iOS Keychain (kSecAttrAccessibleWhenUnlockedThisDeviceOnly).
/// Caller frees via min_free_string. Returns NULL on error.
#[no_mangle]
pub extern "C" fn min_storage_key_generate() -> *mut c_char {
    match catch_unwind(AssertUnwindSafe(|| {
        let mut key = min_storage::generate_storage_key();
        let hex_str = hex::encode(key);
        // AUDIT MIN-03: raw-байты ключа не живут дольше hex-кодирования.
        key.zeroize();
        Ok::<_, ()>(hex_str)
    })) {
        Ok(Ok(hex_str)) => CString::new(hex_str).unwrap().into_raw(),
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// CSPRNG-байты из Rust-ядра, hex-строкой. `n` = число байт (1..=1024).
/// Используется для pull-токенов и иного не-криптографического случайного
/// материала, чтобы CSPRNG-политика ядра не обходилась на стороне Swift.
#[no_mangle]
pub extern "C" fn min_random_hex(n: usize) -> *mut c_char {
    match catch_unwind(AssertUnwindSafe(|| {
        if n == 0 || n > 1024 {
            return Err(());
        }
        use rand_core::RngCore;
        let mut buf = vec![0u8; n];
        rand_core::OsRng.fill_bytes(&mut buf);
        Ok(hex::encode(&buf))
    })) {
        Ok(Ok(s)) => CString::new(s).unwrap().into_raw(),
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// Opens (or creates) an encrypted storage at `path` with `key_hex` (32 bytes hex).
/// Returns an opaque handle, or NULL on error (bad key length / db failure).
#[no_mangle]
pub extern "C" fn min_storage_open(
    path: *const c_char,
    key_hex: *const c_char,
) -> *mut StorageHandle {
    if path.is_null() || key_hex.is_null() {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let path_s = unsafe { cstr_bound::cstr_str(path) }?;
        let key_hex_s = unsafe { cstr_bound::cstr_str(key_hex) }?;
        let key_bytes = hex::decode(key_hex_s).ok()?;
        let key: [u8; min_storage::KEY_LEN] = key_bytes.try_into().ok()?;
        let storage = min_storage::Storage::open(path_s, &key).ok()?;
        let raw = Box::into_raw(Box::new(StorageHandle { inner: storage }));
        // MIN-RED-007: регистрация handle (иначе `min_storage_free` = no-op).
        handles::insert(raw as usize);
        Some(raw)
    })) {
        Ok(Some(ptr)) => ptr,
        Ok(None) | Err(_) => std::ptr::null_mut(),
    }
}

/// Frees a storage handle. The storage file on disk remains (encrypted).
///
/// MIN-RED-007: panic-barrier (unwind через `extern "C"` = UB) + no-op на
/// повторный/чуждый free вместо double free.
#[no_mangle]
pub extern "C" fn min_storage_free(handle: *mut StorageHandle) {
    if handle.is_null() || !handles::is_live(handle as usize) {
        return;
    }
    if !handles::remove(handle as usize) {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(handle));
    }));
}

/// Puts a value (hex-encoded bytes) under `key`.
/// Returns "ok" on success, or NULL on error.
#[no_mangle]
pub extern "C" fn min_storage_put(
    handle: *mut StorageHandle,
    key: *const c_char,
    value_hex: *const c_char,
) -> *mut c_char {
    if handle.is_null()
        || !handles::is_live(handle as usize)
        || key.is_null()
        || value_hex.is_null()
    {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &mut *handle };
        let key_s = unsafe { cstr_bound::cstr_str(key) }?;
        let value_hex_s = unsafe { cstr_bound::cstr_str(value_hex) }?;
        let value = hex::decode(value_hex_s).ok()?;
        h.inner.put(&key_s, &value).ok()?;
        Some("ok")
    })) {
        Ok(Some(s)) => CString::new(s).unwrap().into_raw(),
        Ok(None) | Err(_) => std::ptr::null_mut(),
    }
}

/// Gets the value under `key` (hex-encoded).
/// Returns "" (empty string) if not found — distinct from NULL (error).
/// Caller frees via min_free_string.
#[no_mangle]
pub extern "C" fn min_storage_get(handle: *mut StorageHandle, key: *const c_char) -> *mut c_char {
    if handle.is_null() || !handles::is_live(handle as usize) || key.is_null() {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &mut *handle };
        let key_s = unsafe { cstr_bound::cstr_str(key) }?;
        let value = h.inner.get(&key_s).ok()?;
        Some(hex::encode(value.unwrap_or_default()))
    })) {
        Ok(Some(s)) => CString::new(s).unwrap().into_raw(),
        Ok(None) | Err(_) => std::ptr::null_mut(),
    }
}

/// Checks existence: "1" if present, "0" if absent, NULL on error.
#[no_mangle]
pub extern "C" fn min_storage_exists(
    handle: *mut StorageHandle,
    key: *const c_char,
) -> *mut c_char {
    if handle.is_null() || !handles::is_live(handle as usize) || key.is_null() {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &mut *handle };
        let key_s = unsafe { cstr_bound::cstr_str(key) }?;
        let present = h.inner.get(&key_s).ok()?.is_some();
        Some(if present { "1" } else { "0" })
    })) {
        Ok(Some(s)) => CString::new(s).unwrap().into_raw(),
        Ok(None) | Err(_) => std::ptr::null_mut(),
    }
}

/// Deletes `key`: "1" if deleted, "0" if absent, NULL on error.
#[no_mangle]
pub extern "C" fn min_storage_delete(
    handle: *mut StorageHandle,
    key: *const c_char,
) -> *mut c_char {
    if handle.is_null() || !handles::is_live(handle as usize) || key.is_null() {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &mut *handle };
        let key_s = unsafe { cstr_bound::cstr_str(key) }?;
        let deleted = h.inner.delete(&key_s).ok()?;
        Some(if deleted { "1" } else { "0" })
    })) {
        Ok(Some(s)) => CString::new(s).unwrap().into_raw(),
        Ok(None) | Err(_) => std::ptr::null_mut(),
    }
}

/// Lists all keys, newline-separated. Returns "" if empty, NULL on error.
/// Caller frees via min_free_string.
#[no_mangle]
pub extern "C" fn min_storage_list_keys(handle: *mut StorageHandle) -> *mut c_char {
    if handle.is_null() || !handles::is_live(handle as usize) {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &mut *handle };
        let keys = h.inner.list_keys().ok()?;
        Some(keys.join("\n"))
    })) {
        Ok(Some(s)) => CString::new(s).unwrap().into_raw(),
        Ok(None) | Err(_) => std::ptr::null_mut(),
    }
}

/// Number of records, decimal string. NULL on error.
#[no_mangle]
pub extern "C" fn min_storage_count(handle: *mut StorageHandle) -> *mut c_char {
    if handle.is_null() || !handles::is_live(handle as usize) {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let h = unsafe { &mut *handle };
        Some(h.inner.len().ok()?.to_string())
    })) {
        Ok(Some(s)) => CString::new(s).unwrap().into_raw(),
        Ok(None) | Err(_) => std::ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------
// Recovery (min-recovery): offline бэкап через Argon2id + XChaCha20.
// ---------------------------------------------------------------------------

/// Creates an encrypted backup blob from plaintext (hex) + password.
/// Salt and nonce are generated internally and embedded in the blob.
/// Returns hex-encoded backup, or NULL on error.
#[no_mangle]
pub extern "C" fn min_recovery_create_backup(
    plaintext_hex: *const c_char,
    password: *const c_char,
) -> *mut c_char {
    if plaintext_hex.is_null() || password.is_null() {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let pt_hex = unsafe { cstr_bound::cstr_str(plaintext_hex) }?;
        let password_bytes = unsafe { cstr_bound::BoundedCStr::from_ptr(password) }?
            .to_bytes()
            .to_vec();
        let plaintext = hex::decode(pt_hex).ok()?;
        let backup = min_recovery::create_backup(&plaintext, &password_bytes).ok()?;
        Some(hex::encode(backup))
    })) {
        Ok(Some(s)) => CString::new(s).unwrap().into_raw(),
        Ok(None) | Err(_) => std::ptr::null_mut(),
    }
}

/// Restores plaintext (hex) from a backup blob (hex) + password.
/// Returns NULL on error (wrong password / corrupted backup / bad hex).
#[no_mangle]
pub extern "C" fn min_recovery_restore_backup(
    backup_hex: *const c_char,
    password: *const c_char,
) -> *mut c_char {
    if backup_hex.is_null() || password.is_null() {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let b_hex = unsafe { cstr_bound::cstr_str(backup_hex) }?;
        let password_bytes = unsafe { cstr_bound::BoundedCStr::from_ptr(password) }?
            .to_bytes()
            .to_vec();
        let backup = hex::decode(b_hex).ok()?;
        let plaintext = min_recovery::restore_backup(&backup, &password_bytes).ok()?;
        Some(hex::encode(plaintext))
    })) {
        Ok(Some(s)) => CString::new(s).unwrap().into_raw(),
        Ok(None) | Err(_) => std::ptr::null_mut(),
    }
}

/// Backup metadata without decryption: "version:payload_len" (decimal), NULL on error.
#[no_mangle]
pub extern "C" fn min_recovery_backup_info(backup_hex: *const c_char) -> *mut c_char {
    if backup_hex.is_null() {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let b_hex = unsafe { cstr_bound::cstr_str(backup_hex) }?;
        let backup = hex::decode(b_hex).ok()?;
        let (version, payload_len) = min_recovery::backup_info(&backup).ok()?;
        Some(format!("{}:{}", version, payload_len))
    })) {
        Ok(Some(s)) => CString::new(s).unwrap().into_raw(),
        Ok(None) | Err(_) => std::ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------
// Device (min-device): Ed25519-signed revoke certificates.
// ---------------------------------------------------------------------------

/// `identity_secret_hex` = 32-byte Ed25519 seed of the owner identity.
/// `device_public_hex` = 32-byte Ed25519 public key of the device to revoke.
/// device_id is derived internally (SHA-256 truncated, min-device policy).
/// Returns hex-encoded certificate, or NULL on error.
#[no_mangle]
pub extern "C" fn min_device_revoke_create(
    identity_secret_hex: *const c_char,
    device_public_hex: *const c_char,
    revoked_at: u64,
) -> *mut c_char {
    if identity_secret_hex.is_null() || device_public_hex.is_null() {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let sk_hex = unsafe { cstr_bound::cstr_str(identity_secret_hex) }?;
        let pk_hex = unsafe { cstr_bound::cstr_str(device_public_hex) }?;
        let sk_bytes: [u8; 32] = hex::decode(sk_hex).ok()?.try_into().ok()?;
        let pk_bytes: [u8; 32] = hex::decode(pk_hex).ok()?.try_into().ok()?;
        let sk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).ok()?;
        let device_id = min_device::device_id_from_key(&vk);
        let cert = min_device::create_revoke_certificate(&sk, &device_id, revoked_at);
        Some(hex::encode(min_device::serialize_revoke_certificate(&cert)))
    })) {
        Ok(Some(s)) => CString::new(s).unwrap().into_raw(),
        Ok(None) | Err(_) => std::ptr::null_mut(),
    }
}

/// Verifies a serialized revoke certificate (hex) against the owner's public key.
/// Returns "1" if the signature is valid, "0" if invalid (bad signature /
/// unsupported version), NULL on malformed input.
#[no_mangle]
pub extern "C" fn min_device_revoke_verify(
    cert_hex: *const c_char,
    owner_public_hex: *const c_char,
) -> *mut c_char {
    if cert_hex.is_null() || owner_public_hex.is_null() {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let cert_hex_s = unsafe { cstr_bound::cstr_str(cert_hex) }?;
        let pk_hex = unsafe { cstr_bound::cstr_str(owner_public_hex) }?;
        let cert_bytes = hex::decode(cert_hex_s).ok()?;
        let pk_bytes: [u8; 32] = hex::decode(pk_hex).ok()?.try_into().ok()?;
        let cert = min_device::deserialize_revoke_certificate(&cert_bytes).ok()?;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).ok()?;
        let valid = min_device::verify_revoke_certificate(&cert, &vk).is_ok();
        Some(if valid { "1" } else { "0" })
    })) {
        Ok(Some(s)) => CString::new(s).unwrap().into_raw(),
        Ok(None) | Err(_) => std::ptr::null_mut(),
    }
}

/// Derives the device_id (hex) from a device public key (hex).
/// Caller frees via min_free_string. Returns NULL on error.
#[no_mangle]
pub extern "C" fn min_device_id_from_public_key(device_public_hex: *const c_char) -> *mut c_char {
    if device_public_hex.is_null() {
        return std::ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let pk_hex = unsafe { cstr_bound::cstr_str(device_public_hex) }?;
        let pk_bytes: [u8; 32] = hex::decode(pk_hex).ok()?.try_into().ok()?;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).ok()?;
        Some(hex::encode(min_device::device_id_from_key(&vk)))
    })) {
        Ok(Some(s)) => CString::new(s).unwrap().into_raw(),
        Ok(None) | Err(_) => std::ptr::null_mut(),
    }
}

/// Verifies the envelope header binding (AUDIT MIN-02, PROTOCOL §3 field 7).
///
/// `envelope_hex` — canonical CBOR of EnvelopeV1; `session_id_hex` — session
/// identifier bytes. Returns "1" if aad_commitment matches the recomputed
/// BLAKE3-256(commitment_input), "0" on mismatch/malformed, NULL on FFI error.
/// Swift must call this BEFORE feeding a pulled envelope into session decrypt:
/// any relay/header tampering is detected here, independent of the inner
/// libsignal AEAD.
#[no_mangle]
pub extern "C" fn min_envelope_verify(
    envelope_hex: *const c_char,
    session_id_hex: *const c_char,
) -> *mut c_char {
    if envelope_hex.is_null() || session_id_hex.is_null() {
        return std::ptr::null_mut();
    }
    // FFI contract: NULL только при FFI-ошибке (null-указатели, не-UTF8, паника).
    // Любой парсибельный ввод, не прошедший проверку → "0" (вердикт, не ошибка).
    match catch_unwind(AssertUnwindSafe(|| {
        let env_hex = match unsafe { cstr_bound::cstr_str(envelope_hex) } {
            Some(s) => s,
            None => return "0", // не-терминированный/слишно в envelope_hex → невалидный envelope
        };
        let sid_hex = match unsafe { cstr_bound::cstr_str(session_id_hex) } {
            Some(s) => s,
            None => return "0", // не-терминированный/слишно в session_id_hex → невалидный envelope
        };
        let env_bytes = match hex::decode(env_hex) {
            Ok(b) => b,
            Err(_) => return "0", // не-hex → невалидный envelope
        };
        let sid = match hex::decode(sid_hex) {
            Ok(b) => b,
            Err(_) => return "0", // не-hex → невалидный envelope
        };
        match min_protocol::envelope::EnvelopeV1::from_wire_verified(&env_bytes, &sid) {
            Ok(_) => "1",
            Err(_) => "0",
        }
    })) {
        Ok(s) => CString::new(s).unwrap().into_raw(),
        Err(_) => std::ptr::null_mut(), // только паника → NULL
    }
}

mod app_ffi;
/// MIN-RED-011: ограниченное чтение C-строк (замена `CStr::from_ptr`).
pub mod cstr_bound;
/// MIN-RED-007: реестр живых handle + panic-barrier на FFI-границе.
pub mod handles;

#[cfg(test)]
mod tests {
    use super::*;

    /// Полный цикл storage FFI: key_generate → open → put → get → exists
    /// → delete → count → list → free. Также проверка wrong-key на NULL.
    /// Device revoke FFI: create → verify (valid) → verify with wrong
    /// owner key → "0"; corrupted cert → NULL; device_id derivation.
    #[test]
    fn test_device_revoke_ffi_cycle() {
        // Ed25519 keypair for the test (owner identity + device).
        let (owner_sk, owner_pk) = min_device::generate_test_keypair();
        let (device_sk, device_pk) = min_device::generate_test_keypair();
        let _ = device_sk;
        let sk_hex = hex::encode(owner_sk.to_bytes()[..32].to_vec());
        let owner_pk_hex = hex::encode(owner_pk.as_bytes());
        let device_pk_hex = hex::encode(device_pk.as_bytes());

        // device_id derivation
        let id_c = CString::new(device_pk_hex.as_str()).unwrap();
        let id1 = min_device_id_from_public_key(id_c.as_ptr());
        assert!(!id1.is_null(), "device_id derivation failed");
        let id1_s = unsafe { CStr::from_ptr(id1) }.to_str().unwrap().to_string();
        min_free_string(id1);
        // deterministic: same key → same id
        let id2 = min_device_id_from_public_key(id_c.as_ptr());
        assert_eq!(unsafe { CStr::from_ptr(id2) }.to_str().unwrap(), id1_s);
        min_free_string(id2);

        // create certificate
        let sk_c = CString::new(sk_hex).unwrap();
        let pk_c = CString::new(device_pk_hex.as_str()).unwrap();
        let cert_ptr = min_device_revoke_create(sk_c.as_ptr(), pk_c.as_ptr(), 1700000000);
        assert!(!cert_ptr.is_null(), "revoke create failed");
        let cert_hex = unsafe { CStr::from_ptr(cert_ptr) }
            .to_str()
            .unwrap()
            .to_string();
        min_free_string(cert_ptr);

        // verify valid
        let cert_c = CString::new(cert_hex.as_str()).unwrap();
        let owner_c = CString::new(owner_pk_hex.as_str()).unwrap();
        let verdict = min_device_revoke_verify(cert_c.as_ptr(), owner_c.as_ptr());
        assert!(!verdict.is_null());
        assert_eq!(unsafe { CStr::from_ptr(verdict) }.to_str().unwrap(), "1");
        min_free_string(verdict);

        // verify with wrong owner key → "0" (bad signature)
        let (other_sk, other_pk) = min_device::generate_test_keypair();
        let _ = other_sk;
        let other_c = CString::new(hex::encode(other_pk.as_bytes())).unwrap();
        let verdict2 = min_device_revoke_verify(cert_c.as_ptr(), other_c.as_ptr());
        assert!(!verdict2.is_null());
        assert_eq!(unsafe { CStr::from_ptr(verdict2) }.to_str().unwrap(), "0");
        min_free_string(verdict2);

        // corrupted signature bytes (valid format) → "0" (bad signature)
        let mut corrupted = cert_hex.clone();
        let last = corrupted.pop().unwrap();
        // Гарантированно ДРУГОЙ символ (иначе '0'→'0' не портит подпись и
        // тест флейкает с вероятностью 1/16 — red-team находка MIN-22).
        corrupted.push(if last == '0' { '1' } else { '0' });
        let corrupted_c = CString::new(corrupted).unwrap();
        let verdict3 = min_device_revoke_verify(corrupted_c.as_ptr(), owner_c.as_ptr());
        assert!(!verdict3.is_null());
        assert_eq!(unsafe { CStr::from_ptr(verdict3) }.to_str().unwrap(), "0");
        min_free_string(verdict3);

        // malformed input (not hex) → NULL
        let garbage = CString::new("!!!not-hex!!!").unwrap();
        assert!(min_device_revoke_verify(garbage.as_ptr(), owner_c.as_ptr()).is_null());

        // null inputs
        assert!(min_device_revoke_create(std::ptr::null(), std::ptr::null(), 0).is_null());
        assert!(min_device_revoke_verify(std::ptr::null(), std::ptr::null()).is_null());
        assert!(min_device_id_from_public_key(std::ptr::null()).is_null());
    }

    /// Recovery FFI: create → info → restore (correct password) →
    /// restore with wrong password → NULL; corrupted backup → NULL.
    #[test]
    fn test_recovery_ffi_cycle() {
        let plaintext = CString::new(hex::encode(b"identity seed material")).unwrap();
        let password = CString::new("correct horse battery").unwrap();

        // create
        let backup_ptr = min_recovery_create_backup(plaintext.as_ptr(), password.as_ptr());
        assert!(!backup_ptr.is_null(), "create_backup failed");
        let backup_hex = unsafe { CStr::from_ptr(backup_ptr) }
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            backup_hex.len() > 80,
            "backup blob must include salt+nonce+tag"
        );
        min_free_string(backup_ptr);

        // info
        let info_c = CString::new(backup_hex.as_str()).unwrap();
        let info = min_recovery_backup_info(info_c.as_ptr());
        assert!(!info.is_null());
        assert!(
            unsafe { CStr::from_ptr(info) }
                .to_str()
                .unwrap()
                .starts_with("1:"),
            "version must be 1"
        );
        min_free_string(info);

        // restore correct password
        let restored = min_recovery_restore_backup(info_c.as_ptr(), password.as_ptr());
        assert!(!restored.is_null(), "restore failed");
        let restored_s = unsafe { CStr::from_ptr(restored) }.to_str().unwrap();
        assert_eq!(restored_s, hex::encode(b"identity seed material"));
        min_free_string(restored);

        // restore wrong password → NULL
        let wrong = CString::new("wrong password").unwrap();
        assert!(
            min_recovery_restore_backup(info_c.as_ptr(), wrong.as_ptr()).is_null(),
            "wrong password must return NULL"
        );

        // corrupted backup → NULL. Портим реальный байт в шифротексте
        // (после заголовка: version+salt+nonce = 1+16+24 = 41 байт), а не hex-символ.
        let mut corrupted_bytes = hex::decode(&backup_hex).unwrap();
        if corrupted_bytes.len() > 41 {
            corrupted_bytes[41] ^= 0xFF; // XOR байта в теле шифротекста
        }
        let corrupted_hex = hex::encode(&corrupted_bytes);
        let corrupted_c = CString::new(corrupted_hex).unwrap();
        assert!(
            min_recovery_restore_backup(corrupted_c.as_ptr(), password.as_ptr()).is_null(),
            "corrupted backup must return NULL"
        );

        // null inputs
        assert!(min_recovery_create_backup(std::ptr::null(), std::ptr::null()).is_null());
        assert!(min_recovery_restore_backup(std::ptr::null(), std::ptr::null()).is_null());
        assert!(min_recovery_backup_info(std::ptr::null()).is_null());
    }

    #[test]
    fn test_storage_ffi_full_cycle() {
        // key generate
        let key_ptr = min_storage_key_generate();
        assert!(!key_ptr.is_null(), "key_generate failed");
        let key_hex = unsafe { CStr::from_ptr(key_ptr) }
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(key_hex.len(), 64, "storage key must be 32 bytes hex");
        min_free_string(key_ptr);

        // open
        let dir = std::env::temp_dir().join(format!(
            "min_ffi_storage_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path_c = CString::new(dir.to_str().unwrap()).unwrap();
        let key_c = CString::new(key_hex.as_str()).unwrap();

        let handle = min_storage_open(path_c.as_ptr(), key_c.as_ptr());
        assert!(
            !handle.is_null() || !handles::is_live(handle as usize),
            "storage open failed"
        );

        // put
        let k1 = CString::new("contact:alice").unwrap();
        let v1 = CString::new(hex::encode(b"secret payload 1")).unwrap();
        let put_res = min_storage_put(handle, k1.as_ptr(), v1.as_ptr());
        assert!(!put_res.is_null(), "put failed");
        assert_eq!(unsafe { CStr::from_ptr(put_res) }.to_str().unwrap(), "ok");
        min_free_string(put_res);

        // get roundtrip
        let got = min_storage_get(handle, k1.as_ptr());
        assert!(!got.is_null(), "get failed");
        let got_s = unsafe { CStr::from_ptr(got) }.to_str().unwrap().to_string();
        assert_eq!(got_s, hex::encode(b"secret payload 1"));
        min_free_string(got);

        // get missing → empty string (not NULL)
        let missing = CString::new("nonexistent").unwrap();
        let got_missing = min_storage_get(handle, missing.as_ptr());
        assert!(
            !got_missing.is_null(),
            "missing must be empty string, not NULL"
        );
        assert_eq!(unsafe { CStr::from_ptr(got_missing) }.to_str().unwrap(), "");
        min_free_string(got_missing);

        // exists
        let ex = min_storage_exists(handle, k1.as_ptr());
        assert!(!ex.is_null());
        assert_eq!(unsafe { CStr::from_ptr(ex) }.to_str().unwrap(), "1");
        min_free_string(ex);

        let ex2 = min_storage_exists(handle, missing.as_ptr());
        assert_eq!(unsafe { CStr::from_ptr(ex2) }.to_str().unwrap(), "0");
        min_free_string(ex2);

        // count
        let count = min_storage_count(handle);
        assert_eq!(unsafe { CStr::from_ptr(count) }.to_str().unwrap(), "1");
        min_free_string(count);

        // list
        let list = min_storage_list_keys(handle);
        assert!(!list.is_null());
        assert!(unsafe { CStr::from_ptr(list) }
            .to_str()
            .unwrap()
            .contains("contact:alice"));
        min_free_string(list);

        // delete
        let del = min_storage_delete(handle, k1.as_ptr());
        assert_eq!(unsafe { CStr::from_ptr(del) }.to_str().unwrap(), "1");
        min_free_string(del);
        let del2 = min_storage_delete(handle, k1.as_ptr());
        assert_eq!(unsafe { CStr::from_ptr(del2) }.to_str().unwrap(), "0");
        min_free_string(del2);

        min_storage_free(handle);

        // wrong key length → NULL
        let bad_key = CString::new("abcd").unwrap();
        assert!(min_storage_open(path_c.as_ptr(), bad_key.as_ptr()).is_null());
    }

    #[test]
    fn test_storage_ffi_null_inputs() {
        assert!(min_storage_open(std::ptr::null(), std::ptr::null()).is_null());
        assert!(
            min_storage_put(std::ptr::null_mut(), std::ptr::null(), std::ptr::null()).is_null()
        );
        assert!(min_storage_get(std::ptr::null_mut(), std::ptr::null()).is_null());
        assert!(min_storage_delete(std::ptr::null_mut(), std::ptr::null()).is_null());
        assert!(min_storage_list_keys(std::ptr::null_mut()).is_null());
        assert!(min_storage_count(std::ptr::null_mut()).is_null());
    }

    #[test]
    fn test_min_create_keypair() {
        let ptr = min_create_keypair();
        assert!(!ptr.is_null());
        unsafe {
            let cstr = CStr::from_ptr(ptr);
            let s = cstr.to_str().unwrap();
            assert!(s.contains(':'));
            min_free_string(ptr);
        }
    }

    #[test]
    fn test_derive_shared_secret_roundtrip() {
        let kp_ptr = min_create_keypair();
        unsafe {
            let kp_cstr = CStr::from_ptr(kp_ptr);
            let kp_str = kp_cstr.to_str().unwrap();
            let parts: Vec<&str> = kp_str.split(':').collect();
            assert_eq!(parts.len(), 2);

            let shared_ptr = min_derive_shared_secret(
                CString::new(parts[0]).unwrap().as_ptr(),
                CString::new(parts[1]).unwrap().as_ptr(),
            );
            assert!(!shared_ptr.is_null());
            let shared = CStr::from_ptr(shared_ptr).to_str().unwrap().to_string();
            assert_eq!(shared.len(), 64, "shared secret - hex from 32 bytes");
            min_free_string(shared_ptr);
            min_free_string(kp_ptr);
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let kp_ptr = min_create_keypair();
        unsafe {
            let kp_cstr = CStr::from_ptr(kp_ptr);
            let kp_str = kp_cstr.to_str().unwrap();
            let parts: Vec<&str> = kp_str.split(':').collect();

            let shared_ptr = min_derive_shared_secret(
                CString::new(parts[0]).unwrap().as_ptr(),
                CString::new(parts[1]).unwrap().as_ptr(),
            );
            let shared_hex = CStr::from_ptr(shared_ptr).to_str().unwrap().to_string();

            let plaintext = "Hello from FFI!";
            let ct_ptr = min_encrypt(
                CString::new(shared_hex.as_str()).unwrap().as_ptr(),
                CString::new(plaintext).unwrap().as_ptr(),
            );
            assert!(!ct_ptr.is_null(), "encrypt failed");
            let ct_hex = CStr::from_ptr(ct_ptr).to_str().unwrap().to_string();
            assert!(!ct_hex.is_empty());

            let pt_ptr = min_decrypt(
                CString::new(shared_hex.as_str()).unwrap().as_ptr(),
                CString::new(ct_hex.as_str()).unwrap().as_ptr(),
            );
            assert!(!pt_ptr.is_null(), "decrypt failed");
            let recovered = CStr::from_ptr(pt_ptr).to_str().unwrap();
            assert_eq!(recovered, plaintext);

            min_free_string(pt_ptr);
            min_free_string(ct_ptr);
            min_free_string(shared_ptr);
            min_free_string(kp_ptr);
        }
    }

    #[test]
    fn test_identity_ffi() {
        let ptr = min_create_identity();
        assert!(!ptr.is_null());
        unsafe {
            let cstr = CStr::from_ptr(ptr);
            assert_eq!(cstr.to_str().unwrap(), "identity_created");
            min_free_string(ptr);
        }
    }

    /// AUDIT MIN-05: реальная проверка Contact Key через FFI.
    /// Честный ключ → hex(mailbox_id); мусор → NULL (fail-closed, раньше
    /// placeholder возвращал "parsed:..." на любую строку).
    #[test]
    fn test_contact_key_ffi() {
        use min_identity::{mailbox_id, IdentityKeypair};
        use min_protocol::contact_key::ContactKeyV3;

        let identity = IdentityKeypair::generate();
        let mb = mailbox_id(&identity.public(), min_protocol::EPOCH_INITIAL);
        let ck = ContactKeyV3 {
            identity_public_key: identity.public(),
            mailbox_id: mb,
            signed_prekey_public: [0x11; 32],
            expiry: 0,
            epoch: min_protocol::EPOCH_INITIAL,
            signature: identity.sign(&{
                ContactKeyV3 {
                    identity_public_key: identity.public(),
                    mailbox_id: mb,
                    signed_prekey_public: [0x11; 32],
                    expiry: 0,
                    epoch: min_protocol::EPOCH_INITIAL,
                    signature: [0u8; 64],
                }
                .canonical_payload()
            }),
        };
        let ck_c = CString::new(ck.to_string_form()).unwrap();

        unsafe {
            let parsed = min_parse_contact_key(ck_c.as_ptr());
            assert!(!parsed.is_null(), "valid contact key must parse");
            assert_eq!(CStr::from_ptr(parsed).to_str().unwrap(), hex::encode(mb));
            min_free_string(parsed);
        }

        // Мусор → NULL.
        let garbage = CString::new("test_key").unwrap();
        assert!(min_parse_contact_key(garbage.as_ptr()).is_null());

        // Тамперинг mailbox_id → подпись ломается → NULL.
        let mut forged = ck.clone();
        forged.mailbox_id = [0xFF; 16];
        let forged_c = CString::new(forged.to_string_form()).unwrap();
        assert!(min_parse_contact_key(forged_c.as_ptr()).is_null());
    }

    /// AUDIT MIN-25: форматтер Contact Key — fail-closed канонизация.
    /// Раньше возвращал Rust-Debug-мусор с префиксом MIN1 и без валидации.
    #[test]
    fn test_format_contact_key_ffi() {
        use min_identity::{mailbox_id, IdentityKeypair};
        use min_protocol::contact_key::ContactKeyV3;
        let identity = IdentityKeypair::generate();
        let mb = mailbox_id(&identity.public(), min_protocol::EPOCH_INITIAL);
        let ck = ContactKeyV3 {
            identity_public_key: identity.public(),
            mailbox_id: mb,
            signed_prekey_public: [0x22; 32],
            expiry: 0,
            epoch: min_protocol::EPOCH_INITIAL,
            signature: identity.sign(&{
                ContactKeyV3 {
                    identity_public_key: identity.public(),
                    mailbox_id: mb,
                    signed_prekey_public: [0x22; 32],
                    expiry: 0,
                    epoch: min_protocol::EPOCH_INITIAL,
                    signature: [0u8; 64],
                }
                .canonical_payload()
            }),
        };
        let original = ck.to_string_form();
        let original_c = CString::new(original.as_str()).unwrap();

        unsafe {
            let formatted = min_format_contact_key(original_c.as_ptr());
            assert!(!formatted.is_null(), "valid key must format");
            let out = CStr::from_ptr(formatted).to_str().unwrap();
            // Канонизация: строка та же и без Rust-Debug-артефактов.
            assert_eq!(out, original);
            assert!(out.starts_with("MIN3:"), "canonical prefix required");
            assert!(!out.contains("\""), "no Debug quoting");
            assert!(!out.contains("MIN1:"), "no stale prefix");
            min_free_string(formatted);
        }

        // Мусор → NULL (fail-closed, а не «отформатированный» мусор).
        let garbage = CString::new("not-a-contact-key").unwrap();
        assert!(min_format_contact_key(garbage.as_ptr()).is_null());

        // Подпись/инвариант mailbox проверяются так же, как в parse.
        let mut forged = ck.clone();
        forged.mailbox_id = [0xEE; 16];
        let forged_c = CString::new(forged.to_string_form()).unwrap();
        assert!(min_format_contact_key(forged_c.as_ptr()).is_null());
    }

    #[test]
    fn test_null_input_returns_null() {
        assert!(min_derive_shared_secret(std::ptr::null(), std::ptr::null()).is_null());
        assert!(min_encrypt(std::ptr::null(), std::ptr::null()).is_null());
        assert!(min_decrypt(std::ptr::null(), std::ptr::null()).is_null());
        assert!(min_parse_contact_key(std::ptr::null()).is_null());
        assert!(min_format_contact_key(std::ptr::null()).is_null());
        assert!(
            min_session_init_bound(std::ptr::null_mut(), std::ptr::null(), std::ptr::null())
                .is_null()
        );
    }

    /// AUDIT MIN-05: bound session init — цепочка Contact Key → mailbox → bundle.
    /// Честный цикл проходит; подмена bundle (другая сессия) и тамперинг
    /// Contact Key отвергаются (fail-closed).
    #[test]
    fn test_session_init_bound_ffi() {
        use min_identity::{mailbox_id, IdentityKeypair};
        use min_protocol::contact_key::ContactKeyV3;

        let bob = min_session_create();
        let mallory = min_session_create();
        let alice = min_session_create();
        assert!(!bob.is_null() && !mallory.is_null() && !alice.is_null());

        unsafe {
            let bundle_hex = min_session_generate_bundle(bob);
            assert!(!bundle_hex.is_null());
            let bundle_str = CStr::from_ptr(bundle_hex).to_str().unwrap().to_string();
            min_free_string(bundle_hex);

            // Mallory публикует свой bundle — на его основе строим атаку подмены.
            let mallory_hex = min_session_generate_bundle(mallory);
            assert!(!mallory_hex.is_null());
            let mallory_str = CStr::from_ptr(mallory_hex).to_str().unwrap().to_string();
            min_free_string(mallory_hex);

            // Contact Key Боба: identity → mailbox; signed prekey — из его bundle.
            let bundle =
                min_session::PreKeyBundleData::from_cbor(&hex::decode(&bundle_str).unwrap())
                    .unwrap();
            let mut spk = [0u8; 32];
            spk.copy_from_slice(&bundle.signed_pre_key_public[1..33]);

            let identity = IdentityKeypair::generate();
            let mb = mailbox_id(&identity.public(), min_protocol::EPOCH_INITIAL);
            let ck = ContactKeyV3 {
                identity_public_key: identity.public(),
                mailbox_id: mb,
                signed_prekey_public: spk,
                expiry: 0,
                epoch: min_protocol::EPOCH_INITIAL,
                signature: identity.sign(&{
                    ContactKeyV3 {
                        identity_public_key: identity.public(),
                        mailbox_id: mb,
                        signed_prekey_public: spk,
                        expiry: 0,
                        epoch: min_protocol::EPOCH_INITIAL,
                        signature: [0u8; 64],
                    }
                    .canonical_payload()
                }),
            };
            let ck_c = CString::new(ck.to_string_form()).unwrap();
            let mut bound = bundle.clone();
            bound.bind_contact_key(&identity.secret_bytes()).unwrap();
            let bound_str = hex::encode(bound.to_cbor().unwrap());
            let bound_c = CString::new(bound_str).unwrap();
            let mallory_c = CString::new(mallory_str.clone()).unwrap();
            // 1) Честный цикл: init ok → encrypt по адресу hex(mailbox_id).
            let r = min_session_init_bound(alice, ck_c.as_ptr(), bound_c.as_ptr());
            let peer = CString::new(hex::encode(mb)).unwrap();
            assert!(!r.is_null(), "honest bound init must succeed");
            assert_eq!(CStr::from_ptr(r).to_str().unwrap(), "ok");
            min_free_string(r);

            let pt = CString::new("bound hello").unwrap();
            let ct = min_session_encrypt(alice, peer.as_ptr(), pt.as_ptr());
            assert!(!ct.is_null(), "encrypt to bound session must succeed");
            min_free_string(ct);

            // 2) Атака подмены bundle (relay отдал bundle Mallory): тот же
            //    Contact Key, чужой signed prekey → NULL.
            assert!(
                min_session_init_bound(alice, ck_c.as_ptr(), mallory_c.as_ptr()).is_null(),
                "bundle swap (mallory) must be rejected"
            );

            // 3) Тамперинг Contact Key (mailbox переписан → подпись ломается) → NULL.
            let mut forged = ck.clone();
            forged.mailbox_id = [0xEE; 16];
            let forged_c = CString::new(forged.to_string_form()).unwrap();
            assert!(
                min_session_init_bound(alice, forged_c.as_ptr(), bound_c.as_ptr()).is_null(),
                "forged contact key must be rejected"
            );

            // 4) Мусорный Contact Key (валидный префикс, битый payload) → NULL.
            let garbage = CString::new("MIN3:garbage").unwrap();
            assert!(min_session_init_bound(alice, garbage.as_ptr(), bound_c.as_ptr()).is_null());

            min_session_free(bob);
            min_session_free(mallory);
            min_session_free(alice);
        }
    }

    /// Full PQXDH + Double Ratchet cycle through the FFI boundary.
    #[test]
    fn test_session_pqxdh_cycle_ffi() {
        let bob = min_session_create();
        let alice = min_session_create();
        assert!(!bob.is_null());
        assert!(!alice.is_null());

        unsafe {
            use min_identity::IdentityKeypair;

            // Bob publishes a prekey bundle, binds every public prekey field to
            // his long-term Ed25519 identity, and signs the matching Contact Key.
            let bundle_hex = min_session_generate_bundle(bob);
            assert!(!bundle_hex.is_null());
            let bundle_str = CStr::from_ptr(bundle_hex).to_str().unwrap().to_string();
            min_free_string(bundle_hex);
            let bob_identity = IdentityKeypair::generate();
            let bob_secret = CString::new(hex::encode(bob_identity.secret_bytes())).unwrap();
            let mut bundle =
                min_session::PreKeyBundleData::from_cbor(&hex::decode(&bundle_str).unwrap())
                    .unwrap();
            bundle
                .bind_contact_key(&bob_identity.secret_bytes())
                .unwrap();
            let bundle_str = hex::encode(bundle.to_cbor().unwrap());
            let mut signed_prekey = [0u8; 32];
            signed_prekey.copy_from_slice(&bundle.signed_pre_key_public[1..33]);
            let signed_prekey_c = CString::new(hex::encode(signed_prekey)).unwrap();
            let ck_ptr = min_contact_key_create(
                bob_secret.as_ptr(),
                signed_prekey_c.as_ptr(),
                min_protocol::EPOCH_INITIAL,
                0,
            );
            assert!(!ck_ptr.is_null());
            let contact_key = CStr::from_ptr(ck_ptr).to_str().unwrap().to_string();
            min_free_string(ck_ptr);

            // Alice derives the peer address from Bob's verified Contact Key.
            let peer = CString::new(hex::encode(min_identity::mailbox_id(
                &bob_identity.public(),
                min_protocol::EPOCH_INITIAL,
            )))
            .unwrap();
            let contact_key_c = CString::new(contact_key).unwrap();
            let bundle_c = CString::new(bundle_str).unwrap();
            let init_result =
                min_session_init_bound(alice, contact_key_c.as_ptr(), bundle_c.as_ptr());
            assert!(!init_result.is_null(), "bound init_session failed");
            min_free_string(init_result);

            // Alice encrypts the first message (PreKeySignalMessage).
            let pt1 = CString::new("Hello Bob via FFI!").unwrap();
            let ct1_hex = min_session_encrypt(alice, peer.as_ptr(), pt1.as_ptr());
            assert!(!ct1_hex.is_null(), "encrypt failed");
            let ct1_str = CStr::from_ptr(ct1_hex).to_str().unwrap().to_string();
            min_free_string(ct1_hex);

            // Bob decrypts (establishes his side of the session).
            let alice_peer = CString::new("alice-peer").unwrap();
            let recovered1 = min_session_decrypt(
                bob,
                alice_peer.as_ptr(),
                CString::new(ct1_str).unwrap().as_ptr(),
            );
            assert!(!recovered1.is_null(), "decrypt failed");
            assert_eq!(
                CStr::from_ptr(recovered1).to_str().unwrap(),
                "Hello Bob via FFI!"
            );
            min_free_string(recovered1);

            // Bob replies (Whisper / Double Ratchet).
            let pt2 = CString::new("Hi Alice!").unwrap();
            let ct2_hex = min_session_encrypt(bob, alice_peer.as_ptr(), pt2.as_ptr());
            assert!(!ct2_hex.is_null());
            let ct2_str = CStr::from_ptr(ct2_hex).to_str().unwrap().to_string();
            min_free_string(ct2_hex);

            let recovered2 = min_session_decrypt(
                alice,
                peer.as_ptr(),
                CString::new(ct2_str).unwrap().as_ptr(),
            );
            assert!(!recovered2.is_null());
            assert_eq!(CStr::from_ptr(recovered2).to_str().unwrap(), "Hi Alice!");
            min_free_string(recovered2);

            min_session_free(alice);
            min_session_free(bob);
        }
    }

    #[test]
    fn test_random_hex_bounds_and_format() {
        // RT-26.20: CSPRNG-политика ядра — границы и формат.
        assert!(min_random_hex(0).is_null(), "0 bytes must fail");
        assert!(min_random_hex(1025).is_null(), "over-cap must fail");
        for n in [1usize, 16, 32, 1024] {
            let ptr = min_random_hex(n);
            assert!(!ptr.is_null(), "n={} must succeed", n);
            let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
            assert_eq!(s.len(), n * 2, "hex length must match n");
            assert!(s.chars().all(|c| c.is_ascii_hexdigit()), "hex only");
            min_free_string(ptr);
        }
        // Уникальность (случайность): два вызова не совпадают.
        let a = min_random_hex(16);
        let b = min_random_hex(16);
        let sa = unsafe { CStr::from_ptr(a) }.to_str().unwrap().to_string();
        let sb = unsafe { CStr::from_ptr(b) }.to_str().unwrap().to_string();
        min_free_string(a);
        min_free_string(b);
        assert_ne!(sa, sb, "CSPRNG must not repeat");
    }

    /// Полный цикл delivery FFI через реальный relay (TCP test-link):
    /// open → register → enqueue → pull → ack → close.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_delivery_ffi_full_cycle() {
        // Relay frame server на эфемерном порту.
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound = probe.local_addr().unwrap();
        drop(probe);
        let store: min_relay::store::SharedStore =
            std::sync::Arc::new(tokio::sync::RwLock::new(min_relay::store::Store::new()));
        tokio::spawn(async move {
            min_relay::frame_server::serve_frames(store, &bound.to_string())
                .await
                .unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let addr = CString::new(bound.to_string()).unwrap();
        let kind = CString::new("tcp-dev-harness").unwrap();
        let empty = CString::new("").unwrap();

        let handle =
            min_delivery_open(kind.as_ptr(), addr.as_ptr(), empty.as_ptr(), empty.as_ptr());
        assert!(
            !handle.is_null() || !handles::is_live(handle as usize),
            "open failed"
        );

        // register
        let mb = CString::new("alice-ffi").unwrap();
        let reg = min_delivery_register(handle, mb.as_ptr());
        assert!(!reg.is_null());
        let reg_s = unsafe { CStr::from_ptr(reg) }.to_str().unwrap();
        assert!(reg_s.contains(':'), "register must be epoch:token");
        let token_hex = reg_s
            .split(':')
            .nth(1)
            .expect("register has colon")
            .to_string();
        println!("register_s={}", reg_s);
        println!("token_hex={} len={}", token_hex, token_hex.len());
        min_free_string(reg);

        // enqueue
        let env = hex::encode(vec![9u8; 64]);
        let env_c = CString::new(env).unwrap();
        let item_id = min_delivery_enqueue(handle, mb.as_ptr(), env_c.as_ptr(), 2);
        assert!(!item_id.is_null(), "enqueue failed");
        let item_id_s = unsafe { CStr::from_ptr(item_id) }
            .to_str()
            .unwrap()
            .to_string();
        min_free_string(item_id);

        // pull
        let tok_c = CString::new(token_hex).unwrap();
        let pulled = min_delivery_pull(handle, mb.as_ptr(), tok_c.as_ptr());
        assert!(!pulled.is_null(), "pull failed");
        let pulled_s = unsafe { CStr::from_ptr(pulled) }.to_str().unwrap();
        if pulled_s.starts_with("ERR:") {
            panic!("pull returned error: {}", pulled_s);
        }
        assert!(
            pulled_s.contains(&item_id_s),
            "pulled must contain the item"
        );
        min_free_string(pulled);

        // ack
        let acked_s = unsafe {
            CStr::from_ptr(min_delivery_ack(
                handle,
                mb.as_ptr(),
                tok_c.as_ptr(),
                CString::new(item_id_s).unwrap().as_ptr(),
            ))
            .to_str()
            .unwrap()
        };
        assert_eq!(acked_s, "1");

        // empty pull after ack
        let empty_pull = min_delivery_pull(handle, mb.as_ptr(), tok_c.as_ptr());
        assert!(!empty_pull.is_null());
        assert!(unsafe { CStr::from_ptr(empty_pull) }
            .to_str()
            .unwrap()
            .is_empty());
        min_free_string(empty_pull);

        min_delivery_close(handle);
    }

    /// AUDIT MIN-02: FFI-гейт верификации header binding envelope.
    /// Честный envelope → "1"; подменённый заголовок (пересшитый без знания
    /// session_id) → "0"; мусорный hex → NULL/0.
    #[test]
    fn test_envelope_verify_ffi() {
        use min_protocol::envelope::{EnvelopeV1, MessageType};

        let session = b"ffi-test-session".to_vec();
        let mut env = EnvelopeV1 {
            msg_type: MessageType::Message,
            epoch: 1,
            seq: 1,
            sender_hint: [0u8; 16],
            mailbox_hint: [3u8; 16],
            aad_commitment: [0u8; 16],
            nonce: [5u8; 24],
            ciphertext: b"some aead ciphertext".to_vec(),
            ttl_sec: 600,
            queue_class: 0,
        };
        env.seal(&session);
        let wire = env.to_wire().unwrap();

        let env_c = CString::new(hex::encode(&wire)).unwrap();
        let sid_c = CString::new(hex::encode(&session)).unwrap();

        // Честный envelope → "1".
        let verdict = min_envelope_verify(env_c.as_ptr(), sid_c.as_ptr());
        assert!(
            !verdict.is_null(),
            "verify must not return NULL on valid hex"
        );
        assert_eq!(unsafe { CStr::from_ptr(verdict) }.to_str().unwrap(), "1");
        min_free_string(verdict);

        // Чужая session_id → "0" (cross-session binding).
        let other = CString::new(hex::encode(b"other-session")).unwrap();
        let verdict2 = min_envelope_verify(env_c.as_ptr(), other.as_ptr());
        assert!(!verdict2.is_null());
        assert_eq!(unsafe { CStr::from_ptr(verdict2) }.to_str().unwrap(), "0");
        min_free_string(verdict2);

        // Подменённый seq со «старым» commitment → "0".
        let mut fake = env.clone();
        fake.seq = env.seq + 1;
        fake.aad_commitment = env.aad_commitment;
        let fake_c = CString::new(hex::encode(fake.to_wire().unwrap())).unwrap();
        let verdict3 = min_envelope_verify(fake_c.as_ptr(), sid_c.as_ptr());
        assert!(!verdict3.is_null());
        assert_eq!(unsafe { CStr::from_ptr(verdict3) }.to_str().unwrap(), "0");
        min_free_string(verdict3);

        // Мусорный hex → "0" (не NULL: вердикт «не прошёл проверку»).
        let junk = CString::new("zzzz").unwrap();
        let verdict4 = min_envelope_verify(junk.as_ptr(), sid_c.as_ptr());
        assert!(!verdict4.is_null());
        assert_eq!(unsafe { CStr::from_ptr(verdict4) }.to_str().unwrap(), "0");
        min_free_string(verdict4);
    }

    /// Persistence (v6, RT-26.1): FFI export → restore — identity сохраняется,
    /// tamper/чужой ключ → NULL (fail-closed).
    #[test]
    fn test_session_export_restore_ffi() {
        let sk_hex = hex::encode([0x42u8; 32]);
        let sk_c = CString::new(sk_hex.clone()).unwrap();

        let h = min_session_create();
        assert!(!h.is_null());
        let pub1 = min_session_identity_public(h);
        assert!(!pub1.is_null());
        let pub1_s = unsafe { CStr::from_ptr(pub1) }.to_str().unwrap().to_owned();
        min_free_string(pub1);

        let blob = min_session_export(h, sk_c.as_ptr());
        assert!(!blob.is_null(), "export must succeed");
        let blob_s = unsafe { CStr::from_ptr(blob) }.to_str().unwrap().to_owned();
        min_free_string(blob);
        min_session_free(h);

        // Restore под тем же local_name ("local") и ключом → identity тот же.
        let name_c = CString::new("local").unwrap();
        let blob_c = CString::new(blob_s.clone()).unwrap();
        let h2 = min_session_restore(name_c.as_ptr(), blob_c.as_ptr(), sk_c.as_ptr());
        assert!(!h2.is_null(), "restore must succeed on authentic blob");
        let pub2 = min_session_identity_public(h2);
        assert!(!pub2.is_null());
        assert_eq!(
            unsafe { CStr::from_ptr(pub2) }.to_str().unwrap(),
            pub1_s,
            "restored identity must match"
        );
        min_free_string(pub2);
        min_session_free(h2);

        // Тампер блоба → NULL.
        let mut raw = hex::decode(&blob_s).unwrap();
        let mid = raw.len() / 2;
        raw[mid] ^= 0x01;
        let tampered = CString::new(hex::encode(raw)).unwrap();
        assert!(min_session_restore(name_c.as_ptr(), tampered.as_ptr(), sk_c.as_ptr()).is_null());

        // Чужой storage key → NULL.
        let sk2 = CString::new(hex::encode([0x43u8; 32])).unwrap();
        let blob_ok = CString::new(blob_s.clone()).unwrap();
        assert!(min_session_restore(name_c.as_ptr(), blob_ok.as_ptr(), sk2.as_ptr()).is_null());

        // NULL-аргументы → NULL.
        assert!(min_session_export(std::ptr::null_mut(), sk_c.as_ptr()).is_null());
        assert!(min_session_restore(name_c.as_ptr(), blob_ok.as_ptr(), std::ptr::null()).is_null());
    }

    // ========================================================================
    // PHASE 4 (RT-26.15 / RT-26.16): FFI memory-safety + error oracle
    // ========================================================================

    fn c(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    /// RT-26.15: FFI обязан reject-ить все инвалидные pointer/length-пары
    /// без паники через границу (panic-guarded → NULL):
    /// null-аргументы, пустые строки, не-hex, нечётные/короткие длины,
    /// не-UTF8 байты, null-хэндлы. free(NULL) — no-op.
    #[test]
    fn rt26_15_ffi_rejects_invalid_pointer_length_pairs() {
        let null = std::ptr::null::<c_char>();

        // (1) NULL-строки → NULL (до CStr::from_ptr).
        assert!(min_derive_shared_secret(null, null).is_null());
        assert!(min_encrypt(null, null).is_null());
        assert!(min_parse_contact_key(null).is_null());
        assert!(min_format_contact_key(null).is_null());
        assert!(min_session_init_bound(std::ptr::null_mut(), null, null).is_null());
        assert!(min_session_identity_public(std::ptr::null_mut()).is_null());
        assert!(min_session_generate_bundle(std::ptr::null_mut()).is_null());
        assert!(min_storage_open(null, null).is_null());
        assert!(min_storage_get(std::ptr::null_mut(), null).is_null());
        assert!(min_storage_exists(std::ptr::null_mut(), null).is_null());
        assert!(min_storage_delete(std::ptr::null_mut(), null).is_null());

        // (2) Пустые строки → NULL (инвалидная длина для любых ключей).
        let empty = c("");
        assert!(min_derive_shared_secret(empty.as_ptr(), empty.as_ptr()).is_null());
        assert!(min_encrypt(empty.as_ptr(), empty.as_ptr()).is_null());
        assert!(min_storage_open(empty.as_ptr(), empty.as_ptr()).is_null());

        // (3) Не-hex / нечётная длина / неверная длина ключа → NULL.
        let sk_hex = hex::encode([7u8; 32]);
        let sk = c(&sk_hex);
        let not_hex = c(&"zz".repeat(32));
        let odd_len = c("abc"); // нечётная hex-длина
        let short_key = c(&hex::encode([1u8; 16])); // 16B вместо 32B
        let long_key = c(&hex::encode([1u8; 33])); // 33B вместо 32B
        assert!(min_derive_shared_secret(sk.as_ptr(), not_hex.as_ptr()).is_null());
        assert!(min_derive_shared_secret(sk.as_ptr(), odd_len.as_ptr()).is_null());
        assert!(min_derive_shared_secret(sk.as_ptr(), short_key.as_ptr()).is_null());
        assert!(min_derive_shared_secret(sk.as_ptr(), long_key.as_ptr()).is_null());

        // (4) Не-UTF8 байты в строковом аргументе → NULL (to_str() fail-closed).
        let not_utf8 = CString::new(vec![0xFF, 0xFE, b'a', b'b']).unwrap();
        assert!(min_parse_contact_key(not_utf8.as_ptr()).is_null());
        assert!(min_format_contact_key(not_utf8.as_ptr()).is_null());
        assert!(min_storage_open(not_utf8.as_ptr(), sk.as_ptr()).is_null());

        // (5) free(NULL) — no-op (guard есть, не паникует и не UB).
        min_free_string(std::ptr::null_mut());
        min_session_free(std::ptr::null_mut());
        min_storage_free(std::ptr::null_mut());
    }

    /// RT-26.16: error-оракул FFI. Все error-классы — только NULL
    /// (fail-closed): никаких текстов ошибок, эха секрета или различимых
    /// причин отказа. Success-ответы не содержат чужого секретного
    /// материала (identity_public — только публичный ключ).
    #[test]
    fn rt26_16_ffi_error_classes_do_not_expose_secret_state() {
        let (sk, _pk) = min_crypto::generate_keypair().expect("keygen infallible");
        let sk_hex = hex::encode(sk.0);
        let sk_c = c(&sk_hex);
        let garbage = c(&"deadbeef".repeat(32)); // валидный hex, не ключ

        let h = min_session_create();
        assert!(!h.is_null());

        // (1) Все error-пути → NULL (строки с причиной отказа не существует).
        // NB: derive/encrypt принимают любой валидный по длине вход (X25519
        // не знает «мусорных» точек как ошибку) — error-классы вызываются
        // только инвалидными ДЛИНАМИ/форматом.
        assert!(min_derive_shared_secret(sk_c.as_ptr(), garbage.as_ptr()).is_null());
        let short_pk = c(&hex::encode([1u8; 16]));
        assert!(min_derive_shared_secret(sk_c.as_ptr(), short_pk.as_ptr()).is_null());
        assert!(min_parse_contact_key(garbage.as_ptr()).is_null());
        assert!(min_format_contact_key(garbage.as_ptr()).is_null());
        assert!(min_session_init_bound(h, std::ptr::null(), std::ptr::null()).is_null());

        // (1b) encrypt с валидными длинами — это success-путь: ciphertext
        // не должен содержать plaintext (ни hex, ни сырой вид).
        let plaintext = c("SECRET-PLAINTEXT-DO-NOT-LEAK");
        let ct_ptr = min_encrypt(sk_c.as_ptr(), plaintext.as_ptr());
        assert!(!ct_ptr.is_null(), "valid encrypt must succeed");
        let ct = unsafe { CStr::from_ptr(ct_ptr) }
            .to_str()
            .unwrap()
            .to_string();
        min_free_string(ct_ptr);
        assert!(!ct.contains("SECRET"), "ciphertext must not leak plaintext");

        // (2) Success-пути не содержат секретов: identity_public — только pk.
        let id_ptr = min_session_identity_public(h);
        assert!(!id_ptr.is_null());
        let id_str = unsafe { CStr::from_ptr(id_ptr) }
            .to_str()
            .unwrap()
            .to_string();
        min_free_string(id_ptr);
        assert!(
            !id_str.contains(&sk_hex[..16]),
            "session identity response must not contain private key material"
        );
        // Публичный ключ свежей сессии, а не нашего sk (и не его hex-хвост).
        assert_ne!(id_str, sk_hex);
        assert!(!sk_hex[32..].is_empty() && !id_str.contains(&sk_hex[32..48]));

        min_session_free(h);

        // (3) min_create_keypair: формат "secret:public" — собственный
        // материал клиента (контракт), не error-оракул. Проверяем формат.
        let kp_ptr = min_create_keypair();
        assert!(!kp_ptr.is_null());
        let kp = unsafe { CStr::from_ptr(kp_ptr) }
            .to_str()
            .unwrap()
            .to_string();
        min_free_string(kp_ptr);
        let parts: Vec<&str> = kp.split(':').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].len(), 64, "secret = 32B hex");
        assert_eq!(parts[1].len(), 64, "public = 32B hex");
    }

    /// RT-26.9 / MIN-26: ротация Contact Key на границе FFI. Две эпохи дают
    /// разные адреса; привязка сессии ко второй эпохе закрывает прежний
    /// маршрут, и вернуться к первой эпохе (rollback) уже нельзя.
    #[test]
    fn rt26_9_ffi_epoch_rotation_closes_previous_address() {
        use min_identity::{mailbox_id, IdentityKeypair, EPOCH_INITIAL};

        let ident = IdentityKeypair::generate();
        let sk_hex = hex::encode(ident.secret_bytes());

        let bob = min_session_create();
        let alice = min_session_create();
        assert!(!bob.is_null() && !alice.is_null());

        unsafe {
            let bundle_of = |handle: *mut SessionHandle| -> String {
                let ptr = min_session_generate_bundle(handle);
                assert!(!ptr.is_null());
                let out = CStr::from_ptr(ptr).to_str().unwrap().to_string();
                min_free_string(ptr);
                out
            };
            let bind = |bundle_hex: &str| -> String {
                let mut b =
                    min_session::PreKeyBundleData::from_cbor(&hex::decode(bundle_hex).unwrap())
                        .unwrap();
                b.bind_contact_key(&ident.secret_bytes()).unwrap();
                hex::encode(b.to_cbor().unwrap())
            };

            let spk_of = |bundle_hex: &str| -> [u8; 32] {
                let b = min_session::PreKeyBundleData::from_cbor(&hex::decode(bundle_hex).unwrap())
                    .unwrap();
                let mut spk = [0u8; 32];
                spk.copy_from_slice(&b.signed_pre_key_public[1..33]);
                spk
            };

            let sk_c = c(&sk_hex);
            // (1) Contact Key эпохи 1: адрес = HKDF(identity, 1).
            let bundle1 = bind(&bundle_of(bob));
            let ck1_ptr = min_contact_key_create(
                sk_c.as_ptr(),
                c(&hex::encode(spk_of(&bundle1))).as_ptr(),
                EPOCH_INITIAL,
                0,
            );
            assert!(!ck1_ptr.is_null(), "create must succeed");
            let ck1 = CStr::from_ptr(ck1_ptr).to_str().unwrap().to_string();
            min_free_string(ck1_ptr);
            assert!(ck1.starts_with("MIN3:"), "canonical v3 prefix");

            let mb1_c = c(&ck1);
            let mb1_ptr = min_parse_contact_key(mb1_c.as_ptr());
            assert!(!mb1_ptr.is_null());
            assert_eq!(
                CStr::from_ptr(mb1_ptr).to_str().unwrap(),
                hex::encode(mailbox_id(&ident.public(), EPOCH_INITIAL))
            );
            min_free_string(mb1_ptr);

            let ep_ptr = min_contact_key_epoch(mb1_c.as_ptr());
            assert!(!ep_ptr.is_null());
            assert_eq!(CStr::from_ptr(ep_ptr).to_str().unwrap(), "1");
            min_free_string(ep_ptr);

            // Привязка сессии к эпохе 1.
            let ok1 = min_session_init_bound(alice, mb1_c.as_ptr(), c(&bundle1).as_ptr());
            assert!(!ok1.is_null(), "epoch 1 bind must succeed");
            min_free_string(ok1);

            // (2) Ротация: новый bundle, эпоха 2, новый адрес.
            let bundle2 = bind(&bundle_of(bob));
            let ck2_ptr = min_contact_key_create(
                sk_c.as_ptr(),
                c(&hex::encode(spk_of(&bundle2))).as_ptr(),
                EPOCH_INITIAL + 1,
                0,
            );
            assert!(!ck2_ptr.is_null());
            let ck2 = CStr::from_ptr(ck2_ptr).to_str().unwrap().to_string();
            min_free_string(ck2_ptr);
            assert_ne!(
                mailbox_id(&ident.public(), EPOCH_INITIAL),
                mailbox_id(&ident.public(), EPOCH_INITIAL + 1),
                "rotation must change the address"
            );
            let ok2 = min_session_init_bound(alice, c(&ck2).as_ptr(), c(&bundle2).as_ptr());
            assert!(!ok2.is_null(), "epoch 2 bind must succeed");
            min_free_string(ok2);

            // (3) Rollback к эпохе 1 — fail-closed (старая сессия не оживает).
            let bad = min_session_init_bound(alice, mb1_c.as_ptr(), c(&bundle1).as_ptr());
            assert!(bad.is_null(), "rollback to epoch 1 must fail closed");

            // (4) Инвалидные входы → NULL.
            assert!(min_contact_key_create(
                sk_c.as_ptr(),
                c(&hex::encode(spk_of(&bundle1))).as_ptr(),
                0,
                0
            )
            .is_null());
            assert!(
                min_contact_key_create(sk_c.as_ptr(), c("zz").as_ptr(), EPOCH_INITIAL, 0).is_null()
            );
            assert!(min_contact_key_create(
                c("00").as_ptr(),
                c(&hex::encode(spk_of(&bundle1))).as_ptr(),
                EPOCH_INITIAL,
                0
            )
            .is_null());
            assert!(min_contact_key_epoch(c("MIN3:garbage").as_ptr()).is_null());
            assert!(min_contact_key_epoch(std::ptr::null()).is_null());
        }
    }
}
