#ifndef MIN_FFI_H
#define MIN_FFI_H

#include <stdint.h>

/* Returns "secret:public" hex string (caller frees via min_free_string) */
char* min_create_keypair(void);

/* Derives shared secret; returns hex-encoded string (caller frees via min_free_string) */
char* min_derive_shared_secret(const char* secret_key_hex, const char* public_key_hex);

/* Encrypts plaintext; returns hex-encoded ciphertext (caller frees via min_free_string) */
char* min_encrypt(const char* shared_secret_hex, const char* plaintext);

/* Decrypts hex-encoded ciphertext; returns UTF-8 plaintext (caller frees via min_free_string) */
char* min_decrypt(const char* shared_secret_hex, const char* ciphertext_hex);

/* Frees C strings returned by the above functions */
void min_free_string(char* ptr);

/* Identity & contact keys.
   AUDIT MIN-05/MIN-15: min_parse_contact_key теперь fail-closed верификация
   (строгий парс + Ed25519-подпись + mailbox_id == HKDF(identity_pk)).
   Возвращает hex(mailbox_id) или NULL при любой ошибке валидации. */
char* min_create_identity(void);
char* min_parse_contact_key(const char* key);
char* min_format_contact_key(const char* key);

/* AUDIT MIN-26 / O-5: создание Contact Key и ротация эпохи адреса.
   identity_secret_hex = 32B Ed25519 secret (hex), signed_prekey_hex = 32B
   X25519 signed prekey (hex), epoch >= 1 (ротация = текущая + 1),
   expiry = unix-секунды (0 = без срока). mailbox_id выводится внутри как
   HKDF(identity, LE64(epoch)) - подделать адрес нельзя.
   Возвращает каноническую MIN3-строку или NULL (fail-closed). */
char* min_contact_key_create(const char* identity_secret_hex, const char* signed_prekey_hex, uint64_t epoch, uint64_t expiry);

/* AUDIT MIN-26: эпоха валидного Contact Key (десятичная строка) или NULL. */
char* min_contact_key_epoch(const char* key);

/* Envelope header binding (AUDIT MIN-02): "1" = valid, "0" = mismatch/malformed */
char* min_envelope_verify(const char* envelope_hex, const char* session_id_hex);

/* AUDIT MIN-05: session init, привязанный к верифицированному Contact Key.
   Цепочка: Contact Key (подпись + mailbox==HKDF(identity)) → адрес сессии
   выводится из Contact Key → bundle.signed_pre_key_public == Contact Key
   signed_prekey_public. AUDIT MIN-26: адрес привязывается к (identity, epoch)
   Contact Key - ротация закрывает прежний маршрут, rollback эпохи отвергается.
   Возвращает "ok" или NULL (fail-closed). */
char* min_session_init_bound(void* handle, const char* contact_key_str, const char* bundle_cbor_hex);

/* Persistence (v6, RT-26.1): аутентифицированный snapshot сессий.
   MAC-ключ выводится из storage key (BLAKE3-derive). min_session_export
   возвращает hex(CBOR || tag[32]) или NULL; min_session_restore — новый
   handle или NULL (tamper/чужой ключ/мусор → NULL, fail-closed).
   SECURITY: блоб содержит приватные ключи — хранить только зашифрованным
   (min_storage под storage key). */
char* min_session_export(void* handle, const char* storage_key_hex);
void* min_session_restore(const char* local_name, const char* blob_hex, const char* storage_key_hex);

/* P6 / RT-26.20: секреты генерирует только ядро. min_storage_key_generate —
   32 байта CSPRNG (hex, 64 символа); min_random_hex(n) — n CSPRNG-байт
   (1..=1024, hex). Вызывающий немедленно переносит значение в Keychain
   (kSecAttrAccessibleWhenUnlockedThisDeviceOnly) и освобождает строку. */
char* min_storage_key_generate(void);
char* min_random_hex(int n);

/* MIN-RED-022: сообщения от незнакомцев (тумблер по умолчанию ВКЛ).
   min_app_send_text_to_invite — первое сообщение незнакомцу: получателю
   приходит ЗАЯВКА, а не чат. min_app_requests возвращает
   {discoverable, requests[]}; текст заявки наружу не отдаётся ДО Accept.
   min_app_accept_request открывает чат, reject — нейтральный отказ (причина
   не раскрывается), block — без ответа на провод. min_app_set_discoverable —
   локальный тумблер, в сеть не уходит. */
char* min_app_send_text_to_invite(void* handle, const char* invite, const char* text);
/* Ответ на сообщение: цитата едет в зашифрованный payload, поэтому её видит
   вторая сторона и она переживает перезапуск. */
char* min_app_send_reply(void* handle, const char* peer, const char* text,
                         const char* author, const char* preview);
/* Отправка сообщения: ядро само выбирает путь (сессия или invite) и несёт
   цитату в обоих путях. author/preview/invite — NULL, если не применимо. */
char* min_app_send_message(void* handle, const char* peer, const char* text,
                           const char* author, const char* preview,
                           const char* invite);
char* min_app_requests(void* handle);
char* min_app_accept_request(void* handle, const char* request_id);
char* min_app_reject_request(void* handle, const char* request_id);
char* min_app_block_request(void* handle, const char* request_id);
char* min_app_set_discoverable(void* handle, bool allowed);

#endif /* MIN_FFI_H */
