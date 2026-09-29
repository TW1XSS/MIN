import Foundation

/// Swift facade over the Rust core (min-ffi).
/// All crypto happens in Rust; secrets never enter the Swift heap as raw keys.
///
/// The C functions/prototypes are declared here (`@_silgen_name`) so the Swift
/// compiler knows their ABI without needing a Clang module. The static library
/// `libmin_ffi.a` is linked into the target via MinCore.xcframework.
enum MinCore {

    enum MinError: Error {
        case ffiFailure
    }

    // MARK: - C ABI declarations (must match backend/crates/min-ffi/src/lib.rs)

    @_silgen_name("min_create_keypair")
    private static func cCreateKeypair() -> UnsafeMutablePointer<CChar>?

    @_silgen_name("min_free_string")
    private static func cFreeString(_ ptr: UnsafeMutablePointer<CChar>?)

    @_silgen_name("min_envelope_verify")
    private static func cEnvelopeVerify(_ envelopeHex: UnsafePointer<CChar>?, _ sessionIdHex: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?

    @_silgen_name("min_derive_shared_secret")
    private static func cDeriveSharedSecret(_ sk: UnsafePointer<CChar>?, _ pk: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?

    @_silgen_name("min_encrypt")
    private static func cEncrypt(_ secret: UnsafePointer<CChar>?, _ plaintext: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?

    @_silgen_name("min_decrypt")
    private static func cDecrypt(_ secret: UnsafePointer<CChar>?, _ ciphertext: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?

    @_silgen_name("min_create_identity")
    private static func cCreateIdentity() -> UnsafeMutablePointer<CChar>?

    @_silgen_name("min_parse_contact_key")
    private static func cParseContactKey(_ key: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?

    @_silgen_name("min_format_contact_key")
    private static func cFormatContactKey(_ key: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?

    @_silgen_name("min_contact_key_create")
    private static func cCreateContactKey(_ identitySecretHex: UnsafePointer<CChar>?, _ signedPrekeyHex: UnsafePointer<CChar>?, _ epoch: UInt64, _ expiry: UInt64) -> UnsafeMutablePointer<CChar>?

    @_silgen_name("min_contact_key_epoch")
    private static func cContactKeyEpoch(_ key: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?

    @_silgen_name("min_storage_key_generate")
    private static func cStorageKeyGenerate() -> UnsafeMutablePointer<CChar>?

    @_silgen_name("min_random_hex")
    private static func cRandomHex(_ n: Int) -> UnsafeMutablePointer<CChar>?

    // MARK: - Public API

    /// Освобождает C-строку, возвращённую ядром (min_free_string).
    /// Нужен высокоуровневой обёртке MinApp для всех JSON-ответов.
    static func freeString(_ ptr: UnsafeMutablePointer<CChar>?) {
        guard let ptr = ptr else { return }
        cFreeString(ptr)
    }


    /// Генерирует master key локальной БД (32 байта CSPRNG ядра), hex.
    /// Вызывающий обязан немедленно сохранить значение в Keychain
    /// (`KeychainService.obtainStorageKey`) и не держать его в памяти дольше
    /// необходимого. P6 / RT-26.20.
    static func generateStorageKey() -> String? {
        guard let ptr = cStorageKeyGenerate() else { return nil }
        defer { cFreeString(ptr) }
        let hex = String(cString: ptr)
        return hex.count == 64 ? hex : nil
    }

    /// CSPRNG-байты из Rust-ядра, hex-строкой (для токенов).
    static func randomHex(bytes: Int) -> String? {
        guard bytes > 0, bytes <= 1024 else { return nil }
        guard let ptr = cRandomHex(bytes) else { return nil }
        defer { cFreeString(ptr) }
        let hex = String(cString: ptr)
        return hex.count == bytes * 2 ? hex : nil
    }

    /// Generates a new keypair. Returns (secretHex, publicHex).
    static func createKeypair() throws -> (secret: String, public: String) {
        guard let ptr = cCreateKeypair() else { throw MinError.ffiFailure }
        defer { cFreeString(ptr) }
        let combined = String(cString: ptr)
        let parts = combined.split(separator: ":")
        guard parts.count == 2 else { throw MinError.ffiFailure }
        return (String(parts[0]), String(parts[1]))
    }

    /// Derives a shared secret from a secret key and a peer public key (hex strings).
    static func deriveSharedSecret(secretHex: String, publicHex: String) throws -> String {
        let result = secretHex.withCString { skPtr in
            publicHex.withCString { pkPtr in
                cDeriveSharedSecret(skPtr, pkPtr)
            }
        }
        guard let ptr = result else { throw MinError.ffiFailure }
        defer { cFreeString(ptr) }
        return String(cString: ptr)
    }

    /// Encrypts plaintext with a shared secret. Returns hex-encoded ciphertext.
    static func encrypt(sharedSecretHex: String, plaintext: String) throws -> String {
        let result = sharedSecretHex.withCString { skPtr in
            plaintext.withCString { ptPtr in
                cEncrypt(skPtr, ptPtr)
            }
        }
        guard let ptr = result else { throw MinError.ffiFailure }
        defer { cFreeString(ptr) }
        return String(cString: ptr)
    }

    /// Decrypts hex-encoded ciphertext with a shared secret. Returns plaintext.
    static func decrypt(sharedSecretHex: String, ciphertextHex: String) throws -> String {
        let result = sharedSecretHex.withCString { skPtr in
            ciphertextHex.withCString { ctPtr in
                cDecrypt(skPtr, ctPtr)
            }
        }
        guard let ptr = result else { throw MinError.ffiFailure }
        defer { cFreeString(ptr) }
        return String(cString: ptr)
    }

    // MARK: - Contact keys

    /// Verifies a MIN3: contact key string (AUDIT MIN-05, fail-closed).
    ///
    /// Проверяет: строгий парс (канонический CBOR, поля 1..=7), Ed25519-подпись
    /// identity-ключа, инвариант mailbox_id == HKDF(identity_pk).
    /// - Returns: mailbox id (hex) — адрес маршрутизации.
    /// - Throws: `MinError.ffiFailure` при любой ошибке валидации
    ///   (мусорная строка, BadSignature, тамперинг).
    static func parseContactKey(_ key: String) throws -> String {
        guard let ptr = key.withCString({ cParseContactKey($0) }) else {
            throw MinError.ffiFailure
        }
        defer { cFreeString(ptr) }
        return String(cString: ptr)
    }

    /// Formats a key into a shareable MIN3: string.
    static func formatContactKey(_ key: String) throws -> String {
        guard let ptr = key.withCString({ cFormatContactKey($0) }) else {
            throw MinError.ffiFailure
        }
        defer { cFreeString(ptr) }
        return String(cString: ptr)
    }

    /// AUDIT MIN-26 / O-5: создаёт Contact Key на заданную эпоху
    /// (ротация = текущая эпоха + 1).
    ///
    /// - Parameters:
    ///   - identitySecretHex: 32B Ed25519 secret (hex, 64 символа).
    ///   - signedPrekeyHex: 32B X25519 signed prekey (hex).
    ///   - epoch: эпоха адреса, >= 1.
    ///   - expiry: unix-секунды (0 = без срока).
    /// - Returns: каноническая MIN3-строка.
    /// - Note: mailbox_id выводится в Rust как HKDF(identity, LE64(epoch)) —
    ///   подделать адрес или сохранить старую эпоху нельзя.
    static func createContactKey(
        identitySecretHex: String,
        signedPrekeyHex: String,
        epoch: UInt64,
        expiry: UInt64 = 0
    ) throws -> String {
        let ptr = identitySecretHex.withCString { sk in
            signedPrekeyHex.withCString { spk in
                cCreateContactKey(sk, spk, epoch, expiry)
            }
        }
        guard let ptr = ptr else { throw MinError.ffiFailure }
        defer { cFreeString(ptr) }
        return String(cString: ptr)
    }

    /// AUDIT MIN-26: эпоха валидного Contact Key (fail-closed, как parse).
    static func contactKeyEpoch(_ key: String) throws -> UInt64 {
        guard let ptr = key.withCString({ cContactKeyEpoch($0) }) else {
            throw MinError.ffiFailure
        }
        defer { cFreeString(ptr) }
        guard let epoch = UInt64(String(cString: ptr)) else { throw MinError.ffiFailure }
        return epoch
    }

    // MARK: - Sessions (PQXDH + Double Ratchet)

    @_silgen_name("min_session_create")
    private static func cSessionCreate() -> OpaquePointer?

    @_silgen_name("min_session_free")
    private static func cSessionFree(_ handle: OpaquePointer?)

    @_silgen_name("min_session_identity_public")
    private static func cSessionIdentityPublic(_ handle: OpaquePointer?) -> UnsafeMutablePointer<CChar>?

    @_silgen_name("min_session_generate_bundle")
    private static func cSessionGenerateBundle(_ handle: OpaquePointer?) -> UnsafeMutablePointer<CChar>?

    @_silgen_name("min_session_init_bound")
    private static func cSessionInitBound(_ handle: OpaquePointer?, _ contactKey: UnsafePointer<CChar>?, _ bundle: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?

    @_silgen_name("min_session_export")
    private static func cSessionExport(_ handle: OpaquePointer?, _ storageKey: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?

    @_silgen_name("min_session_restore")
    private static func cSessionRestore(_ localName: UnsafePointer<CChar>?, _ blob: UnsafePointer<CChar>?, _ storageKey: UnsafePointer<CChar>?) -> OpaquePointer?

    @_silgen_name("min_session_encrypt")
    private static func cSessionEncrypt(_ handle: OpaquePointer?, _ peer: UnsafePointer<CChar>?, _ plaintext: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?

    @_silgen_name("min_session_decrypt")
    private static func cSessionDecrypt(_ handle: OpaquePointer?, _ peer: UnsafePointer<CChar>?, _ ciphertext: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?

    /// Opaque handle to a Rust session manager (PQXDH + Double Ratchet).
    ///
    /// Backed by libsignal-protocol: post-quantum secure (ML-KEM-1024 + X25519),
    /// forward-secret (Double Ratchet), break-in-recovering. NOT thread-safe —
    /// a single Session must be accessed from one serial queue.
    final class Session {
        private var handle: OpaquePointer?

        init?() {
            guard let h = cSessionCreate() else { return nil }
            handle = h
        }

        /// Adopts an existing handle (restore path, v6 RT-26.1).
        private init(adopting h: OpaquePointer) {
            handle = h
        }

        deinit {
            if let h = handle { cSessionFree(h) }
        }

        private func validHandle() throws -> OpaquePointer {
            guard let h = handle else { throw MinError.ffiFailure }
            return h
        }

        /// Persistence (v6, RT-26.1): экспортирует аутентифицированный snapshot
        /// всех сессий (hex `CBOR || tag[32]`). MAC-ключ выводится FFI из
        /// `storageKeyHex`. Блоб содержит приватные ключи — вызывающий обязан
        /// хранить его зашифрованным (min_storage под storage key).
        func exportSnapshot(storageKeyHex: String) throws -> String {
            let h = try validHandle()
            guard let ptr = storageKeyHex.withCString({ cSessionExport(h, $0) }) else {
                throw MinError.ffiFailure
            }
            defer { cFreeString(ptr) }
            return String(cString: ptr)
        }

        /// Persistence (v6, RT-26.1): восстанавливает Session из snapshot'а,
        /// снятого `exportSnapshot`. tamper/чужой ключ → nil (fail-closed).
        static func restoreSnapshot(localName: String, blobHex: String, storageKeyHex: String) -> Session? {
            guard let h = localName.withCString({ ln in
                blobHex.withCString({ blob in
                    storageKeyHex.withCString({ sk in
                        cSessionRestore(ln, blob, sk)
                    })
                })
            }) else { return nil }
            return Session(adopting: h)
        }

        /// Public identity key (hex). Used when building the local Contact Key.
        func identityPublicKey() throws -> String {
            let h = try validHandle()
            guard let ptr = cSessionIdentityPublic(h) else { throw MinError.ffiFailure }
            defer { cFreeString(ptr) }
            return String(cString: ptr)
        }

        /// Generates a fresh prekey bundle. Returns hex-encoded CBOR (carries
        /// one-time prekey, signed prekey + signature, identity key, and
        /// ML-KEM-1024 prekey + signature). A peer must bind this bundle to the
        /// same long-term identity before using the strict bound init API.
        func generateBundle() throws -> String {
            let h = try validHandle()
            guard let ptr = cSessionGenerateBundle(h) else { throw MinError.ffiFailure }
            defer { cFreeString(ptr) }
            return String(cString: ptr)
        }

        /// AUDIT MIN-05: session init, привязанный к верифицированному Contact Key.
        ///
        /// Fail-closed цепочка: Contact Key проверяется (Ed25519-подпись +
        /// mailbox_id == HKDF(identity_pk)), адрес сессии выводится ИЗ Contact Key
        /// (не принимается от вызывающего), bundle.signed_pre_key_public сверяется
        /// с ContactKey.signed_prekey_public до process_prekey_bundle.
        /// Блокирует подмену bundle relay'ем (Signal-2026 класс атак).
        ///
        /// - Returns: literal `"ok"` after successful authenticated initialization.
        /// - Throws: `MinError.ffiFailure` при любой ошибке валидации.
        @discardableResult
        func initSessionBound(contactKey: String, bundleCborHex: String) throws -> String {
            let h = try validHandle()
            guard let mailboxPtr = contactKey.withCString({ ckPtr in
                cSessionInitBound(h, ckPtr, bundleCborHex)
            }) else {
                throw MinError.ffiFailure
            }
            defer { cFreeString(mailboxPtr) }
            return String(cString: mailboxPtr)
        }

        /// Encrypts `plaintext` for `peer`. Returns hex ciphertext (with a
        /// 1-byte type prefix: 0x01 prekey, 0x02 whisper / Double Ratchet).
        func encrypt(peer: String, plaintext: String) throws -> String {
            let h = try validHandle()
            let result = peer.withCString { peerPtr in
                plaintext.withCString { ptPtr in
                    cSessionEncrypt(h, peerPtr, ptPtr)
                }
            }
            guard let ptr = result else { throw MinError.ffiFailure }
            defer { cFreeString(ptr) }
            return String(cString: ptr)
        }

        /// Decrypts hex `ciphertext` from `peer`. Returns plaintext.
        func decrypt(peer: String, ciphertextHex: String) throws -> String {
            let h = try validHandle()
            let result = peer.withCString { peerPtr in
                ciphertextHex.withCString { ctPtr in
                    cSessionDecrypt(h, peerPtr, ctPtr)
                }
            }
            guard let ptr = result else { throw MinError.ffiFailure }
            defer { cFreeString(ptr) }
            return String(cString: ptr)
        }
    }

    /// Creates the local identity (placeholder until min-identity is wired).
    static func createIdentity() throws -> String {
        guard let ptr = cCreateIdentity() else { throw MinError.ffiFailure }
        defer { cFreeString(ptr) }
        return String(cString: ptr)
    }

    // MARK: - Envelope header binding (AUDIT MIN-02)

    /// Verifies the envelope aad_commitment (header binding, PROTOCOL §3
    /// field 7) against `sessionId`. MUST be called on every pulled envelope
    /// BEFORE session decrypt — detects relay tampering of any header field
    /// (seq/epoch/hints/nonce/ttl) that the inner AEAD cannot see.
    /// Throws on mismatch, malformed input or FFI failure (fail-closed).
    static func verifyEnvelope(envelopeHex: String, sessionIdHex: String) throws {
        let verdict = envelopeHex.withCString { envPtr in
            sessionIdHex.withCString { sidPtr in
                cEnvelopeVerify(envPtr, sidPtr)
            }
        }
        guard let ptr = verdict else { throw MinError.ffiFailure }
        defer { cFreeString(ptr) }
        guard String(cString: ptr) == "1" else { throw MinError.ffiFailure }
    }
}
