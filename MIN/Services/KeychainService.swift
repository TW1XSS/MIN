import Foundation
import Security

/// Keychain-хранилище master key MIN (P6 / RT-26.20, OWASP MASVS-STORAGE-1).
///
/// Политика:
/// - Долговременные секреты: storage key в iOS Keychain. Pull-token и
///   остальные записи хранятся в SQLite, зашифрованной этим storage key.
/// - Ключ шифрования БД генерируется Rust-ядром (`MinCore.generateStorageKey`),
///   в Swift попадает один раз и немедленно сохраняется в Keychain; повторная
///   выдача — только из Keychain.
/// - Файлы данных (SQLite/файлы ядра) помечаются `isExcludedFromBackup = true`.
///   См. `KeychainService.excludeFromBackup(_:)`.
///
/// Views не трогает: используется только слоем Services.
final class KeychainService {

    static let shared = KeychainService()

    private enum Key {
        static let storageKey = "MIN.storage.master-key.v1"
        static let service = "app.min.core"
        /// MIN-RED-019: recovery-блоб личности. Слот с `#<n>` в будущем даёт
        /// мультиаккаунт без миграции схемы Keychain.
        static let recoveryBlob = "MIN.identity.recovery.v1#0"
        /// Ключ офлайн-кэша списка чатов (см. `chatCacheKey`).
        static let chatCache = "MIN.chats.cache-key.v1"
    }

    /// Ключ для офлайн-кэша списка чатов.
    ///
    /// Отдельный от `storageKey` намеренно: у storage-ключа своя ротация
    /// (пересоздание при удалённой БД), и если бы кэш шифровался им же, то
    /// после ротации сохранённая переписка стала бы нечитаемой.
    func chatCacheKey() -> Data {
        if let existing = readData(Key.chatCache), existing.count == 32 {
            return existing
        }
        // Тот же источник энтропии, что у storage-ключа: 64 hex-символа = 32 байта.
        guard let fresh = MinCore.generateStorageKey(), fresh.count == 64 else {
            return Data(repeating: 0, count: 32)
        }
        let chars = Array(fresh)
        var bytes = Data(count: 32)
        for i in 0..<32 {
            guard let hi = chars[2 * i].hexDigitValue,
                  let lo = chars[2 * i + 1].hexDigitValue else {
                return Data(repeating: 0, count: 32)
            }
            bytes[bytes.startIndex + i] = UInt8(truncatingIfNeeded: hi << 4 | lo)
        }
        _ = saveData(Key.chatCache, value: bytes)
        return bytes
    }

    /// Порог, выше которого блоб не пишем в Keychain. Крупные items iOS
    /// начинает отказывать (`errSecParam`) — лучше потерять блоб, чем уронить
    /// открытие приложения. В байтах: блоб — это шифротекст, а не текст.
    private static let maxRecoveryBlobBytes = 48 * 1024

    private init() {}

    /// MIN-RED-019: recovery-блоб личности (Keychain-предмет), сырые байты.
    /// Блоб внутри содержит приватный ключ identity, поэтому наружу он уходит
    /// только через `MinApp.open()` и никогда — в лог.
    func recoveryBlob() -> Data? { readData(Key.recoveryBlob) }

    /// Сохраняет блоб. Возвращает false, если Keychain отказал: это НЕ повод
    /// ронять приложение, лишь повод не рассчитывать на восстановление.
    @discardableResult
    func saveRecoveryBlob(_ blob: Data) -> Bool {
        guard !blob.isEmpty, blob.count <= Self.maxRecoveryBlobBytes else {
            NSLog("MIN: recovery blob is too large (%d bytes) — not stored",
                  blob.count)
            return false
        }
        return saveData(Key.recoveryBlob, value: blob)
    }

    func deleteRecoveryBlob() {
        SecItemDelete(baseQuery(Key.recoveryBlob) as CFDictionary)
    }

    /// MIN-RED-010: master key берётся из Keychain, а БД лежит в контейнере
    /// приложения. После удаления/переустановки контейнер (и `min-app.db`)
    /// уничтожается, но Keychain-предмет `ThisDeviceOnly` переживает удаление
    /// приложения.
    ///
    /// MIN-RED-019 (важное исключение к ротации): если БД исчезла, НО в Keychain
    /// лежит recovery-блоб, ключ ротировать НЕЛЬЗЯ. Блоб зашифрован производной
    /// от этого ключа, поэтому смена ключа сделала бы восстановление невозможным
    /// — и мы бы тихо получили новую identity вместо прежней. Ротация остаётся
    /// только для случая «блоба нет» (то есть восстанавливать нечего).
    ///
    /// Возвращается признак ротации — вызывающий показывает его в строке статуса.
    func obtainStorageKey(databaseExists: Bool) -> (key: String, rotated: Bool) {
        let existing = read(Key.storageKey)
        if databaseExists, let existing = existing, existing.count == 64 {
            return (existing, false)
        }
        if let existing = existing, existing.count == 64, recoveryBlob() != nil {
            // БД удалена, но блоб есть: восстанавливаемся на прежнем ключе.
            return (existing, false)
        }
        guard let fresh = MinCore.generateStorageKey(), fresh.count == 64 else {
            // Генерация не удалась: для читабельности БД нужен какой-то ключ;
            // лучше старый (БД пуста, ломать нечего), чем открыть с нулевым.
            return (existing ?? String(repeating: "0", count: 64), false)
        }
        let rotated = existing != nil
        return (save(Key.storageKey, value: fresh) ? fresh : fresh, rotated)
    }

    /// Удаляет все секреты этого сервиса из Keychain (wipe-политика).
    func wipeAll() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Key.service,
        ]
        SecItemDelete(query as CFDictionary)
    }

    /// Помечает файл данных как исключённый из любых бэкапов (MASVS-BACKUP).
    /// Вызывать для каждого файла локальной БД/состояния ядра.
    static func excludeFromBackup(_ url: URL) {
        var mutable = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? mutable.setResourceValues(values)
    }

    // MARK: - Private

    private func baseQuery(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Key.service,
            kSecAttrAccount as String: account,
        ]
    }

    private func read(_ account: String) -> String? {
        guard let data = readData(account) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// MIN-RED-019: блоб — шифротекст, а не текст, поэтому хранится и читается
    /// как `Data`. Строковый путь выше остаётся для master-ключа.
    private func readData(_ account: String) -> Data? {
        var query = baseQuery(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return data
    }

    private func save(_ account: String, value: String) -> Bool {
        saveData(account, value: Data(value.utf8))
    }

    private func saveData(_ account: String, value: Data) -> Bool {
        let data = value
        var add = baseQuery(account)
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] =
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        // Item мог остаться от прошлой версии API — обновляем существующий.
        var update = baseQuery(account)
        update[kSecValueData as String] = data
        switch SecItemAdd(add as CFDictionary, nil) {
        case errSecSuccess:
            return true
        case errSecDuplicateItem:
            return SecItemUpdate(
                baseQuery(account) as CFDictionary,
                [kSecValueData as String: data] as CFDictionary
            ) == errSecSuccess
        default:
            return false
        }
    }
}