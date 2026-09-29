//
//  MinApp.swift
//  MIN
//
//  Высокоуровневый слой приложения: типизированная обёртка над Rust-ядром
//  (`min-app` через FFI). UI работает только с этим файлом и не знает
//  ничего про сессии, ключи и relay.
//
//  Контракт и список вызовов описаны в CONTRIBUTING.md.
//  Блокирующие методы (open/register/poll) вызывать с фонового потока.
//

import Foundation
import os

// MARK: - Модели (совпадают с JSON из Rust)

/// Статус исходящего сообщения.
enum MinMessageStatus: String, Codable {
    case sending, sent, delivered, failed
}

/// Состояние контакта.
enum MinContactState: String, Codable {
    case pending, accepted, rejected, blocked
}

/// Сообщение в переписке.
struct MinMessage: Codable, Identifiable, Hashable {
    var itemId: String?
    var peer: String
    var outgoing: Bool
    var text: String
    var sentAt: UInt64
    var status: MinMessageStatus
    /// CONTROL-ответ на заявку: "accepted" / "not_delivered" (nil = обычное
    /// сообщение). Причина не раскрывается — на проводе всего два кода.
    var control: String?
    /// Цитата ответа (автор + превью). Приходит из ядра вместе с текстом,
    /// поэтому видна обеим сторонам и переживает перезапуск — раньше цитата
    /// жила только в UI и пропадала при первом reloadChats.
    var reply: MinReplyRef?

    /// Локальный id для SwiftUI-списков.
    var id: String { itemId ?? "\(peer)-\(sentAt)-\(outgoing)-\(text.hashValue)" }

    /// Ядро отдаёт snake_case (model.rs) — маппим на camelCase Swift.
    enum CodingKeys: String, CodingKey {
        case peer, outgoing, text, status, control, reply
        case itemId = "item_id"
        case sentAt = "sent_at"
    }
}

/// Цитата ответа: на что отвечает сообщение.
struct MinReplyRef: Codable, Hashable {
    var author: String
    var preview: String
}

/// Заявки от незнакомцев + состояние тумблера (MIN-RED-022).
struct MinRequests: Codable {
    /// Разрешены ли заявки сейчас (тумблер; по умолчанию ВКЛ).
    var discoverable: Bool
    var requests: [MinRequest]

    enum CodingKeys: String, CodingKey {
        case discoverable, requests
    }
}

/// Карточка заявки. Текста здесь нет by design: он лежит в зашифрованном
/// конверте и читается только после Accept.
struct MinRequest: Codable, Identifiable, Hashable {
    var requestId: String
    var identityHex: String
    var firstSeen: UInt64
    var expiresAt: UInt64
    var envelopes: Int

    var id: String { requestId }

    enum CodingKeys: String, CodingKey {
        case identityHex = "identity_hex"
        case firstSeen = "first_seen"
        case expiresAt = "expires_at"
        case requestId = "request_id"
        case envelopes
    }
}

/// Контакт (запись адресной книги).
struct MinContact: Codable, Identifiable, Hashable {
    var name: String
    var identityHex: String
    var mailboxIdHex: String
    var epoch: UInt64
    var state: MinContactState

    var id: String { identityHex }

    /// Ядро отдаёт snake_case (model.rs) — маппим на camelCase Swift.
    enum CodingKeys: String, CodingKey {
        case name, epoch, state
        case identityHex = "identity_hex"
        case mailboxIdHex = "mailbox_id_hex"
    }
}

/// Чат в списке.
struct MinChat: Codable, Identifiable, Hashable {
    var peer: String
    var name: String
    var lastText: String
    var lastAt: UInt64
    var unread: UInt32

    var id: String { peer }

    /// Ядро отдаёт snake_case (model.rs) — маппим на camelCase Swift.
    enum CodingKeys: String, CodingKey {
        case peer, name, unread
        case lastText = "last_text"
        case lastAt = "last_at"
    }
}

/// Публичные данные аккаунта.
struct MinSelf: Codable, Hashable {
    var identityHex: String
    var mailboxIdHex: String
    var epoch: UInt64

    /// Ядро отдаёт snake_case (core.rs self_public) — маппим на camelCase.
    enum CodingKeys: String, CodingKey {
        case epoch
        case identityHex = "identity_hex"
        case mailboxIdHex = "mailbox_id_hex"
    }
}

/// Ошибка слоя приложения.
enum MinAppError: Error {
    case ffiFailed(String)
    case notOpen
}

// MARK: - FFI (Rust `min-app`)

private enum FFIMinApp {
    @_silgen_name("min_app_open")
    static func appOpen(_ storagePath: UnsafePointer<CChar>?, _ storageKeyHex: UnsafePointer<CChar>?,
                        _ linkKind: UnsafePointer<CChar>?, _ addr: UnsafePointer<CChar>?,
                        _ stateDir: UnsafePointer<CChar>?, _ cacheDir: UnsafePointer<CChar>?) -> OpaquePointer?
    @_silgen_name("min_app_free")
    static func appFree(_ handle: OpaquePointer?)
    @_silgen_name("min_app_self")
    static func appSelf(_ handle: OpaquePointer?) -> UnsafeMutablePointer<CChar>?
    @_silgen_name("min_app_recovery_export_bin")
    static func appRecoveryExportBin(_ handle: OpaquePointer?,
                                     _ withSession: Int32,
                                     _ outLen: UnsafeMutablePointer<Int>?) -> UnsafeMutablePointer<UInt8>?
    @_silgen_name("min_free_bytes")
    static func freeBytes(_ ptr: UnsafeMutablePointer<UInt8>?, _ len: Int)
    @_silgen_name("min_app_open_with_recovery")
    static func appOpenWithRecovery(_ storagePath: UnsafePointer<CChar>?,
                                    _ storageKeyHex: UnsafePointer<CChar>?,
                                    _ linkKind: UnsafePointer<CChar>?,
                                    _ addr: UnsafePointer<CChar>?,
                                    _ stateDir: UnsafePointer<CChar>?,
                                    _ cacheDir: UnsafePointer<CChar>?,
                                    _ recoveryBlob: UnsafePointer<UInt8>?,
                                    _ recoveryBlobLen: Int) -> OpaquePointer?
    @_silgen_name("min_app_contact_key")
    static func appContactKey(_ handle: OpaquePointer?) -> UnsafeMutablePointer<CChar>?
    @_silgen_name("min_app_bundle")
    static func appBundle(_ handle: OpaquePointer?) -> UnsafeMutablePointer<CChar>?
    @_silgen_name("min_app_register")
    static func appRegister(_ handle: OpaquePointer?) -> UnsafeMutablePointer<CChar>?
    @_silgen_name("min_app_invite")
    static func appInvite(_ handle: OpaquePointer?) -> UnsafeMutablePointer<CChar>?
    @_silgen_name("min_app_add_contact")
    static func appAddContact(_ handle: OpaquePointer?, _ name: UnsafePointer<CChar>?,
                              _ invite: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?
    @_silgen_name("min_app_send_text")
    static func appSendText(_ handle: OpaquePointer?, _ peer: UnsafePointer<CChar>?,
                            _ text: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?
    @_silgen_name("min_app_poll")
    static func appPoll(_ handle: OpaquePointer?) -> UnsafeMutablePointer<CChar>?
    @_silgen_name("min_app_chats")
    static func appChats(_ handle: OpaquePointer?) -> UnsafeMutablePointer<CChar>?
    @_silgen_name("min_app_messages")
    static func appMessages(_ handle: OpaquePointer?, _ peer: UnsafePointer<CChar>?)
        -> UnsafeMutablePointer<CChar>?
    @_silgen_name("min_app_contacts")
    static func appContacts(_ handle: OpaquePointer?) -> UnsafeMutablePointer<CChar>?
    @_silgen_name("min_app_last_error")
    static func appLastError() -> UnsafeMutablePointer<CChar>?
    // MIN-RED-022: сообщения от незнакомцев
    @_silgen_name("min_app_send_text_to_invite")
    static func appSendTextToInvite(_ handle: OpaquePointer?, _ invite: UnsafePointer<CChar>?,
                                    _ text: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?
    @_silgen_name("min_app_send_reply")
    static func appSendReply(_ handle: OpaquePointer?, _ peer: UnsafePointer<CChar>?,
                             _ text: UnsafePointer<CChar>?,
                             _ author: UnsafePointer<CChar>?,
                             _ preview: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?
    @_silgen_name("min_app_send_message")
    static func appSendMessage(_ handle: OpaquePointer?, _ peer: UnsafePointer<CChar>?,
                               _ text: UnsafePointer<CChar>?,
                               _ author: UnsafePointer<CChar>?,
                               _ preview: UnsafePointer<CChar>?,
                               _ invite: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?
    @_silgen_name("min_app_mark_chat_read")
    static func appMarkChatRead(_ handle: OpaquePointer?, _ peer: UnsafePointer<CChar>?)
        -> UnsafeMutablePointer<CChar>?
    @_silgen_name("min_app_send_text_to_invite_reply")
    static func appSendTextToInviteReply(
        _ handle: OpaquePointer?, _ invite: UnsafePointer<CChar>?,
        _ text: UnsafePointer<CChar>?, _ author: UnsafePointer<CChar>?,
        _ preview: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?
    @_silgen_name("min_app_mark_chat_read_at")
    static func appMarkChatReadAt(_ handle: OpaquePointer?, _ peer: UnsafePointer<CChar>?,
                                  _ at: UInt64) -> UnsafeMutablePointer<CChar>?
    @_silgen_name("min_app_read_markers")
    static func appReadMarkers(_ handle: OpaquePointer?) -> UnsafeMutablePointer<CChar>?
    @_silgen_name("min_app_requests")
    static func appRequests(_ handle: OpaquePointer?) -> UnsafeMutablePointer<CChar>?
    @_silgen_name("min_app_accept_request")
    static func appAcceptRequest(_ handle: OpaquePointer?, _ requestId: UnsafePointer<CChar>?)
        -> UnsafeMutablePointer<CChar>?
    @_silgen_name("min_app_reject_request")
    static func appRejectRequest(_ handle: OpaquePointer?, _ requestId: UnsafePointer<CChar>?)
        -> UnsafeMutablePointer<CChar>?
    @_silgen_name("min_app_block_request")
    static func appBlockRequest(_ handle: OpaquePointer?, _ requestId: UnsafePointer<CChar>?)
        -> UnsafeMutablePointer<CChar>?
    @_silgen_name("min_app_set_discoverable")
    static func appSetDiscoverable(_ handle: OpaquePointer?, _ allowed: Bool)
        -> UnsafeMutablePointer<CChar>?
}

// MARK: - Обёртка над типизированным API

final class MinApp {
    static let shared = MinApp()

    private var handle: OpaquePointer?

    private init() {}

    /// Диагностический текст последнего NULL-вызова Rust-FFI. Строка содержит
    /// только тип/статус операции (delivery/session/storage), не payload, ключи и токены.
    private func lastFFIError(_ fallback: String) -> String {
        guard let raw = FFIMinApp.appLastError() else { return fallback }
        defer { MinCore.freeString(raw) }
        let value = String(cString: raw).trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? fallback : value
    }

    private func decode<T: Codable>(_ raw: UnsafeMutablePointer<CChar>?) throws -> T {
        guard let raw = raw else {
            throw MinAppError.ffiFailed(lastFFIError("core вернул NULL"))
        }
        defer { MinCore.freeString(raw) }
        let json = String(cString: raw)
        do {
            return try JSONDecoder().decode(T.self, from: Data(json.utf8))
        } catch {
            os_log("min_app decode failed: %{public}@", type: .error, String(describing: error))
            throw MinAppError.ffiFailed("bad JSON от ядра")
        }
    }

    /// Строковый результат FFI (без JSON): освобождает C-память ядра.
    private func decodeString(_ raw: UnsafeMutablePointer<CChar>?) throws -> String {
        guard let raw = raw else {
            throw MinAppError.ffiFailed(lastFFIError("core вернул NULL"))
        }
        defer { MinCore.freeString(raw) }
        return String(cString: raw)
    }

    private func requireHandle() throws -> OpaquePointer {
        guard let handle = handle else { throw MinAppError.notOpen }
        return handle
    }

    // MARK: - Жизненный цикл

    /// Адрес relay: публичный onion задаётся при сборке через `MIN_RELAY_ADDR`
    /// (Info.plist build setting), а для локальной разработки — env/UserDefaults.
    /// Приватный onion-ключ и LAN-адрес в приложение/Git не попадают.
    static var relayAddress: String {
        if let env = ProcessInfo.processInfo.environment["MIN_RELAY_ADDR"], !env.isEmpty {
            return env
        }
        if let stored = UserDefaults.standard.string(forKey: "min.relay"), !stored.isEmpty {
            return stored
        }
        if let bundled = Bundle.main.object(forInfoDictionaryKey: "MinRelayAddress") as? String,
           !bundled.isEmpty,
           !bundled.contains("$(") {
            return bundled
        }
        // Fail-closed: неизвестный relay лучше явной ошибки, чем неверный маршрут.
        return ""
    }

    /// Транспорт ядра: iOS — SOCKS5 к локальному C Tor (мосты IPtProxy).
    /// `tcp-dev-harness` существует только в dev/test-сборке и не попадает
    /// в release xcframework. Оверрайды: env `MIN_LINK` / UserDefaults `min.link`.
    static var linkKind: String {
        if let env = ProcessInfo.processInfo.environment["MIN_LINK"], !env.isEmpty {
            return env
        }
        if let stored = UserDefaults.standard.string(forKey: "min.link"), !stored.isEmpty {
            return stored
        }
        return "socks"
    }

    /// Открывает ядро (identity + сессии + relay + история).
    /// Блокирующий (Tor bootstrap) — звать с фонового потока.
    @discardableResult
    func open() throws -> MinSelf {
        if handle != nil { return try selfPublic() }
        let fm = FileManager.default
        let base = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("min", isDirectory: true)
        try? fm.createDirectory(at: base, withIntermediateDirectories: true)
        KeychainService.excludeFromBackup(base)
        let dbPath = base.appendingPathComponent("min-app.db").path
        // MIN-RED-010: контейнер удаляется при удалении приложения, а Keychain —
        // нет. Проверяем БД ДО получения ключа, иначе старый ключ подставится
        // к пустой БД и identity молча сменится.
        let (storageKey, keyRotated) =
            KeychainService.shared.obtainStorageKey(databaseExists: fm.fileExists(atPath: dbPath))
        if keyRotated {
            NSLog("MIN: local account data was removed (reinstall/restore); "
                + "storage key rotated, a new identity was created")
        }
        // MIN-RED-019: блоб из Keychain (переживает удаление приложения).
        // Передаётся в ядро, чтобы оно восстановило identity вместо новой.
        let recoveryBlob = KeychainService.shared.recoveryBlob()
        if recoveryBlob == nil, !keyRotated {
            NSLog("MIN: no recovery blob in Keychain — recovery after a reinstall "
                + "will not be possible")
        }
        let stateDir = base.appendingPathComponent("tor-state", isDirectory: true).path
        let cacheDir = base.appendingPathComponent("tor-cache", isDirectory: true).path
        guard !Self.relayAddress.isEmpty else {
            // Fail-closed, но с указанием КУДА смотреть: иначе разработчик
            // ищет причину в Rust, хотя причина — незаданная build-переменная.
            NSLog("MIN: relay address is empty. Ожидается одно из: "
                + "build setting MIN_RELAY_ADDR (Info.plist ключ MinRelayAddress), "
                + "env MIN_RELAY_ADDR, или UserDefaults 'min.relay'")
            throw MinAppError.ffiFailed(
                "relay address is not configured — задай MIN_RELAY_ADDR "
                + "в build settings таргета MIN (Debug и Release)"
            )
        }
        // Блоб передаётся в ядро сырыми байтами: он шифротекст, и hex-строка
        // удвоила бы его ровно настолько, насколько iOS Keychain не готов
        // принять крупный item. Копия нужна потому, что `open` читает буфер
        // синхронно, а на байты Keychain нельзя держать указатель дольше
        // вызова; после чтения копия затирается.
        if let blob = recoveryBlob, !blob.isEmpty {
            recoveryBuf = [UInt8](blob)
        }
        var bufCopy = recoveryBuf ?? []
        var opened: OpaquePointer? = bufCopy.withUnsafeBufferPointer { buf in
            FFIMinApp.appOpenWithRecovery(
                dbPath, storageKey, Self.linkKind, Self.relayAddress,
                stateDir, cacheDir, buf.baseAddress, buf.count)
        }
        // Затираем копию сразу: в ней приватный ключ identity.
        bufCopy.resetBytes(in: 0..<bufCopy.count)
        recoveryBuf = nil

        if opened == nil, recoveryBlob != nil {
            // Блоб оказался нечитаемым: другая версия формата, другой
            // storage-ключ или повреждение. Страховка не должна превращаться в
            // кирпич — приложение обязано открыться. Ядро при этом НЕ создаёт
            // новый аккаунт молча: блоб удаляется явно, а факт попадает в лог и
            // в строку статуса (см. `recoveryDiscarded`).
            let why = lastFFIError("open")
            NSLog("MIN: recovery blob unusable (%@) — discarded, creating a new account", why)
            KeychainService.shared.deleteRecoveryBlob()
            recoveryDiscarded = true
            opened = [].withUnsafeBufferPointer { buf in
                FFIMinApp.appOpenWithRecovery(
                    dbPath, storageKey, Self.linkKind, Self.relayAddress,
                    stateDir, cacheDir, buf.baseAddress, buf.count)
            }
        }
        guard let opened = opened else {
            throw MinAppError.ffiFailed(lastFFIError("min_app_open: ядро не открылось"))
        }
        handle = opened
        // MIN-RED-019: identity кладём в Keychain сразу, ДО сети — иначе
        // окно между «БД удалена» и «register прошёл» оставляло бы переустановку
        // без восстановления. Блоб на этом шаге ещё БЕЗ pull_token: токен
        // выдаёт relay в register(), который зовёт вызывающий код уже после
        // open(). Поэтому блоб перезаписывается после успешного register()
        // (см. `register()`), иначе после переустановки клиент знал бы свой
        // mailbox_id, но не знал бы токен — и не смог бы забрать свою очередь.
        persistRecoveryBlob()
        return try selfPublic()
    }

    /// Временная копия блоба на время вызова `open`: указатель на байты
    /// Keychain нельзя удерживать за пределами `withUnsafeBytes`, а `open`
    /// читает его синхронно. После вызова копия затирается.
    private var recoveryBuf: [UInt8]?

    /// Страховочный блоб оказался нечитаемым и был удалён; аккаунт создан заново.
    /// Показывается в строке статуса, чтобы пользователь не думал, что его
    /// переписка просто исчезла сама.
    private(set) var recoveryDiscarded = false

    /// Кладёт recovery-блоб в Keychain. Безопасность: блоб содержит приватный
    /// ключ identity, поэтому наружу он не выходит и не логируется; в лог — только
    /// размер и факт записи. Буфер ядра затирается сразу после копирования.
    @discardableResult
    private func persistRecoveryBlob() -> Bool {
        guard let handle = handle else { return false }
        // Полный блоб может не влезти в Keychain, если снапшот ratchet вырос.
        // Отказ записи означал бы, что следующая переустановка оборвёт mailbox,
        // поэтому при нехватке места пишем сокращённый блоб: identity, эпоха,
        // mailbox, pull_token и контакты в нём остаются.
        if var full = exportBlob(withSession: 1) {
            let ok = KeychainService.shared.saveRecoveryBlob(Data(full))
            // Затираем локальную копию сразу: в ней приватный ключ identity.
            full.resetBytes(in: 0..<full.count)
            if ok {
                NSLog("MIN: recovery blob persisted (full): %d bytes", full.count)
                return true
            }
        }
        guard var lean = exportBlob(withSession: 0) else {
            NSLog("MIN: recovery blob export failed (keychain not updated)")
            return false
        }
        let size = lean.count
        let ok = KeychainService.shared.saveRecoveryBlob(Data(lean))
        lean.resetBytes(in: 0..<lean.count)
        NSLog("MIN: recovery blob persisted (reduced, no ratchet snapshot): "
            + "%d bytes, ok=%@", size, ok ? "yes" : "no")
        return ok
    }

    /// Забирает блоб из ядра сырым буфером и сразу затирает его в Rust.
    private func exportBlob(withSession: Int32) -> [UInt8]? {
        var len = 0
        guard let ptr = FFIMinApp.appRecoveryExportBin(handle, withSession, &len),
              len > 0 else { return nil }
        let data = Data(bytes: ptr, count: len)
        FFIMinApp.freeBytes(ptr, len)   // zeroize + free в Rust
        return [UInt8](data)
    }

    /// Закрывает ядро (освобождает handle; данные уже в зашифрованной БД).
    func close() {
        if let handle = handle { FFIMinApp.appFree(handle) }
        handle = nil
    }

    // MARK: - Профиль и ключи

    /// Публичные данные аккаунта (identity/mailbox/epoch).
    func selfPublic() throws -> MinSelf {
        try decode(FFIMinApp.appSelf(try requireHandle()))
    }

    /// Мой Contact Key (`MIN3:...`) — то, что я передаю собеседнику.
    func contactKey() throws -> String {
        try decodeString(FFIMinApp.appContactKey(try requireHandle()))
    }

    /// Мой prekey bundle (hex) — уходит вместе с Contact Key.
    func bundleHex() throws -> String {
        try decodeString(FFIMinApp.appBundle(try requireHandle()))
    }

    // MARK: - Relay и переписка

    /// Регистрирует mailbox на relay (идемпотентно).
    ///
    /// MIN-RED-019: только после успеха токен появляется в состоянии ядра, и
    /// только теперь блоб в Keychain становится полным. До этого момента блоб
    /// содержал identity без токена, и переустановка восстанавливала mailbox_id,
    /// но не давала забрать собственную очередь. Перезапись здесь закрывает
    /// окно «БД удалена, а блоб уже записан».
    func register() throws {
        do {
            _ = try decodeString(FFIMinApp.appRegister(try requireHandle()))
        } catch {
            // MIN-RED-019: блоб без pull_token + занятый mailbox = тупик. Relay
            // отдаёт токен только первому claim'у, доказать «свой mailbox» без
            // токена клиент не может (это задача протокола, не бага). Раньше
            // здесь был кирпич: приложение не открывалось вообще. Теперь
            // единственный честный выход — новый аккаунт вместо мёртвого.
            let text = String(describing: error)
            guard text.contains("mailbox уже занят") else { throw error }
            NSLog("MIN: recovery blob carries no pull token and the mailbox is "
                + "already claimed — recreating the account")
            KeychainService.shared.deleteRecoveryBlob()
            close()
            _ = try open()
            _ = try decodeString(FFIMinApp.appRegister(try requireHandle()))
            persistRecoveryBlob()
            return
        }
        persistRecoveryBlob()
    }
    /// Мой инвайт (Contact Key + bundle одним текстом) — то, что я передаю собеседнику.
    func invite() throws -> String {
        let text = try decodeString(FFIMinApp.appInvite(try requireHandle()))
        // MIN-RED-019: invite — первая операция, которая ДОГРУЖАЕТ prekey
        // bundle в ядро (identity/prekey/bundle/binding). Блоб, записанный при
        // open()/register(), сделан до этого момента и bundle не содержит.
        // Без перезаписи после переустановки восстанавливался mailbox, но не
        // было чем подтвердить сессию: собеседник держал бы наш Contact Key с
        // prekey, которого на новой установке уже нет.
        persistRecoveryBlob()
        return text
    }

    /// Добавляет контакт по инвайту собеседника.
    func addContact(name: String, invite: String) throws -> MinContact {
        let handle = try requireHandle()
        let contact: MinContact = try name.withCString { namePtr in
            try invite.withCString { invitePtr in
                try decode(FFIMinApp.appAddContact(handle, namePtr, invitePtr))
            }
        }
        persistRecoveryBlob()  // MIN-RED-019: контакты входят в блоб
        return contact
    }

    /// Отправляет текст контакту (по имени или identity hex).
    func sendText(peer: String, text: String) throws -> MinMessage {
        let handle = try requireHandle()
        let sent: MinMessage = try peer.withCString { peerPtr in
            try text.withCString { textPtr in
                try decode(FFIMinApp.appSendText(handle, peerPtr, textPtr))
            }
        }
        // MIN-RED-019: ratchet сдвинулся, снапшот сессии устарел. Без обновления
        // блоба восстановление вернуло бы состояние ДО этого сообщения, и всё
        // написанное после было бы нерасшифровываемым.
        persistRecoveryBlob()
        return sent
    }

    /// Забирает очередь с relay: новые входящие (идемпотентно, дублей нет).
    func poll() throws -> [MinMessage] {
        let incoming: [MinMessage] = try decode(FFIMinApp.appPoll(try requireHandle()))
        if !incoming.isEmpty {
            // Приём двигает receiving chain, поэтому снапшот меняется даже когда
            // пользователь ничего не отправлял.
            persistRecoveryBlob()
        }
        return incoming
    }

    /// Список чатов для главного экрана.
    func chats() throws -> [MinChat] {
        try decode(FFIMinApp.appChats(try requireHandle()))
    }

    /// История переписки с контактом.
    func messages(peer: String) throws -> [MinMessage] {
        let handle = try requireHandle()
        return try peer.withCString { peerPtr in
            try decode(FFIMinApp.appMessages(handle, peerPtr))
        }
    }

    /// Все контакты (адресная книга).
    func contacts() throws -> [MinContact] {
        try decode(FFIMinApp.appContacts(try requireHandle()))
    }

    // MARK: - MIN-RED-022: сообщения от незнакомцев

    /// Первое сообщение незнакомцу по его invite: у него появится ЗАЯВКА,
    /// а не чат. Ручное добавление контакта не требуется.
    func sendTextToInvite(invite: String, text: String) throws -> MinMessage {
        let handle = try requireHandle()
        return try invite.withCString { invitePtr in
            try text.withCString { textPtr in
                try decode(FFIMinApp.appSendTextToInvite(handle, invitePtr, textPtr))
            }
        }
    }

    /// Ответ незнакомцу, у которого ещё нет сессии: заявка и цитата уезжают
    /// одним первым сообщением.
    func sendTextToInviteReply(invite: String, text: String, author: String,
                               preview: String) throws -> MinMessage {
        let handle = try requireHandle()
        return try invite.withCString { i in
            try text.withCString { t in
                try author.withCString { a in
                    try preview.withCString { p in
                        try decode(FFIMinApp.appSendTextToInviteReply(handle, i, t, a, p))
                    }
                }
            }
        }
    }

    /// Отправка сообщения с цитатой. Выбор пути (сессия или invite) делает ЯДРО
    /// по фактическому состоянию — в Swift «сначала обычная отправка, потом
    /// invite при любой ошибке» теряло цитату (обычная отправка проходила, и до
    /// цитаты управление не доходило) и повторяло `Enqueue` после неоднозначного
    /// сетевого сбоя.
    func sendMessage(peer: String, text: String, reply: MinReplyRef?,
                     invite: String?) throws -> MinMessage {
        let handle = try requireHandle()
        // nil для цитаты и invite превращается в NULL — ядро трактует это как
        // «цитаты нет» / «invite неизвестен». Пустую строку сюда не передаём:
        // она была бы цитатой с пустым автором.
        let sent: MinMessage = try decode(FFIMinApp.appSendMessage(
            handle, peer, text, reply?.author, reply?.preview, invite))
        // Приём/отправка двигают ratchet — снапшот сессии устареет (MIN-RED-019).
        persistRecoveryBlob()
        return sent
    }

    /// Ответ на сообщение: цитата уходит в ядро, поэтому её видит вторая
    /// сторона (в UI-только цитата исчезала при первом reloadChats).
    func sendReply(peer: String, text: String, author: String, preview: String) throws -> MinMessage {
        let handle = try requireHandle()
        return try peer.withCString { peerPtr in
            try text.withCString { textPtr in
                try author.withCString { authorPtr in
                    try preview.withCString { previewPtr in
                        try decode(FFIMinApp.appSendReply(handle, peerPtr, textPtr, authorPtr, previewPtr))
                    }
                }
            }
        }
    }

    /// Отметка «прочитано» с явным временем — только для миграции старых
    /// отметок из кэша. Обычная всегда ставит «сейчас».
    @discardableResult
    func markChatRead(peer: String, at: UInt64) throws -> [String: UInt64] {
        let handle = try requireHandle()
        return try peer.withCString { ptr in
            try decode(FFIMinApp.appMarkChatReadAt(handle, ptr, at))
        }
    }

    /// Отметки «прочитано» для UI: peer → unix-время. Ядро — источник истины.
    @discardableResult
    func readMarkers() throws -> [String: UInt64] {
        try decode(FFIMinApp.appReadMarkers(try requireHandle()))
    }

    /// Помечает чат прочитанным и возвращает все отметки из ядра.
    /// Отметки живут в зашифрованном хранилище ядра, а не в контейнере
    /// приложения: контейнер удаляется при переустановке, и прочитанное снова
    /// выглядело бы непрочитанным.
    @discardableResult
    func markChatRead(peer: String) throws -> [String: UInt64] {
        let handle = try requireHandle()
        return try peer.withCString { ptr in
            try decode(FFIMinApp.appMarkChatRead(handle, ptr))
        }
    }

    /// Заявки + состояние тумблера. Текста заявки здесь нет by design.
    func requests() throws -> MinRequests {
        try decode(FFIMinApp.appRequests(try requireHandle()))
    }

    /// Принять заявку: открывается чат, текст заявки становится сообщением.
    @discardableResult
    func acceptRequest(_ id: String) throws -> MinContact {
        let handle = try requireHandle()
        return try id.withCString { try decode(FFIMinApp.appAcceptRequest(handle, $0)) }
    }

    func rejectRequest(_ id: String) throws {
        let handle = try requireHandle()
        _ = try decodeString(id.withCString { FFIMinApp.appRejectRequest(handle, $0) })
    }

    func blockRequest(_ id: String) throws {
        let handle = try requireHandle()
        _ = try decodeString(id.withCString { FFIMinApp.appBlockRequest(handle, $0) })
    }

    /// Тумблер «кто может мне писать». По умолчанию включён.
    func setDiscoverable(_ allowed: Bool) throws {
        _ = try decodeString(FFIMinApp.appSetDiscoverable(try requireHandle(), allowed))
    }
}
