import SwiftUI
import CryptoKit

/// Центральное состояние приложения. Данные — из Rust-ядра (`MinApp`);
/// моков больше нет. Все вызовы ядра сериализуются через `dataQueue`:
/// FFI блокирующий и не потокобезопасен снаружи.
final class AppState: ObservableObject {
    @Published var chats: [Chat] = []
    @Published var user: User = .init(publicKey: "")
    /// Ядро открыто и mailbox зарегистрирован на relay.
    @Published var isCoreReady = false
    /// Последняя ошибка/статус ядра (для отладки MVP).
    @Published var coreStatus = ""
    /// peer (identity hex), чат с которым нужно открыть после добавления.
    @Published var pendingOpenPeer: String?

    /// peer → стабильный UUID чата (переживает перезагрузку списка).
    private var chatIDs: [String: UUID] = [:]
    /// peer → дата последнего открытия чата. Локальный счётчик
    /// непрочитанных: сетевых read-receipts нет намеренно (MIN-RED-018),
    /// это знание живёт только на устройстве.
    private var lastReadAt: [String: Date] = [:]
    /// Отвечало ли ядро про отметки. До его ответа отсутствие отметки — это
    /// неизвестность, а не «не прочитано» (см. `unreadCountLocked`).
    private var readMarkersFromCore = false
    /// peer → исходный invite этого контакта. Нужен для ПЕРВОГО сообщения:
    /// сессии ещё нет, ядро требует invite. После перезапуска восстанавливается
    /// из офлайн-снимка, иначе «написать незнакомцу» ломалось бы до добавления.
    private var peerInvites: [String: String] = [:]
    private let dataQueue = DispatchQueue(label: "min.app.data", qos: .userInitiated)
    /// Только dataQueue: защита от параллельных/повторных bootstrap.
    private var bootstrapStarted = false

    var sortedChats: [Chat] {
        chats.sorted { a, b in
            let aUnread = (a.unreadCount > 0)
            let bUnread = (b.unreadCount > 0)
            if aUnread != bUnread { return aUnread && !bUnread }
            let aDate = a.messages.last?.date ?? .distantPast
            let bDate = b.messages.last?.date ?? .distantPast
            return aDate > bDate
        }
    }

    func index(for chat: Chat) -> Int? { chats.firstIndex(where: { $0.id == chat.id }) }

    func unreadExcluding(chatID: UUID) -> Int {
        chats.filter { $0.id != chatID }.map(\.unreadCount).reduce(0,+)
    }

    // MARK: - Bootstrap

    /// Открывает ядро, регистрирует mailbox и публикует мой инвайт.
    /// FFI блокирующий (Tor bootstrap при первом запуске) — работает в фоне.
    func bootstrapCore() {
        dataQueue.async { [weak self] in
            guard let self = self, !self.bootstrapStarted, !self.isCoreReady else { return }
            self.bootstrapStarted = true
            do {
                // Транспорт socks=onion: сперва поднимаем Tor (C Tor + мосты
                // IPtProxy) и ждём bootstrap — иначе ядру некуда подключаться.
                if MinApp.linkKind == "socks" {
                    DispatchQueue.main.async {
                        self.coreStatus = "Connecting via Tor…"
                    }
                    NSLog("MIN bootstrap: starting Tor")
                    TorService.shared.start()
                    if let torError = TorService.shared.waitUntilReady() {
                        DispatchQueue.main.async { self.coreStatus = "Tor: \(torError)" }
                        self.bootstrapStarted = false
                        return
                    }
                    NSLog("MIN bootstrap: Tor ready")
                }
                NSLog("MIN bootstrap: opening core (relay=\(MinApp.relayAddress), link=\(MinApp.linkKind))")
                _ = try MinApp.shared.open()
                NSLog("MIN bootstrap: core opened")
                try MinApp.shared.register()
                NSLog("MIN bootstrap: mailbox registered")
                let invite = try MinApp.shared.invite()
                NSLog("MIN bootstrap: invite built (\(invite.count) chars)")
                // MIN-RED-008: invite — долговременные публичные ключи (identity,
                // signed prekey, kyber prekey). Публикация в unified log и в
                // Application Support означала: содержимое syslog (читается
                // сторонними инструментами/крашами, переживает перезапуск) и
                // файл, который по умолчанию УХОДИТ В iCLOUD BACKUP.
                // Поэтому наружу (лог/файл) invite попадает только в DEBUG и
                // только когда явно задан E2E-харнесс; в обычном запуске он
                // живёт лишь в памяти и отдаётся UI через `user.publicKey`.
                let wantsDebugInvite = ProcessInfo.processInfo
                    .arguments
                    .contains { $0.hasPrefix("-e2e") }
                #if DEBUG
                    if wantsDebugInvite {
                        // NSLog режет длинные события — дублируем в файл,
                        // иначе харнесс не прочитает полный invite.
                        NSLog("MIN invite: \(invite)")
                        let inviteFile = FileManager.default
                            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                            .appendingPathComponent("min", isDirectory: true)
                            .appendingPathComponent("invite-debug.txt")
                        let parent = inviteFile.deletingLastPathComponent()
                        try? FileManager.default.createDirectory(
                            at: parent, withIntermediateDirectories: true,
                            attributes: nil)
                        try? invite.write(to: inviteFile, atomically: true, encoding: .utf8)
                        // Явно исключаем из бэкапа даже в debug: файл содержит
                        // долговременные публичные ключи устройства.
                        var resourceValues = URLResourceValues()
                        resourceValues.isExcludedFromBackup = true
                        var mutable = inviteFile
                        try? mutable.setResourceValues(resourceValues)
                    }
                #else
                    _ = wantsDebugInvite
                #endif
                DispatchQueue.main.async { [weak self] in
                    guard let self = self else { return }
                    self.user = User(publicKey: invite)
                    self.isCoreReady = true
                    // MIN-RED-019: страховочный блоб оказался нечитаемым, и ядро
                    // создало новый аккаунт. Без этой строки пользователь увидел
                    // бы просто пустой чат и решил, что переписка исчезла сама.
                    self.coreStatus = MinApp.shared.recoveryDiscarded
                        ? "New account: previous data could not be restored"
                        : ""
                    self.reloadChats()
                    // Debug-флаги E2E на симуляторах (-e2eAddContact/-e2eSend).
                    self.runE2EDebugArgsIfNeeded()
                    // Холодный старт: didBecomeActive уже прошёл (ядро ещё не
                    // было ready) — без этого pull не случится до следующего
                    // сворачивания. Очередь dataQueue: addContact успеет раньше.
                    self.pollAndReload()
                }
            } catch {
                NSLog("MIN bootstrap failed: \(error)")
                DispatchQueue.main.async { [weak self] in
                    self?.coreStatus = String(describing: error)
                }
                // Сеть могла мигнуть — разрешаем повторную попытку
                // (следующий applicationDidBecomeActive вызовет bootstrap снова).
                self.bootstrapStarted = false
            }
        }
    }

    /// Быстрый pull очереди с relay + перезагрузка списка чатов.
    /// Зовётся при активации приложения, открытии чата и после отправки.
    func pollAndReload() {
        dataQueue.async { [weak self] in
            guard let self = self, self.isCoreReady else { return }
            // Повтор отправок ПЕРЕД опросом: если Tor только что поднялся,
            // сначала уйдёт давно застрявшее сообщение, а не новый pull.
            self.retryPendingSends()
            do { _ = try MinApp.shared.poll() } catch { /* сеть может мигать */ }
            self.reloadChats()
        }
    }

    // MARK: - Повтор отправки после сетевого отказа

    /// Сообщение, которое не ушло и ждёт повтора. Живёт только в памяти и
    /// только на dataQueue.
    private struct PendingSend {
        let peer: String
        let text: String
        let reply: MinReplyRef?
        let invite: String?
        let optimisticID: UUID
        var attempt: Int
        var nextTryAt: Date
    }

    private var pendingSends: [PendingSend] = []

    /// Тикер повторов. Живёт ТОЛЬКО пока очередь не пуста: постоянный таймер в
    /// мессенджере означает лишний расход батареи, а нужен он только пока
    /// висит неотправленное сообщение. В фоне приложение suspension'ится iOS,
    /// и таймер просто не стреляет — при возврате продолжит.
    private var retryTimer: DispatchSourceTimer?

    private func startRetryTimerIfNeeded() {
        guard pendingSends.isEmpty == false, retryTimer == nil else { return }
        let timer = DispatchSource.makeTimerSource(queue: dataQueue)
        timer.schedule(deadline: .now() + 5, repeating: 5)
        timer.setEventHandler { [weak self] in
            self?.retryPendingSends()
        }
        retryTimer = timer
        timer.resume()
    }

    private func stopRetryTimerIfDone() {
        guard pendingSends.isEmpty else { return }
        retryTimer?.cancel()
        retryTimer = nil
    }

    /// Паузы между попытками. Суммарно около 10 минут — Tor на телефоне
    /// поднимается минутами, дальше повторять бессмысленно: человек увидит
    /// ошибку и нажмёт сам.
    private static let retryBackoff: [TimeInterval] =
        [5, 10, 20, 40, 60, 120, 120, 120, 120, 120]

    /// Ставит сообщение в очередь повтора.
    ///
    /// Повтор безопасен ТОЛЬКО при «not sent»: слой доставки сообщает, что из
    /// устройства ничего не ушло, значит дубля не будет. На любой другой ошибке
    /// повтор молча не делаем — там результат отправки неизвестен, и повтор
    /// мог бы отправить сообщение дважды.
    private func enqueueRetry(
        peer: String, text: String, reply: MinReplyRef?, invite: String?,
        optimisticID: UUID, error: Error
    ) {
        guard Self.isNothingSent(error) else {
            markFailed(peer: peer, optimisticID: optimisticID,
                       status: Self.sendFailureMessage(error))
            return
        }
        // Не плодим дубли: ручной повтор того же пузыря перезаписывает запись.
        pendingSends.removeAll { $0.optimisticID == optimisticID }
        let backoff = Self.retryBackoff.first ?? 5
        pendingSends.append(PendingSend(peer: peer, text: text, reply: reply,
                                        invite: invite, optimisticID: optimisticID,
                                        attempt: 1,
                                        nextTryAt: Date().addingTimeInterval(backoff)))
        markPending(peer: peer, optimisticID: optimisticID,
                    status: "Сообщение в очереди: Tor ещё подключается, отправим автоматически")
        startRetryTimerIfNeeded()
    }

    /// Одна попытка для всех, кому пора. Вызывается с dataQueue.
    private func retryPendingSends() {
        guard !pendingSends.isEmpty else { return }
        let now = Date()
        var retrying: [PendingSend] = []
        for item in pendingSends where item.nextTryAt <= now {
            do {
                _ = try MinApp.shared.sendMessage(peer: item.peer, text: item.text,
                                                  reply: item.reply, invite: item.invite)
                markSent(peer: item.peer, optimisticID: item.optimisticID)
            } catch {
                if Self.isNothingSent(error), item.attempt < Self.retryBackoff.count {
                    var next = item
                    next.attempt += 1
                    let pause = Self.retryBackoff[min(item.attempt, Self.retryBackoff.count - 1)]
                    next.nextTryAt = now.addingTimeInterval(pause)
                    retrying.append(next)
                } else {
                    markFailed(peer: item.peer, optimisticID: item.optimisticID,
                               status: Self.sendFailureMessage(error))
                }
            }
        }
        // Не запускавшиеся в этот раз остаются ждать своей паузы; ушедшие
        // успешно и признанные безнадёжными из списка исчезают.
        pendingSends = pendingSends.filter { $0.nextTryAt > now } + retrying
        stopRetryTimerIfDone()
        NSLog("MIN: повтор отправки, в очереди осталось %d", pendingSends.count)
    }

    private func markSent(peer: String, optimisticID: UUID) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            if let i = self.chats.firstIndex(where: { $0.cryptoID == peer }),
               let j = self.chats[i].messages.firstIndex(where: { $0.id == optimisticID }) {
                self.chats[i].messages[j].localStatus = .sent
            }
        }
    }

    private func markPending(peer: String, optimisticID: UUID, status: String) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            if let i = self.chats.firstIndex(where: { $0.cryptoID == peer }),
               let j = self.chats[i].messages.firstIndex(where: { $0.id == optimisticID }) {
                // `pending` честнее `failed`: сообщение не потеряно, оно ждёт
                // сети, и цвет ошибки пугает людей без причины.
                self.chats[i].messages[j].localStatus = .pending
            }
            if !status.isEmpty { self.coreStatus = status }
        }
    }

    private func markFailed(peer: String, optimisticID: UUID, status: String) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            if let i = self.chats.firstIndex(where: { $0.cryptoID == peer }),
               let j = self.chats[i].messages.firstIndex(where: { $0.id == optimisticID }) {
                self.chats[i].messages[j].localStatus = .failed
            }
            self.coreStatus = status
        }
    }

    /// Форсирует немедленное обновление (pull-to-refresh чат-листа).
    ///
    /// Отдельный метод, а не `pollAndReload`, потому что UI ждёт завершения
    /// (спиннер крутится, пока идёт) — здесь ждём реального pull.
    func refreshNow() async {
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            dataQueue.async { [weak self] in
                guard let self = self, self.isCoreReady else {
                    DispatchQueue.main.async { cont.resume() }
                    return
                }
                do { _ = try MinApp.shared.poll() } catch { /* сеть может мигать */ }
                self.reloadChats { cont.resume() }
            }
        }
    }

    /// Живой приёмочный прогон «написать незнакомцу по его invite»:
    /// `-smokePeerInvite <путь-к-файлу>` + `-smokePeerText <текст>`.
    ///
    /// Только для стенда: путь/текст приходят аргументами запуска, поэтому
    /// в релизной сборке флаги игнорируются (ветка под #if DEBUG). Нужен,
    /// чтобы проверить настоящий путь simulator → Tor → relay → телефон
    /// владельца, а не только E2E-тесты в одном процессе.
    func runDebugPeerSmokeIfRequested() {
        #if DEBUG
        let args = ProcessInfo.processInfo.arguments
        guard let i = args.firstIndex(of: "-smokePeerInvite"), i + 1 < args.count else { return }
        let path = args[i + 1]
        let text: String
        if let t = args.firstIndex(of: "-smokePeerText"), t + 1 < args.count {
            text = args[t + 1]
        } else {
            text = "MIN: проверка связи с живого устройства"
        }
        guard let raw = try? String(contentsOfFile: path, encoding: .utf8) else {
            NSLog("MIN smoke: не читается invite-файл \(path)")
            return
        }
        // Ждём готовности ядра: Tor-bootstrap занимает десятки секунд и время
        // от запуска не предсказуемо, поэтому опрашиваем флаг, а не спим 90 с.
        func waitAndSend(_ left: Int) {
            guard left > 0 else {
                NSLog("MIN smoke: ядро не поднялось за отведённое время — пропуск")
                return
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + 10) { [weak self] in
                guard let self else { return }
                guard self.isCoreReady else { return waitAndSend(left - 1) }
                self.dataQueue.async {
                do {
                    let contact = try MinApp.shared.addContact(name: "", invite: raw.trimmingCharacters(in: .whitespacesAndNewlines))
                    self.peerInvites[contact.identityHex] = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                    NSLog("MIN smoke: контакт \(contact.identityHex.prefix(8)) добавлен, шлю")
                    _ = try MinApp.shared.sendTextToInvite(
                        invite: raw.trimmingCharacters(in: .whitespacesAndNewlines),
                        text: text)
                    NSLog("MIN smoke: ОТПРАВЛЕНО → \(contact.identityHex.prefix(8)): \(text)")
                } catch {
                    NSLog("MIN smoke: ОШИБКА отправки: \(error)")
                }
                }
            }
        }
        waitAndSend(60) // до ~10 минут ожидания Tor-bootstrap
        #endif
    }

    /// Перезагружает чаты из ядра и мержит их в опубликованное состояние.
    /// Первое сообщение к незнакомцу идёт через его invite, а последующие —
    func reloadChats() { reloadChats(completion: nil) }

    private func reloadChats(completion: (() -> Void)?) {
        dataQueue.async { [weak self] in
            guard let self = self else { return }
            do {
                // Отметки «прочитано» берём ЗДЕСЬ, а не при старте приложения:
                // в момент старта ядро ещё не готово (Tor-подъём занимает
                // минуты), и прежний вызов молча ничего не делал — отметки не
                // загружались вообще, поэтому после перезахода всё снова
                // выглядело непрочитанным. Здесь ядро уже готово, и это
                // единственное место, где считается непрочитанное.
                if let markers = try? MinApp.shared.readMarkers() {
                    self.readMarkersFromCore = true
                    for (peer, ts) in markers {
                        let fromCore = Date(timeIntervalSince1970: TimeInterval(ts))
                        // Более новую локальную отметку НЕ затираем: запись в
                        // ядро асинхронна, и опрос мог пересчитать список раньше,
                        // чем маркер доехал — из-за этого бейдж «воскресал» сразу
                        // после прочтения. Ядро источник истины, но не источник
                        // регрессий: максимум из двух.
                        if let local = self.lastReadAt[peer], local >= fromCore { continue }
                        self.lastReadAt[peer] = fromCore
                    }
                }
                let minChats = try MinApp.shared.chats()
                let contacts = try MinApp.shared.contacts()
                var names: [String: String] = [:]
                for c in contacts { names[c.identityHex] = c.name }
                var mapped: [Chat] = []
                for mc in minChats {
                    let peer = mc.peer
                    let raw = (try? MinApp.shared.messages(peer: peer)) ?? []
                    var messages: [Message] = []
                    for m in raw {
                        messages.append(Message(
                            sender: m.outgoing ? .me : .other,
                            text: m.text,
                            date: Date(timeIntervalSince1970: TimeInterval(m.sentAt)),
                            localStatus: m.outgoing ? .sent : .received,
                            replyPreview: m.reply?.preview,
                            replyAuthor: m.reply?.author
                        ))
                    }
                    var chat = Chat(id: self.chatID(for: peer),
                                    cryptoID: peer,
                                    displayName: self.displayName(peer: peer, stored: names[peer]),
                                    avatarColorHex: self.avatarColorHex(peer: peer),
                                    messages: messages)
                    if let last = messages.last {
                        chat.lastTimeText = DateFormatters.hhmm.string(from: last.date)
                    }
                    // Локальный счётчик непрочитанных (чисто на устройстве).
                    // Считаем входящие новее отметки последнего открытия чата:
                    // раньше здесь жёстко ставился .unread(count: 0), поэтому
                    // бейдж не появлялся вовсе (в моках работал из addMessage).
                    let unread = self.unreadCountLocked(peer: peer, messages: messages)
                    chat.unreadCount = unread
                    chat.lastStatus = unread > 0 ? .unread(count: unread) : .readIncoming
                    mapped.append(chat)
                }
                // Снимок lastReadAt делаем на dataQueue: отметки живут там, и
                // читать их с main — гонка. В снимок идёт ТОЛЬКО время отметки.
                let readMarks = self.lastReadAt
                DispatchQueue.main.async { [weak self] in
                    self?.merge(mapped)
                    // Снимок на диск — в фоне, чтобы не блокировать отрисовку.
                    let snap = mapped.map { c in
                        ChatCache.SnapChat(peer: c.cryptoID,
                                           displayName: c.displayName,
                                           avatarColorHex: c.avatarColorHex,
                                           messages: c.messages.map {
                            ChatCache.SnapMessage(outgoing: $0.sender == .me,
                                                  text: $0.text,
                                                  sentAt: $0.date.timeIntervalSince1970,
                                                  replyAuthor: $0.replyAuthor,
                                                  replyPreview: $0.replyPreview)
                           },
                                           invite: self?.peerInvites[c.cryptoID],
                                           readAt: readMarks[c.cryptoID]?.timeIntervalSince1970)
                    }
                    self?.dataQueue.async { ChatCacheStore.save(snap) }
                    completion?()
                }
            } catch {
                DispatchQueue.main.async { [weak self] in
                    self?.coreStatus = String(describing: error)
                }
            }
        }
    }

    /// Нормализация вставленного инвайта.
    ///
    /// ЖИВОЙ БАГ (2026-09-26, root cause): поле ввода — `UITextField`, он
    /// ОДНОСТРОЧНЫЙ. При вставке инвайта вида `MIN3:…\nBND:…` перенос строки
    /// не выживал, строка `BND:` терялась, и ядро отвечало «invite missing BND
    /// line» — то есть вставить корректный инвайт было невозможно.
    ///
    /// Здесь не трогаем UI: восстанавливаем канонический двухстрочный вид
    /// перед отправкой в ядро. Принимаем и перенос строки, и пробел/табуляцию,
    /// и слитный `…MIN3:abcBND:def…` — вставляем перенос перед `BND:`.
    static func normalizeInvite(_ raw: String) -> String {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        // Уже корректный двухстрочный вид — не трогаем содержимое.
        if text.contains("\n") { return text }
        guard let range = text.range(of: "BND:") else { return text }
        let head = text[text.startIndex..<range.lowerBound].trimmingCharacters(in: .whitespaces)
        let tail = text[range.lowerBound...].trimmingCharacters(in: .whitespaces)
        return head + "\n" + tail
    }

    /// Быстрая проверка формата инвайта — до входа в `dataQueue`.
    ///
    /// ЖИВОЙ БАГ (2026-09-26): `addContact` вставал в сериальную очередь, где
    /// каждые ~20 с висит БЛОКИРУЮЩИЙ сетевой `poll`. Ошибка формата
    /// формировалась мгновенно, но пользователь ждал конца сетевого вызова.
    ///
    /// Здесь только дешёвый отсев очевидного мусора (не наш формат, нет BND).
    /// Авторитетная криптографическая проверка подписи Contact Key остаётся
    /// в ядре (`add_contact_by_invite`): этот метод ничего не «одобряет»,
    /// он лишь не отправляет заведомо невалидный ввод в сеть.
    static func validateInviteFormat(_ invite: String) -> String? {
        let lines = normalizeInvite(invite)
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }

        guard let keyLine = lines.first else {
            return "invite is empty"
        }
        guard keyLine.hasPrefix("MIN3:") else {
            return "not a MIN invite: expected \"MIN3:…\" (got \(keyLine.prefix(12))…)"
        }
        guard keyLine.count > 8 else {
            return "Contact Key looks truncated"
        }
        guard lines.contains(where: { $0.hasPrefix("BND:") && $0.count > 8 }) else {
            return "invite missing BND line — copy the whole invite (2 lines)"
        }
        return nil
    }

    /// Добавляет контакт по инвайту (Contact Key + bundle). MVP: авто-accept.
    func addContact(invite rawInvite: String, completion: @escaping (Bool) -> Void) {
        // Нормализация ДО очереди: однострочный UITextField теряет перенос
        // строки, из-за чего терялась вся строка BND (root cause, см. выше).
        let invite = Self.normalizeInvite(rawInvite)
        // Отсев мусора — синхронно, до очереди и до сети (см. комментарий выше).
        if let formatError = Self.validateInviteFormat(invite) {
            DispatchQueue.main.async {
                self.coreStatus = formatError
                completion(false)
            }
            return
        }
        dataQueue.async { [weak self] in
            guard let self = self else { return }
            do {
                // Имя генерирует ядро из identity («User-XXXXXX»): «Contact»
                // делал все контакты одинаковыми и ломал find_contact.
                let contact = try MinApp.shared.addContact(name: "", invite: invite)
                // Храним исходный invite: без него первое сообщение к незнакомцу
                // невозможно (нет сессии), а знать его больше неоткуда — ядро
                // публичный ключ наружу не отдаёт.
                self.peerInvites[contact.identityHex] = invite
                _ = self.chatID(for: contact.identityHex)
                DispatchQueue.main.async {
                    self.pendingOpenPeer = contact.identityHex
                    completion(true)
                }
                self.reloadChats()
            } catch {
                DispatchQueue.main.async {
                    self.coreStatus = String(describing: error)
                    completion(false)
                }
            }
        }
    }

    /// Реальная отправка на ядро (фон) + poll и обновление списка.
    /// `optimisticID` удаляется только после подтверждённого enqueue; при ошибке
    /// тот же пузырь остаётся в UI со статусом `.failed`, а не исчезает.
    /// Ответ на сообщение. `reply` — цитата (автор + превью): она уходит в
    /// ядро, поэтому её видят обе стороны и она переживает перезапуск.
    func sendOnCore(peer: String, text: String, optimisticID: UUID,
                    reply: MinReplyRef? = nil) {
        dataQueue.async { [weak self] in
            guard let self = self else { return }
            do {
                // Один вызов на всё: ядро выбирает путь по наличию сессии и несёт
                // цитату в обоих путях. Раньше здесь сначала звался обычный
                // `sendText` даже с цитатой, и при живой сессии он проходил
                // успешно — цитата просто терялась, а получатель видел «просто
                // текст» (владелец, ответ на своё сообщение).
                // Fallback-на-любую-ошибку тоже убран: сетевой сбой после
                // принятия relay приводил к повторному `Enqueue` — дублю.
                _ = try MinApp.shared.sendMessage(peer: peer, text: text,
                                                  reply: reply,
                                                  invite: self.peerInvites[peer])
                DispatchQueue.main.async { [weak self] in
                    guard let self else { return }
                    // Оптимистичную пилюлю НЕ удаляем: иначе между этим
                    // моментом и reloadChats() список пустеет и пузырь
                    // «моргает» (исчезает и появляется). Вместо этого
                    // подтверждаем статус; следом poll + reloadChats() заменят
                    // список реальными данными ядра одной атомарной
                    // публикацией — дубликата не будет видно.
                    if let i = self.chats.firstIndex(where: { $0.cryptoID == peer }),
                       let j = self.chats[i].messages.firstIndex(where: { $0.id == optimisticID }) {
                        self.chats[i].messages[j].localStatus = .sent
                    }
                }
                do { _ = try MinApp.shared.poll() } catch { /* сеть мигнула */ }
                self.reloadChats()
            } catch {
                // Не ушло и сетевой отказ — ждём автоматический повтор вместо
                // требования перезайти в приложение. Ошибка, при которой
                // отправка могла частично пройти, в очередь не попадает.
                self.enqueueRetry(peer: peer, text: text, reply: reply,
                                  invite: self.peerInvites[peer],
                                  optimisticID: optimisticID, error: error)
                // Технический текст — в лог, но НЕ в интерфейс: «ffiFailed
                // (delivery: connect failed (not sent) … os error 61)» ничего
                // не объясняет человеку и выглядит как авария. Содержимого
                // сообщения в ошибке нет.
                NSLog("MIN send failed: %@", String(describing: error))
            }
        }
    }

    /// Что показать пользователю при неудачной отправке.
    ///
    /// Метка `(not sent)` от слоя доставки — важная: она означает, что из
    /// устройства НИЧЕГО не ушло, сообщение не потеряно, повтор безопасен.
    /// Обычно это «Tor ещё не подключился» — самый частый случай, когда жмут
    /// отправить во время подъёма сети.
    static func sendFailureMessage(_ error: Error) -> String {
        isNothingSent(error)
            ? "Сеть ещё не готова (Tor не подключился) — сообщение не отправлено, можно повторить"
            : "Отправка не удалась"
    }

    /// Отправилось ли что-нибудь из устройства. Слой доставки помечает ошибку
    /// как «not sent», когда байты НЕ ушли в сеть: только в этом случае
    /// повтор безопасен. На остальных ошибках результат неизвестен, и повтор
    /// рисковал бы продублировать сообщение.
    ///
    /// Не `private`: на этом условии держится гарантия «не пришлёт дважды»,
    /// значит оно обязано проверяться тестом (см. MINTests).
    static func isNothingSent(_ error: Error) -> Bool {
        let raw = String(describing: error).lowercased()
        return raw.contains("not sent") || raw.contains("connect failed")
            || raw.contains("connection refused") || raw.contains("timed out")
            || raw.contains("os error 61") || raw.contains("os error 51")
    }

    // MARK: - Внутреннее

    /// E2E-харнесс для симуляторов (debug-флаги запуска, НЕ прода):
    ///   -e2eAddContact <invite>  — добавить контакт после bootstrap;
    ///   -e2eSend <text>          — отправить текст первому контакту.
    /// Вызывается на main после успешного bootstrap (см. bootstrapCore).
    func runE2EDebugArgsIfNeeded() {
        let args = ProcessInfo.processInfo.arguments
        let inviteIdx = args.firstIndex(of: "-e2eAddContact")

        if let i = inviteIdx, i + 1 < args.count {
            let invite = args[i + 1]
            NSLog("E2E: adding contact…")
            addContact(invite: invite) { [weak self] ok in
                guard let self = self else { return }
                NSLog("E2E: addContact ok=\(ok) status=\(self.coreStatus)")
                self.e2eSendIfRequested(args)
            }
        } else {
            e2eSendIfRequested(args)
        }
    }

    private func e2eSendIfRequested(_ args: [String]) {
        guard let i = args.firstIndex(of: "-e2eSend"), i + 1 < args.count else { return }
        let text = args[i + 1]
        dataQueue.async { [weak self] in
            guard let self = self else { return }
            do {
                let contacts = try MinApp.shared.contacts()
                // Последний добавленный, а не первый в списке: иначе прогон
                // уходил в старый контакт и падал с «mailbox не зарегистрирован».
                guard let peer = contacts.last?.identityHex else {
                    NSLog("E2E: no contacts to send to")
                    return
                }
                NSLog("E2E: sending to \(peer.prefix(12))…")
                _ = try MinApp.shared.sendText(peer: peer, text: text)
                _ = try? MinApp.shared.poll()
                self.reloadChats()
                NSLog("E2E: send OK")
            } catch {
                NSLog("E2E: send failed: \(error)")
            }
        }
    }

    // MARK: - Офлайн-снимок

    /// Показывает переписку из снимка ДО Tor-bootstrap: ядро поднимается
    /// десятки секунд, а человек не должен в это время смотреть в пустой
    /// список. Данные из кэша — только для чтения; как только `reloadChats`
    /// отдаст свежее из ядра, снимок перезаписывается.
    func loadCachedChats() {
        guard chats.isEmpty else { return }
        let snap = ChatCacheStore.load()
        guard !snap.isEmpty else { return }
        // Отметки — до Tor, из снимка: иначе список минуты показывал бейджи на
        // всём прочитанном, пока не поднималась сеть. Ядро их перезапишет своим
        // (более новым) значением, когда будет готово.
        primeReadMarkersFromCache(snap)
        for c in snap {
            if let inv = c.invite { peerInvites[c.peer] = inv }
        }
        let restored: [Chat] = snap.map { c in
            var chat = Chat(id: chatID(for: c.peer),
                            cryptoID: c.peer,
                            displayName: c.displayName,
                            avatarColorHex: c.avatarColorHex,
                            messages: c.messages.map {
                                Message(sender: $0.outgoing ? .me : .other,
                                        text: $0.text,
                                        date: Date(timeIntervalSince1970: $0.sentAt),
                                        localStatus: $0.outgoing ? .sent : .received,
                                        replyPreview: $0.replyPreview,
                                        replyAuthor: $0.replyAuthor)
                            })
            if let last = chat.messages.last {
                chat.lastTimeText = DateFormatters.hhmm.string(from: last.date)
                chat.unreadCount = unreadCountLocked(peer: c.peer, messages: chat.messages)
                chat.lastStatus = chat.unreadCount > 0 ? .unread(count: chat.unreadCount) : .readIncoming
            }
            return chat
        }
        NSLog("MIN cache: restored \(restored.count) chats from disk")
        chats = restored.sorted { $0.lastTimeText > $1.lastTimeText }
    }

    private func merge(_ fresh: [Chat]) {
        for f in fresh {
            if let i = chats.firstIndex(where: { $0.cryptoID == f.cryptoID }) {
                if chats[i] != f { chats[i] = f }
            } else {
                chats.append(f)
            }
        }
    }

    /// Помечает чат прочитанным (вызывается при открытии чата). Только
    /// локально: собеседник ничего не узнаёт о том, что ты открыл переписку.
    ///
    /// Отметка уходит в ЯДРО, а не в Swift-кэш. Кэш лежит в контейнере
    /// приложения, который удаляется при переустановке, — и прочитанное снова
    /// выглядело бы непрочитанным (именно так и вышло). Ядро — единственный
    /// источник истины, там же где сама переписка.
    func markChatRead(peer: String) {
        let now = Date()
        lastReadAt[peer] = now
        dataQueue.async { [weak self] in
            guard let self else { return }
            if self.isCoreReady {
                _ = try? MinApp.shared.markChatRead(peer: peer)
            }
            // Зеркало отметки в снимок. До подъёма Tor список рисуется из
            // кэша, и без этого бейдж висел минутами и исчезал только когда
            // сеть наконец поднималась — то есть «прочитанное» выглядело
            // непрочитанным всё это время. В снимок попадает ТОЛЬКО время
            // отметки: текст переписки не трогаем.
            var snap = ChatCacheStore.load()
            if let i = snap.firstIndex(where: { $0.peer == peer }) {
                snap[i] = snap[i].withReadAt(now.timeIntervalSince1970)
                ChatCacheStore.save(snap)
            }
        }
        if let i = chats.firstIndex(where: { $0.cryptoID == peer }) {
            chats[i].unreadCount = 0
            chats[i].lastStatus = .readIncoming
        }
    }

    /// Одноразовая миграция отметок «прочитано» из старого Swift-кэша в ядро.
    ///
    /// Источник истины теперь ядро, но у людей, обновлявшихся с прежней
    /// версии, отметки лежат в `chats-cache.json`. Без переноса первый запуск
    /// новой версии выглядел бы как «всё снова непрочитанное» — то есть
    /// обновление ломало бы привычное состояние. Переносим ОДИН раз и только
    /// отсутствующие в ядре ключи, поэтому свежие отметки старыми не затираются.
    ///
    /// Переносятся только timestamp'ы — ни текста, ни адресов, ни ключей.
    func migrateReadMarkersFromCache() {
        guard let cached = try? ChatCacheStore.loadReadMarksOnly() else { return }
        guard !cached.isEmpty else { return }
        dataQueue.async { [weak self] in
            guard let self, self.isCoreReady else { return }
            guard let existing = try? MinApp.shared.readMarkers() else { return }
            let missing = cached.filter { existing[$0.peer] == nil && $0.readAt > 0 }
            guard !missing.isEmpty else { return }
            for m in missing {
                _ = try? MinApp.shared.markChatRead(peer: m.peer, at: UInt64(m.readAt))
            }
            NSLog("MIN: отметок «прочитано» перенесено в ядро: \(missing.count)")
        }
    }

    /// Отметки «прочитано» из снимка — на время, пока ядро ещё не готово.
    /// Без них список, нарисованный из кэша, показывал бы бейджи на всём
    /// прочитанном: ядро с Tor поднимается минутами.
    func primeReadMarkersFromCache(_ snap: [ChatCache.SnapChat]? = nil) {
        let marks: [(peer: String, readAt: Double)]
        if let snap = snap {
            // Берём ТОЛЬКО отметку. Никаких догадок вида «снимок значит
            // прочитано»: сообщение, пришедшее при закрытом приложении, тоже
            // попадает в снимок — и такая догадка съедала его бейдж после
            // перезапуска (проверено владельцем на своём сообщении).
            //
            // Нет отметки — значит состояние прочтения НЕИЗВЕСТНО, а не
            // «не прочитано». Показывать бейдж по неизвестности значит врать
            // пользователю; ядро через минуты придёт с точным ответом.
            marks = snap.compactMap { c in c.readAt.map { (c.peer, $0) } }
        } else {
            marks = ChatCacheStore.loadReadMarksOnly()
        }
        for (peer, ts) in marks {
            let d = Date(timeIntervalSince1970: ts)
            if let local = lastReadAt[peer], local >= d { continue }
            lastReadAt[peer] = d
        }
    }

    /// Подтягивает отметки «прочитано» из ядра — источника истины. Вызывается
    /// после открытия ядра, до первой перезагрузки списка.
    func loadReadMarkers() {
        dataQueue.async { [weak self] in
            guard let self, self.isCoreReady else { return }
            guard let markers = try? MinApp.shared.readMarkers() else { return }
            self.readMarkersFromCore = true
            // Как и в reloadChats: более новую локальную отметку не затираем.
            for (peer, ts) in markers {
                let fromCore = Date(timeIntervalSince1970: TimeInterval(ts))
                if let local = self.lastReadAt[peer], local >= fromCore { continue }
                self.lastReadAt[peer] = fromCore
            }
        }
    }

    /// Сколько входящих пришло после последнего открытия чата. Вызывается
    /// только из dataQueue (снимок lastReadAt), поэтому гонок нет.
    private func unreadCountLocked(peer: String, messages: [Message]) -> Int {
        // Нет отметки «открыт» — значит чат не открывали ни разу, и ВСЕ входящие
        // непрочитанные. Раньше здесь стояло `guard ... else { return 0 }`, то
        // есть бейдж не появлялся именно у новых чатов — самых важных.
        guard let since = lastReadAt[peer] else {
            // Пока ядро не ответило, отсутствие отметки — это НЕИЗВЕСТНОСТЬ
            // («Connecting via tor…»), а не «не прочитано». Отвечать бейджем на
            // неизвестность — значит врать: так кружки висели до подключения и
            // пропадали после. Ядро ответило → отсутствие отметки уже факт.
            return readMarkersFromCore
                ? messages.filter { $0.sender == .other }.count
                : 0
        }
        return messages.filter { $0.sender == .other && $0.date > since }.count
    }

    private func chatID(for peer: String) -> UUID {
        if let id = chatIDs[peer] { return id }
        let id = UUID()
        chatIDs[peer] = id
        return id
    }

    private func displayName(peer: String, stored: String?) -> String {
        if let stored = stored, !stored.isEmpty, stored != "Contact" { return stored }
        return "User-" + String(peer.prefix(6))
    }

    private func avatarColorHex(peer: String) -> String {
        var hash = 0
        for b in peer.utf8 { hash = (hash &* 31 &+ Int(b)) & 0xFFFFFF }
        return String(format: "%06X", hash)
    }
}

/// Снимок списка чатов на диске: приложение показывает переписку сразу при
/// запуске, не дожидаясь Tor-bootstrap и первого poll.
///
/// Отдельные Codable-структуры, а не сами `Chat`/`Message`: модели — это UI,
/// снимок — это формат хранения, и его нельзя ломать правкой вёрстки.
struct ChatCache: Codable {
    struct SnapMessage: Codable {
        let outgoing: Bool
        let text: String
        let sentAt: Double
        /// Цитата ответа в офлайн-снимке: без неё после перезахода ответ
        /// выглядел бы обычным сообщением до первого ответа ядра.
        let replyAuthor: String?
        let replyPreview: String?
    }
    struct SnapChat: Codable {
        let peer: String
        let displayName: String
        let avatarColorHex: String
        let messages: [SnapMessage]
        /// Invite исходного контакта: без него после перезапуска нельзя
        /// отправить ПЕРВОЕ сообщение (сессии ещё нет). Старые снимки без поля
        /// декодируются как nil — обратная совместимость.
        let invite: String?
        /// Отметка «прочитано» на момент снимка. Без неё в памяти знание
        /// о прочтении живёт только до перезапуска приложения, и после
        /// перезахода ВСЕ входящие снова выглядят непрочитанными — бейдж
        /// «залипает», хотя человек всё прочитал.
        let readAt: Double?
        /// Копия снимка с новой отметкой «прочитано» (остальные поля — как есть).
        func withReadAt(_ ts: Double) -> SnapChat {
            SnapChat(peer: peer, displayName: displayName,
                     avatarColorHex: avatarColorHex, messages: messages,
                     invite: invite, readAt: ts)
        }
    }
    var chats: [SnapChat]
}

/// Хранилище снимка. Application Support + AES-GCM ключом из Keychain.
///
/// Шифрование обязательно: снимок содержит ТЕКСТ переписки, а основная БД
/// зашифрована row-level AEAD. Находка аудита: первая версия писала
/// `chats-cache.json` открытым текстом — то есть вся история лежала на диске
/// читаемой, минуя модель «история под AEAD» (MIN-RED-004/009).
enum ChatCacheStore {
    private static let fileURL: URL = {
        let dir = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("chats-cache.json")
    }()

    static func load() -> [ChatCache.SnapChat] {
        guard let sealed = try? Data(contentsOf: fileURL) else { return [] }
        guard let plain = unseal(sealed) else {
            // Ключ сменился или файл подделан — тихо начинаем с пустого кэша,
            // а не падаем: кэш только ускоряет отрисовку, источник истины —
            // ядро. Подделанный файл удаляем, чтобы не копить мусор.
            try? FileManager.default.removeItem(at: fileURL)
            return []
        }
        return (try? JSONDecoder().decode(ChatCache.self, from: plain))?.chats ?? []
    }

    /// Только отметки «прочитано» из снимка, без текста сообщений: миграции не
    /// нужно ничего лишнего, а лишнее в руках миграции — лишний риск.
    static func loadReadMarksOnly() -> [(peer: String, readAt: Double)] {
        guard let plain = try? Data(contentsOf: fileURL),
              let cache = try? JSONDecoder().decode(ChatCache.self, from: unseal(plain) ?? Data())
        else { return [] }
        return cache.chats.compactMap { c in
            c.readAt.map { (c.peer, $0) }
        }
    }

    static func save(_ chats: [ChatCache.SnapChat]) {
        guard let plain = try? JSONEncoder().encode(ChatCache(chats: chats)) else { return }
        guard let sealed = seal(plain) else { return }
        try? sealed.write(to: fileURL, options: [.atomic, .completeFileProtection])
    }

    /// Контекст шифрования: файл, переименованный в чат, не расшифруется.
    private static let aad = Data("MIN.chats-cache.v1".utf8)

    private static func seal(_ plain: Data) -> Data? {
        try? AES.GCM.seal(plain, using: SymmetricKey(data: KeychainService.shared.chatCacheKey()),
                          authenticating: aad).combined
    }

    private static func unseal(_ sealed: Data) -> Data? {
        try? AES.GCM.open(AES.GCM.SealedBox(combined: sealed),
                          using: SymmetricKey(data: KeychainService.shared.chatCacheKey()),
                          authenticating: aad)
    }
}

extension View {
    /// Pull-to-refresh на iOS 15 (где у `ScrollView` его ещё нет) и выше.
    /// MIN-RED: чат-лист обновлялся только по таймеру, поэтому на живом Tor
    /// входящее приходилось ждать до 30 с — теперь достаточно потянуть вниз.
    @ViewBuilder
    func pullToRefresh(_ action: @escaping () async -> Void) -> some View {
        if #available(iOS 16.0, *) {
            refreshable { await action() }
        } else {
            self
        }
    }
}


