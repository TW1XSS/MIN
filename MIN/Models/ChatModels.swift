import Foundation

enum Peer { case me, other }
/// Локальный статус доставки. Сетевых read-receipts нет намеренно:
/// «прочитано» — метаданные активности собеседника (MIN-RED-018).
enum LocalMessageStatus: String { case pending, sent, received, failed }
enum LastStatus: Equatable {
    case unread(count: Int)
    /// Просмотренные входящие. Значения «прочитано мной/прочитано им» в MVP
    /// не различаются: различение раскрывает активность собеседника.
    case readIncoming
}

struct Message: Identifiable, Equatable {
    let id: UUID
    let sender: Peer
    let text: String
    let date: Date
    var localStatus: LocalMessageStatus
    // краткий текст-тизер для превью ответа
    var replyPreview: String?
    var replyAuthor: String?

    init(id: UUID = UUID(),
         sender: Peer,
         text: String,
         date: Date,
         localStatus: LocalMessageStatus = .pending,
         replyPreview: String? = nil,
         replyAuthor: String? = nil) {
        self.id = id
        self.sender = sender
        self.text = text
        self.date = date
        self.localStatus = localStatus
        self.replyPreview = replyPreview
        self.replyAuthor = replyAuthor
    }

    static func ==(lhs: Message, rhs: Message) -> Bool {
        lhs.id == rhs.id
            && lhs.text == rhs.text
            && lhs.localStatus == rhs.localStatus
            && lhs.replyPreview == rhs.replyPreview
            && lhs.replyAuthor == rhs.replyAuthor
    }
}

struct Chat: Identifiable, Equatable {
    let id: UUID
    let cryptoID: String
    var displayName: String
    var avatarColorHex: String
    var messages: [Message]
    var unreadCount: Int
    var lastStatus: LastStatus
    var lastTimeText: String

    init(id: UUID = UUID(),
         cryptoID: String,
         displayName: String,
         avatarColorHex: String,
         messages: [Message],
         unreadCount: Int = 0,
         lastStatus: LastStatus = .readIncoming,
         lastTimeText: String = "") {
        self.id = id
        self.cryptoID = cryptoID
        self.displayName = displayName
        self.avatarColorHex = avatarColorHex
        self.messages = messages
        self.unreadCount = unreadCount
        self.lastStatus = lastStatus
        self.lastTimeText = lastTimeText
    }

    // Сетевых read-receipts в MVP нет намеренно: «прочитано» — метаданные
    // активности собеседника (MIN-RED-018). Ни локального флага, ни его
    // имитации в модели не держим.

    // Real preview for the chat list ("You: ..." prefix for own messages).
    var lastMessagePreview: String? {
        guard let m = messages.last else { return nil }
        return m.sender == .me ? "You: \(m.text)" : m.text
    }

    mutating func markIncomingAsRead() {
        // Локальный счётчик непрочитанного: сетевого «прочитано» нет.
    }

    // Content-based equality so SwiftUI re-renders rows when messages change
    // (id-only comparison made the chat list show a stale last message).
    static func ==(lhs: Chat, rhs: Chat) -> Bool {
        lhs.id == rhs.id
            && lhs.displayName == rhs.displayName
            && lhs.messages.count == rhs.messages.count
            && lhs.messages.last == rhs.messages.last
            && lhs.unreadCount == rhs.unreadCount
            && lhs.lastStatus == rhs.lastStatus
            && lhs.lastTimeText == rhs.lastTimeText
    }

    mutating func addMessage(_ m: Message) {
        messages.append(m)
        lastTimeText = DateFormatters.hhmm.string(from: m.date)
        if m.sender == .other {
            unreadCount += 1
            lastStatus = .unread(count: unreadCount)
        }
        // Исходящим ставим .unread(count: 0): отдельного «прочитано» нет.
    }
}
