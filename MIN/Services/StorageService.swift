import Foundation

protocol StorageServiceProtocol {
    func saveMessage(_ message: Message, in chatID: UUID) throws
    func loadMessages(for chatID: UUID) throws -> [Message]
}

final class StorageServiceMock: StorageServiceProtocol {
    private var store: [UUID: [Message]] = [:]
    func saveMessage(_ message: Message, in chatID: UUID) throws { store[chatID, default: []].append(message) }
    func loadMessages(for chatID: UUID) throws -> [Message] { store[chatID] ?? [] }
}
