import Foundation

protocol CryptoServiceProtocol {
    func generateIdentity() async throws -> String
    func encrypt(plaintext: Data, toPublicKey: String) async throws -> Data
    func decrypt(ciphertext: Data) async throws -> Data
}

// Изолированный мок
final class CryptoServiceMock: CryptoServiceProtocol {
    func generateIdentity() async throws -> String { "~local_mock_\(Int.random(in: 1000...9999))" }
    func encrypt(plaintext: Data, toPublicKey: String) async throws -> Data { plaintext }
    func decrypt(ciphertext: Data) async throws -> Data { ciphertext }
}
