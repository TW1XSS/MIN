import Foundation

private func makeDate(year: Int, month: Int, day: Int, hour: Int, minute: Int) -> Date {
    var c = Calendar.current
    c.timeZone = .current
    var dc = DateComponents()
    dc.year = year; dc.month = month; dc.day = day; dc.hour = hour; dc.minute = minute
    return c.date(from: dc) ?? Date()
}

enum SampleData {
    static let chats: [Chat] = [
        Chat(
            cryptoID: "~mock_5678",
            displayName: "Wizard",
            avatarColorHex: "#FF5733",
            messages: [
                Message(sender: .other,
                        text: "Dude, as they say: trust the minimum, fear maximum.",
                        date: Date().addingTimeInterval(-3600),
                        localStatus: .received)
            ],
            unreadCount: 1,
            lastStatus: .unread(count: 1),
            lastTimeText: "00:00"
        ),
        Chat(
            cryptoID: "~mock_1234",
            displayName: "Monk",
            avatarColorHex: "#3399FF",
            messages: [
                Message(sender: .me,
                        text: "Do you think this app is as safe as they say? Or should we still be careful? Are we under a good roof?",
                        date: Date().addingTimeInterval(-7200),
                        localStatus: .sent),
                Message(sender: .other,
                        text: "This app — greet",
                        date: Date().addingTimeInterval(-7100),
                        localStatus: .received,
                        replyPreview: "Do you think this app is as safe as they say? Or should we still be careful? Are we under a good roof?",
                        replyAuthor: "You"),
                Message(sender: .other,
                        text: "We will use!",
                        date: Date().addingTimeInterval(-7000),
                        localStatus: .received)
            ],
            unreadCount: 0,
            lastStatus: .readIncoming,
            lastTimeText: "19:11"
        ),
        Chat(
            cryptoID: "~mock_9012",
            displayName: "Elon",
            avatarColorHex: "#33FF57",
            messages: [
                Message(sender: .other,
                        text: "Hello 💤",
                        date: makeDate(year: Calendar.current.component(.year, from: Date()),
                                       month: 5, day: 5, hour: 10, minute: 0),
                        localStatus: .received)
            ],
            unreadCount: 0,
            lastStatus: .unread(count: 0),
            lastTimeText: "05.05"
        )
    ]
}
