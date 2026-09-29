import SwiftUI

@available(iOS 15.0, *)
struct ChatRowView: View {
    @Binding var chat: Chat
    var showsDivider: Bool = true

    // Real time of the last message: HH:MM today, otherwise dd.MM
    private static let listDateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "dd.MM"
        return f
    }()

    private var timeText: String {
        guard let date = chat.messages.last?.date else { return chat.lastTimeText }
        return Calendar.current.isDateInToday(date)
            ? DateFormatters.hhmm.string(from: date)
            : Self.listDateFormatter.string(from: date)
    }

    var body: some View {
        NavigationLink(destination: ChatView(chat: $chat)) {
            VStack(spacing: 0) {
                HStack(spacing: 14) {
                    AvatarView(name: chat.displayName, colorHex: chat.avatarColorHex, size: 56, showInitials: false)
                        .frame(minWidth: 56, alignment: .leading)

                    VStack(alignment: .leading, spacing: 7) {
                        HStack(spacing: 8) {
                            Text(chat.displayName)
                                .font(.system(size: 17, weight: .semibold))
                                .foregroundColor(MINTheme.textPrimary)
                                .lineLimit(1)

                            Spacer()

                            // Плашка READ убрана намеренно (MIN-RED-018): «прочитано»
                            // — это метаданные активности собеседника. В MVP
                            // статусы чтения не показываем и не имитируем.
                            Text(timeText)
                                .font(.system(size: 14))
                                .foregroundColor(MINTheme.textSecondary)
                        }

                        HStack(spacing: 8) {
                            Text(chat.lastMessagePreview ?? "")
                                .font(.system(size: 15))
                                .foregroundColor(MINTheme.textSecondary)
                                .lineLimit(1)
                                .truncationMode(.tail)

                            Spacer()

                            if case .unread(let count) = chat.lastStatus, count > 0 {
                                Text("\(count)")
                                    .font(.system(size: 12, weight: .semibold))
                                    .foregroundColor(.white)
                                    .frame(width: 22, height: 22)
                                    .background(Circle().fill(MINTheme.accent))
                                    .transition(.scale(scale: 0.4).combined(with: .opacity))
                            }
                        }
                    }
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 11)
                .contentShape(Rectangle())

                if showsDivider {
                    Rectangle()
                        .fill(MINTheme.divider)
                        .frame(height: 0.5)
                        .padding(.leading, 84)
                }
            }
        }
        .buttonStyle(PressableButtonStyle(scale: 0.98))
        // Telegram-like bounce when the unread badge appears/disappears
        // (локальный счётчик; сетевых read-статусов в MVP нет — MIN-RED-018).
        .animation(.spring(response: 0.35, dampingFraction: 0.65), value: chat.unreadCount)
    }
}

// VisualEffectBlur fallback for iOS 13/14 (kept for reuse)
struct VisualEffectBlur: UIViewRepresentable {
    var blurStyle: UIBlurEffect.Style

    func makeUIView(context: Context) -> UIVisualEffectView {
        UIVisualEffectView(effect: UIBlurEffect(style: blurStyle))
    }

    func updateUIView(_ uiView: UIVisualEffectView, context: Context) {}
}
