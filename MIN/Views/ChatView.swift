import SwiftUI

@available(iOS 15.0, *)
struct ChatView: View {
    @Binding var chat: Chat
    // Debug-only prefill (-openChatDebug) for composer layout verification.
    var debugPrefill: String? = nil
    @EnvironmentObject var appState: AppState
    @Environment(\.presentationMode) private var presentationMode
    @ObservedObject private var keyboard = KeyboardWatcher.shared

    @State private var replyTo: Message? = nil
    @State private var focusToken = 0
    // Live height of the input capsule (one line ≈ 40pt, grows with the text).
    // Piped into the message list's bottom inset, so the last bubble stays
    // ABOVE the growing composer instead of sliding under it.
    @State private var composerHeight: CGFloat = 40
    // NOTE: input text intentionally lives inside ComposerView. Keeping it
    // here re-rendered the whole chat (messages list included) per keystroke.

    var body: some View {
        GeometryReader { geo in
            ZStack {
                MINTheme.background.edgesIgnoringSafeArea(.all)

                // Messages scroll UNDER the glass layers.
                // Value inputs + .equatable(): keyboard ticks (keyboard.height
                // in ChatView state) no longer rebuild this list — the body is
                // skipped unless messages/insets actually change. The keyboard
                // gap below the last bubble is applied via contentBottomInset.
                MessagesListView(
                    chatID: chat.id,
                    messages: chat.messages,
                    onReply: { message in
                        reply(to: message)
                    },
                    // 58pt header (38 pill + 2x10 padding) + 8pt gap: the day
                    // pill ("Today" / "Mar 12") must start BELOW the username
                    // header, not under its glass blur.
                    contentTopInset: geo.safeAreaInsets.top + 66,
                    // Measured on device: the visible bubble-to-capsule gap
                    // tracks the spacer 1:1 minus ~18pt of safe-area/bubble
                    // padding, so a +3pt trim lands the bubble ~9pt over the
                    // capsule top at ANY field height. The keyboard overlap is
                    // added on top (Spacer) — the keyboard-locked position
                    // floats the last bubble above the composer exactly like
                    // the growth does. With the reply bar: + bar (40) + 6.
                    contentBottomInset: keyboard.height + (replyTo == nil
                        ? composerHeight + 3
                        : composerHeight + 48),
                    keyboardInset: keyboard.height
                )
                .equatable()
                .edgesIgnoringSafeArea(.top)

                // Glass fade layers (BEHIND the controls, IN FRONT of messages):
                // top = soapy near the status bar -> clear downward;
                // bottom = clear upward -> soapy near the home indicator.
                // Black overlay keeps the fade exactly the background color.
                VStack(spacing: 0) {
                    GlassFadeView(isTop: true)
                        .frame(height: 150)
                        .frame(maxWidth: .infinity)
                        .edgesIgnoringSafeArea(.top)
                        .allowsHitTesting(false)
                    Spacer()
                    GlassFadeView(isTop: false)
                        .frame(height: geo.safeAreaInsets.bottom + (replyTo == nil ? 48 : 94))
                        .frame(maxWidth: .infinity)
                        .frame(maxHeight: .infinity, alignment: .bottom)
                        .edgesIgnoringSafeArea(.bottom)
                        .allowsHitTesting(false)
                        // Follow the composer up when the keyboard opens so the
                        // frosted backdrop stays behind the input field.
                        .offset(y: -keyboard.height)
                }

                // Transparent controls (header & composer) sit ON TOP of the glass
                VStack(spacing: 0) {
                    header
                    Spacer()
                    composerArea
                }
                // Manual keyboard avoidance: the composer is lifted by the
                // keyboard overlap while the header and the messages stay put.
                // System avoidance is disabled below (ignoresKeyboardSafeArea),
                // so this padding is the ONLY lift — no double offset.
                .padding(.bottom, keyboard.height)
            }
        }
        .ignoresKeyboardSafeArea()
        // The message list keeps its own bottom inset in sync with the
        // keyboard, so the last bubble stays visible above the composer.
        .navigationBarHidden(true)
        .onAppear {
            // Открытие чата снимает локальный непрочитанный счётчик. Сетевых
            // read-receipts в MVP нет: «прочитано» — метаданные активности
            // собеседника, поэтому статус чтения не моделируется вовсе
            // (MIN-RED-018) и тем более не имитируется таймером.
            //
            // Важно: метку времени ставим в AppState (lastReadAt), а не только
            // обнуляем счётчик у локальной копии чата. Иначе следующий
            // reloadChats() снова насчитал бы те же входящие как непрочитанные
            // (счётчик всегда был бы 0, бейдж не появлялся бы).
            appState.markChatRead(peer: chat.cryptoID)
            HapticManager.shared.prepare()

            // Debug (-openChatDebug): focus the composer so the LIVE typing
            // path (textViewDidChange) can be exercised via hardware keys.
            if let prefill = debugPrefill, !prefill.isEmpty {
                focusToken += 1
            }

            // Реальный pull: забрать входящие из очереди relay при открытии чата.
            appState.pollAndReload()
        }
    }

    // MARK: - Header

    /// Counter on the back pill = unread messages in ALL OTHER chats
    /// (not the current one). 0 -> plain round "<" button without the counter.
    private var otherUnread: Int {
        appState.unreadExcluding(chatID: chat.id)
    }

    // Mockup: "<" + unread badge on the left, bold name centered, avatar on the right.
    private var header: some View {
        VStack(spacing: 0) {
            ZStack {
                Text(chat.displayName)
                    .font(.system(size: 17, weight: .bold))
                    .foregroundColor(MINTheme.textPrimary)
                    .lineLimit(1)
                    .padding(.horizontal, 16)
                    .frame(height: 38)
                    .glassPanel(cornerRadius: 19, tint: MINTheme.control)

                HStack(spacing: 8) {
                    Button {
                        HapticManager.shared.lightImpact()
                        presentationMode.wrappedValue.dismiss()
                    } label: {
                        // Telegram-style back pill: "<" + white unread counter
                        // INSIDE the button (white circle, dark number).
                        // With no unread anywhere the button is a perfect 38x38 circle.
                        Group {
                            if otherUnread > 0 {
                                HStack(spacing: 5) {
                                    Image(systemName: "chevron.left")
                                        .font(.system(size: 17, weight: .semibold))
                                        .foregroundColor(.white)

                                    Text("\(otherUnread)")
                                        .font(.system(size: 13, weight: .semibold))
                                        .foregroundColor(.black)
                                        .frame(width: 20, height: 20)
                                        .background(Circle().fill(Color.white))
                                        .transition(.scale(scale: 0.4).combined(with: .opacity))
                                }
                                .padding(.leading, 12)
                                .padding(.trailing, 7)
                                .frame(height: 38)
                            } else {
                                Image(systemName: "chevron.left")
                                    .font(.system(size: 17, weight: .semibold))
                                    .foregroundColor(.white)
                                    .frame(width: 38, height: 38)
                            }
                        }
                        .glassPanel(cornerRadius: 19, tint: MINTheme.control)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(PressableButtonStyle())

                    Spacer()
                }

                HStack {
                    Spacer()
                    AvatarView(name: chat.displayName, colorHex: chat.avatarColorHex, size: 34, showInitials: false)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
        }
        // No background: the glass gradient layer sits behind this bar in the ZStack
    }

    // MARK: - Composer

    private var composerArea: some View {
        VStack(spacing: 6) {
            if let rep = replyTo {
                ReplyBar(reply: rep, onCancel: {
                    withAnimation(.spring(response: 0.3, dampingFraction: 0.8)) {
                        replyTo = nil
                    }
                })
                .transition(.move(edge: .bottom).combined(with: .opacity))
                .padding(.horizontal, 2)
            }

            ComposerView(focusToken: focusToken, onSend: sendMessage, debugPrefill: debugPrefill, contentHeight: $composerHeight)
        }
        .padding(.horizontal, 10)
        .padding(.top, 6)
        .padding(.bottom, 8)
        // No background: the glass gradient layer sits behind this bar in the ZStack
    }

    // MARK: - Actions

    private func reply(to message: Message) {
        withAnimation(.spring(response: 0.3, dampingFraction: 0.8)) {
            replyTo = message
        }
        focusToken += 1
    }

    private func sendMessage(_ text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }

        HapticManager.shared.success()

        var msg = Message(sender: .me, text: trimmed, date: Date(), localStatus: .pending)
        // Цитату снимаем ДО сброса replyTo: ниже он уже nil, и ответ ушёл бы
        // обычным сообщением.
        let quote: MinReplyRef? = replyTo.map {
            MinReplyRef(author: $0.sender == .me ? "You" : chat.displayName, preview: $0.text)
        }
        if let r = replyTo {
            msg.replyPreview = r.text
            msg.replyAuthor = r.sender == .me ? "You" : chat.displayName
        }
        withAnimation(.spring(response: 0.3, dampingFraction: 0.8)) {
            chat.addMessage(msg)
            replyTo = nil
        }

        // Реальная отправка: ядро шифрует и кладёт конверт в очередь relay.
        // Блокирующий FFI уходит в фон, пузырь уже показан (оптимистичный UI).
        appState.sendOnCore(peer: chat.cryptoID, text: trimmed, optimisticID: msg.id,
                            reply: quote)
    }
}
