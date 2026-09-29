import SwiftUI

struct MessageBubble: View {
    let message: Message
    let isFromMe: Bool
    let isFirstInGroup: Bool
    let isLastInGroup: Bool
    var onReply: (() -> Void)? = nil
    var onCopy: (() -> Void)? = nil
    /// Удаление не реализовано — поэтому и кнопки Delete в меню нет.


    // Telegram-style "swipe left to reply" (right-to-left)
    @State private var swipeOffset: CGFloat = 0
    private let swipeTrigger: CGFloat = 60
    private let swipeMax: CGFloat = 72

    var body: some View {
        ZStack(alignment: .trailing) {
            // Reply arrow revealed behind the bubble while swiping left
            Image(systemName: "arrowshape.turn.up.left.fill")
                .font(.system(size: 16, weight: .semibold))
                .foregroundColor(MINTheme.accent)
                .frame(width: 34, height: 34)
                .opacity(progress)
                .scaleEffect(0.6 + 0.4 * progress)
                .padding(.trailing, 14)

            HStack(alignment: .bottom, spacing: 0) {
                if isFromMe { Spacer(minLength: 56) }
                bubble
                if !isFromMe { Spacer(minLength: 56) }
            }
            .offset(x: swipeOffset)
        }
        .padding(.horizontal, 16)
        .padding(.top, isFirstInGroup ? 10 : 3)
        .padding(.bottom, isLastInGroup ? 10 : 3)
        .contextMenu {
            Button(action: {
                onReply?()
            }) {
                HStack {
                    Image(systemName: "arrowshape.turn.up.left.fill")
                    Text("Reply")
                }
            }
            Button(action: {
                UIPasteboard.general.string = message.text
                onCopy?()
                HapticManager.shared.success()
            }) {
                HStack {
                    Image(systemName: "doc.on.doc.fill")
                    Text("Copy")
                }
            }
            // Кнопки Delete нет: удаление не реализовано, а показывать
            // неработающее действие — значит обещать то, чего нет. Вернётся
            // вместе с реальным удалением (и для всех сторон, не только своих).
        }
        .gesture(replySwipe)
    }

    private var progress: CGFloat { min(max(-swipeOffset / swipeTrigger, 0), 1) }

    @ViewBuilder
    private var textContent: some View {
        let base = Text(message.text)
            .font(.system(size: 16))
            .foregroundColor(.white)
            .fixedSize(horizontal: false, vertical: true)
            .multilineTextAlignment(.leading)
            .frame(maxWidth: message.replyPreview != nil ? .infinity : nil, alignment: .leading)
            .padding(.trailing, 38)
        if #available(iOS 15.0, *) {
            base.textSelection(.enabled)
        } else {
            base
        }
    }

    // Bubble hugs its content; timestamp pinned bottom-right WITHOUT stretching
    // the bubble width (Telegram style: short messages stay compact).
    private var bubble: some View {
        VStack(alignment: .leading, spacing: 5) {
            if let replyText = message.replyPreview {
                replyHeader(text: replyText)
            }
            // Reserved room keeps the time from covering the text, while the bubble
            // still hugs its content. When a reply quote is present the text fills
            // the bubble width, so both blocks share the same right edge (symmetric)
            // and the time always sits in the very corner of the bubble.
            ZStack(alignment: .bottomTrailing) {
                textContent
                Text(DateFormatters.hhmm.string(from: message.date))
                    .font(.system(size: 11))
                    .foregroundColor(Color.white.opacity(0.55))
                    .padding(.trailing, 2)
                    .padding(.bottom, 2)
            }
        }
        .padding(.leading, 14)
        .padding(.trailing, 14)
        .padding(.top, 10)
        .padding(.bottom, 8)
        .background(
            RoundedRectangle(cornerRadius: MINTheme.cornerRadius, style: .continuous)
                .fill(isFromMe ? MINTheme.bubbleMe : MINTheme.bubbleOther)
                // Depth: soft drop shadow under every bubble (Telegram-like)
                .shadow(color: Color.black.opacity(0.30), radius: 6, x: 0, y: 3)
        )
        .frame(maxWidth: UIScreen.main.bounds.width * 0.78, alignment: isFromMe ? .trailing : .leading)
        .contentShape(RoundedRectangle(cornerRadius: MINTheme.cornerRadius, style: .continuous))
    }

    // Reply ONLY by swiping the message left — right to left (like Telegram).
    private var replySwipe: some Gesture {
        DragGesture(minimumDistance: 20)
            .onChanged { value in
                let w = value.translation.width
                if w < 0 {
                    swipeOffset = max(w, -swipeMax)
                } else {
                    // rubber-band resistance when dragging right — no action there
                    swipeOffset = min(w * 0.12, 10)
                }
            }
            .onEnded { value in
                if value.translation.width < -swipeTrigger {
                    HapticManager.shared.lightImpact()
                    onReply?()
                }
                swipeOffset = 0
            }
    }

    private func replyHeader(text: String) -> some View {
        HStack(alignment: .center, spacing: 8) {
            // Accent quote bar STETCHES with the quoted content (no fixed notch),
            // bounded by the block's vertical padding — never touching the edges.
            RoundedRectangle(cornerRadius: 2)
                .fill(MINTheme.accent)
                .frame(width: 3)

            VStack(alignment: .leading, spacing: 1) {
                Text(message.replyAuthor ?? "")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundColor(MINTheme.accent)
                Text(text)
                    .font(.system(size: 13))
                    .foregroundColor(MINTheme.textSecondary)
                    .lineLimit(2)
                    .multilineTextAlignment(.leading)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        // Fills the bubble content width — the quote never sticks out narrower
        // than the message text, keeping the bubble perfectly symmetric.
        .padding(.leading, 8)
        .padding(.trailing, 12)
        .padding(.vertical, 5)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(
                    isFromMe
                        ? Color.white.opacity(0.10)
                        : Color.white.opacity(0.05)
                )
        )
        .padding(.bottom, 4)
    }
}
