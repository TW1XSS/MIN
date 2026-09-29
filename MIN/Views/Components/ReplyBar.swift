import SwiftUI

struct ReplyBar: View {
    let reply: Message
    let onCancel: () -> Void
    
    var body: some View {
        HStack(spacing: 10) {
            // Quote bar stretches with the reply block height, rounded, never to the edges
            RoundedRectangle(cornerRadius: 2)
                .fill(MINTheme.accent)
                .frame(width: 3)
                .padding(.vertical, 4)

            VStack(alignment: .leading, spacing: 2) {
                Text(reply.sender == .me ? "You" : "Reply")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(MINTheme.accent)

                Text(reply.text)
                    .lineLimit(1)
                    .foregroundColor(MINTheme.textSecondary)
                    .font(.caption)
            }

            Spacer()

            Button(action: {
                HapticManager.shared.lightImpact()
                onCancel()
            }) {
                Image(systemName: "xmark.circle.fill")
                    .foregroundColor(MINTheme.textTertiary)
                    .font(.system(size: 18))
            }
            .buttonStyle(PlainButtonStyle())
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        // Same shape & height as the message input field (40pt) — they sit
        // consecutively above the keyboard and must read as one continuous block.
        .frame(minHeight: 40)
        .glassPanel(cornerRadius: MINTheme.inputRadius, tint: MINTheme.control)
        .fixedSize(horizontal: false, vertical: true)
    }
}
