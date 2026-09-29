import SwiftUI

struct SectionPill: View {
    let title: String

    var body: some View {
        Text(title)
            .font(.system(size: 12, weight: .semibold))
            .foregroundColor(MINTheme.textSecondary)
            .padding(.horizontal, 14)
            .padding(.vertical, 6)
            .background(Capsule().fill(MINTheme.pill))
            .overlay(Capsule().stroke(Color.white.opacity(0.06), lineWidth: 0.5))
            .frame(maxWidth: .infinity)
            .padding(.horizontal, 10)
    }
}
