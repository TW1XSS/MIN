import SwiftUI

struct AvatarView: View {
    var name: String
    var colorHex: String
    var size: CGFloat = 50
    var showInitials: Bool = false

    var body: some View {
        ZStack {
            Circle().fill(Color(hex: colorHex)).frame(width: size, height: size)
            if showInitials {
                let initials = String(name.prefix(1)).uppercased()
                Text(initials)
                    .foregroundColor(.white)
                    .font(.system(size: size / 2, weight: .bold))
            }
        }
    }
}
