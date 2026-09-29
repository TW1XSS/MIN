import SwiftUI

enum MINTheme {
    // Core colors — pure black canvas, dark gray surfaces, light-blue accent (per MIN mockups)
    static let background = Color.black
    static let divider = Color.white.opacity(0.08)

    // Accents & text
    static let accent = Color(hex: "62AEEE")
    static let textPrimary = Color.white
    static let textSecondary = Color.white.opacity(0.70)
    static let textTertiary = Color.white.opacity(0.45)

    // Surfaces
    static let card = Color(hex: "1C1C1E")     // gray cards (chat list card, fields)
    static let pill = Color(hex: "2C2C2E")     // section pills ("add contact", "Chats")
    static let control = Color(hex: "1C1C1E")  // big "+" card, buttons
    static let inputBG = Color(hex: "1C1C1E")  // message field, key field

    // Single shared corner radius — perfect symmetry across ALL surfaces.
    // 20pt = Liquid Glass / iOS 26 pill language (matches the round send button,
    // input capsule, cards, buttons and bubbles).
    static let cornerRadius: CGFloat = 20

    // Alias kept for readability in the composer/reply bar — same value.
    static let inputRadius: CGFloat = cornerRadius

    // Chat bubble tints (mockup: slate gray for me, darker graphite for others)
    static let bubbleMe = Color(hex: "2A3947")
    static let bubbleOther = Color(hex: "212227")
}
