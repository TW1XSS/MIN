import SwiftUI

/// iMessage-style chat bubble: rounded body with ONE integrated, smooth,
/// fully proportional tail (bottom-right for outgoing, bottom-left for incoming).
/// All tail geometry scales with the bubble size, so it never looks "broken".
struct ChatBubbleShape: Shape {
    let isFromMe: Bool
    var showTail: Bool = true

    func path(in rect: CGRect) -> Path {
        var p = Path()
        let w = rect.width
        let h = rect.height

        // Scale tail to the bubble so tiny bubbles keep a sane shape.
        let tailH: CGFloat = showTail ? min(7, h * 0.30) : 0
        let bodyH = h - tailH
        let r: CGFloat = min(17, bodyH / 2)      // main corner radius
        let small: CGFloat = showTail ? 5 : r    // radius next to the tail

        // Tail geometry (proportional)
        let tipInset: CGFloat = 5                // tip distance from the edge
        let tailTopInset: CGFloat = 14           // where the tail meets the bottom edge
        let bottom = bodyH

        if isFromMe {
            // Start top-left, go clockwise
            p.move(to: CGPoint(x: r, y: 0))
            p.addLine(to: CGPoint(x: w - r, y: 0))
            p.addArc(center: CGPoint(x: w - r, y: r), radius: r,
                     startAngle: .degrees(270), endAngle: .degrees(0), clockwise: false)
            p.addLine(to: CGPoint(x: w, y: bottom - small))
            p.addArc(center: CGPoint(x: w - small, y: bottom - small), radius: small,
                     startAngle: .degrees(0), endAngle: .degrees(90), clockwise: false)

            if showTail {
                // Smooth outward curve to the tail tip...
                p.addCurve(
                    to: CGPoint(x: w - tipInset, y: h),
                    control1: CGPoint(x: w, y: bottom + tailH * 0.72),
                    control2: CGPoint(x: w - 1.5, y: h - 1)
                )
                // ...and a soft inward curve back to the bottom edge.
                p.addCurve(
                    to: CGPoint(x: w - tailTopInset, y: bottom),
                    control1: CGPoint(x: w - tailTopInset * 0.62, y: h - 0.5),
                    control2: CGPoint(x: w - tailTopInset * 0.80, y: bottom)
                )
            } else {
                p.addArc(center: CGPoint(x: w - r, y: bottom - r), radius: r,
                         startAngle: .degrees(0), endAngle: .degrees(90), clockwise: false)
            }

            p.addLine(to: CGPoint(x: r, y: bottom))
            p.addArc(center: CGPoint(x: r, y: bottom - r), radius: r,
                     startAngle: .degrees(90), endAngle: .degrees(180), clockwise: false)
            p.addLine(to: CGPoint(x: 0, y: r))
            p.addArc(center: CGPoint(x: r, y: r), radius: r,
                     startAngle: .degrees(180), endAngle: .degrees(270), clockwise: false)
        } else {
            // Mirrored: tail bottom-left, counter-clockwise start top-right
            p.move(to: CGPoint(x: w - r, y: 0))
            p.addLine(to: CGPoint(x: r, y: 0))
            p.addArc(center: CGPoint(x: r, y: r), radius: r,
                     startAngle: .degrees(270), endAngle: .degrees(180), clockwise: false)
            p.addLine(to: CGPoint(x: 0, y: bottom - small))
            p.addArc(center: CGPoint(x: small, y: bottom - small), radius: small,
                     startAngle: .degrees(180), endAngle: .degrees(90), clockwise: false)

            if showTail {
                p.addCurve(
                    to: CGPoint(x: tipInset, y: h),
                    control1: CGPoint(x: 0, y: bottom + tailH * 0.72),
                    control2: CGPoint(x: 1.5, y: h - 1)
                )
                p.addCurve(
                    to: CGPoint(x: tailTopInset, y: bottom),
                    control1: CGPoint(x: tailTopInset * 0.62, y: h - 0.5),
                    control2: CGPoint(x: tailTopInset * 0.80, y: bottom)
                )
            } else {
                p.addArc(center: CGPoint(x: r, y: bottom - r), radius: r,
                         startAngle: .degrees(180), endAngle: .degrees(90), clockwise: false)
            }

            p.addLine(to: CGPoint(x: w - r, y: bottom))
            p.addArc(center: CGPoint(x: w - r, y: bottom - r), radius: r,
                     startAngle: .degrees(90), endAngle: .degrees(0), clockwise: false)
            p.addLine(to: CGPoint(x: w, y: r))
            p.addArc(center: CGPoint(x: w - r, y: r), radius: r,
                     startAngle: .degrees(0), endAngle: .degrees(270), clockwise: false)
        }

        p.closeSubpath()
        return p
    }
}

