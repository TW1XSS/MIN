import SwiftUI
import UIKit

struct ComposerView: View {
    var focusToken: Int
    @State private var localFocusToken = 0
    // The composer OWNS its text. If the text lived in ChatView (as it did
    // before), every keystroke invalidated the whole screen state — SwiftUI
    // rebuilt the entire message list, header and glass layers on each
    // character, which visibly lagged on real devices.
    @State private var text = ""
    var onSend: (String) -> Void
    // Debug-only prefill (-openChatDebug): long unbroken text to verify
    // the composer wraps instead of stretching past the screen edge.
    var debugPrefill: String? = nil

    // Live capsule height, owned by ChatView: the message list lifts its
    // bottom inset by the SAME value, so the last bubble rides ABOVE the
    // growing field (Telegram) instead of sliding under it.
    @Binding var contentHeight: CGFloat
    // True while the UITextView is first responder — drives the iOS 26
    // metaball neck (visible only while the field is focused/expanded).
    @State private var isFieldFocused = false
    // True once the text wraps beyond a single line — the neck also stays
    // while the field is expanded, even if focus is dropped.
    @State private var isMultiline = false

    // The field grows upward up to ~38% of the screen height (≈6–10 lines
    // depending on Dynamic Type); beyond that it scrolls internally.
    var composerMaxHeight: CGFloat { UIScreen.main.bounds.height * 0.38 }

    private var isEmpty: Bool {
        text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var body: some View {
        Group {
            if #available(iOS 26.0, *) {
                // iOS 26: field + button live in a GlassEffectContainer —
                // tagged with glassEffectID they merge with a gooey
                // "droplet" neck (the iOS 26 metaball look).
                MetaballComposerRow(
                    text: $text,
                    focusToken: focusToken,
                    localFocusToken: $localFocusToken,
                    contentHeight: $contentHeight,
                    isFocused: $isFieldFocused,
                    isMultiline: $isMultiline,
                    composerMaxHeight: composerMaxHeight,
                    isEmpty: isEmpty,
                    sendAction: { sendIfPossible() }
                )
            } else {
                composerRow
            }
        }
        .onAppear {
            if let prefill = debugPrefill, text.isEmpty {
                // Emulate LIVE TYPING: feed the text in chunks through the
                // binding so every keystroke-sized step exercises the same
                // layout + glass-morph path as real typing (a single bulk
                // assignment would skip the incremental growth the bug
                // hides in).
                for (i, _) in prefill.enumerated() where i > 0 {
                    let chunk = String(prefill.prefix(i + 1))
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.02 * Double(i)) {
                        text = chunk
                    }
                }
            }
        }
    }

    // Pre-iOS 26 row: same layout, no glass blending (no GlassEffectContainer).
    private var composerRow: some View {
        // Separate field & button (Telegram style): a rounded input capsule
        // + a round send button floating beside it. Both share the SAME
        // pill radius so they read as one symmetric pair.
        HStack(alignment: .bottom, spacing: 8) {
            inputField
            sendButton
        }
    }

    private var inputField: some View {
        ZStack(alignment: .leading) {
            if isEmpty {
                Text("Message...")
                    .font(.body)
                    .foregroundColor(MINTheme.textTertiary)
                    .padding(.leading, 17)
                    // Never intercept taps (first tap must reach the field).
                    .allowsHitTesting(false)
            }
            GrowingTextView(
                text: $text,
                focusToken: focusToken,
                contentHeight: $contentHeight,
                isFocused: $isFieldFocused,
                isMultiline: $isMultiline,
                composerMaxHeight: composerMaxHeight
            )
        }
        // Fill ALL remaining width: the UITextView's intrinsic width for one
        // long unbroken line is unbounded — without this frame it stretched
        // the HStack past the right screen edge instead of wrapping inside
        // the field.
        .frame(maxWidth: .infinity, alignment: .leading)
        .frame(height: min(max(40, contentHeight), composerMaxHeight))
        .clipShape(RoundedRectangle(cornerRadius: MINTheme.inputRadius))
        .glassPanel(cornerRadius: MINTheme.inputRadius, tint: MINTheme.inputBG, interactive: true)
    }

    private var sendButton: some View {
        Button(action: sendIfPossible) {
            Image(systemName: "arrow.up")
                .font(.system(size: 17, weight: .bold))
                .foregroundColor(.white)
                .frame(width: 40, height: 40)
                .glassCircle(tint: isEmpty ? MINTheme.inputBG : MINTheme.accent, tintOpacity: isEmpty ? 0.32 : 1)
                .shadow(color: MINTheme.accent.opacity(isEmpty ? 0 : 0.4), radius: 8, x: 0, y: 3)
        }
        .buttonStyle(PressableButtonStyle())
        .disabled(isEmpty)
        .animation(.spring(response: 0.25, dampingFraction: 0.7), value: isEmpty)
    }

    private func sendIfPossible() {
        guard !isEmpty else { return }
        HapticManager.shared.mediumImpact()
        onSend(text)
        // The parent added the message; clear the field. Done in the next
        // runloop tick so UITextView finishes processing the current edit
        // session first.
        DispatchQueue.main.async {
            withAnimation(.spring(response: 0.25, dampingFraction: 0.8)) {
                text = ""
            }
        }
    }
}

// MARK: - iOS 26 metaball composer (Liquid Glass blend)

/// iOS 26-only copy of the composer row. Inside a GlassEffectContainer the
/// input capsule and the send button (both tagged with glassEffectID) blend
/// with a gooey "droplet" neck when close. Keep visuals in sync with
/// ComposerView.composerRow. Owns its own @Namespace — @Namespace is iOS 14+,
/// so it cannot live in the main (iOS 13) struct.
@available(iOS 26.0, *)
private struct MetaballComposerRow: View {
    @Binding var text: String
    var focusToken: Int
    @Binding var localFocusToken: Int
    @Binding var contentHeight: CGFloat
    @Binding var isFocused: Bool
    @Binding var isMultiline: Bool
    var composerMaxHeight: CGFloat
    var isEmpty: Bool
    var sendAction: () -> Void

    var body: some View {
        // Metaball container. spacing: 4 sits BELOW the static gap between
        // the field and the button (8pt): the container auto-blends any
        // glass shapes closer than `spacing`, so with the old spacing: 12
        // the two were fused into one blob PERMANENTLY — that was the stuck
        // neck that never retracted. With spacing: 4 they auto-fuse only
        // during system-driven motion (tap/typing) and sit as two separate
        // droplets in every static state. No custom bridge geometry:
        // Apple's own glass blending draws the gooey neck — a hand-drawn
        // MetaballNeckShape overlaid on top of it produced a SECOND, wonky
        // neck on first tap.
        GlassEffectContainer(spacing: 4) {
            HStack(alignment: .bottom, spacing: 8) {
                inputField
                sendButton
            }
        }
    }

    private var inputField: some View {
        ZStack(alignment: .leading) {
            if isEmpty {
                Text("Message...")
                    .font(.body)
                    .foregroundColor(MINTheme.textTertiary)
                    .padding(.leading, 17)
                    // Never intercept taps: a hit-testable placeholder sat
                    // ON TOP of the UITextView, so the FIRST tap landed on
                    // the label instead of focusing the field — no caret
                    // appeared until after the first send.
                    .allowsHitTesting(false)
            }
            GrowingTextView(
                text: $text,
                focusToken: focusToken + localFocusToken,
                contentHeight: $contentHeight,
                isFocused: $isFocused,
                isMultiline: $isMultiline,
                composerMaxHeight: composerMaxHeight
            )
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .frame(height: min(max(40, contentHeight), composerMaxHeight))
        // NO spring on the capsule height: the UITextView sits INSIDE this
        // frame, and during a height spring SwiftUI re-lays it out on every
        // animation frame — the wrapped text visibly flickers and the
        // per-frame re-layout is exactly the typing lag on line wraps.
        .clipShape(RoundedRectangle(cornerRadius: MINTheme.inputRadius))
        // glassEffect applied DIRECTLY (not via the glassPanel helper).
        // NOTE: deliberately NO glassEffectID — ID-tagging makes the
        // container fuse the field and the button into one blob PERMANENTLY
        // (gap 8 < container spacing 12). The system draws the connecting
        // neck during motion, so the shapes stay untagged and separate.
        .glassEffect(
            Glass.regular.tint(MINTheme.inputBG.opacity(0.32)).interactive(),
            in: .rect(cornerRadius: MINTheme.inputRadius)
        )
        .contentShape(Rectangle())
        .onTapGesture {
            localFocusToken += 1
        }
    }

    private var sendButton: some View {
        // NOT disabled on empty input: a disabled Button is a classic source
        // of "send does nothing" when the empty-state flag goes stale. The
        // button is ALWAYS touchable and sendIfPossible() guards the actual
        // send; the accent tint + shadow already express active/inactive.
        Button(action: sendAction) {
            Image(systemName: "arrow.up")
                .font(.system(size: 17, weight: .bold))
                .foregroundColor(.white)
                .frame(width: 40, height: 40)
                .glassEffect(
                    Glass.regular.tint(isEmpty ? MINTheme.inputBG.opacity(0.32) : MINTheme.accent),
                    in: Circle()
                )
                .shadow(color: MINTheme.accent.opacity(isEmpty ? 0 : 0.4), radius: 8, x: 0, y: 3)
        }
        .buttonStyle(PressableButtonStyle())
        // Explicit circular hit-area: the neck overlay may DRAW over the
        // button, so the tappable region must be the glass circle itself,
        // non-dependent on the content's glass effect.
        .contentShape(Circle())
        .animation(.spring(response: 0.25, dampingFraction: 0.7), value: isEmpty)
    }
}

// MARK: - Growing text input (UITextView, iOS 13 compatible)

// UITextView reports an UNBOUNDED intrinsic width when scrolling is disabled:
// one long unbroken line blew the composer horizontally past the screen edge
// (and pushed the header's avatar/title off-screen with it). Pinning the
// intrinsic width to the current layout width makes SwiftUI's frame() the
// ONLY source of the horizontal size — the field can now grow in HEIGHT only.
final class WidthPinnedTextView: UITextView {
    /// Growth cap: past it the view scrolls internally instead of growing
    /// (kept in sync with GrowingTextView.composerMaxHeight). Without the
    /// clamp the intrinsic height outgrew the SwiftUI frame and the text
    /// drew OUTSIDE the glass capsule.
    var composerMaxHeight: CGFloat = 120

    // UIKit reads intrinsicContentSize MANY times per layout pass (and per
    // keystroke). The old code ran sizeThatFits — a full text re-layout — on
    // EVERY read, which multiplied into the per-keystroke typing lag. The
    // fitted height is now cached and recomputed only when explicitly
    // invalidated or when the width changes (rotation / split view).
    private var cachedFittedHeight: CGFloat = 0
    private var cachedWidth: CGFloat = 0
    private var cacheValid = false

    override func invalidateIntrinsicContentSize() {
        cacheValid = false
        super.invalidateIntrinsicContentSize()
    }

    override var intrinsicContentSize: CGSize {
        let w = bounds.width
        guard w > 0 else {
            return CGSize(width: UIView.noIntrinsicMetric, height: 40)
        }
        if !cacheValid || abs(w - cachedWidth) > 0.5 {
            // The classic growing-UITextView measurement: sizeThatFits INCLUDES
            // textContainerInset, but the insets are FIXED (makeUIView sets the
            // base 10/13/10/13 once and NOTHING ever mutates them), so the
            // measurement can never feed back into itself — that was the
            // original never-shrink bug. The intermediate usedRect-based
            // measurement was worse: ensureLayout cached line fragments against
            // a stale wide container width, so a long word drew on ONE line
            // extending right past the frame and the height never grew.
            cachedFittedHeight = sizeThatFits(CGSize(width: w, height: .greatestFiniteMagnitude)).height
            cachedWidth = w
            cacheValid = true
        }
        let lineHeight = ceil(font?.lineHeight ?? 20)
        let oneLine = lineHeight + textContainerInset.top + textContainerInset.bottom
        return CGSize(width: w, height: min(max(ceil(cachedFittedHeight), oneLine), composerMaxHeight))
    }
}

struct GrowingTextView: UIViewRepresentable {
    @Binding var text: String
    var focusToken: Int
    @Binding var contentHeight: CGFloat
    @Binding var isFocused: Bool
    // True once the text wraps past a single line — the neck is then KEPT even
    // if focus drops (tapping away shouldn't rip the fused droplet apart on
    // a long message). No rounded height comparisons (stale-neck fix).
    @Binding var isMultiline: Bool
    // The field grows up to ~38% of the screen height; beyond that the text
    // view scrolls internally instead of getting taller.
    var composerMaxHeight: CGFloat

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    func makeUIView(context: Context) -> UITextView {
        let tv = WidthPinnedTextView()
        tv.composerMaxHeight = composerMaxHeight
        tv.font = UIFont.preferredFont(forTextStyle: .body)
        tv.textColor = UIColor.white
        tv.backgroundColor = .clear
        tv.tintColor = UIColor(red: 0.38, green: 0.68, blue: 0.93, alpha: 1.0) // #62AEEE
        tv.isScrollEnabled = false
        tv.alwaysBounceVertical = false
        // Telegram style: the keyboard's key is a plain RETURN — it inserts a
        // newline (the capsule grows; the message list follows the last
        // bubble). SENDING is the arrow button only.
        tv.returnKeyType = .default
        tv.enablesReturnKeyAutomatically = true
        tv.textContainerInset = UIEdgeInsets(top: 10, left: 13, bottom: 10, right: 13)
        tv.textContainer.lineFragmentPadding = 0
        tv.delegate = context.coordinator
        return tv
    }

    func updateUIView(_ tv: UITextView, context: Context) {
        (tv as? WidthPinnedTextView)?.composerMaxHeight = composerMaxHeight
        if tv.text != text {
            tv.text = text
            tv.invalidateIntrinsicContentSize()
            context.coordinator.scrollToBottom(tv)
        } else if tv.bounds.width > 0, abs(tv.bounds.width - context.coordinator.lastLayoutWidth) > 0.5 {
            // Width changed (rotation, split view, sidebar): the same text
            // wraps differently — recompute height/scroll state.
            context.coordinator.lastLayoutWidth = tv.bounds.width
        }
        // Recompute every pass (cached, writes only on real change) — the
        // one-line floor applies on first layout and every focus gain.
        recalculateHeight(tv)
        if focusToken != context.coordinator.lastFocusToken {
            context.coordinator.lastFocusToken = focusToken
            tv.becomeFirstResponder()
            tv.setNeedsLayout()
            context.coordinator.showCaret(tv)
        }
    }

    func recalculateHeight(_ tv: UITextView) {
        let width = tv.bounds.width > 0 ? tv.bounds.width : UIScreen.main.bounds.width - 80
        // Same battle-tested measurement intrinsicContentSize uses:
        // sizeThatFits INCLUDES textContainerInset, which is safe because the
        // insets are FIXED — set once in makeUIView and never mutated (the old
        // layoutSubviews caret-parking hack that fed its own output back into
        // this measurement is GONE). No feedback loop → the capsule grows with
        // the text and shrinks back to one line when it is cleared/sent.
        let fitted = ceil(tv.sizeThatFits(CGSize(width: width, height: .greatestFiniteMagnitude)).height)
        let lineHeight = ceil(tv.font?.lineHeight ?? 22)
        let oneLine = lineHeight + 20
        let clamped = min(max(oneLine, fitted), composerMaxHeight)
        // Single-line reference (one text line + vertical insets): only a
        // height clearly above it counts as "multiline". A bare `> 40` check
        // fired on rounded-up single-line heights (40.x → 41) and kept the
        // metaball neck alive after the text was cleared.
        let multiline = fitted > oneLine + 2
        DispatchQueue.main.async {
            if abs(clamped - self.contentHeight) > 0.5 { self.contentHeight = clamped }
            if self.isMultiline != multiline { self.isMultiline = multiline }
        }
        // Toggling scroll state is the classic "stuck" trap: a UITextView
        // keeps its old contentOffset after scroll turns OFF (text appeared
        // clipped/overflowing) and its rounded intrinsic height lingers one
        // layout pass longer than the neck's exit animation. Reset both
        // atomically on the transition.
        let shouldScroll = fitted > composerMaxHeight
        if tv.isScrollEnabled != shouldScroll {
            tv.isScrollEnabled = shouldScroll
            if !shouldScroll {
                tv.setContentOffset(.zero, animated: false)
            }
            tv.invalidateIntrinsicContentSize()
        }
    }

    final class Coordinator: NSObject, UITextViewDelegate {
        var parent: GrowingTextView
        var lastFocusToken: Int = 0
        /// Width the height was last computed against (rotation/split guard).
        var lastLayoutWidth: CGFloat = 0

        init(_ parent: GrowingTextView) {
            self.parent = parent
        }

        func textViewDidChange(_ textView: UITextView) {
            parent.text = textView.text
            textView.invalidateIntrinsicContentSize()
            parent.recalculateHeight(textView)
            if textView.isScrollEnabled {
                scrollToBottom(textView)
            }
        }

        // Keeps the caret line visible: when the field is at its height cap
        // and scrolls internally, pin the view to the bottom like Telegram.
        func scrollToBottom(_ tv: UITextView) {
            DispatchQueue.main.async {
                // A NON-scrolling UITextView still honors contentOffset for
                // DRAWING: with isScrollEnabled == false contentSize equals
                // bounds, so the old `bottom = inset.bottom` (≥ 0) shifted the
                // text AND the caret ~10pt ABOVE their true position — the
                // "caret too high / text crooked" bug. Vertical alignment is
                // handled by textContainerInset; only a view that actually
                // scrolls (text taller than the cap) may have an offset.
                guard tv.isScrollEnabled else {
                    if tv.contentOffset != .zero {
                        tv.setContentOffset(.zero, animated: false)
                    }
                    return
                }
                let bottom = max(0, tv.contentSize.height - tv.bounds.height + tv.textContainerInset.bottom)
                tv.setContentOffset(CGPoint(x: 0, y: bottom), animated: false)
            }
        }

        // Ensures the caret `|` is visible after becomeFirstResponder().
        // Without this, the caret may appear at the top of the text view
        // (outside the visible area) or not appear at all on first tap.
        func showCaret(_ tv: UITextView) {
            DispatchQueue.main.async {
                // updateUIView called becomeFirstResponder before scheduling
                // this; keep a defensive retry.
                if !tv.isFirstResponder {
                    tv.becomeFirstResponder()
                }
                // Explicitly place the caret at the END of the text (0 when
                // empty) — UITextView may not render the blinking bar at all
                // otherwise on first focus.
                let length = tv.text.isEmpty ? 0 : tv.text.utf16.count
                tv.selectedRange = NSRange(location: length, length: 0)
                // Scroll so the caret LINE is visible at the bottom of the
                // capsule (Telegram style: last line sits above the field's
                // bottom edge, not clipped at the top).
                self.scrollToBottom(tv)
                tv.setNeedsLayout()
            }
        }    }
}
