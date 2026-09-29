import SwiftUI
import UIKit

struct MessagesListView: View, Equatable {
    // Value-based inputs (not a Chat binding) + Equatable: the parent re-renders
    // on every keyboard-height tick, and without Equatable SwiftUI rebuilt this
    // whole list (sort + all bubbles) on each tick — the source of the typing/
    // keyboard lag on real devices. With Equatable the body is SKIPPED unless
    // messages actually change.
    let chatID: UUID
    let messages: [Message]
    var onReply: (Message) -> Void
    var contentTopInset: CGFloat = 64
    var contentBottomInset: CGFloat = 88
    var keyboardInset: CGFloat = 0
    // Keyboard overlap (0 when closed). Piped as a SwiftUI input instead of
    // the old native contentInset write: SwiftUI owns the scroll's
    // contentInset and RESETS a direct write on the next layout pass (the
    // inset read 0 again while the keyboard was visibly open — the chat
    // could not be scrolled with the keyboard up). Keyboard height changes
    // only on open/close, so the Equatable skip still holds for typing.

    static func == (lhs: MessagesListView, rhs: MessagesListView) -> Bool {
        // onReply is intentionally excluded: the parent recreates the closure on
        // every render, but the captured @State references keep it valid.
        lhs.chatID == rhs.chatID
            && lhs.messages == rhs.messages
            && lhs.contentTopInset == rhs.contentTopInset
            && lhs.contentBottomInset == rhs.contentBottomInset
            && lhs.keyboardInset == rhs.keyboardInset
    }

    private var scrollTrigger: AutoScroll.Trigger {
        // Only message count (and chat switch) drives auto-scroll. Keyboard height
        // and bottom-inset changes were firing on every animation frame and on the
        // reply-bar toggle — the source of the reply/typing lag.
        AutoScroll.Trigger(
            chatID: chatID,
            messageCount: messages.count
        )
    }

    var body: some View {
        // No scroll indicator: the chat draws its own glass header/footer,
        // the default scrollbar looks out of place on top of them.
        ScrollView(Axis.Set.vertical, showsIndicators: false) {
            VStack(spacing: 0) {
                // Content starts below the floating header and scrolls under its blur
                Spacer().frame(height: contentTopInset)

                ForEach(rows, id: \.key) { row in
                    rowView(row)
                }

                Spacer().frame(height: contentBottomInset)

                // Invisible anchor that scrolls the enclosing UIScrollView
                // to the bottom whenever the trigger changes (iOS 13+).
                AutoScroll(trigger: scrollTrigger)
                    .frame(width: 0, height: 1)
                    .opacity(0)
                // Native composer-follow: re-pins the scroll to the bottom
                // when the input capsule grows (multiline) OR the keyboard
                // opens/closes, so the last bubble stays ABOVE the composer
                // (Telegram). No-op while the user has scrolled up — reading
                // history must keep working. totalInset = composer + keyboard.
                ComposerFollowView(bottomInset: contentBottomInset)
                    .frame(width: 0, height: 0)
                    .opacity(0)
            }
            .padding(.horizontal, 4)
            // Tap-to-dismiss keyboard: this view is INSIDE the scroll view's
            // hierarchy, so enclosingScrollView() can find it reliably.
            .background(ScrollViewTapToDismiss())
        }
        // Extend under the status bar so bubbles scroll beneath the glass header
        .edgesIgnoringSafeArea(.top)
        // Telegram-style pop animation whenever a message is added/removed
        .animation(.spring(response: 0.4, dampingFraction: 0.76), value: messages.count)
    }

    @ViewBuilder
    private func rowView(_ row: Row) -> some View {
        switch row {
        case .day(_, let title):
            DayPill(title: title)
                .padding(.vertical, 10)

        case .msg(let message, let isFirst, let isLast):
            MessageBubble(
                message: message,
                isFromMe: message.sender == .me,
                isFirstInGroup: isFirst,
                isLastInGroup: isLast,
                onReply: {
                    HapticManager.shared.lightImpact()
                    onReply(message)
                }
            )
            .transition(.asymmetric(
                insertion: .scale(scale: 0.85, anchor: .bottom)
                    .combined(with: .offset(y: 24))
                    .combined(with: .opacity),
                removal: .opacity
            ))
        }
    }

    // MARK: - Row model

    private enum Row {
        case day(String, String)
        case msg(Message, Bool, Bool)

        var key: String {
            switch self {
            case .day(let k, _): return "day-\(k)"
            case .msg(let m, _, _): return m.id.uuidString
            }
        }
    }

    private var rows: [Row] {
        var result: [Row] = []
        let msgs = messages.sorted { $0.date < $1.date }
        var lastKey: String?

        for (i, m) in msgs.enumerated() {
            let key = dayKey(m.date)
            if key != lastKey {
                result.append(.day(key, dayTitle(m.date)))
                lastKey = key
            }

            let prev = i > 0 ? msgs[i - 1] : nil
            let next = i < msgs.count - 1 ? msgs[i + 1] : nil
            result.append(.msg(m, prev?.sender != m.sender, next?.sender != m.sender))
        }

        return result
    }

    private func dayKey(_ d: Date) -> String {
        let c = Calendar.current
        let dc = c.dateComponents([.year, .month, .day], from: d)
        return "\(dc.year ?? 0)-\(dc.month ?? 0)-\(dc.day ?? 0)"
    }

    private func dayTitle(_ d: Date) -> String {
        Calendar.current.isDateInToday(d) ? "Today" : DateFormatters.dayTitle.string(from: d)
    }
}

// MARK: - Tap-to-dismiss keyboard via UIKit (never delays touches, ignores text inputs)

struct ScrollViewTapToDismiss: UIViewRepresentable {
    func makeUIView(context: Context) -> UIView {
        let v = UIView()
        v.backgroundColor = .clear
        // Attempt attach now (view may already be inside the scroll hierarchy);
        // updateUIView retries until success.
        context.coordinator.attach(to: v)
        return v
    }

    func updateUIView(_ uiView: UIView, context: Context) {
        context.coordinator.attach(to: uiView)
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    final class Coordinator: NSObject, UIGestureRecognizerDelegate {
        private weak var scrollView: UIScrollView?
        private var gestureAttached = false
        // Bounded retry: if the view never reaches a scroll view hierarchy
        // (e.g. detached branch), stop after ~1 second of attempts instead of
        // spinning async retries forever.
        private var retryCount = 0
        private let maxRetries = 60

        func attach(to view: UIView) {
            guard !gestureAttached else { return }
            guard let scrollView = view.enclosingScrollView() else {
                retryCount += 1
                guard retryCount < maxRetries else { return }
                // The view is built before it enters the hierarchy — retry shortly.
                DispatchQueue.main.async { [weak self] in
                    self?.attach(to: view)
                }
                return
            }
            gestureAttached = true
            self.scrollView = scrollView
            let tap = UITapGestureRecognizer(target: self, action: #selector(handleTap))
            tap.cancelsTouchesInView = false
            tap.delegate = self
            scrollView.addGestureRecognizer(tap)
        }

        @objc func handleTap() { KeyboardWatcher.dismissKeyboard() }

        func gestureRecognizer(_ gestureRecognizer: UIGestureRecognizer, shouldReceive touch: UITouch) -> Bool {
            // Never steal touches from text inputs — that was causing keyboard lag
            !(touch.view is UITextView)
        }

        func gestureRecognizer(
            _ gestureRecognizer: UIGestureRecognizer,
            shouldRecognizeSimultaneouslyWith otherGestureRecognizer: UIGestureRecognizer
        ) -> Bool { true }
    }
}


// MARK: - iOS 13 auto-scroll (ScrollViewReader needs iOS 14)

struct AutoScroll: UIViewRepresentable {
    struct Trigger: Equatable {
        let chatID: UUID
        let messageCount: Int
    }

    var trigger: Trigger

    func makeUIView(context: Context) -> UIView {
        let v = UIView()
        v.isHidden = true
        return v
    }

    func updateUIView(_ view: UIView, context: Context) {
        // MUST fire on the very first update too: the coordinator seeds its
        // state with the current trigger, so an initial `!=` check would
        // silently skip the launch scroll and an overflowing chat opened
        // with its tail hidden behind the composer. The fired flag makes the
        // FIRST update always scroll; later updates still require a change.
        guard !context.coordinator.fired || context.coordinator.lastTrigger != trigger else { return }
        context.coordinator.fired = true
        context.coordinator.lastTrigger = trigger
        // Staggered (0 / 0.15 / 0.45s), each write recomputing the target
        // live: on the first hop contentSize is still mid-build — a single
        // async write computed the bottom target against a half-laid list
        // and the chat opened scrolled UP with its tail under the composer.
        // The last write always sees the fully laid-out list.
        for delay in [0.0, 0.15, 0.45] {
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
                guard let scrollView = view.enclosingScrollView() else { return }
                let target = max(0, scrollView.contentSize.height - scrollView.bounds.height + scrollView.adjustedContentInset.bottom)
                // Reading history must keep working: a user who scrolled
                // up away from the last auto-pinned bottom is not yanked.
                guard scrollView.contentOffset.y >= context.coordinator.lastSetOffset - 30 else { return }
                UIView.animate(withDuration: 0.25, delay: 0, options: [.curveEaseOut, .allowUserInteraction]) {
                    scrollView.contentOffset = CGPoint(x: scrollView.contentOffset.x, y: target)
                }
                context.coordinator.lastSetOffset = target
            }
        }
    }

    func makeCoordinator() -> Coordinator { Coordinator(trigger) }

    final class Coordinator {
        var lastTrigger: Trigger
        var fired = false
        // Last bottom offset this anchor set; the reader guard compares the
        // live offset against it (seeded -1 so the FIRST fire — the launch
        // scroll — always passes).
        var lastSetOffset: CGFloat = -1
        init(_ t: Trigger) { lastTrigger = t }
    }
}

private extension UIView {
    func enclosingScrollView() -> UIScrollView? {
        var current: UIView? = self
        while let candidate = current {
            if let scrollView = candidate as? UIScrollView { return scrollView }
            current = candidate.superview
        }
        return nil
    }
}

// MARK: - Native composer-follow (last bubble above the growing field)

/// Tracks the composer height (piped through the list's SwiftUI input —
/// `contentBottomInset` already includes the live capsule height) and re-pins
/// the enclosing UIScrollView to the bottom whenever the capsule grows or
/// shrinks WHILE the user is near the bottom — the last message then rides
/// just above the composer's top edge (Telegram). When the user has scrolled
/// up, the pin does NOT fire: reading history keeps working and the grown
/// capsule simply covers the bottom of the viewport.
///
/// This works through the content SPACER, not `contentInset.bottom`: the
/// keyboard's native view writes the inset ABSOLUTELY (`= overlap`) and would
/// wipe any composer component living there — the two mechanisms coexist.
struct ComposerFollowView: UIViewRepresentable {
    var bottomInset: CGFloat

    func makeUIView(context: Context) -> FollowView {
        let v = FollowView()
        v.current = bottomInset
        return v
    }

    func updateUIView(_ view: FollowView, context: Context) {
        view.apply(newInset: bottomInset)
    }

    final class FollowView: UIView {
        var current: CGFloat = 0
        // Active follow-pin state. pendingWrites/generation dedupe the
        // staggered chases (see chaseBottom).
        private var lastSetOffset: CGFloat = -1
        private var pendingWrites = 0
        private var generation = 0

        override init(frame: CGRect) {
            super.init(frame: frame)
        }

        required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

        func apply(newInset: CGFloat) {
            guard abs(newInset - current) > 0.5 else { return }
            let wasClosed = current < 1
            current = newInset
            guard let scrollView = enclosingScrollView() else { return }
            // Chase on EVERY bottom-gap change: keyboard open/close, composer
            // grow/shrink (multiline), reply bar toggle. This is the ONLY
            // reliable event — FollowView is a 0x0 view, so its layoutSubviews
            // stops firing after the first layout pass and a grown Spacer
            // (composer/keyboard) never re-layouts it: chasing from
            // layoutSubviews left the last bubble under the grown field.
            // force=true only for the true closed->open transition (inset was
            // ~0): the user just focused the field. Otherwise the chase is
            // guarded by userScrolledAway — reading history must keep working
            // (Telegram keeps the position of a reader too).
            chaseBottom(in: scrollView, force: wasClosed && newInset > 1)
        }

        // Chasing = up to 3 staggered offset writes (0 / 0.15 / 0.45s), each
        // recomputing the target LIVE: SwiftUI applies the taller Spacer over
        // the next few layout passes, so a single write races the layout and
        // lands short (bubble flush against / under the capsule). The last
        // write always sees the fully laid-out list.
        //
        // force=true (true closed->open keyboard transition) skips the
        // user-scroll guard: the offset legitimately lags the new target by
        // the keyboard overlap.
        private func userScrolledAway(in scrollView: UIScrollView) -> Bool {
            // The user manually scrolled up away from the last bottom WE set.
            scrollView.contentOffset.y < lastSetOffset - 30
        }

        private func chaseBottom(in scrollView: UIScrollView, force: Bool) {
            // Dedupe: the keyboard slide emits ~30 inset ticks; without this
            // each tick would schedule 3 more writes = the open/close stutter.
            // A non-force chase while a stagger is already converging is
            // redundant: those writes recompute the target live and converge
            // on the new gap too. A FORCE chase preempts: generation bump
            // invalidates the in-flight writes.
            guard force || pendingWrites == 0 else { return }
            generation += 1
            for delay in [0.0, 0.15, 0.45] {
                let gen = generation
                pendingWrites += 1
                DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
                    guard let self = self else { return }
                    defer { self.pendingWrites -= 1 }
                    guard gen == self.generation, scrollView.window != nil else { return }
                    if !force, self.userScrolledAway(in: scrollView) { return }
                    self.setContentOffset(self.maxOffset(in: scrollView), in: scrollView)
                }
            }
        }

        private func maxOffset(in scrollView: UIScrollView) -> CGFloat {
            max(0, scrollView.contentSize.height - scrollView.bounds.height + scrollView.adjustedContentInset.bottom)
        }

        private func setContentOffset(_ target: CGFloat, in scrollView: UIScrollView) {
            scrollView.contentOffset.y = target
            lastSetOffset = target
        }

        // Initial pin ONLY: the very first real layout pass. A 0x0 view's
        // layoutSubviews never fires again afterwards (its frame does not
        // change when the Spacer grows), so all later chasing is event-driven
        // via apply(). The staggered chase corrects the open race: the first
        // passes here can see a mid-build contentSize (bubbles not yet laid
        // out) and pin to a target that is a few hundred pt short.
        override func layoutSubviews() {
            super.layoutSubviews()
            guard lastSetOffset < 0, let scrollView = enclosingScrollView() else { return }
            let target = maxOffset(in: scrollView)
            guard target > 0 else { return }
            setContentOffset(target, in: scrollView)
            chaseBottom(in: scrollView, force: false)
        }
    }
}

// MARK: - Day Pill Component

struct DayPill: View {
    let title: String

    var body: some View {
        Text(title)
            .font(.system(size: 12, weight: .semibold))
            .foregroundColor(MINTheme.textSecondary)
            .padding(.horizontal, 12)
            .padding(.vertical, 5)
            .background(Capsule().fill(Color.white.opacity(0.08)))
            .overlay(Capsule().stroke(Color.white.opacity(0.08), lineWidth: 0.5))
    }
}
