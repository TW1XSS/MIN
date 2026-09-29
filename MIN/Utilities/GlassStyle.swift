import SwiftUI
import UIKit

// MARK: - Haptic Feedback

final class HapticManager {
    static let shared = HapticManager()

    // On the simulator there is no Taptic Engine — constructing or firing
    // generators spams "CoreHaptics CHHapticPattern ... hapticpatternlibrary.plist"
    // errors into the log. So on the simulator all haptics are no-ops.
    #if !targetEnvironment(simulator)
    private lazy var lightGenerator = UIImpactFeedbackGenerator(style: .light)
    private lazy var mediumGenerator = UIImpactFeedbackGenerator(style: .medium)
    private lazy var heavyGenerator = UIImpactFeedbackGenerator(style: .heavy)
    private lazy var notificationGenerator = UINotificationFeedbackGenerator()
    private lazy var selectionGenerator = UISelectionFeedbackGenerator()
    #endif

    private init() {
        #if !targetEnvironment(simulator)
        prepare()
        #endif
    }

    func prepare() {
        #if targetEnvironment(simulator)
        return
        #else
        lightGenerator.prepare()
        mediumGenerator.prepare()
        heavyGenerator.prepare()
        notificationGenerator.prepare()
        selectionGenerator.prepare()
        #endif
    }

    #if targetEnvironment(simulator)
    // No-op stubs keep call sites unchanged across the codebase.
    func lightImpact() {}
    func mediumImpact() {}
    func heavyImpact() {}
    func success() {}
    func error() {}
    func selectionChanged() {}
    #else
    func lightImpact() { lightGenerator.impactOccurred() }
    func mediumImpact() { mediumGenerator.impactOccurred() }
    func heavyImpact() { heavyGenerator.impactOccurred() }
    func success() { notificationGenerator.notificationOccurred(.success) }
    func error() { notificationGenerator.notificationOccurred(.error) }
    func selectionChanged() { selectionGenerator.selectionChanged() }
    #endif
}

// MARK: - Keyboard (iOS 13 compatible, replaces @FocusState)

final class KeyboardWatcher: ObservableObject {
    static let shared = KeyboardWatcher()

    @Published var height: CGFloat = 0

    private init() {
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(keyboardFrameChanged(_:)),
            name: UIResponder.keyboardWillChangeFrameNotification,
            object: nil
        )
    }

    private var bottomSafeInset: CGFloat {
        // More safe version for new iOS
        (UIApplication.shared.connectedScenes.first as? UIWindowScene)?
            .windows.first(where: { $0.isKeyWindow })?.safeAreaInsets.bottom ?? 0
    }

    @objc private func keyboardFrameChanged(_ notification: Notification) {
        guard let endFrame = (notification.userInfo?[UIResponder.keyboardFrameEndUserInfoKey] as? NSValue)?.cgRectValue else {
            return
        }
        let screenBottom = UIScreen.main.bounds.height
        let overlap = max(0, screenBottom - endFrame.minY - bottomSafeInset)
        height = overlap
    }

    static func dismissKeyboard() {
        UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
    }
}

extension View {
    /// Opts the view OUT of SwiftUI's automatic keyboard avoidance
    /// (`.ignoresSafeArea(.keyboard)` is iOS 14+; on iOS 13 it is a no-op
    /// and the system avoidance stays in charge).
    /// ChatView pairs this with a manual KeyboardWatcher-driven padding.
    @ViewBuilder
    func ignoresKeyboardSafeArea() -> some View {
        if #available(iOS 14.0, *) {
            self.ignoresSafeArea(.keyboard, edges: .bottom)
        } else {
            self
        }
    }
}

// MARK: - Liquid Glass surfaces (iOS 13+)

// MARK: - Glass gradient fade (Telegram/iMessage style)
// A real UIVisualEffectView whose blur fades through a gradient mask:
// soapy/frosted at the screen edge -> fully transparent at mid-screen.
// No tint/fill color, no borders — only blur intensity fading.

struct GlassFadeView: UIViewRepresentable {
    var isTop: Bool // true = solid near the status bar, fades downward

    func makeUIView(context: Context) -> FrostedGlassView {
        FrostedGlassView(isTop: isTop)
    }

    func updateUIView(_ uiView: FrostedGlassView, context: Context) {
        uiView.isTop = isTop
    }
}

final class FrostedGlassView: UIVisualEffectView {
    var isTop: Bool {
        didSet {
            guard isTop != oldValue else { return }
            updateMask()
        }
    }

    private let gradient = CAGradientLayer()
    private let blackTint = UIView()

    init(isTop: Bool) {
        self.isTop = isTop
        super.init(effect: UIBlurEffect(style: .systemMaterialDark))
        backgroundColor = .clear
        blackTint.backgroundColor = UIColor.black.withAlphaComponent(0.84)
        contentView.addSubview(blackTint)
        layer.mask = gradient
        updateMask()
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func layoutSubviews() {
        super.layoutSubviews()
        blackTint.frame = contentView.bounds
        gradient.frame = bounds
    }

    private func updateMask() {
        let opaque = UIColor.black.withAlphaComponent(0.95).cgColor
        let clear = UIColor.clear.cgColor
        let soft = UIColor.black.withAlphaComponent(0.70).cgColor
        gradient.colors = isTop
            ? [opaque, soft, clear]
            : [clear, soft, opaque]
        gradient.locations = isTop ? [0, 0.55, 1] : [0, 0.55, 1]
        gradient.startPoint = CGPoint(x: 0.5, y: 0)
        gradient.endPoint = CGPoint(x: 0.5, y: 1)
        gradient.frame = bounds
    }
}

// MARK: - Liquid Glass panels (native on iOS 26, glass-gradient fallback below)

extension View {
    /// Native Liquid Glass on iOS 26; on earlier iOS — tinted panel with a specular glass border.
    /// `tintOpacity` 1.0 = solid surface (accent CTAs), <1 = translucent glass.
    @ViewBuilder
    func glassPanel(cornerRadius: CGFloat, tint: Color, interactive: Bool = false, tintOpacity: CGFloat = 0.32) -> some View {
        if #available(iOS 26, *) {
            if interactive {
                self.glassEffect(Glass.regular.tint(tint.opacity(tintOpacity)).interactive(), in: .rect(cornerRadius: cornerRadius))
            } else {
                self.glassEffect(Glass.regular.tint(tint.opacity(tintOpacity)), in: .rect(cornerRadius: cornerRadius))
            }
        } else {
            self
                .background(
                    RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                        .fill(tint.opacity(tintOpacity))
                )
                .glassEdge(cornerRadius: cornerRadius)
        }
    }

    /// Round glass button (native tinted glass on iOS 26, filled circle below).
    @ViewBuilder
    func glassCircle(tint: Color, tintOpacity: CGFloat = 0.32) -> some View {
        if #available(iOS 26, *) {
            // Semi-transparent tint: a fully opaque color would kill the
            // liquid-glass effect and render the button as a solid pill.
            self.glassEffect(Glass.regular.tint(tint.opacity(tintOpacity)).interactive(), in: Circle())
        } else {
            self.background(Circle().fill(tint.opacity(tintOpacity)))
        }
    }

    /// Specular gradient border — the visible edge that makes a surface read as glass.
    func glassEdge(cornerRadius: CGFloat) -> some View {
        overlay(
            RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                .strokeBorder(
                    LinearGradient(
                        colors: [Color.white.opacity(0.35), Color.white.opacity(0.10), Color.white.opacity(0.04)],
                        startPoint: .top,
                        endPoint: .bottom
                    ),
                    lineWidth: 1
                )
        )
    }
    /// Overlays a black gradient on top of the frosted blur so the fade
    /// reads as "black -> transparent" (matches the pure-black app background).
    func blackenedGlass(isTop: Bool) -> some View {
        self.overlay(
            LinearGradient(
                stops: isTop
                    ? [Gradient.Stop(color: .black, location: 0),
                       Gradient.Stop(color: .black, location: 0.55),
                       Gradient.Stop(color: .clear, location: 1)]
                          : [Gradient.Stop(color: .clear, location: 0),
                              Gradient.Stop(color: .black.opacity(0.28), location: 0.30),
                              Gradient.Stop(color: .black.opacity(0.72), location: 0.68),
                               Gradient.Stop(color: .black.opacity(0.80), location: 1)],
                startPoint: .top,
                endPoint: .bottom
            )
        )
    }
}

// MARK: - Minimal press feedback (system-like, no custom animation)

struct PressableButtonStyle: ButtonStyle {
    var scale: CGFloat = 1.0

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .opacity(configuration.isPressed ? 0.7 : 1.0)
    }
}

// MARK: - Interactive swipe-back from the left edge (works even with hidden nav bar)

extension UINavigationController: UIGestureRecognizerDelegate {
    override open func viewDidLoad() {
        super.viewDidLoad()
        interactivePopGestureRecognizer?.delegate = self
    }

    public func gestureRecognizer(_ gestureRecognizer: UIGestureRecognizer, shouldBegin: Bool) -> Bool {
        // "< Back" via swipe from the left edge, only when there is somewhere to go back
        viewControllers.count > 1
    }

    public func gestureRecognizer(
        _ gestureRecognizer: UIGestureRecognizer,
        shouldRecognizeSimultaneouslyWith otherGestureRecognizer: UIGestureRecognizer
    ) -> Bool {
        false
    }
}

