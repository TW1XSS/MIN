import SwiftUI

struct AddContactView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.presentationMode) private var presentationMode

    @State private var publicKeyInput = ""
    @State private var showCopied = false
    /// Статус добавления контакта (ошибка ядра/сети — коротким текстом).
    @State private var statusText = ""

    private let controlH: CGFloat = 52

    var body: some View {
        ZStack {
            Color.black.edgesIgnoringSafeArea(.all)

            VStack(spacing: 0) {
                header

                // find section
                Text("You can scan the QR code or enter the public key to start a conversation.")
                    .font(.system(size: 15))
                    .foregroundColor(Color.white.opacity(0.75))
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: .infinity)
                    .padding(.top, 16)
                    .padding(.bottom, 18)

                Button {
                    HapticManager.shared.mediumImpact()
                } label: {
                    Text("Scan QR code")
                        .font(.system(size: 17, weight: .semibold))
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity, minHeight: controlH)
                        .glassPanel(cornerRadius: MINTheme.cornerRadius, tint: MINTheme.accent, interactive: true, tintOpacity: 1)
                        .contentShape(RoundedRectangle(cornerRadius: MINTheme.cornerRadius, style: .continuous))
                }
                .buttonStyle(PressableButtonStyle(scale: 0.97))

                HStack(spacing: 10) {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(Color.white.opacity(0.45))
                    StableTextField(
                        text: $publicKeyInput,
                        placeholder: "Enter the public key",
                        placeholderColor: UIColor.white.withAlphaComponent(0.40),
                        textColor: UIColor.white,
                        onSubmit: { submitContact() }
                    )
                }
                .padding(.horizontal, 16)
                // Без maxWidth контейнер раздувается intrinsic-шириной
                // UITextField (длинный ключ растягивал ВЕСЬ лист в 4 раза —
                // UI-тест testAddContactKeyInputLayout).
                .frame(maxWidth: .infinity)
                .frame(height: controlH)
                .glassPanel(cornerRadius: MINTheme.cornerRadius, tint: MINTheme.inputBG, interactive: true)
                .padding(.top, 12)

                if !statusText.isEmpty {
                    Text(statusText)
                        .font(.system(size: 13))
                        .foregroundColor(.white.opacity(0.65))
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: .infinity)
                        .padding(.top, 8)
                }
                SectionPill(title: "share")
                    .padding(.top, 28)

                Text("You can share your QR code or public key to let other users start a conversation with you.")
                    .font(.system(size: 15))
                    .foregroundColor(Color.white.opacity(0.75))
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: .infinity)
                    .padding(.top, 16)
                    .padding(.bottom, 18)

                Button {
                    HapticManager.shared.mediumImpact()
                } label: {
                    Text("Your QR code")
                        .font(.system(size: 17, weight: .semibold))
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity, minHeight: controlH)
                        .glassPanel(cornerRadius: MINTheme.cornerRadius, tint: MINTheme.accent, interactive: true, tintOpacity: 1)
                        .contentShape(RoundedRectangle(cornerRadius: MINTheme.cornerRadius, style: .continuous))
                }
                .buttonStyle(PressableButtonStyle(scale: 0.97))

                Button {
                    UIPasteboard.general.string = appState.user.publicKey
                    HapticManager.shared.success()
                    withAnimation(.easeInOut(duration: 0.2)) { showCopied = true }
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
                        withAnimation(.easeInOut(duration: 0.2)) { showCopied = false }
                    }
                } label: {
                    Text(appState.user.publicKey)
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundColor(.white)
                        .underline()
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .frame(maxWidth: .infinity, minHeight: controlH)
                        .glassPanel(cornerRadius: MINTheme.cornerRadius, tint: MINTheme.inputBG, interactive: true)
                        .contentShape(RoundedRectangle(cornerRadius: MINTheme.cornerRadius, style: .continuous))
                }
                .buttonStyle(PressableButtonStyle(scale: 0.97))
                .padding(.top, 12)

                Spacer(minLength: 40)
            }
            .padding(.horizontal, 20)
            .padding(.top, 8)

            if showCopied {
                Text("Copied!")
                    .font(.footnote)
                    .foregroundColor(.white)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(Capsule().fill(Color(hex: "2C2C2E")))
                    .transition(.opacity)
                    .padding(.bottom, 28)
                    .frame(maxHeight: .infinity, alignment: .bottom)
            }
        }
        .navigationBarHidden(true)
        .onAppear {
            HapticManager.shared.prepare()
        }
    }

    // "< Back" on the left, centered "find" pill
    private var header: some View {
        ZStack {
            SectionPill(title: "find")

            HStack {
                Button {
                    HapticManager.shared.lightImpact()
                    presentationMode.wrappedValue.dismiss()
                } label: {
                    Image(systemName: "chevron.left")
                        .font(.system(size: 17, weight: .semibold))
                        .foregroundColor(.white)
                        .frame(width: 38, height: 38)
                        .glassCircle(tint: MINTheme.control)
                        .contentShape(Circle())
                }
                .buttonStyle(PressableButtonStyle())

                Spacer()
            }
        }
        .padding(.top, 10)
    }

    // MARK: - Actions

    /// MVP-поток: ввёл инвайт собеседника → контакт добавлен → чат открывается сам.
    private func submitContact() {
        let trimmed = publicKeyInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        HapticManager.shared.mediumImpact()
        statusText = "Adding contact…"
        appState.addContact(invite: trimmed) { ok in
            if ok {
                statusText = ""
                presentationMode.wrappedValue.dismiss()
            } else {
                statusText = "Failed to add contact: " + appState.coreStatus
            }
        }
    }
}

// MARK: - Stable text field (reliable first-responder behavior)

struct StableTextField: UIViewRepresentable {
    @Binding var text: String
    var placeholder: String
    var placeholderColor: UIColor
    var textColor: UIColor
    /// Вызывается по нажатию Return на клавиатуре (MVP: «ввёл ключ → чат открылся»).
    var onSubmit: (() -> Void)? = nil

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeUIView(context: Context) -> UITextField {
        let tf = UITextField()
        tf.backgroundColor = .clear
        tf.textColor = textColor
        // Текст и плейсхолдер — всегда слева (как поле ввода в браузере).
        tf.textAlignment = .left
        tf.autocorrectionType = .no
        tf.autocapitalizationType = .none
        tf.keyboardAppearance = .dark
        tf.delegate = context.coordinator
        // Длинный ключ (7k+ символов) не должен растягивать layout:
        // intrinsic-ширина текста сжимается контейнером, текст обрезается.
        // Hugging low — поле в норме растягивается на всю ширину пилюли.
        tf.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        tf.setContentHuggingPriority(.defaultLow, for: .horizontal)
        return tf
    }

    func updateUIView(_ tf: UITextField, context: Context) {
        if tf.text != text {
            tf.text = text
        }
        tf.attributedPlaceholder = NSAttributedString(
            string: placeholder,
            attributes: [.foregroundColor: placeholderColor]
        )
    }

    final class Coordinator: NSObject, UITextFieldDelegate {
        var parent: StableTextField
        init(_ parent: StableTextField) { self.parent = parent }

        func textFieldDidChangeSelection(_ textField: UITextField) {
            parent.text = textField.text ?? ""
        }

        func textFieldShouldReturn(_ textField: UITextField) -> Bool {
            parent.onSubmit?()
            textField.resignFirstResponder()
            return true
        }
    }
}
