import UIKit
import SwiftUI

// iOS 13 compatible entry point (SwiftUI App lifecycle requires iOS 14+).
@available(iOS 15.0, *)
@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {
    static let appState = AppState()

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        // Окно/сцена — в SceneDelegate (iOS 27 требует scene lifecycle,
        // иначе SIGTRAP «NoSceneLifecycleAdoption» — миграция обязательна).
        HapticManager.shared.prepare()
        // Реальное ядро: открыть/создать identity, зарегистрировать mailbox,
        // получить инвайт для обмена контактами. Асинхронно — UI стартует сразу.
        // Снимок с диска — сразу, до Tor: список чатов не должен быть пустым,
        // пока ядро поднимается. Bootstrap его потом перезапишет свежим.
        Self.appState.loadCachedChats()
        Self.appState.bootstrapCore()
        Self.appState.runDebugPeerSmokeIfRequested()
        // Отметки «прочитано» живут в ядре (источник истины) и зеркалятся в
        // снимок: до подъёма Tor список рисуется из кэша, где без отметки
        // всё прочитанное выглядело бы непрочитанным.
        Self.appState.primeReadMarkersFromCache()
        Self.appState.loadReadMarkers()
        // Перенос старых отметок из кэша в ядро — один раз, чтобы обновление
        // не выглядело как «всё снова непрочитанное».
        Self.appState.migrateReadMarkersFromCache()
        return true
    }

    /// iOS 13+ scene lifecycle: конфигурация сцены задаётся программно —
    /// Info.plist не требует UIApplicationSceneManifest-конфигураций.
    func application(
        _ application: UIApplication,
        configurationForConnecting connectingSceneSession: UISceneSession,
        options: UIScene.ConnectionOptions
    ) -> UISceneConfiguration {
        let config = UISceneConfiguration(name: "Default", sessionRole: connectingSceneSession.role)
        config.delegateClass = SceneDelegate.self
        return config
    }
}

/// Владелец окна. Перенесено из AppDelegate (UIScene-миграция, iOS 15+).
@available(iOS 15.0, *)
class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    /// Foreground pull: mailbox клиента переживает перезапуск relay через
    /// persistent auth-state. Jitter 20±5 c не создаёт одинаковый ритм у всех.
    private var foregroundPollTimer: Timer?
    private var foregroundPollJitter = 3.0

    func scene(
        _ scene: UIScene,
        willConnectTo session: UISceneSession,
        options connectionOptions: UIScene.ConnectionOptions
    ) {
        guard let windowScene = scene as? UIWindowScene else { return }
        let appState = AppDelegate.appState

        let uiWindow = UIWindow(windowScene: windowScene)

        if (ProcessInfo.processInfo.arguments.contains("-openChatDebug")
            || ProcessInfo.processInfo.arguments.contains("-openChatPlain")),
           !appState.chats.isEmpty {
            // DEBUG: open the first chat so the composer can be verified in
            // screenshots. -openChatDebug also prefills long unbroken text
            // (wrapping + metaball merge check); -openChatPlain opens the
            // chat cold — unfocused, empty field (neck-hidden state check).
            // The chat lives inside the normal ChatListView so the "<" back
            // button pops to the list — NOT to an empty root (black screen).
            let prefill = ProcessInfo.processInfo.arguments.contains("-openChatDebug")
                ? String(repeating: "О", count: 96)
                : ""
            let chat = appState.chats[0]
            // -openChatDebug also floods the FIRST chat with mock messages so
            // the list OVERFLOWS the screen: composer-follow, top-alignment
            // and the bubble-to-field gap can only be verified with a
            // scrollable history.
            var debugChat = chat
            let base = chat.messages.last?.date ?? Date()
            for i in 0..<14 {
                debugChat.messages.append(Message(
                    sender: i % 2 == 0 ? .other : .me,
                    text: "Overflow msg \(i + 1)",
                    date: base.addingTimeInterval(TimeInterval(i * 60)),
                    localStatus: i % 2 == 0 ? .received : .sent
                ))
            }
            appState.chats[0] = debugChat
            uiWindow.rootViewController = UIHostingController(
                rootView: NavigationView {
                    ChatListView(debugPrefill: prefill, autoOpenChatID: chat.id)
                }
                .navigationViewStyle(StackNavigationViewStyle())
                .environmentObject(appState)
                .preferredColorScheme(.dark)
            )
        } else {
            let root = NavigationView {
                ChatListView()
            }
            .navigationViewStyle(StackNavigationViewStyle())
            .environmentObject(appState)
            .preferredColorScheme(.dark)
            uiWindow.rootViewController = UIHostingController(rootView: root)
        }

        uiWindow.makeKeyAndVisible()
        window = uiWindow
    }

    /// Возврат в приложение (сцена активна): быстрый pull очереди с relay.
    /// Раньше был applicationDidBecomeActive в AppDelegate.
    func sceneDidBecomeActive(_ scene: UIScene) {
        // Ядро ещё не поднялось (сеть/relay были недоступны) — повторяем;
        // иначе обычный быстрый pull очереди.
        if AppDelegate.appState.isCoreReady {
            AppDelegate.appState.pollAndReload()
        } else {
            AppDelegate.appState.bootstrapCore()
        }
        startForegroundPolling()
    }

    func sceneWillResignActive(_ scene: UIScene) {
        stopForegroundPolling()
    }

    private func startForegroundPolling() {
        stopForegroundPolling()
        foregroundPollJitter = Double.random(in: 0.0...10.0)
        let timer = Timer(timeInterval: 20.0 + foregroundPollJitter, repeats: true) { _ in
            guard AppDelegate.appState.isCoreReady else { return }
            AppDelegate.appState.pollAndReload()
        }
        // .common: продолжает корректно отсчитывать при работе с системными
        // UI-событиями, но НЕ работает в background — там сцену выключает stop.
        RunLoop.main.add(timer, forMode: .common)
        foregroundPollTimer = timer
    }

    private func stopForegroundPolling() {
        foregroundPollTimer?.invalidate()
        foregroundPollTimer = nil
    }
}
