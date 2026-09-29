import SwiftUI

private struct ChatsPillPositionKey: PreferenceKey {
    static var defaultValue: CGFloat = .greatestFiniteMagnitude

    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
        value = nextValue()
    }
}

@available(iOS 15.0, *)
struct ChatListView: View {
    @EnvironmentObject var appState: AppState
    @State private var showAddContact = false
    @State private var chatsPillMinY = CGFloat.greatestFiniteMagnitude
    // Debug helpers (-openChatDebug / -openChatPlain): the build opens a
    // chat straight from launch, but it must STILL live inside the normal
    // list so the "<" back button pops back to the list instead of tearing
    // down an empty root (which painted a black screen).
    var debugPrefill: String? = nil
    var autoOpenChatID: UUID? = nil
    @State private var autoOpenActive = false
    // Tag/selection variant: the link must stay mounted while the transition
    // is active (the old `if !autoOpenActive` condition tore the NavigationLink
    // down in the same render pass — the push was never processed).
    @State private var autoOpenSelection: UUID?
    // Debug auto-open must fire exactly once per launch.
    @State private var didAutoOpen = false
    // Runtime auto-open (MVP): после добавления контакта чат открывается сам.
    // Флаг — per-peer: иначе ВТОРОЙ добавленный контакт никогда не откроется.
    @State private var runtimeOpenSelection: UUID?
    @State private var didRuntimeOpenPeer: String? = nil

    var body: some View {
        GeometryReader { geo in
            ZStack(alignment: .top) {
                // Debug auto-open: a regular NavigationLink pushed the
                // target chat; dismissing it returns to this list.
                if let id = autoOpenChatID,
                   let idx = appState.chats.firstIndex(where: { $0.id == id }) {
                    NavigationLink(
                        destination: ChatView(chat: $appState.chats[idx], debugPrefill: debugPrefill),
                        tag: id,
                        selection: $autoOpenSelection
                    ) { EmptyView().frame(width: 0, height: 0) }
                }
                if let peer = appState.pendingOpenPeer,
                   let chat = appState.chats.first(where: { $0.cryptoID == peer }) {
                    // MVP: после добавления контакта чат открывается сам.
                    // Selection ставится в onAppear (отдельный render pass) —
                    // иначе SwiftUI не успевает обработать push (урок debug-ветки).
                    NavigationLink(
                        destination: ChatView(chat: chatBinding(for: chat)),
                        tag: chat.id,
                        selection: $runtimeOpenSelection
                    ) { EmptyView().frame(width: 0, height: 0) }
                    .onAppear {
                        if runtimeOpenSelection == nil, didRuntimeOpenPeer != peer {
                            didRuntimeOpenPeer = peer
                            runtimeOpenSelection = chat.id
                        }
                    }
                }
                MINTheme.background.edgesIgnoringSafeArea(.all)

                ScrollView(showsIndicators: false) {
                    VStack(spacing: 0) {
                        SectionPill(title: "Add Contact")
                            .padding(.top, 16)

                        Button {
                            HapticManager.shared.lightImpact()
                            showAddContact = true
                        } label: {
                            Image(systemName: "plus")
                                .font(.system(size: 22, weight: .medium))
                                .foregroundColor(.white)
                                .frame(maxWidth: .infinity, minHeight: 56)
                                .glassPanel(cornerRadius: MINTheme.cornerRadius, tint: MINTheme.control, interactive: true)
                                .contentShape(RoundedRectangle(cornerRadius: MINTheme.cornerRadius, style: .continuous))
                        }
                        .buttonStyle(PressableButtonStyle(scale: 0.97))
                        .padding(.top, 12)
                        .accessibilityIdentifier("addContactButton")

                        // Статус ядра: пока подключается / при ошибке — чтобы
                        // MVP не «молчал» пустым списком (доработает UI-агент).
                        if !appState.isCoreReady {
                            Text(appState.coreStatus.isEmpty
                                 ? "Connecting to relay…"
                                 : appState.coreStatus)
                                .font(.system(size: 12))
                                .foregroundColor(.white.opacity(0.5))
                                .frame(maxWidth: .infinity, alignment: .center)
                                .padding(.top, 10)
                        } else if !appState.coreStatus.isEmpty {
                            Text(appState.coreStatus)
                                .font(.system(size: 12))
                                .foregroundColor(.red.opacity(0.75))
                                .frame(maxWidth: .infinity, alignment: .center)
                                .padding(.top, 10)
                        }

                        // Пилюля «Chats» — только когда есть чаты: пустой
                        // список не должен показывать заголовок ниоткуда.
                        if !appState.chats.isEmpty {
                            SectionPill(title: "Chats")
                                .padding(.top, 28)
                                .opacity(chatsPillMinY <= 16 ? 0 : 1)
                                .background(
                                    GeometryReader { pillGeometry in
                                        Color.clear.preference(
                                            key: ChatsPillPositionKey.self,
                                            value: pillGeometry.frame(in: .named("chatListScroll")).minY
                                        )
                                    }
                                )
                        }

                        if !appState.chats.isEmpty {
                            VStack(spacing: 0) {
                                ForEach(Array(appState.chats.enumerated()), id: \.element.id) { index, chat in
                                    ChatRowView(chat: chatBinding(for: chat), showsDivider: index < appState.chats.count - 1)
                                }
                            }
                            .clipShape(RoundedRectangle(cornerRadius: MINTheme.cornerRadius, style: .continuous))
                            .glassPanel(cornerRadius: MINTheme.cornerRadius, tint: MINTheme.card)
                            .shadow(color: Color.black.opacity(0.35), radius: 10, x: 0, y: 5)
                            .padding(.trailing, 2)
                            .padding(.top, 12)
                        }

                        Spacer().frame(height: 40)
                    }
                    .padding(.horizontal, 16)
                }
                .coordinateSpace(name: "chatListScroll")
                .onPreferenceChange(ChatsPillPositionKey.self) { minY in
                    chatsPillMinY = minY
                }

                GlassFadeView(isTop: true)
                .frame(height: geo.safeAreaInsets.top + 16)
                .frame(maxWidth: .infinity)
                .edgesIgnoringSafeArea(.top)
                .allowsHitTesting(false)

                if chatsPillMinY <= 16, !appState.chats.isEmpty {
                    SectionPill(title: "Chats")
                        .padding(.top, geo.safeAreaInsets.top + 16)
                        .transition(.opacity)
                }
            }
        }
        .pullToRefresh { await appState.refreshNow() }
        .navigationBarHidden(true)
        .sheet(isPresented: $showAddContact) {
            AddContactView().environmentObject(appState)
        }
        .onAppear {
            // Fire the debug auto-open exactly once: `didAutoOpen` survives
            // the "<" pop (unlike the selection, which SwiftUI resets to nil
            // on pop — re-firing there would loop push/pop forever).
            if autoOpenChatID != nil, autoOpenSelection == nil, !didAutoOpen {
                didAutoOpen = true
                autoOpenSelection = autoOpenChatID
            }
        }
    }

    private func chatBinding(for chat: Chat) -> Binding<Chat> {
        if let index = appState.chats.firstIndex(where: { $0.id == chat.id }) {
            return $appState.chats[index]
        } else {
            return .constant(chat)
        }
    }
}
