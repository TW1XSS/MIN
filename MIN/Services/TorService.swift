//
//  TorService.swift — поднимает C Tor (Tor.framework) с мостами через IPtProxy.
//
//  Архитектура MVP: IPtProxy + C Tor работают внутри приложения,
//    IPtProxy  → локальные socks5-порты PT (obfs4/snowflake)
//    C Tor      → UseBridges + ClientTransportPlugin(socks5 к IPtProxy) → onion
//    SOCKS Tor  → 127.0.0.1:9050 → наш Rust SOCKS5-транспорт (min-tor)
//
//  Всё in-process: без VPN/Network Extension, без запроса локальной сети.
//
//  Threading/жизненный цикл (важно):
//  * вся работа — на serial-очереди `queue` (gomobile не thread-safe);
//  * IPtProxyController — ЕДИН на процесс (gomobile-объекты нельзя
//    пересоздавать: краш go_seq_go_to_refnum);
//  * TORThread — ЕДИН на процесс (NSAssert в Tor.framework): ретраи после
//    fail переподключаются к control-сокету, но никогда не создают новый.

import Foundation
import Network
import Tor
import IPtProxy

/// Статус подключения Tor для UI.
enum TorState: Equatable {
    case stopped
    case starting
    /// Bootstrap завершён — SOCKS готов принимать соединения к onion.
    case ready
    case failed(String)
}

final class TorService {
    static let shared = TorService()

// MARK: - BridgeManager
//
//  Пользователю MVP не нужно никуда идти за мостами: приложение само
//  держит рабочий пул. Схема (по мотивам Tor Browser built-in bridges):
//   1) встроенный пул (fallback, всегда есть в бинаре);
//   2) кэш проверенных мостов в UserDefaults (переживает запуски);
//   3) автопроверка при старте: мёртвые obfs4 отбрасываются до запуска
//      C Tor — bootstrap идёт по живому каналу сразу;
//   4) фоновое обновление пула из сети, когда связь есть (опционально).
//  Источники обновления перечислены в updateSources; ответы — строки
//  мостов (формат @GetBridgesBot/builtInBridges.json), каждая проверяется.

enum BridgeManager {
    /// Источники со свежими мостами. Первый — РФ-специфичный (обновляется
    /// каждые 6 ч), дальше — общие сборщики. Неприоритетный: в части сетей
    /// недоступны — тогда работает встроенный пул (fallback).
    static let updateSources = [
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/TOR-BRIDGES/TOR_BRIDGES_OBFS4.txt",
        "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-obfs4",
    ]

    /// Максимум мостов в конфиге C Tor (иначе bootstrap перебирает сотни).
    static let poolCap = 40

    /// Мосты, прошедшие проверку в прошлых запусках (кэш).
    private static let cacheKey = "min.bridges.checked"

    /// Пул для C Tor: встроенные мосты + кэш ранее проверенных (кэш —
    /// ДОПОЛНЕНИЕ: свежие из сети не вытесняют дефолтные obfs4).
    static func activePool(defaults: [String]) -> [String] {
        let cached = UserDefaults.standard.stringArray(forKey: cacheKey) ?? []
        return Array(Set(defaults + cached))
    }

    /// Быстрая ПАРАЛЛЕЛЬНАЯ проверка obfs4-мостов (TCP до host:port, 4 c).
    /// Snowflake/webtunnel не проверяем — их апстрим живой по брокеру.
    /// Возвращает выжившие строки (пусто → пул пуст, Tor пойдёт напрямую).
    static func checkBridges(_ lines: [String], timeout: TimeInterval = 4) -> [String] {
        // Ограничиваем пул: дефолтные (1 snowflake + N obfs4) + первые обfs4
        // из сети. Порядок сохраняем (дефолтные = проверенные временем).
        let pool = Array(lines.prefix(poolCap + 3))
        var results = [Bool](repeating: false, count: pool.count)
        let lock = NSLock()
        let group = DispatchGroup()
        for (i, line) in pool.enumerated() {
            group.enter()
            DispatchQueue.global(qos: .utility).async {
                let parts = line.split(separator: " ").map(String.init)
                if parts.count < 2 {
                    group.leave(); return
                }
                if parts[0] != "obfs4" {
                    lock.lock(); results[i] = true; lock.unlock() // проверится при bootstrap
                    group.leave(); return
                }
                let hp = parts[1].split(separator: ":")
                guard hp.count == 2, let portNum = UInt16(hp[1]) else {
                    group.leave(); return
                }
                let one = DispatchSemaphore(value: 0)
                let okBox = NSLock()
                var connected = false
                let nw = NWConnection(host: NWEndpoint.Host(String(hp[0])),
                                      port: NWEndpoint.Port(rawValue: portNum) ?? .any,
                                      using: .tcp)
                nw.stateUpdateHandler = { st in
                    if st == .ready {
                        okBox.lock(); connected = true; okBox.unlock()
                        one.signal()
                    }
                    if case .failed = st { one.signal() }
                    if case .cancelled = st { one.signal() }
                }
                nw.start(queue: .global())
                _ = one.wait(timeout: .now() + timeout)
                nw.cancel()
                if connected {
                    lock.lock(); results[i] = true; lock.unlock()
                }
                group.leave()
            }
        }
        _ = group.wait(timeout: .now() + timeout + 5)
        var alive: [String] = []
        for (i, ok) in results.enumerated() where ok {
            alive.append(pool[i])
        }
        return alive
    }

    /// Сохранить проверенный пул в кэш (synchronize — запись переживёт
    /// kill процесса сразу после старта, иначе кэш терялся).
    static func cache(_ lines: [String]) {
        UserDefaults.standard.set(lines, forKey: cacheKey)
        UserDefaults.standard.synchronize()
    }

    /// Разобрать JSON/текст со списком мостов в строки Bridge-конфига.
    static func parseBridges(from text: String) -> [String] {
        var out: [String] = []
        // JSON-массив строк (builtInBridges.json) или произвольный текст.
        for rawLine in text.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            var line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("\"") && line.hasSuffix("\"") {
                line = String(line.dropFirst().dropLast())
            }
            // JSON-объекты: вытащим поля, если строка — JSON.
            if line.hasPrefix("{") {
                if let addr = jsonField(line, "address"),
                   let fp = jsonField(line, "fingerprint") {
                    let port = jsonField(line, "port") ?? "443"
                    var l = "obfs4 \(addr):\(port) \(fp)"
                    if let cert = jsonField(line, "certificate") { l += " cert=\(cert)" }
                    if let iat = jsonField(line, "iat_mode"), iat == "0" { l += " iat-mode=0" }
                    line = l
                } else {
                    continue
                }
            }
            if line.hasPrefix("//") || line.isEmpty { continue }
            // "obfs4 host:port FP cert=… iat-mode=0" — полная строка
            // "Bridge obfs4 …" — готовая (допускаем с префиксом).
            let body = line.hasPrefix("Bridge ") ? String(line.dropFirst(7)) : line
            let parts = body.split(separator: " ").map(String.init)
            guard ["obfs4", "snowflake", "webtunnel"].contains(parts.first ?? ""),
                  parts.count >= 2 else { continue }
            out.append(body)
        }
        return Array(Set(out)).sorted()
    }

    private static func jsonField(_ line: String, _ key: String) -> String? {
        guard let r = line.range(of: "\"\(key)\"") else { return nil }
        let rest = line[r.upperBound...].drop(while: { $0 == " " || $0 == ":" })
        guard rest.hasPrefix("\"") else { return nil }
        let tail = rest.dropFirst()
        guard let end = tail.firstIndex(of: "\"") else { return nil }
        return String(tail[..<end])
    }
}

    /// SOCKS-порт C Tor на loopback. Tor стартует с `SocksPort auto`
    /// (конфликтов не бывает); фактический порт узнаём через control
    /// GETINFO и отдаём Rust через MIN_SOCKS_ADDR. Значение до bootstrap —
    /// только для логов.
    static private(set) var socksPort: UInt16 = 9050

    private(set) var state: TorState = .stopped
    private var thread: TorThread?
    private var controller: TorController?
    /// Конфиг запущенного Tor (нужен cookie) и файл с control-портом.
    private var torConfig: TorConfiguration?
    private var controlPortFile: URL?
    private var ptStarted = false

    /// IPtProxyController — един на процесс (см. шапку).
    private lazy var pt: IPtProxyController? = {
        IPtProxyController(
            (try? Self.ptStateDir())?.path ?? NSTemporaryDirectory(),
            enableLogging: false,
            unsafeLogging: false,
            logLevel: "WARN",
            transportEvents: nil)
    }()

    /// Вся работа с Tor/PT — на одной serial-очереди.
    private let queue = DispatchQueue(label: "min.tor", qos: .userInitiated)

        /// Транспорт по умолчанию: obfs4. Проверено на iOS 2026-09-24: obfs4 →
    /// 100% за ~1 c, snowflake зависал на TLS-хендшейке (10%) и тянул весь
    /// bootstrap. Snowflake/webtunnel/dnstt включаются явно через
    /// UserDefaults min.transport ("both"/"snowflake"/"webtunnel") — когда
    /// obfs4-пул исчерпан/заблокирован.
    private var activeTransport: String {
        UserDefaults.standard.string(forKey: "min.transport") ?? "obfs4"
    }

    /// Мосты для C Tor: кэш проверенных ∪ пользовательские (`min.bridges`)
    /// ∪ дефолтные; фильтр по активному транспорту. Пул проверяется
    /// BridgeManager.checkBridges перед стартом Tor (мёртвые obfs4 не тащим).
    private var bridgeLines: [String] {
        let user = UserDefaults.standard.stringArray(forKey: "min.bridges") ?? []
        let pool = BridgeManager.activePool(defaults: Self.defaultBridgeLines)
        let source = user.isEmpty ? pool : Array(Set(user + pool))
        switch activeTransport {
        case "obfs4":
            let only = source.filter { $0.hasPrefix("obfs4 ") }
            return only.isEmpty ? Self.defaultBridgeLines.filter { $0.hasPrefix("obfs4 ") } : only
        case "snowflake":
            let only = source.filter { $0.hasPrefix("snowflake ") }
            return only.isEmpty ? Self.defaultBridgeLines.filter { $0.hasPrefix("snowflake ") } : only
        case "webtunnel":
            let only = source.filter { $0.hasPrefix("webtunnel ") }
            return only
        default: // both
            return source
        }
    }

    /// Дефолтные мосты. ПОРЯДОК ВАЖЕН: Tor пробует мосты сверху вниз, и
    /// первый ушедший в долгий обход тормозит весь bootstrap. Проверено
    /// 2026-09-24 на iOS: obfs4-мосты дают 100% за ~1 c, snowflake зависал
    /// на 10% (TLS-хендшейк). Поэтому: 4 obfs4 первыми, snowflake — резерв
    /// последним. Обновлять при массовых блокировках (план шаг 10).
    static let defaultBridgeLines: [String] = [
        "obfs4 5.45.101.108:41437 15B2D5D8A6005635751CF0B9F24B6A9ECC8728C3 cert=Ec5EoyiZK/D0gYUr93d825FJ8k09o/pV6QZXOFfaLGc1NUd2QZ3P753F9/RkuTv1ZmAcNQ iat-mode=0",
        "obfs4 5.45.103.192:2828 EE6B1DE5DEEAD9CFFE970360C3306C81BC6E8030 cert=RqUOIGSlNamAECvzfHSXfaPQxlwuEudnd5Tk64/uU8JHPgxMNrzhp1qpELivbS8vBvOEMw iat-mode=0",
        "obfs4 5.45.109.122:1992 F805F6B4E5E203EFE2A7FFB1E5042AFE8BD986B4 cert=0GcjnEnZ0rJ8/nfxo4ZSkjMZ0fqHSrvj/MdwEtbbuzx8qgqFTaqHTuWelGw2MxJ5wW2QaQ iat-mode=0",
        "obfs4 5.83.147.191:8080 84DE70C3735D1F2D3D8142AAAD785521750310D2 cert=1EAtrN2FDSjOvdC/kznspxRnQegwZGnJ4Wk74L9Zs/wU/KRclyNn/Et10UGNC+fv0wGCUQ iat-mode=0",
        "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 " +
            "url=https://snowflake-broker.torproject.net/global/ " +
            "front=cdn.sstatic.net " +
            "ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478," +
            "stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478," +
            "stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478," +
            "stun:stun.nextcloud.com:3478",
    ]

    /// Применяет мосты из текста (формат @GetBridgesBot). TorThread — один
    /// на процесс, поэтому новые мосты вступят в силу при СЛЕДУЮЩЕМ запуске
    /// приложения. Возвращает количество принятых валидных строк.
    @discardableResult
    static func applyBridges(from text: String) -> Int {
        let valid = text.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { line in
                ["obfs4 ", "snowflake ", "webtunnel "].contains { line.hasPrefix($0) }
                    && line.split(separator: " ").count >= 3
            }
        if valid.isEmpty { return 0 }
        UserDefaults.standard.set(valid, forKey: "min.bridges")
        NSLog("Tor: сохранено мостов: \(valid.count) (применятся при след. запуске)")
        return valid.count
    }

    private init() {}

    /// Поднимает PT (один раз) и C Tor (один раз). Повтор после .failed —
    /// только переподключение к control-сокету.
    func start() {
        queue.async { [weak self] in self?.startLocked() }
    }

    private func startLocked() {
        guard state == .stopped || isFailed else { return }
        state = .starting

        // НЕ вызываем TORInstall*Logging: add_callback_log требует
        // инициализированный log-mutex (иначе tor_raw_abort в log.c:993).
        // Логи тора получаем через --Log notice file (cfg.logfile) + NSLog ниже.

        if TorThread.active == nil {
            guard let pt = pt else {
                failLocked("IPtProxyController init")
                return
            }
            // 1) Пул мостов: отбрасываем мёртвые obfs4 ДО старта Tor
            //    (быстрый TCP-check) — Tor сразу идёт по живому каналу.
            let pool = bridgeLines
            let alive = BridgeManager.checkBridges(pool)
            NSLog("Tor bridges: \(pool.count) в пуле, \(alive.count) живых")
            BridgeManager.cache(alive.isEmpty ? pool : alive)
            refreshBridgesInBackground()
            if !makeConfigAndStartTor(pt: pt) { return }
        }
        guard let cfg = torConfig, let portFile = controlPortFile else {
            failLocked("нет конфигурации Tor")
            return
        }
        connectControl(cfg: cfg, portFile: portFile)

        // Watchdog: мосты в РФ могут перестать отвечать (новые блокировки).
        // Через 8 мин без ready — внятный статус с подсказкой про мосты.
        queue.asyncAfter(deadline: .now() + 480) { [weak self] in
            guard let self = self, self.state == .starting else { return }
            self.failLocked("Tor bootstrap timeout: мосты не отвечают. Новые мосты — @GetBridgesBot")
        }
    }

    /// Фоновое обновление пула мостов: тянем источники (Tor Project CDN/raw),
    /// валидируем строки, сохраняем в кэш для СЛЕДУЮЩЕГО запуска. Ошибки
    /// игнорируем — работаем на текущем пуле. Пользователю делать ничего не
    /// нужно: пул в бинаре + авто-проверка + авто-обновление.
    private func refreshBridgesInBackground() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self = self else { return }
            for urlString in BridgeManager.updateSources {
                guard let url = URL(string: urlString) else { continue }
                var req = URLRequest(url: url)
                req.timeoutInterval = 10
                let sem = DispatchSemaphore(value: 0)
                var body: Data?
                URLSession.shared.dataTask(with: req) { d, _, _ in
                    body = d
                    sem.signal()
                }.resume()
                _ = sem.wait(timeout: .now() + 12)
                guard let data = body,
                      let text = String(data: data, encoding: .utf8) else { continue }
                let parsed = BridgeManager.parseBridges(from: text)
                guard !parsed.isEmpty else { continue }
                // Проверяем только obfs4 (TCP), snowflake/webtunnel — как есть.
                let alive = BridgeManager.checkBridges(parsed)
                guard !alive.isEmpty else { continue }
                BridgeManager.cache(alive)
                NSLog("Tor bridges: обновлено из \(urlString): \(alive.count)")
                return
            }
        }
    }

    /// Строит конфиг с мостами и запускает единственный TorThread.
    private func makeConfigAndStartTor(pt: IPtProxyController) -> Bool {
        // PT: локальные SOCKS-серверы — стартуем один раз (только активные).
        if !ptStarted {
            let mode = activeTransport
            do {
                if mode == "both" || mode == "obfs4" {
                    // Swift-импорт start(_:proxy:) как throws -> Void: результат
                    // BOOL ObjC отброшен, успех проверяем портом (port() != 0).
                    try pt.start("obfs4", proxy: nil)
                    if pt.port("obfs4") == 0 {
                        NSLog("PT: obfs4 не поднялся (порт 0) — работает snowflake")
                    }
                }
                if mode == "both" || mode == "snowflake" {
                    try pt.start("snowflake", proxy: nil)
                }
                ptStarted = true
                NSLog("PT started: obfs4=\(pt.port("obfs4")) snowflake=\(pt.port("snowflake"))")
            } catch {
                failLocked("PT start: \(error.localizedDescription)")
                return false
            }
        }

        // Мосты + PT-порты: arguments append'аются в argv как есть
        // (пары [флаг, значение], TORConfiguration.compile). Плагины — только
        // для активного транспорта (UserDefaults min.transport, дефолт obfs4).
        let mode = activeTransport
        var args: [String] = ["--UseBridges", "1"]
        if mode == "both" || mode == "obfs4" {
            args.append(contentsOf: [
                "--ClientTransportPlugin", "obfs4 socks5 127.0.0.1:\(pt.port("obfs4"))",
            ])
        }
        if mode == "both" || mode == "snowflake" {
            args.append(contentsOf: [
                "--ClientTransportPlugin",
                "snowflake socks5 127.0.0.1:\(pt.port("snowflake"))",
            ])
        }
        for line in bridgeLines {
            args.append("--Bridge")
            args.append(line)
        }

        // Persistent state/cache Tor (guards, consensus, кэш цепей): без него
        // каждый холодный старт = полный bootstrap (~2+ мин через мосты),
        // с кэшем — десятки секунд. Приоритет: скорость (см. MVP-план).
        let dataDir = Self.torStateDir()
        // Скорость bootstrap: CircuitBuildTimeout 20 — не ждём долго отказавший
        // канал (C Tor быстро уходит на другой мост); MaxCircuitDirtiness 900 —
        // цепи живут дольше, меньше перестроений на активной сессии.
        args.append(contentsOf: ["--CircuitBuildTimeout", "20"])
        args.append(contentsOf: ["--MaxCircuitDirtiness", "900"])
        // ControlPort auto + файл с портом: unix-сокет на iOS-симуляторе
        // упирается в лимит пути (~104 симв.), файл — нет.
        let portFile = dataDir.appendingPathComponent("control.port")
        args.append(contentsOf: [
            "--SocksPort", "auto",
            "--ControlPort", "auto",
            "--ControlPortWriteToFile", portFile.path,
        ])

        let cfg = TorConfiguration()
        cfg.ignoreMissingTorrc = true
        cfg.cookieAuthentication = true
        cfg.clientOnly = true
        cfg.avoidDiskWrites = false   // иначе Tor не пишет кэш на диск
        cfg.dataDirectory = dataDir
        cfg.logfile = dataDir.appendingPathComponent("tor.log")
        cfg.arguments = NSMutableArray(array: args)

        let t = TorThread(configuration: cfg)
        t.start()
        thread = t
        torConfig = cfg
        controlPortFile = portFile
        return true
    }

    /// Подключение к control-порту с ретраем.
    /// ВАЖНО: TorController(controlPortFile:) подключается САМ в init —
    /// повторный connect() вернёт NO (канал уже есть) и Swift бросит
    /// GenericObjCError. Поэтому только создаём + проверяем isConnected.
    private func connectControl(cfg: TorConfiguration, portFile: URL) {
        var lastError = ""
        for _ in 0..<30 {
            Thread.sleep(forTimeInterval: 1.0)
            guard FileManager.default.fileExists(atPath: portFile.path) else { continue }
            let c = TorController(controlPortFile: portFile)  // connect внутри init
            if c.isConnected {
                controller = c
                authenticate(cfg: cfg, c: c)
                return
            }
            lastError = "controller not connected"
        }
        let hint = (try? String(
            contentsOf: portFile.deletingLastPathComponent().appendingPathComponent("tor.log"),
            encoding: .utf8))?.suffix(300) ?? ""
        failLocked("control connect timeout (\(lastError)); tor.log: \(hint)")
    }

    private func authenticate(cfg: TorConfiguration, c: TorController) {
        guard let cookie = cfg.cookie else {
            failLocked("control cookie пуст")
            return
        }
        c.authenticate(with: cookie, completion: { [weak self] ok, err in
            guard let self = self else { return }
            self.queue.async { [weak self] in
                guard let self = self else { return }
                guard ok else {
                    self.failLocked("control auth: \(err?.localizedDescription ?? "?")")
                    return
                }
                _ = c.addObserver(forCircuitEstablished: { established in
                    guard established else { return }
                    self.queue.async { [weak self] in
                        guard let self = self, self.state == .starting else { return }
                        // Фактический SOCKS-порт (SocksPort auto) — GETINFO
                        // "net/listeners/socks" → "127.0.0.1:PORT".
                        c.getInfoForKeys(["net/listeners/socks"]) { [weak self] values in
                            guard let self = self, let first = values.first else { return }
                            // "127.0.0.1:39051" (или список — берём socks-запись).
                            for entry in first.split(separator: "\"") {
                                let e = String(entry)
                                guard e.contains("127.0.0.1:"),
                                      let p = UInt16(e.split(separator: ":").last ?? "")
                                else { continue }
                                TorService.socksPort = p
                                setenv("MIN_SOCKS_ADDR", "127.0.0.1:\(p)", 1)
                                self.state = .ready
                                NSLog("TOR ready: socks=127.0.0.1:\(p) (MIN_SOCKS_ADDR для Rust)")
                                return
                            }
                            // Порт не распознали — остаёмся на дефолте.
                            self.state = .ready
                            NSLog("TOR ready (socks port unknown): using 9050")
                        }
                    }
                })
            }
        })
    }

    private var isFailed: Bool {
        if case .failed = state { return true }
        return false
    }

    private func failLocked(_ msg: String) {
        NSLog("TOR failed: \(msg)")
        state = .failed(msg)
    }

    private static func ptStateDir() throws -> URL {
        let dir = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("min/pt", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    /// Persistent state Tor (Application Support, исключён из iCloud backup).
    private static func torStateDir() -> URL {
        let base = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("min", isDirectory: true)
        let dir = base.appendingPathComponent("tor", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        KeychainService.excludeFromBackup(base)
        return dir
    }

    /// Блокирующее ожидание готовности (для вызова с фоновой очереди, не main).
    /// nil при успехе, иначе — текст ошибки для UI.
    func waitUntilReady(timeout: TimeInterval = 300) -> String? {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let snapshot = queue.sync { state }
            switch snapshot {
            case .ready:
                return nil
            case .failed(let msg):
                return msg
            case .stopped, .starting:
                Thread.sleep(forTimeInterval: 0.25)
            }
        }
        return "Tor bootstrap timeout"
    }
}

