import XCTest

final class MINUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    private func log(_ s: String) {
        let line = s + "\n"
        if let d = line.data(using: .utf8) {
            if let fh = FileHandle(forWritingAtPath: "/tmp/min_ui_diag.txt") {
                defer { try? fh.close() }
                _ = fh.seekToEndOfFile()
                fh.write(d)
            } else {
                FileManager.default.createFile(atPath: "/tmp/min_ui_diag.txt", contents: d)
            }
        }
    }

    func testComposerSizes() throws {
        let app = XCUIApplication()
        app.launchArguments = ["-openChatPlain"]
        app.launch()

        let tv = app.textViews.firstMatch
        XCTAssertTrue(tv.waitForExistence(timeout: 8), "composer UITextView not found")
        log("DIAG empty tv.frame = " + String(describing: tv.frame))
        let screen = app.windows.firstMatch.frame
        log("DIAG screen = " + String(describing: screen))

        tv.tap()
        tv.typeText("Line one")
        log("DIAG after 8 chars tv.frame = " + String(describing: tv.frame))
        tv.typeText("\nLine two")
        log("DIAG after newline tv.frame = " + String(describing: tv.frame))

        let long = String(repeating: "О ", count: 40)
        tv.typeText("\n" + long)
        _ = tv.waitForExistence(timeout: 2)
        log("DIAG after long   tv.frame = " + String(describing: tv.frame))

        tv.tap(withNumberOfTaps: 3, numberOfTouches: 1)
        tv.typeText(XCUIKeyboardKey.delete.rawValue)
        _ = tv.waitForExistence(timeout: 2)
        log("DIAG after clear  tv.frame = " + String(describing: tv.frame))
    }

    /// Репро: ввод ключа в AddContact — «интерфейс багается, всё растягивается».
    /// Логируем frames всех элементов листа и сохраняем скриншоты в /tmp.
    private func snap(_ name: String, _ app: XCUIApplication) {
        let url = URL(fileURLWithPath: "/tmp/min_ui_\(name).png")
        try? app.screenshot().pngRepresentation.write(to: url)
        log("SNAP \(name) saved")
    }

    func testAddContactKeyInputLayout() throws {
        let app = XCUIApplication()
        app.launch()
        Thread.sleep(forTimeInterval: 2.0)
        snap("a0_launch", app)
        log("DIAG hierarchy:\n" + app.debugDescription.prefix(3000).description)

        let addBtn = app.buttons["addContactButton"]
        if !addBtn.waitForExistence(timeout: 8) {
            log("DIAG buttons exist: " + String(app.buttons.count))
            var labels = ""
            for b in app.buttons.allElementsBoundByIndex.prefix(10) {
                labels += "[id=\(b.identifier) label=\(b.label)] "
            }
            log("DIAG first buttons: " + labels)
            XCTFail("addContactButton not found")
        }
        let screen = app.windows.firstMatch.frame
        log("DIAG screen = " + String(describing: screen))
        log("DIAG main addBtn.frame = " + String(describing: addBtn.frame))
        snap("a1_main", app)

        addBtn.tap()
        let field = app.textFields["Enter the public key"]
        XCTAssertTrue(field.waitForExistence(timeout: 5), "key field not found")
        _ = app.staticTexts["Your QR code"].waitForExistence(timeout: 3)

        log("DIAG sheet field   = " + String(describing: field.frame))
        log("DIAG sheet scanQR  = " + String(describing: app.buttons["Scan QR code"].frame))
        log("DIAG sheet yourQR  = " + String(describing: app.buttons["Your QR code"].frame))
        let keyBtn = app.buttons.matching(NSPredicate(format: "label CONTAINS[c] 'MIN3:'")).firstMatch
        if keyBtn.exists {
            log("DIAG sheet keyBtn  = " + String(describing: keyBtn.frame))
        }
        snap("a2_sheet", app)

        // Фокус: клавиатура появляется — главный кандидат «растягивания».
        field.tap()
        Thread.sleep(forTimeInterval: 1.0)
        log("DIAG focus field   = " + String(describing: field.frame))
        log("DIAG focus scanQR  = " + String(describing: app.buttons["Scan QR code"].frame))
        log("DIAG focus yourQR  = " + String(describing: app.buttons["Your QR code"].frame))
        snap("a3_focus", app)

        // Набор короткого ключа (посимвольно, как пользователь).
        field.typeText("MIN3:shortTestKey")
        Thread.sleep(forTimeInterval: 0.8)
        log("DIAG typed field   = " + String(describing: field.frame))
        log("DIAG typed scanQR  = " + String(describing: app.buttons["Scan QR code"].frame))
        log("DIAG typed yourQR  = " + String(describing: app.buttons["Your QR code"].frame))
        snap("a4_typed", app)

        // Длинный ввод (имитация вставки большого invite).
        field.typeText(String(repeating: "X", count: 120))
        Thread.sleep(forTimeInterval: 1.0)
        log("DIAG long  field   = " + String(describing: field.frame))
        log("DIAG long  scanQR  = " + String(describing: app.buttons["Scan QR code"].frame))
        log("DIAG long  yourQR  = " + String(describing: app.buttons["Your QR code"].frame))
        log("DIAG long  screen  = " + String(describing: app.windows.firstMatch.frame))
        snap("a5_long", app)
    }

    /// Регресс: «в поле с public key ничего нету, копируется ничего».
    /// Проверяем: ключ сгенерирован (MIN3:…) и кнопка копирует его
    /// (появляется тост «Copied!»).
    func testOwnKeyVisibleAndCopyable() throws {
        let app = XCUIApplication()
        app.launch()

        let addBtn = app.buttons["addContactButton"]
        XCTAssertTrue(addBtn.waitForExistence(timeout: 10), "addContactButton not found")

        // Ждём готовности ядра (Tor+relay через мосты, ~1-2 мин).
        let deadline = Date().addingTimeInterval(240)
        while Date() < deadline {
            let connecting = app.staticTexts["Connecting to relay…"].exists
                || app.staticTexts["Connecting via Tor…"].exists
            if !connecting { break }
            Thread.sleep(forTimeInterval: 5)
        }

        addBtn.tap()
        let keyBtn = app.buttons.matching(
            NSPredicate(format: "label BEGINSWITH 'MIN3:'")).firstMatch
        XCTAssertTrue(keyBtn.waitForExistence(timeout: 15),
                      "own key button not found (invite not generated?)")
        snap("b1_ownkey", app)

        keyBtn.tap()
        XCTAssertTrue(app.staticTexts["Copied!"].waitForExistence(timeout: 3),
                      "Copied! toast not shown — копирование не сработало")
        log("DIAG own key length = \(keyBtn.label.count)")
    }
}
