//
//  MINTests.swift
//  MINTests
//

import XCTest
@testable import MIN

final class MINTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testExample() throws {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        // Any test you write for XCTest can be annotated as throws and async.
        // Mark your test throws to produce an unexpected failure when your test encounters an uncaught error.
        // Mark your test async to allow awaiting for asynchronous code to complete. Check the results with assertions afterwards.
    }

    /// Автоматический повтор отправки разрешён ТОЛЬКО когда из устройства
    /// ничего не ушло. Ошибки, при которых результат отправки неизвестен,
    /// повторяться не должны — иначе сообщение уйдёт дважды.
    func testRetryAllowedOnlyWhenNothingWasSent() {
        struct FFIError: Error, CustomStringConvertible {
            let description: String
            init(_ d: String) { description = d }
        }

        // Реальная строка с телефона: Tor не поднялся, ничего не отправлено.
        let notSent = FFIError("ffiFailed(\"delivery: connect failed (not sent): "
            + "transport error: Connection refused (os error 61)\")")
        XCTAssertTrue(AppState.isNothingSent(notSent))
        XCTAssertTrue(AppState.sendFailureMessage(notSent).contains("Tor"))

        // Неоднозначные исходы: relay принял, ответа не дошло, и т.п. Повтор
        // здесь = риск дубликата, поэтому повторять НЕЛЬЗЯ.
        for ambiguous in ["delivery: relay rejected (forbidden)",
                          "delivery: ack timeout after enqueue",
                          "protocol: no session",
                          "min app: contact limit reached"] {
            XCTAssertFalse(AppState.isNothingSent(FFIError(ambiguous)),
                           "не должен повторяться: \(ambiguous)")
        }
    }

    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
