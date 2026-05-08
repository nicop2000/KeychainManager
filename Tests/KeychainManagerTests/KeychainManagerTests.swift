import XCTest
@testable import KeychainManager

final class KeychainManagerTests: XCTestCase {
    func testKeychainManagerProtocolExposesConfiguredValues() {
        let manager = KeychainManager(serviceName: "service", accessGroup: "group")
        assertKeychainManagerProtocolConformance(manager)
    }

    func testGenericItemsProtocolExposesConfiguredValues() {
        let manager = KeychainManager(serviceName: "service", accessGroup: "group")
        let genericItems: any GenericItemsManagerProtocol = manager.genericItems

        XCTAssertEqual(genericItems.serviceName, "service")
        XCTAssertEqual(genericItems.accessGroup, "group")
    }

    private func assertKeychainManagerProtocolConformance<T: KeychainManagerProtocol>(_ manager: T) {
        XCTAssertEqual(manager.serviceName, "service")
        XCTAssertEqual(manager.accessGroup, "group")
    }
}
