//
//  KeychainManager.swift
//
//
//  Created by Nico Petersen on 09.09.23.
//

import Foundation

public final class KeychainManager: KeychainManagerProtocol {

    public let serviceName: String
    public let accessGroup: String?

    private static let defaultServiceName: String = Bundle.main.bundleIdentifier ?? "SwiftCommonsKeychainWrapper"
    public let genericItems: GenericItemsManager

    private convenience init() {
        self.init(serviceName: KeychainManager.defaultServiceName)
    }

    public init(serviceName: String, accessGroup: String? = nil) {
        self.serviceName = serviceName
        self.accessGroup = accessGroup
        self.genericItems = GenericItemsManager(serviceName: serviceName, accessGroup: accessGroup)
    }


    public func wipeKeychain() throws {
        try genericItems.deleteAllFromKeychain()
    }

}
