//
//  KeychainManagerExtension.swift
//
//
//  Created by Nico Petersen on 09.09.23.
//

import Foundation

public protocol GenericItemsManagerProtocol {
    var serviceName: String { get }
    var accessGroup: String? { get }

    func saveItem<T: Encodable>(
        item: T,
        key: String,
        accessLevel: KeychainItemAccessLevel,
        synchronize: Bool,
        updateWhenExists: Bool,
        attributes: ItemAttributes?) throws
    func fetchItem<T: Decodable>(
        key: String,
        accessLevel: KeychainItemAccessLevel?,
        attributes: ItemAttributes?) throws -> T
    func updateItemData<T: Encodable>(
        with item: T,
        key: String,
        accessLevel: KeychainItemAccessLevel,
        synchronize: Bool,
        attributes: ItemAttributes?) throws
    func deleteItem(
        key: String,
        accessLevel: KeychainItemAccessLevel?,
        attributes: ItemAttributes?) throws
    func allKeys() -> Set<String>
    func deleteAllFromKeychain() throws
    func accessLevelFor(key: String) -> KeychainItemAccessLevel?
    func getAttributesFor(key: String) -> KeychainDict?
}

public protocol KeychainManagerProtocol {
    associatedtype GenericItems: GenericItemsManagerProtocol

    var serviceName: String { get }
    var accessGroup: String? { get }
    var genericItems: GenericItems { get }

    func wipeKeychain() throws
}
