//
//  KeychainManager.swift
//
//
//  Created by Nico Petersen on 09.09.23.
//

import Foundation

public final class KeychainManager {
    public typealias ItemAttributes = [CFString: Any]
    public typealias KeychainDict = [String: Any]

    public private(set) var serviceName: String
    public private(set) var accessGroup: String?

    private static let defaultServiceName: String = Bundle.main.bundleIdentifier ?? "SwiftCommonsKeychainWrapper"

    private convenience init() {
        self.init(serviceName: KeychainManager.defaultServiceName)
    }

    public init(serviceName: String, accessGroup: String? = nil) {
        self.serviceName = serviceName
        self.accessGroup = accessGroup
    }

    private func buildQueryDict(
        type: ItemType,
        key: String,
        attributes: ItemAttributes?,
        accessLevel: KeychainItemAccessLevel?,
        synchronize: Bool) -> KeychainDict
    {
        var query: KeychainDict = [
            kSecAttrService as String: serviceName as AnyObject,
            kSecAttrAccount as String: key as AnyObject,
            kSecClass as String: type.rawValue as AnyObject,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        if let accessLevel {
            query[kSecAttrAccessible as String] = accessLevel.rawValue as AnyObject
        }

        if let attributes {
            for (key, value) in attributes {
                query[key as String] = value
            }
        }
        query[kSecAttrSynchronizable as String] = synchronize ? kCFBooleanTrue : kCFBooleanFalse
        print(query)
        return query
    }

    public func saveItem<T: Encodable>(
        item: T,
        type: ItemType,
        key: String,
        accessLevel: KeychainItemAccessLevel = .whenUnlocked,
        synchronize: Bool = true,
        updateWhenExists: Bool = true,
        attributes: ItemAttributes? = nil) throws
    {
        let data = try JSONEncoder().encode(item)
        var query = buildQueryDict(type: type, key: key, attributes: attributes, accessLevel: accessLevel, synchronize: synchronize)
        query[kSecValueData as String] = data

        let result = SecItemAdd(query as CFDictionary, nil)

        if result != errSecSuccess {
            let error = convertError(result)
            if error == .duplicateItem && updateWhenExists {
                do {
                    try self.updateItemData(with: item, ofClass: type, key: key, accessLevel: accessLevel, attributes: attributes)
                } catch let updateError {
                    if (updateError as! KeychainError) == .itemNotFound {
                        do {
                            try self.deleteItem(ofClass: type, key: key)
                            try self.saveItem(item: item, type: type, key: key, accessLevel: accessLevel, synchronize: synchronize, attributes: attributes)
                        } catch let deleteError {
                            print("Error deleting item: \(deleteError)")
                        }
                    }
                }
            } else {
                throw error
            }
        }
    }

    public func fetchItem<T: Decodable>(
        ofType type: ItemType,
        key: String,
        accessLevel: KeychainItemAccessLevel? = nil,
        synchronize: Bool = true,
        attributes: ItemAttributes? = nil) throws -> T
    {
        var access = accessLevel ?? accessLevelFor(key: key) ?? .whenUnlocked
        var query = buildQueryDict(type: type, key: key, attributes: attributes, accessLevel: access, synchronize: synchronize)
        query[kSecReturnAttributes as String] = true
        query[kSecReturnData as String] = true

        var item: CFTypeRef?

        let result = SecItemCopyMatching(query as CFDictionary, &item)

        if result != errSecSuccess {
            throw convertError(result)
        }

        guard
            let keychainItem = item as? [String: Any],
            let data = keychainItem[kSecValueData as String] as? Data
        else {
            throw KeychainError.invalidData
        }
        return try JSONDecoder().decode(T.self, from: data)
    }

    public func updateItemData<T: Encodable>(
        with item: T,
        ofClass type: ItemType,
        key: String,
        accessLevel: KeychainItemAccessLevel = .whenUnlocked,
        synchronize: Bool = true,
        attributes: ItemAttributes? = nil) throws
    {
        let itemData = try JSONEncoder().encode(item)

        let query = buildQueryDict(type: type, key: key, attributes: attributes, accessLevel: accessLevel, synchronize: synchronize)

        let attributesToUpdate: KeychainDict = [
            kSecValueData as String: itemData as AnyObject,
        ]

        let result = SecItemUpdate(
            query as CFDictionary,
            attributesToUpdate as CFDictionary)

        if result != errSecSuccess {
            throw convertError(result)
        }
    }

    public func deleteItem(
        ofClass type: ItemType,
        key: String,
        accessLevel: KeychainItemAccessLevel? = nil,
        synchronize: Bool = true,
        attributes: ItemAttributes? = nil) throws
    {
        var query = buildQueryDict(type: type, key: key, attributes: attributes, accessLevel: accessLevel ?? accessLevelFor(key: key), synchronize: synchronize)
        let attributes = getAttributesFor(key: key)
        if let attributes {
            for (key, value) in attributes {
                query[key as String] = value
            }
        }
        let result = SecItemDelete(query as CFDictionary)
        if result != errSecSuccess {
            throw convertError(result)
        }
    }

    public func wipeKeychain() throws {
        try deleteItemTypeFromKeychain(.generic)
        try deleteItemTypeFromKeychain(.password)
        try deleteItemTypeFromKeychain(.certificate)
        try deleteItemTypeFromKeychain(.cryptography)
        try deleteItemTypeFromKeychain(.certificate)
    }

    public func deleteItemTypeFromKeychain(_ type: ItemType) throws {
        let query = [kSecClass as String: type.rawValue,
                     kSecAttrSynchronizable as String: kSecAttrSynchronizableAny]
        SecItemDelete(query as CFDictionary)
    }

    public func allKeys() -> Set<String> {
        var keys = Set<String>()
        for item in ItemType.allCases {
            for level in KeychainItemAccessLevel.allCases {
                for bool in [true, false] {
                    var query: KeychainDict = [
                        kSecAttrService as String: serviceName as AnyObject,
                        kSecReturnAttributes as String: kCFBooleanTrue!,
                        kSecClass as String: item.rawValue,
                        kSecMatchLimit as String: kSecMatchLimitAll,
                        kSecReturnData as String  : kCFBooleanTrue,
                        kSecReturnRef as String : kCFBooleanTrue,
                        kSecAttrSynchronizable as String: bool ? kCFBooleanTrue : kCFBooleanFalse,
                        kSecAttrAccessible as String: level.rawValue as AnyObject,
                    ]
                    if let accessGroup {
                        query[kSecAttrAccessGroup as String] = accessGroup
                    }
                    var results: AnyObject?

                    let status = SecItemCopyMatching(query as CFDictionary, &results)

                    guard status == errSecSuccess else { continue }
                    print("Query Dict: \(query)\n\n")
                    if let results = results as? [[String: AnyObject]] {
                        for result in results {
                            if let accountData = result[kSecAttrAccount as String] as? String {
                                keys.insert(accountData)
                                print("Result: \(result)")
                                print("--------------------")
                            }
                        }
                    }
                }
            }
        }
        return keys
    }
    public func accessLevelFor(key: String) -> KeychainItemAccessLevel? {
        var dict = getAttributesFor(key: key)
        guard let dict, let level = dict[kSecAttrAccessible as String] as? String else {
            return nil
        }
        return KeychainItemAccessLevel(rawValue: level as CFString)
    }

    public func getAttributesFor(key: String) -> KeychainDict? {
        for item in ItemType.allCases {
            for level in KeychainItemAccessLevel.allCases {
                for bool in [true, false] {
                    var query: KeychainDict = [
                        kSecAttrService as String: serviceName as AnyObject,
                        kSecReturnAttributes as String: kCFBooleanTrue!,
                        kSecClass as String: item.rawValue,
                        kSecMatchLimit as String: kSecMatchLimitOne,
                        kSecReturnData as String  : kCFBooleanTrue,
                        kSecReturnRef as String : kCFBooleanTrue,
                        kSecAttrSynchronizable as String: bool ? kCFBooleanTrue : kCFBooleanFalse,
                        kSecAttrAccessible as String: level.rawValue as AnyObject,
                        kSecAttrAccount as String: key
                    ]
                    if let accessGroup {
                        query[kSecAttrAccessGroup as String] = accessGroup
                    }
                    if let accessGroup {
                        query[kSecAttrAccessGroup as String] = accessGroup
                    }
                    var results: AnyObject?
                    let status = SecItemCopyMatching(query as CFDictionary, &results)
                    if status == errSecSuccess {
                        return results as? KeychainDict
                    }
                }
            }
        }
        return nil
    }
}
