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
        return query
    }
    
    public func saveItem<T: Encodable>(
        item: T,
        type: ItemType,
        key: String,
        attributes: ItemAttributes? = nil,
        accessLevel: KeychainItemAccessLevel? = nil, synchronize: Bool = false, updateWhenExists: Bool = false) throws
    {
        let data = try JSONEncoder().encode(item)
        var query = buildQueryDict(type: type, key: key, attributes: attributes, accessLevel: accessLevel, synchronize: synchronize)
        query[kSecValueData as String] = data
        
        let result = SecItemAdd(query as CFDictionary, nil)
        
        if result != errSecSuccess {
            let error = convertError(result)
            if error == .duplicateItem && updateWhenExists {
                try self.updateItemData(with: item, ofClass: type, key: key, attributes: attributes, accessLevel: accessLevel)
            } else {
                throw error
            }
        }
    }
    
    public func fetchItem<T: Decodable>(
        ofType type: ItemType,
        key: String,
        attributes: ItemAttributes? = nil, accessLevel: KeychainItemAccessLevel? = nil, synchronize: Bool = false) throws -> T
    {
        var query = buildQueryDict(type: type, key: key, attributes: attributes, accessLevel: accessLevel, synchronize: synchronize)
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
        attributes: ItemAttributes? = nil, accessLevel: KeychainItemAccessLevel? = nil, synchronize: Bool = false) throws
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
        attributes: ItemAttributes? = nil, accessLevel: KeychainItemAccessLevel? = nil, synchronize: Bool = false) throws
    {
        let query = buildQueryDict(type: type, key: key, attributes: attributes, accessLevel: accessLevel, synchronize: synchronize)
        
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
}
