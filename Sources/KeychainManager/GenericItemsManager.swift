import Foundation

public final class GenericItemsManager: GenericItemsManagerProtocol {

    public let serviceName: String
    public let accessGroup: String?

    init(serviceName: String, accessGroup: String?) {
        self.serviceName = serviceName
        self.accessGroup = accessGroup
    }

    private func buildQueryDict(
        key: String,
        attributes: ItemAttributes?,
        accessLevel: KeychainItemAccessLevel?,
        synchronize: Bool) -> KeychainDict {
            var query: KeychainDict = [
                kSecAttrService as String: serviceName as AnyObject,
                kSecAttrAccount as String: key as AnyObject,
                kSecClass as String: ItemType.generic.rawValue,
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
        key: String,
        accessLevel: KeychainItemAccessLevel = .whenUnlocked,
        synchronize: Bool = true,
        updateWhenExists: Bool = true,
        attributes: ItemAttributes? = nil) throws {
            try self.saveItem(
                item: item,
                key: key,
                accessLevel: accessLevel,
                synchronize: synchronize,
                updateWhenExists: updateWhenExists,
                attributes: attributes,
                isRetrying: false
            )
        }

    private func saveItem<T: Encodable>(
        item: T,
        key: String,
        accessLevel: KeychainItemAccessLevel = .whenUnlocked,
        synchronize: Bool = true,
        updateWhenExists: Bool = true,
        attributes: ItemAttributes? = nil,
        isRetrying: Bool = false) throws {
            let data = try JSONEncoder().encode(item)
            var query = buildQueryDict(
                key: key,
                attributes: attributes,
                accessLevel: accessLevel,
                synchronize: synchronize
            )
            query[kSecValueData as String] = data

            let result = SecItemAdd(query as CFDictionary, nil)

            if result != errSecSuccess {
                let error = KeychainError.convert(result)
                if error == .duplicateItem && updateWhenExists {
                    do {
                        try self.updateItemData(
                            with: item,
                            key: key,
                            accessLevel: accessLevel,
                            attributes: attributes
                        )
                    } catch let updateError {
                        if let keychainError = updateError as? KeychainError,
                           keychainError == .itemNotFound,
                           !isRetrying {
                            // Delete and retry saving one time only
                            try self.deleteItem(key: key)
                            try self.saveItem(
                                item: item,
                                key: key,
                                accessLevel: accessLevel,
                                synchronize: synchronize,
                                updateWhenExists: updateWhenExists,
                                attributes: attributes,
                                isRetrying: true // prevent infinite recursion
                            )
                        } else {
                            throw updateError
                        }
                    }
                } else {
                    throw error
                }
            }
        }

    public func fetchItem<T: Decodable>(
        key: String,
        accessLevel: KeychainItemAccessLevel? = nil,
        attributes: ItemAttributes? = nil) throws -> T {
            let access = accessLevel ?? accessLevelFor(key: key) ?? .whenUnlocked
            var query = buildQueryDict(key: key, attributes: attributes, accessLevel: access, synchronize: false)
            query[kSecAttrSynchronizable as String] = kSecAttrSynchronizableAny
            query[kSecReturnAttributes as String] = true
            query[kSecReturnData as String] = true

            var item: CFTypeRef?

            let result = SecItemCopyMatching(query as CFDictionary, &item)

            if result != errSecSuccess {
                throw KeychainError.convert(result)
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
        key: String,
        accessLevel: KeychainItemAccessLevel = .whenUnlocked,
        synchronize: Bool = true,
        attributes: ItemAttributes? = nil) throws {
            let itemData = try JSONEncoder().encode(item)

            let query = buildQueryDict(key: key, attributes: attributes, accessLevel: accessLevel, synchronize: synchronize)

            let attributesToUpdate: KeychainDict = [
                kSecValueData as String: itemData as AnyObject,
            ]

            let result = SecItemUpdate(
                query as CFDictionary,
                attributesToUpdate as CFDictionary)

            if result != errSecSuccess {
                throw KeychainError.convert(result)
            }
        }

    public func deleteItem(
        key: String,
        accessLevel: KeychainItemAccessLevel? = nil,
        attributes: ItemAttributes? = nil) throws
    {
        var query = buildQueryDict(
            key: key,
            attributes: attributes,
            accessLevel: accessLevel ?? accessLevelFor(key: key),
            synchronize: false
        )
        let attributes = getAttributesFor(key: key)
        if let attributes {
            for (key, value) in attributes {
                query[key as String] = value
            }
        }
        query[kSecAttrSynchronizable as String] = kSecAttrSynchronizableAny
        let result = SecItemDelete(query as CFDictionary)
        if result != errSecSuccess {
            throw KeychainError.convert(result)
        }
    }

    public func allKeys() -> Set<String> {
        var keys = Set<String>()
        for level in KeychainItemAccessLevel.allCases {
            for bool in [true, false] {
                var query: KeychainDict = [
                    kSecAttrService as String: serviceName as AnyObject,
                    kSecReturnAttributes as String: kCFBooleanTrue!,
                    kSecClass as String: ItemType.generic.rawValue,
                    kSecMatchLimit as String: kSecMatchLimitAll,
                    kSecReturnData as String  : kCFBooleanTrue!,
                    kSecReturnRef as String : kCFBooleanTrue!,
                    kSecAttrSynchronizable as String: bool ? kCFBooleanTrue! : kCFBooleanFalse!,
                    kSecAttrAccessible as String: level.rawValue as AnyObject,
                ]
                if let accessGroup {
                    query[kSecAttrAccessGroup as String] = accessGroup
                }
                var results: AnyObject?

                let status = SecItemCopyMatching(query as CFDictionary, &results)

                guard status == errSecSuccess else { continue }
                if let results = results as? [[String: AnyObject]] {
                    for result in results {
                        if let accountData = result[kSecAttrAccount as String] as? String {
                            keys.insert(accountData)
                        }
                    }
                }
            }
        }
        return keys
    }

    public func deleteAllFromKeychain() throws {
        var query: KeychainDict = [kSecClass as String: ItemType.generic.rawValue,
                     kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
                     kSecAttrService as String: serviceName as AnyObject]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        SecItemDelete(query as CFDictionary)
    }

    public func accessLevelFor(key: String) -> KeychainItemAccessLevel? {
        let dict = getAttributesFor(key: key)
        guard let dict, let level = dict[kSecAttrAccessible as String] as? String else {
            return nil
        }
        return KeychainItemAccessLevel(rawValue: level as CFString)
    }

    public func getAttributesFor(key: String) -> KeychainDict? {
        for level in KeychainItemAccessLevel.allCases {
            for bool in [true, false] {
                var query: KeychainDict = [
                    kSecAttrService as String: serviceName as AnyObject,
                    kSecReturnAttributes as String: kCFBooleanTrue!,
                    kSecClass as String: ItemType.generic.rawValue,
                    kSecMatchLimit as String: kSecMatchLimitOne,
                    kSecReturnData as String  : kCFBooleanTrue!,
                    kSecReturnRef as String : kCFBooleanTrue!,
                    kSecAttrSynchronizable as String: bool ? kCFBooleanTrue! : kCFBooleanFalse!,
                    kSecAttrAccessible as String: level.rawValue as AnyObject,
                    kSecAttrAccount as String: key
                ]
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
        return nil
    }
}
