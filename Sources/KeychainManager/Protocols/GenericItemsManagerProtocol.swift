import Security

public protocol GenericItemsManagerProtocol {
    var serviceName: String { get }
    var accessGroup: String? { get }
    
    func saveItem<T: Encodable>(
        item: T,
        key: String,
        accessLevel: KeychainItemAccessLevel,
        accessControl: SecAccessControlCreateFlags?,
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
        accessControl: SecAccessControlCreateFlags?,
        synchronize: Bool,
        attributes: ItemAttributes?) throws
    func deleteItem(
        key: String,
        accessLevel: KeychainItemAccessLevel?,
        attributes: ItemAttributes?) throws
    func allKeys() -> Set<String>
    func deleteAllFromKeychain() throws
}

public extension GenericItemsManagerProtocol {
    func saveItem<T: Encodable>(
        item: T,
        key: String,
        accessLevel: KeychainItemAccessLevel,
        synchronize: Bool,
        updateWhenExists: Bool) throws {
            try saveItem(
                item: item,
                key: key,
                accessLevel: accessLevel,
                accessControl: nil,
                synchronize: synchronize,
                updateWhenExists: updateWhenExists,
                attributes: nil
            )
        }

    func fetchItem<T: Decodable>(
        key: String,
        accessLevel: KeychainItemAccessLevel?) throws -> T {
            try fetchItem(key: key, accessLevel: accessLevel, attributes: nil)
        }
    
    func updateItemData<T: Encodable>(
        with item: T,
        key: String,
        accessLevel: KeychainItemAccessLevel,
        synchronize: Bool) throws {
            try updateItemData(
                with: item,
                key: key,
                accessLevel: accessLevel,
                accessControl: nil,
                synchronize: synchronize,
                attributes: nil
            )
        }
    
    func deleteItem(
        key: String,
        accessLevel: KeychainItemAccessLevel?) throws {
            try deleteItem(key: key, accessLevel: accessLevel, attributes: nil)
        }
}
