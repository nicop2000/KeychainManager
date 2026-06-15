import Foundation
public class GenericItemsManagerMock: GenericItemsManagerProtocol {
    public let serviceName: String
    
    public let accessGroup: String?
    
    private var storedItems: [String: Data] = [:]

    public func saveItem<T>(
        item: T,
        key: String,
        accessLevel: KeychainItemAccessLevel,
        accessControl: SecAccessControlCreateFlags?,
        synchronize: Bool,
        updateWhenExists: Bool,
        attributes: ItemAttributes?
    ) throws where T : Encodable {
        let data = try JSONEncoder().encode(item)
        storedItems[key] = data
    }
    
    public func fetchItem<T>(
        key: String,
        accessLevel: KeychainItemAccessLevel?,
        attributes: ItemAttributes?
    ) throws -> T where T : Decodable {
        guard let data = storedItems[key] else {
            throw KeychainError.itemNotFound
        }
        return try JSONDecoder().decode(T.self, from: data)
    }

    public func updateItemData<T>(
        with item: T,
        key: String,
        accessLevel: KeychainItemAccessLevel,
        accessControl: SecAccessControlCreateFlags?,
        synchronize: Bool,
        attributes: ItemAttributes?
    ) throws where T : Encodable {
        let data = try JSONEncoder().encode(item)
        storedItems[key] = data
    }

    public func deleteItem(
        key: String,
        accessLevel: KeychainItemAccessLevel?,
        attributes: ItemAttributes?
    ) throws {
        storedItems.removeValue(forKey: key)
    }

    public func allKeys() -> Set<String> {
        Set(storedItems.keys)
    }
    
    public func deleteAllFromKeychain() throws {
        storedItems.removeAll()
    }
    
    init(serviceName: String, accessGroup: String?) {
        self.serviceName = serviceName
        self.accessGroup = accessGroup
    }
}
