public class GenericItemsManagerMock: GenericItemsManagerProtocol {
    public let serviceName: String
    
    public let accessGroup: String?
    
    var storedItems: [String: Codable] = [:]

    public func saveItem<T>(item: T, key: String, accessLevel: KeychainItemAccessLevel, synchronize: Bool, updateWhenExists: Bool, attributes: ItemAttributes?) throws where T : Encodable {
        storedItems[key] = item as? any Codable
    }
    
    public func fetchItem<T>(key: String, accessLevel: KeychainItemAccessLevel?, attributes: ItemAttributes?) throws -> T where T : Decodable {
        return storedItems[key] as! T
    }

    public func updateItemData<T>(with item: T, key: String, accessLevel: KeychainItemAccessLevel, synchronize: Bool, attributes: ItemAttributes?) throws where T : Encodable {
        storedItems[key] = item as? any Codable
    }

    public func deleteItem(key: String, accessLevel: KeychainItemAccessLevel?, attributes: ItemAttributes?) throws {
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
