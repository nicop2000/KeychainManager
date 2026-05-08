public class KeychainManagerMock: KeychainManagerProtocol {
    public let genericItems: GenericItemsManagerMock
    
    public typealias GenericItems = GenericItemsManagerMock
    
    public let serviceName: String
    
    public let accessGroup: String?
    
    public func wipeKeychain() throws {
        try genericItems.deleteAllFromKeychain()
    }
    
    public init(serviceName: String, accessGroup: String?) {
        self.genericItems = GenericItems(serviceName: serviceName, accessGroup: accessGroup)
        self.serviceName = serviceName
        self.accessGroup = accessGroup
    }
}
