public protocol KeychainManagerProtocol {
    associatedtype GenericItems: GenericItemsManagerProtocol

    var serviceName: String { get }
    var accessGroup: String? { get }
    var genericItems: GenericItems { get }

    func wipeKeychain() throws
}