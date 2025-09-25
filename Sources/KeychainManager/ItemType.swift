import Foundation

public enum ItemType: RawRepresentable, CaseIterable {
    public typealias RawValue = CFString

    case generic

    public var rawValue: CFString {
        switch self {
            case .generic:
                return kSecClassGenericPassword
        }
    }

    public init?(rawValue: CFString) {
        switch rawValue {
            case kSecClassGenericPassword:
                self = .generic
            default:
                return nil
        }
    }
}
