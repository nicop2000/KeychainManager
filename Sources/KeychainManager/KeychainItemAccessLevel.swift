import Foundation

public enum KeychainItemAccessLevel: RawRepresentable, CaseIterable {
    /// After a restart the phone must be unlocked once to access the data.
    /// Encrypted backups contain this item
    case afterFirstUnlock

    /// After a restart the phone must be unlocked once to access the data.
    /// Encrypted backups do not contain this item
    case afterFirstUnlockThisDeviceOnly

    /// Accessable while the phone is unlocked.
    /// - Note: Default behaviour for a keychain item
    /// Encrypted backups contain this item
    case whenUnlocked

    /// Accessable while the phone is unlocked.
    /// Encrypted backups do not contain this item
    case whenUnlockedThisDeviceOnly

    /// The data is only available when the devicde is unlocked. A passcode must be set to use this option. Upon deleting the passcode the data will be deleted as well.
    /// Encrypted backups do not contain this item
    case whenPasscodeSetThisDeviceOnly

    public var displayName: String {
        switch self {
            case .afterFirstUnlock:
                return "After First Unlock"
            case .afterFirstUnlockThisDeviceOnly:
                return "After First Unlock This Device Only"
            case .whenPasscodeSetThisDeviceOnly:
                return "When Passcode Set This Device Only"
            case .whenUnlocked:
                return "When Unlocked"
            case .whenUnlockedThisDeviceOnly:
                return "When Unlocked This Device Only"
        }
    }
    public var rawValue: CFString {
        switch self {
            case .afterFirstUnlock:
                return kSecAttrAccessibleAfterFirstUnlock
            case .afterFirstUnlockThisDeviceOnly:
                return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            case .whenPasscodeSetThisDeviceOnly:
                return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
            case .whenUnlocked:
                return kSecAttrAccessibleWhenUnlocked
            case .whenUnlockedThisDeviceOnly:
                return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
    }

    public init?(rawValue: CFString) {
        switch rawValue {
            case kSecAttrAccessibleAfterFirstUnlock:
                self = .afterFirstUnlock
            case kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly:
                self = .afterFirstUnlockThisDeviceOnly
            case kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly:
                self = .whenPasscodeSetThisDeviceOnly
            case kSecAttrAccessibleWhenUnlocked:
                self = .whenUnlocked
            case kSecAttrAccessibleWhenUnlockedThisDeviceOnly:
                self = .whenUnlockedThisDeviceOnly
            default:
                return nil
        }
    }
}
