//
//  KeychainManagerExtension.swift
//
//
//  Created by Nico Petersen on 09.09.23.
//

import Foundation

public extension KeychainManager {
    enum ItemType: RawRepresentable, CaseIterable {
        public typealias RawValue = CFString
        
        case generic
        case certificate
        case password
        case identity
        case cryptography
        
        public var rawValue: CFString {
            switch self {
            case .generic:
                return kSecClassGenericPassword
            case .certificate:
                return kSecClassCertificate
            case .password:
                return kSecClassInternetPassword
            case .identity:
                return kSecClassIdentity
            case .cryptography:
                return kSecClassKey
            }
        }
        
        public init?(rawValue: CFString) {
            switch rawValue {
            case kSecClassGenericPassword:
                self = .generic
            case kSecClassCertificate:
                self = .certificate
            case kSecClassInternetPassword:
                self = .password
            case kSecClassIdentity:
                self = .identity
            case kSecClassKey:
                self = .cryptography
            default:
                return nil
            }
        }
    }

    public enum KeychainError: Error, Equatable {
        case success
        case unimplemented
        case diskFull
        case io
        case opWr
        case param
        case wrPerm
        case allocate
        case userCanceled
        case badReq
        case internalComponent
        case coreFoundationUnknown
        case missingEntitlement
        case restrictedAPI
        case notAvailable
        case readOnly
        case authFailed
        case invalidKeychain
        case duplicateKeychain
        case duplicateCallback
        case invalidCallback
        case bufferTooSmall
        case dataTooLarge
        case noSuchAttr
        case invalidItemRef
        case invalidSearchRef
        case noSuchClass
        case noDefaultKeychain
        case interactionNotAllowed
        case readOnlyAttr
        case wrongSecVersion
        case keySizeNotAllowed
        case noStorageModule
        case noCertificateModule
        case noPolicyModule
        case interactionRequired
        case dataNotAvailable
        case dataNotModifiable
        case createChainFailed
        case invalidPrefsDomain
        case inDarkWake
        case invalidData
        case itemNotFound
        case duplicateItem
        case incorrectAttributeForClass
        case noSuchKeychain
        case unexpected(OSStatus)

        public var localizedDescription: String {
            switch self {
                case .success: return "Operation successful"
                case .unimplemented: return "Function or operation not implemented"
                case .diskFull: return "Disk full"
                case .io: return "I/O error"
                case .opWr: return "Write operation failed"
                case .param: return "Invalid parameter"
                case .wrPerm: return "Write permission error"
                case .allocate: return "Memory allocation error"
                case .userCanceled: return "User canceled the operation"
                case .badReq: return "Bad request"
                case .internalComponent: return "Internal component error"
                case .coreFoundationUnknown: return "Unknown Core Foundation error"
                case .missingEntitlement: return "Missing entitlement"
                case .restrictedAPI: return "Restricted API"
                case .notAvailable: return "Service not available"
                case .readOnly: return "Read-only error"
                case .authFailed: return "Authentication failed"
                case .invalidKeychain: return "Invalid keychain"
                case .duplicateKeychain: return "Duplicate keychain"
                case .duplicateCallback: return "Duplicate callback"
                case .invalidCallback: return "Invalid callback"
                case .bufferTooSmall: return "Buffer too small"
                case .dataTooLarge: return "Data too large"
                case .noSuchAttr: return "No such attribute"
                case .invalidItemRef: return "Invalid item reference"
                case .invalidSearchRef: return "Invalid search reference"
                case .noSuchClass: return "No such class"
                case .noDefaultKeychain: return "No default keychain"
                case .interactionNotAllowed: return "Interaction not allowed"
                case .readOnlyAttr: return "Read-only attribute"
                case .wrongSecVersion: return "Wrong security version"
                case .keySizeNotAllowed: return "Key size not allowed"
                case .noStorageModule: return "No storage module"
                case .noCertificateModule: return "No certificate module"
                case .noPolicyModule: return "No policy module"
                case .interactionRequired: return "Interaction required"
                case .dataNotAvailable: return "Data not available"
                case .dataNotModifiable: return "Data not modifiable"
                case .createChainFailed: return "Failed to create trust chain"
                case .invalidPrefsDomain: return "Invalid preferences domain"
                case .inDarkWake: return "Operation not allowed in dark wake"
                case .invalidData: return "Invalid data"
                case .itemNotFound: return "Item not found"
                case .duplicateItem: return "Duplicate Item"
                case .incorrectAttributeForClass: return "Incorrect Attribute for Class"
                case .noSuchKeychain: return "No such keychain"
                case .unexpected(let oSStatus): return "Unexpected error - \(oSStatus)"
                default: return "Nope"
            }
        }
    }

    internal func convertError(_ error: OSStatus) -> KeychainError {
        switch error {
            case errSecSuccess: return .success
            case errSecUnimplemented: return .unimplemented
            case errSecDiskFull, errSecDskFull: return .diskFull
            case errSecIO: return .io
            case errSecOpWr: return .opWr
            case errSecParam: return .param
            case errSecWrPerm: return .wrPerm
            case errSecAllocate: return .allocate
            case errSecUserCanceled: return .userCanceled
            case errSecBadReq: return .badReq
            case errSecInternalComponent: return .internalComponent
            case errSecCoreFoundationUnknown: return .coreFoundationUnknown
            case errSecMissingEntitlement: return .missingEntitlement
            case errSecRestrictedAPI: return .restrictedAPI
            case errSecNotAvailable: return .notAvailable
            case errSecReadOnly: return .readOnly
            case errSecAuthFailed: return .authFailed
            case errSecInvalidKeychain: return .invalidKeychain
            case errSecDuplicateKeychain: return .duplicateKeychain
            case errSecDuplicateCallback: return .duplicateCallback
            case errSecInvalidCallback: return .invalidCallback
            case errSecDuplicateItem: return .duplicateItem
            case errSecItemNotFound: return .itemNotFound
            case errSecBufferTooSmall: return .bufferTooSmall
            case errSecDataTooLarge: return .dataTooLarge
            case errSecNoSuchAttr: return .noSuchAttr
            case errSecInvalidItemRef: return .invalidItemRef
            case errSecInvalidSearchRef: return .invalidSearchRef
            case errSecNoSuchClass: return .noSuchClass
            case errSecNoDefaultKeychain: return .noDefaultKeychain
            case errSecInteractionNotAllowed: return .interactionNotAllowed
            case errSecReadOnlyAttr: return .readOnlyAttr
            case errSecWrongSecVersion: return .wrongSecVersion
            case errSecKeySizeNotAllowed: return .keySizeNotAllowed
            case errSecNoStorageModule: return .noStorageModule
            case errSecNoCertificateModule: return .noCertificateModule
            case errSecNoPolicyModule: return .noPolicyModule
            case errSecInteractionRequired: return .interactionRequired
            case errSecDataNotAvailable: return .dataNotAvailable
            case errSecDataNotModifiable: return .dataNotModifiable
            case errSecCreateChainFailed: return .createChainFailed
            case errSecInvalidPrefsDomain: return .invalidPrefsDomain
            case errSecInDarkWake: return .inDarkWake
            case errSecNoSuchKeychain: return .noSuchKeychain
            default: return .unexpected(error)
        }
    }
    
    enum KeychainItemAccessLevel: RawRepresentable, CaseIterable {
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
}
