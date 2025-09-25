import Foundation

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
        }
    }

    static internal func convert(_ error: OSStatus) -> KeychainError {
        switch error {
            case errSecSuccess: return .success
            case errSecUnimplemented: return .unimplemented
            case errSecDiskFull: return .diskFull
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
}
