//
//  VaultBridge.swift
//  SentinelPass
//
//  Bridge to SentinelPass Rust library via C ABI
//

import Foundation
import LocalAuthentication

/// Bridge class to communicate with the SentinelPass Rust mobile bridge
@MainActor
class VaultBridge {
    private var vaultHandle: UInt64 = 0

    // MARK: - Error Codes

    enum BridgeError: Int32 {
        case success = 0
        case invalidParam = -1
        case vaultLocked = -2
        case notFound = -3
        case crypto = -4
        case database = -5
        case io = -6
        case alreadyUnlocked = -7
        case invalidPassword = -8
        case notInitialized = -9
        case biometric = -10
        case totp = -11
        case sync = -12
        case outOfMemory = -13
        case unknown = -99
    }

    // MARK: - Vault Management

    /// Create a new vault
    func createVault(vaultPath: String, masterPassword: String) async -> Bool {
        return await withCheckedContinuation { continuation in
            let pathC = vaultPath.cString(using: .utf8)!
            let passwordC = masterPassword.cString(using: .utf8)!
            var handle: UInt64 = 0

            let errorCode = sp_vault_init(pathC, passwordC, &handle)

            if errorCode == BridgeError.success.rawValue {
                self.vaultHandle = handle
                continuation.resume(returning: true)
            } else {
                continuation.resume(returning: false)
            }
        }
    }

    /// Unlock existing vault
    func unlockVault(vaultPath: String, masterPassword: String) async -> Bool {
        return await withCheckedContinuation { continuation in
            let pathC = vaultPath.cString(using: .utf8)!
            let passwordC = masterPassword.cString(using: .utf8)!
            var handle: UInt64 = 0

            let errorCode = sp_vault_init(pathC, passwordC, &handle)

            if errorCode == BridgeError.success.rawValue {
                self.vaultHandle = handle
                continuation.resume(returning: true)
            } else {
                continuation.resume(returning: false)
            }
        }
    }

    /// Check if vault is unlocked
    func isUnlocked() async -> Bool {
        return await withCheckedContinuation { continuation in
            var unlocked: Bool = false
            let errorCode = sp_vault_is_unlocked(vaultHandle, &unlocked)
            continuation.resume(returning: errorCode == BridgeError.success.rawValue && unlocked)
        }
    }

    /// Lock the vault
    func lockVault() {
        _ = sp_vault_lock(vaultHandle)
        vaultHandle = 0
    }

    /// Destroy vault handle
    func destroyVault() {
        _ = sp_vault_destroy(vaultHandle)
        vaultHandle = 0
    }

    // MARK: - Entry Management

    /// Add a new entry
    func addEntry(title: String, username: String, password: String, url: String, notes: String) async -> String? {
        return await withCheckedContinuation { continuation in
            let titleC = title.cString(using: .utf8)!
            let usernameC = username.cString(using: .utf8)!
            let passwordC = password.cString(using: .utf8)!
            let urlC = url.cString(using: .utf8)!
            let notesC = notes.cString(using: .utf8)!

            var entryIdPointer: UnsafeMutablePointer<CChar>?

            let result = sp_entry_add(
                vaultHandle,
                titleC,
                usernameC,
                passwordC,
                urlC,
                notesC,
                &entryIdPointer
            )

            guard result == BridgeError.success.rawValue, let entryId = entryIdPointer else {
                continuation.resume(returning: nil)
                return
            }

            let entryIdString = String(cString: entryId)
            sp_string_free(entryIdPointer)

            continuation.resume(returning: entryIdString)
        }
    }

    /// Get entry by ID
    func getEntry(id: String) async -> EntryDetails? {
        return await withCheckedContinuation { continuation in
            let idC = id.cString(using: .utf8)!
            var entry = SPEntry()

            let result = sp_entry_get_by_id(vaultHandle, idC, &entry)

            guard result == BridgeError.success.rawValue else {
                continuation.resume(returning: nil)
                return
            }

            let details = EntryDetails(
                id: String(cString: entry.id!),
                title: String(cString: entry.title!),
                username: String(cString: entry.username!),
                password: String(cString: entry.password!),
                url: entry.url != nil ? String(cString: entry.url!) : nil,
                notes: entry.notes != nil ? String(cString: entry.notes!) : nil,
                favorite: entry.favorite,
                createdAt: Date(timeIntervalSince1970: TimeInterval(entry.created_at)),
                modifiedAt: Date(timeIntervalSince1970: TimeInterval(entry.modified_at))
            )

            // Free strings
            sp_string_free(entry.id!)
            sp_string_free(entry.title!)
            sp_string_free(entry.username!)
            sp_string_free(entry.password!)
            if entry.url != nil { sp_string_free(entry.url!) }
            if entry.notes != nil { sp_string_free(entry.notes!) }

            continuation.resume(returning: details)
        }
    }

    /// List all entries
    func listEntries() async -> [EntrySummary] {
        return await withCheckedContinuation { continuation in
            var entriesPointer: UnsafeMutablePointer<UnsafeMutablePointer<SPEntrySummary>?>?
            var count: UInt = 0

            let result = sp_entry_list_all(vaultHandle, &entriesPointer, &count)

            guard result == BridgeError.success.rawValue, let entries = entriesPointer else {
                continuation.resume(returning: [])
                return
            }

            var summaries: [EntrySummary] = []

            for i in 0..<count {
                let entry = entries![Int(i)].pointee
                let summary = EntrySummary(
                    id: String(cString: entry.id!),
                    title: String(cString: entry.title!),
                    username: String(cString: entry.username!),
                    favorite: entry.favorite
                )
                summaries.append(summary)

                // Free strings
                sp_string_free(entry.id!)
                sp_string_free(entry.title!)
                sp_string_free(entry.username!)
            }

            // Free array
            sp_bytes_free(entriesPointer, UInt(count))

            continuation.resume(returning: summaries)
        }
    }

    /// Search entries
    func searchEntries(query: String) async -> [EntrySummary] {
        return await withCheckedContinuation { continuation in
            let queryC = query.cString(using: .utf8)!
            var entriesPointer: UnsafeMutablePointer<UnsafeMutablePointer<SPEntrySummary>?>?
            var count: UInt = 0

            let result = sp_entry_search(vaultHandle, queryC, &entriesPointer, &count)

            guard result == BridgeError.success.rawValue, let entries = entriesPointer else {
                continuation.resume(returning: [])
                return
            }

            var summaries: [EntrySummary] = []

            for i in 0..<count {
                let entry = entries![Int(i)].pointee
                let summary = EntrySummary(
                    id: String(cString: entry.id!),
                    title: String(cString: entry.title!),
                    username: String(cString: entry.username!),
                    favorite: entry.favorite
                )
                summaries.append(summary)

                // Free strings
                sp_string_free(entry.id!)
                sp_string_free(entry.title!)
                sp_string_free(entry.username!)
            }

            // Free array
            sp_bytes_free(entriesPointer, UInt(count))

            continuation.resume(returning: summaries)
        }
    }

    /// Delete entry
    func deleteEntry(id: String) async -> Bool {
        return await withCheckedContinuation { continuation in
            let idC = id.cString(using: .utf8)!
            let result = sp_entry_delete(vaultHandle, idC)
            continuation.resume(returning: result == BridgeError.success.rawValue)
        }
    }

    /// Update entry (not in C ABI yet, placeholder)
    func updateEntry(id: String, title: String, username: String, password: String, url: String, notes: String) async -> Bool {
        // Note: The C ABI doesn't have sp_entry_update yet
        // This is a placeholder that would need to be added
        return await withCheckedContinuation { continuation in
            // TODO: Implement update via delete + add for now
            continuation.resume(returning: true)
        }
    }

    // MARK: - TOTP

    /// Generate TOTP code
    func generateTotp(entryId: String) async -> TotpCode? {
        return await withCheckedContinuation { continuation in
            let entryIdC = entryId.cString(using: .utf8)!
            var totpCode = SPTotpCode()

            let result = sp_totp_generate_code(vaultHandle, entryIdC, &totpCode)

            guard result == BridgeError.success.rawValue else {
                continuation.resume(returning: nil)
                return
            }

            let code = String(cString: totpCode.code!)
            let seconds = totpCode.seconds_remaining

            sp_string_free(totpCode.code!)

            continuation.resume(returning: TotpCode(code: code, secondsRemaining: seconds))
        }
    }

    // MARK: - Password Generation

    /// Generate random password
    static func generatePassword(length: Int, includeSymbols: Bool) async -> String? {
        return await withCheckedContinuation { continuation in
            var passwordPointer: UnsafeMutablePointer<CChar>?

            let result = sp_password_generate(
                UInt(length),
                includeSymbols ? 1 : 0,
                &passwordPointer
            )

            guard result == BridgeError.success.rawValue, let password = passwordPointer else {
                continuation.resume(returning: nil)
                return
            }

            let passwordStr = String(cString: password)
            sp_string_free(password)

            continuation.resume(returning: passwordStr)
        }
    }

    /// Check password strength
    static func checkPasswordStrength(password: String) async -> PasswordAnalysis? {
        return await withCheckedContinuation { continuation in
            let passwordC = password.cString(using: .utf8)!
            var analysis = SPPasswordAnalysis()

            let result = sp_password_check_strength(passwordC, &analysis)

            guard result == BridgeError.success.rawValue else {
                continuation.resume(returning: nil)
                return
            }

            let strength = PasswordAnalysis(
                score: Int(analysis.score),
                entropyBits: analysis.entropy_bits,
                crackTimeSeconds: analysis.crack_time_seconds,
                length: Int(analysis.length),
                hasLower: analysis.has_lower,
                hasUpper: analysis.has_upper,
                hasDigit: analysis.has_digit,
                hasSymbol: analysis.has_symbol
            )

            continuation.resume(returning: strength)
        }
    }

    // MARK: - Biometric

    /// Set biometric key
    func setBiometricKey(keyData: Data) async -> Bool {
        return await withCheckedContinuation { continuation in
            let result = keyData.withUnsafeBytes { bytes in
                sp_biometric_set_key(
                    vaultHandle,
                    bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    keyData.count
                )
            }
            continuation.resume(returning: result == BridgeError.success.rawValue)
        }
    }

    /// Check if biometric key exists
    func hasBiometricKey() async -> Bool {
        return await withCheckedContinuation { continuation in
            var hasKey: Bool = false
            let result = sp_biometric_has_key(vaultHandle, &hasKey)
            continuation.resume(returning: result == BridgeError.success.rawValue && hasKey)
        }
    }

    /// Remove biometric key
    func removeBiometricKey() async -> Bool {
        return await withCheckedContinuation { continuation in
            let result = sp_biometric_remove_key(vaultHandle)
            continuation.resume(returning: result == BridgeError.success.rawValue)
        }
    }

    /// Unlock with biometric
    func unlockWithBiometric() async -> Bool {
        return await withCheckedContinuation { continuation in
            let result = sp_biometric_unlock(vaultHandle)
            continuation.resume(returning: result == BridgeError.success.rawValue)
        }
    }
}

// MARK: - Supporting Types

struct EntryDetails {
    let id: String
    let title: String
    let username: String
    let password: String
    let url: String?
    let notes: String?
    let favorite: Bool
    let createdAt: Date
    let modifiedAt: Date
}

// MARK: - C Structs (from sentinelpass_bridge.h)

struct SPEntry {
    var id: UnsafeMutablePointer<CChar>?
    var title: UnsafeMutablePointer<CChar>?
    var username: UnsafeMutablePointer<CChar>?
    var password: UnsafeMutablePointer<CChar>?
    var url: UnsafeMutablePointer<CChar>?
    var notes: UnsafeMutablePointer<CChar>?
    var created_at: Int64
    var modified_at: Int64
    var favorite: Bool
}

struct SPEntrySummary {
    var id: UnsafeMutablePointer<CChar>?
    var title: UnsafeMutablePointer<CChar>?
    var username: UnsafeMutablePointer<CChar>?
    var favorite: Bool
}

struct SPPasswordAnalysis {
    var score: Int32
    var entropy_bits: Double
    var crack_time_seconds: Double
    var length: UInt32
    var has_lower: Bool
    var has_upper: Bool
    var has_digit: Bool
    var has_symbol: Bool
}

struct SPTotpCode {
    var code: UnsafeMutablePointer<CChar>?
    var seconds_remaining: UInt32
}

// MARK: - C Function Declarations

func sp_vault_init(
    _ vaultPath: UnsafePointer<CChar>,
    _ masterPassword: UnsafePointer<CChar>,
    _ outHandle: UnsafeMutablePointer<UInt64>
) -> Int32 {
    fatalError("C function will be linked from sentinelpass-mobile-bridge")
}

func sp_vault_destroy(_ handle: UInt64) -> Int32 {
    fatalError("C function will be linked from sentinelpass-mobile-bridge")
}

func sp_vault_is_unlocked(_ handle: UInt64, _ outUnlocked: UnsafeMutablePointer<Bool>) -> Int32 {
    fatalError("C function will be linked from sentinelpass-mobile-bridge")
}

func sp_vault_lock(_ handle: UInt64) -> Int32 {
    fatalError("C function will be linked from sentinelpass-mobile-bridge")
}

func sp_entry_add(
    _ handle: UInt64,
    _ title: UnsafePointer<CChar>,
    _ username: UnsafePointer<CChar>,
    _ password: UnsafePointer<CChar>,
    _ url: UnsafePointer<CChar>,
    _ notes: UnsafePointer<CChar>,
    _ outEntryId: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    fatalError("C function will be linked from sentinelpass-mobile-bridge")
}

func sp_entry_get_by_id(
    _ handle: UInt64,
    _ entryId: UnsafePointer<CChar>,
    _ outEntry: UnsafeMutablePointer<SPEntry>
) -> Int32 {
    fatalError("C function will be linked from sentinelpass-mobile-bridge")
}

func sp_entry_list_all(
    _ handle: UInt64,
    _ outEntries: UnsafeMutablePointer<UnsafeMutablePointer<UnsafeMutablePointer<SPEntrySummary>?>?>,
    _ outCount: UnsafeMutablePointer<UInt>
) -> Int32 {
    fatalError("C function will be linked from sentinelpass-mobile-bridge")
}

func sp_entry_search(
    _ handle: UInt64,
    _ query: UnsafePointer<CChar>,
    _ outEntries: UnsafeMutablePointer<UnsafeMutablePointer<UnsafeMutablePointer<SPEntrySummary>?>?>,
    _ outCount: UnsafeMutablePointer<UInt>
) -> Int32 {
    fatalError("C function will be linked from sentinelpass-mobile-bridge")
}

func sp_entry_delete(_ handle: UInt64, _ entryId: UnsafePointer<CChar>) -> Int32 {
    fatalError("C function will be linked from sentinelpass-mobile-bridge")
}

func sp_totp_generate_code(
    _ handle: UInt64,
    _ entryId: UnsafePointer<CChar>,
    _ outCode: UnsafeMutablePointer<SPTotpCode>
) -> Int32 {
    fatalError("C function will be linked from sentinelpass-mobile-bridge")
}

func sp_password_generate(
    _ length: UInt,
    _ includeSymbols: Int32,
    _ outPassword: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    fatalError("C function will be linked from sentinelpass-mobile-bridge")
}

func sp_password_check_strength(
    _ password: UnsafePointer<CChar>,
    _ outAnalysis: UnsafeMutablePointer<SPPasswordAnalysis>
) -> Int32 {
    fatalError("C function will be linked from sentinelpass-mobile-bridge")
}

func sp_biometric_set_key(
    _ handle: UInt64,
    _ keyData: UnsafePointer<UInt8>?,
    _ keyDataLen: Int
) -> Int32 {
    fatalError("C function will be linked from sentinelpass-mobile-bridge")
}

func sp_biometric_has_key(_ handle: UInt64, _ outHasKey: UnsafeMutablePointer<Bool>) -> Int32 {
    fatalError("C function will be linked from sentinelpass-mobile-bridge")
}

func sp_biometric_remove_key(_ handle: UInt64) -> Int32 {
    fatalError("C function will be linked from sentinelpass-mobile-bridge")
}

func sp_biometric_unlock(_ handle: UInt64) -> Int32 {
    fatalError("C function will be linked from sentinelpass-mobile-bridge")
}

func sp_string_free(_ ptr: UnsafeMutablePointer<CChar>) {
    fatalError("C function will be linked from sentinelpass-mobile-bridge")
}

func sp_bytes_free(_ ptr: UnsafeMutablePointer<UInt8>?, _ len: UInt) {
    fatalError("C function will be linked from sentinelpass-mobile-bridge")
}
