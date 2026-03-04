//
//  CloudKitService.swift
//  SentinelPass
//
//  iCloud sync service using CloudKit for iOS.
//  Integrates with the Rust iCloud sync module via FFI.
//

import Foundation
import CloudKit
import CryptoKit

/// CloudKit sync service for SentinelPass
///
/// This service handles encrypted sync blob storage in iCloud using CloudKit's
/// private database. All sync operations use the core sync logic from Rust,
/// while this Swift class handles the CloudKit API integration.
@MainActor
public class CloudKitService: ObservableObject {

    // MARK: - Properties

    /// CloudKit container for SentinelPass
    private let container: CKContainer

    /// Private database for user-specific data
    private var database: CKDatabase {
        container.privateCloudDatabase
    }

    /// Device ID for this instance
    public let deviceID: UUID

    /// Current sync state
    @Published public private(set) var syncState: SyncState = .idle

    /// Last sync token (for incremental sync)
    private var lastServerChangeToken: CKServerChangeToken?

    /// Sync state enumeration
    public enum SyncState: Equatable {
        case idle
        case syncing(progress: Double)
        case complete
        case error(Error)

        public static func == (lhs: SyncState, rhs: SyncState) -> Bool {
            switch (lhs, rhs) {
            case (.idle, .idle), (.syncing, .syncing), (.complete, .complete):
                return true
            case (.error, .error):
                return true
            default:
                return false
            }
        }
    }

    /// CloudKit-specific errors
    public enum CloudKitError: LocalizedError {
        case notAuthenticated
        case quotaExceeded
        case networkError(Error)
        case syncFailed(String)
        case recordNotFound(String)

        public var errorDescription: String? {
            switch self {
            case .notAuthenticated:
                return "iCloud is not authenticated. Please sign in to iCloud."
            case .quotaExceeded:
                return "iCloud storage quota exceeded."
            case .networkError(let error):
                return "Network error: \(error.localizedDescription)"
            case .syncFailed(let message):
                return "Sync failed: \(message)"
            case .recordNotFound(let id):
                return "Record not found: \(id)"
            }
        }
    }

    // MARK: - Initialization

    /// Initialize CloudKit service
    ///
    /// - Parameters:
    ///   - deviceID: Unique identifier for this device
    ///   - containerID: Optional custom container ID (defaults to "iCloud.com.sentinelpass.sync")
    public init(deviceID: UUID, containerID: String? = nil) {
        self.deviceID = deviceID

        if let containerID = containerID {
            self.container = CKContainer(identifier: containerID)
        } else {
            self.container = CKContainer.default()
        }
    }

    // MARK: - Public API

    /// Check if iCloud is available
    ///
    /// - Returns: Boolean indicating iCloud account status
    public func checkCloudKitAvailability() async -> Bool {
        do {
            let status = try await container.accountStatus()
            return status == .available
        } catch {
            return false
        }
    }

    /// Push sync entries to CloudKit
    ///
    /// - Parameters:
    ///   - blobs: Array of sync entry blobs to upload
    ///
    /// - Returns: Result indicating success or failure
    public func pushEntries(_ blobs: [CloudKitRecord]) async -> Result<Void, Error> {
        syncState = .syncing(progress: 0.0)

        // Prepare records for CloudKit
        let records = blobs.map { blob -> CKRecord in
            let record = CKRecord(recordType: "SyncEntry", recordID: CKRecord.ID(recordName: blob.recordID))
            record["encryptedPayload"] = blob.encryptedPayload
            record["modifiedAt"] = blob.modifiedAt
            record["isTombstone"] = blob.isTombstone
            record["entryType"] = blob.entryType
            record["syncVersion"] = blob.syncVersion
            record["originDeviceId"] = blob.originDeviceId
            return record
        }

        // Save records in batches
        let batchSize = 100
        let totalBatches = (records.count + batchSize - 1) / batchSize

        for batchIndex in 0..<totalBatches {
            let start = batchIndex * batchSize
            let end = min(start + batchSize, records.count)
            let batch = Array(records[start..<end])

            do {
                try await saveRecords(batch)
                syncState = .syncing(progress: Double(batchIndex + 1) / Double(totalBatches))
            } catch {
                syncState = .error(error)
                return .failure(error)
            }
        }

        syncState = .complete
        return .success(())
    }

    /// Pull sync entries from CloudKit
    ///
    /// - Parameters:
    ///   - sinceToken: Optional server change token for incremental sync
    ///
    /// - Returns: Result with array of CloudKit records and next token
    public func pullEntries(sinceToken: String? = nil) async -> Result<([CloudKitRecord], String?), Error> {
        syncState = .syncing(progress: 0.0)

        var fetchedRecords: [CloudKitRecord] = []
        var nextToken: String?

        do {
            // Query for all SyncEntry records
            let query = CKQuery(recordType: "SyncEntry", predicate: NSPredicate(value: true))

            // Configure query operation
            let operation = CKQueryOperation(query: query)
            operation.resultsLimit = 100

            // Records handler
            var recordsPerBatch: [CKRecord] = []
            operation.recordMatchedBlock = { recordID, result in
                switch result {
                case .success(let record):
                    recordsPerBatch.append(record)
                case .failure(let error):
                    print("Error fetching record: \(error)")
                }
            }

            // Completion handler
            operation.queryResultBlock = { result in
                switch result {
                case .success(let cursor):
                    if let cursor = cursor {
                        // More results available
                        nextToken = self.encodeServerChangeToken(cursor)
                    }
                case .failure(let error):
                    print("Query failed: \(error)")
                }
            }

            try await database.add(operation)

            // Convert CKRecords to CloudKitRecords
            fetchedRecords = recordsPerBatch.compactMap { record in
                self.convertCKRecordToCloudKitRecord(record)
            }

            syncState = .complete
            return .success((fetchedRecords, nextToken))

        } catch {
            syncState = .error(error)
            return .failure(error)
        }
    }

    /// Delete entries from CloudKit
    ///
    /// - Parameters:
    ///   - recordIDs: Array of record IDs to delete
    ///
    /// - Returns: Result indicating success or failure
    public func deleteEntries(recordIDs: [String]) async -> Result<Void, Error> {
        let ckRecordIDs = recordIDs.map { CKRecord.ID(recordName: $0) }

        do {
            try await database.deleteRecords(withIDs: ckRecordIDs)
            return .success(())
        } catch {
            return .failure(error)
        }
    }

    /// Register this device with CloudKit
    ///
    /// - Returns: Result indicating success or failure
    public func registerDevice() async -> Result<Void, Error> {
        // Create a device registration record
        let recordID = CKRecord.ID(recordName: "device_\(deviceID.uuidString)")
        let record = CKRecord(recordType: "DeviceInfo", recordID: recordID)

        record["deviceID"] = deviceID.uuidString
        record["deviceName"] = UIDevice.current.name
        record["deviceType"] = "iOS"
        record["registeredAt"] = Date()

        do {
            try await database.save(record)
            return .success(())
        } catch {
            // Ignore "already exists" error
            if let ckError = error as? CKError,
               case .serverRecordChanged = ckError.code {
                return .success(())
            }
            return .failure(error)
        }
    }

    // MARK: - Private Helpers

    /// Save records to CloudKit
    private func saveRecords(_ records: [CKRecord]) async throws {
        let operation = CKModifyRecordsOperation(recordsToSave: records, recordIDsToDelete: nil)

        try await database.add(operation)
    }

    /// Convert CKRecord to CloudKitRecord
    private func convertCKRecordToCloudKitRecord(_ record: CKRecord) -> CloudKitRecord? {
        guard let encryptedPayload = record["encryptedPayload"] as? String,
              let modifiedAt = record["modifiedAt"] as? Int64,
              let isTombstone = record["isTombstone"] as? Bool,
              let entryType = record["entryType"] as? String,
              let syncVersion = record["syncVersion"] as? Int64,
              let originDeviceId = record["originDeviceId"] as? String else {
            return nil
        }

        return CloudKitRecord(
            recordType: "SyncEntry",
            recordID: record.recordID.recordName,
            encryptedPayload: encryptedPayload,
            modifiedAt: modifiedAt,
            isTombstone: isTombstone,
            entryType: entryType,
            syncVersion: UInt64(syncVersion),
            originDeviceId: originDeviceId
        )
    }

    /// Encode server change token to string for storage
    private func encodeServerChangeToken(_ token: CKServerChangeToken) -> String? {
        do {
            let data = try NSKeyedArchiver.archivedData(withRootObject: token, requiringSecureCoding: true)
            return data.base64EncodedString()
        } catch {
            return nil
        }
    }

    /// Decode server change token from string
    private func decodeServerChangeToken(_ tokenString: String) -> CKServerChangeToken? {
        guard let data = Data(base64Encoded: tokenString) else { return nil }
        do {
            return try NSKeyedUnarchiver.unarchivedObject(ofClass: CKServerChangeToken.self, from: data)
        } catch {
            return nil
        }
    }
}

// MARK: - CloudKitRecord Model

/// CloudKit record representation
public struct CloudKitRecord: Codable {
    public let recordType: String
    public let recordID: String
    public let encryptedPayload: String
    public let modifiedAt: Int64
    public let isTombstone: Bool
    public let entryType: String
    public let syncVersion: UInt64
    public let originDeviceId: String
}

// MARK: - Array Extension

extension Array {
    /// Compact map implementation for older Swift versions
    func compactMap<ElementOfResult>(_ transform: (Element) throws -> ElementOfResult?) rethrows -> [ElementOfResult] {
        var result: [ElementOfResult] = []
        for element in self {
            if let transformed = try? transform(element) {
                result.append(transformed)
            }
        }
        return result
    }
}
