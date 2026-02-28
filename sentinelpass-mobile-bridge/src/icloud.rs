//! iCloud sync implementation using CloudKit
//!
//! This module provides the core functionality for syncing with iCloud via CloudKit.
//! The actual CloudKit API calls happen in Swift (iOS), this module handles:
//! - Data serialization for CloudKit records
//! - Sync state management
//! - Conflict resolution (using existing sync module)

use crate::error::{BridgeError, BridgeResult, ErrorCode};
use base64::Engine;
use sentinelpass_core::sync::models::{SyncEntryBlob, SyncEntryType};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// CloudKit record representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudKitRecord {
    /// Record type (always "SyncEntry" for our sync)
    #[serde(rename = "recordType")]
    pub record_type: String,

    /// Unique record ID
    #[serde(rename = "recordID")]
    pub record_id: String,

    /// Encrypted sync entry data
    #[serde(rename = "encryptedPayload")]
    pub encrypted_payload: String,

    /// Modification timestamp
    #[serde(rename = "modifiedAt")]
    pub modified_at: i64,

    /// Whether this is a tombstone (deleted entry)
    #[serde(rename = "isTombstone")]
    pub is_tombstone: bool,

    /// Sync entry type
    #[serde(rename = "entryType")]
    pub entry_type: String,

    /// Sync version
    #[serde(rename = "syncVersion")]
    pub sync_version: u64,

    /// Device ID that created this entry
    #[serde(rename = "originDeviceId")]
    pub origin_device_id: String,
}

impl CloudKitRecord {
    /// Create a CloudKit record from a sync entry blob
    pub fn from_sync_blob(blob: &SyncEntryBlob) -> Self {
        // Encode encrypted payload as base64 string for JSON transport
        let encrypted_payload =
            base64::engine::general_purpose::STANDARD.encode(&blob.encrypted_payload);

        Self {
            record_type: "SyncEntry".to_string(),
            record_id: blob.sync_id.to_string(),
            encrypted_payload,
            modified_at: blob.modified_at,
            is_tombstone: blob.is_tombstone,
            entry_type: format!("{:?}", blob.entry_type),
            sync_version: blob.sync_version,
            origin_device_id: blob.origin_device_id.to_string(),
        }
    }

    /// Convert to sync entry blob
    pub fn to_sync_blob(&self) -> BridgeResult<SyncEntryBlob> {
        // Decode base64 encrypted payload
        let encrypted_payload = base64::engine::general_purpose::STANDARD
            .decode(&self.encrypted_payload)
            .map_err(|e| BridgeError::Sync(format!("Invalid base64: {}", e)))?;

        // Parse entry type from string
        let entry_type = match self.entry_type.as_str() {
            "Credential" => SyncEntryType::Credential,
            "TotpSecret" => SyncEntryType::TotpSecret,
            "SshKey" => SyncEntryType::SshKey,
            _ => {
                return Err(BridgeError::InvalidParam(format!(
                    "Unknown entry type: {}",
                    self.entry_type
                )))
            }
        };

        Ok(SyncEntryBlob {
            sync_id: Uuid::parse_str(&self.record_id)
                .map_err(|e| BridgeError::InvalidParam(format!("Invalid UUID: {}", e)))?,
            entry_type,
            sync_version: self.sync_version,
            modified_at: self.modified_at,
            encrypted_payload,
            is_tombstone: self.is_tombstone,
            origin_device_id: Uuid::parse_str(&self.origin_device_id)
                .map_err(|e| BridgeError::InvalidParam(format!("Invalid device UUID: {}", e)))?,
        })
    }
}

/// CloudKit sync state
#[derive(Debug, Clone, PartialEq)]
pub struct CloudKitSyncState {
    /// Last sync timestamp
    pub last_sync_at: Option<i64>,
    /// Server sequence number
    pub server_sequence: Option<u64>,
    /// Device ID
    pub device_id: Uuid,
    /// Container name
    pub container_name: String,
}

impl Default for CloudKitSyncState {
    fn default() -> Self {
        Self {
            last_sync_at: None,
            server_sequence: None,
            device_id: Uuid::new_v4(),
            container_name: "iCloud.com.sentinelpass.sync".to_string(),
        }
    }
}

/// iCloud sync manager
pub struct ICloudSyncManager {
    state: Arc<Mutex<CloudKitSyncState>>,
}

impl ICloudSyncManager {
    /// Create a new iCloud sync manager
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(CloudKitSyncState::default())),
        }
    }

    /// Initialize sync with a device ID
    pub fn init(&self, device_id: Uuid, container_name: Option<String>) -> BridgeResult<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|e| BridgeError::Sync(format!("Lock error: {}", e)))?;

        state.device_id = device_id;
        if let Some(name) = container_name {
            state.container_name = name;
        }

        Ok(())
    }

    /// Prepare records for upload to CloudKit
    pub fn prepare_upload(&self, blobs: &[SyncEntryBlob]) -> BridgeResult<Vec<CloudKitRecord>> {
        let state = self
            .state
            .lock()
            .map_err(|e| BridgeError::Sync(format!("Lock error: {}", e)))?;

        blobs
            .iter()
            .map(|blob| {
                let mut record = CloudKitRecord::from_sync_blob(blob);
                // Add device ID if not present
                if record.origin_device_id.is_empty() {
                    record.origin_device_id = state.device_id.to_string();
                }
                Ok(record)
            })
            .collect()
    }

    /// Process records downloaded from CloudKit
    pub fn process_download(
        &self,
        records: Vec<CloudKitRecord>,
    ) -> BridgeResult<Vec<SyncEntryBlob>> {
        records
            .into_iter()
            .map(|record| record.to_sync_blob())
            .collect()
    }

    /// Get current sync state
    pub fn get_state(&self) -> BridgeResult<CloudKitSyncState> {
        let state_guard = self
            .state
            .lock()
            .map_err(|e| BridgeError::Sync(format!("Lock error: {}", e)))?;
        Ok(state_guard.clone())
    }

    /// Update last sync timestamp
    pub fn update_last_sync(&self, timestamp: i64) -> BridgeResult<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|e| BridgeError::Sync(format!("Lock error: {}", e)))?;
        state.last_sync_at = Some(timestamp);
        Ok(())
    }

    /// Update server sequence
    pub fn update_sequence(&self, sequence: u64) -> BridgeResult<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|e| BridgeError::Sync(format!("Lock error: {}", e)))?;
        state.server_sequence = Some(sequence);
        Ok(())
    }
}

impl Default for ICloudSyncManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// FFI Functions for iOS (CloudKit calls happen in Swift)
// ============================================================================

use std::ffi::{c_char, CStr, CString};
use std::ptr;

/// Handle to iCloud sync manager (opaque pointer)
pub type ICloudSyncHandle = usize;

/// Global sync manager registry
static SYNC_MANAGER: Mutex<Option<ICloudSyncManager>> = Mutex::new(None);
static NEXT_HANDLE: Mutex<usize> = Mutex::new(1);

#[no_mangle]
/// Initialize iCloud sync
///
/// # Safety
/// - `device_id` must be a valid null-terminated UTF-8 string
/// - `container_name` can be null (uses default)
/// - `out_handle` must point to valid memory
pub unsafe extern "C" fn sp_icloud_sync_init(
    device_id: *const c_char,
    container_name: *const c_char,
    out_handle: *mut ICloudSyncHandle,
) -> i32 {
    catch_unwind(|| {
        // Parse device ID
        let device_id_str = unsafe {
            if device_id.is_null() {
                return Err(BridgeError::InvalidParam("device_id is null".to_string()));
            }
            CStr::from_ptr(device_id)
                .to_str()
                .map_err(|e| BridgeError::InvalidParam(format!("Invalid UTF-8: {}", e)))?
        };

        let device_uuid = Uuid::parse_str(device_id_str)
            .map_err(|e| BridgeError::InvalidParam(format!("Invalid UUID: {}", e)))?;

        // Parse container name (optional)
        let container_opt = if !container_name.is_null() {
            let name_str = CStr::from_ptr(container_name)
                .to_str()
                .map_err(|e| BridgeError::InvalidParam(format!("Invalid UTF-8: {}", e)))?;
            Some(name_str.to_string())
        } else {
            None
        };

        // Create sync manager
        let manager = ICloudSyncManager::new();
        manager.init(device_uuid, container_opt)?;

        // Register and get handle
        let mut registry = SYNC_MANAGER
            .lock()
            .map_err(|e| BridgeError::Sync(format!("Lock error: {}", e)))?;
        *registry = Some(manager);

        let mut handle_guard = NEXT_HANDLE
            .lock()
            .map_err(|e| BridgeError::Sync(format!("Lock error: {}", e)))?;
        let handle = *handle_guard;
        *handle_guard = handle + 1;

        if !out_handle.is_null() {
            *out_handle = handle;
        }

        Ok(())
    })
}

#[no_mangle]
/// Prepare sync records for upload
///
/// # Safety
/// - `json_blobs` must be a valid null-terminated UTF-8 string (JSON array of SyncEntryBlob)
/// - `out_json` must be either null or point to valid memory for output
/// - Returns a JSON string that must be freed with `sp_string_free`
pub unsafe extern "C" fn sp_icloud_sync_prepare_upload(
    handle: ICloudSyncHandle,
    json_blobs: *const c_char,
    out_json: *mut *mut c_char,
) -> i32 {
    catch_unwind(|| {
        let _handle = handle; // TODO: validate handle

        let json_str = unsafe {
            if json_blobs.is_null() {
                return Err(BridgeError::InvalidParam("json_blobs is null".to_string()));
            }
            CStr::from_ptr(json_blobs)
                .to_str()
                .map_err(|e| BridgeError::InvalidParam(format!("Invalid UTF-8: {}", e)))?
        };

        let blobs: Vec<SyncEntryBlob> = serde_json::from_str(json_str)
            .map_err(|e| BridgeError::InvalidParam(format!("Invalid JSON: {}", e)))?;

        let records = {
            let lock_guard = SYNC_MANAGER
                .lock()
                .map_err(|e| BridgeError::Sync(format!("Lock error: {}", e)))?;
            let manager = lock_guard.as_ref().ok_or(BridgeError::NotInitialized)?;
            manager.prepare_upload(&blobs)?
        };

        if !out_json.is_null() {
            let json = serde_json::to_string(&records)
                .map_err(|e| BridgeError::Sync(format!("JSON error: {}", e)))?;
            let c_str = CString::new(json)
                .map_err(|e| BridgeError::Sync(format!("String error: {}", e)))?;
            *out_json = c_str.into_raw();
        }

        Ok(())
    })
}

#[no_mangle]
/// Process downloaded sync records
///
/// # Safety
/// - `json_records` must be a valid null-terminated UTF-8 string (JSON array of CloudKitRecord)
/// - `out_json` must be either null or point to valid memory for output
/// - Returns a JSON string that must be freed with `sp_string_free`
pub unsafe extern "C" fn sp_icloud_sync_process_download(
    handle: ICloudSyncHandle,
    json_records: *const c_char,
    out_json: *mut *mut c_char,
) -> i32 {
    catch_unwind(|| {
        let _handle = handle; // TODO: validate handle

        let json_str = unsafe {
            if json_records.is_null() {
                return Err(BridgeError::InvalidParam(
                    "json_records is null".to_string(),
                ));
            }
            CStr::from_ptr(json_records)
                .to_str()
                .map_err(|e| BridgeError::InvalidParam(format!("Invalid UTF-8: {}", e)))?
        };

        let records: Vec<CloudKitRecord> = serde_json::from_str(json_str)
            .map_err(|e| BridgeError::InvalidParam(format!("Invalid JSON: {}", e)))?;

        let blobs = {
            let lock_guard = SYNC_MANAGER
                .lock()
                .map_err(|e| BridgeError::Sync(format!("Lock error: {}", e)))?;
            let manager = lock_guard.as_ref().ok_or(BridgeError::NotInitialized)?;
            manager.process_download(records)?
        };

        if !out_json.is_null() {
            let json = serde_json::to_string(&blobs)
                .map_err(|e| BridgeError::Sync(format!("JSON error: {}", e)))?;
            let c_str = CString::new(json)
                .map_err(|e| BridgeError::Sync(format!("String error: {}", e)))?;
            *out_json = c_str.into_raw();
        }

        Ok(())
    })
}

#[no_mangle]
/// Update sync state after successful sync
pub unsafe extern "C" fn sp_icloud_sync_update_state(
    handle: ICloudSyncHandle,
    last_sync: i64,
    server_sequence: u64,
) -> i32 {
    catch_unwind(|| {
        let _handle = handle; // TODO: validate handle

        {
            let lock_guard = SYNC_MANAGER
                .lock()
                .map_err(|e| BridgeError::Sync(format!("Lock error: {}", e)))?;
            let manager = lock_guard.as_ref().ok_or(BridgeError::NotInitialized)?;
            manager.update_last_sync(last_sync)?;
            manager.update_sequence(server_sequence)?;
        }

        Ok(())
    })
}

// ============================================================================
// Helper: panic catch for FFI
// ============================================================================

use std::panic::catch_unwind as std_catch_unwind;

fn catch_unwind<F>(f: F) -> i32
where
    F: FnOnce() -> BridgeResult<()> + std::panic::UnwindSafe,
{
    match std_catch_unwind(f) {
        Ok(Ok(())) => ErrorCode::Success as i32,
        Ok(Err(e)) => e.to_error_code() as i32,
        Err(_) => ErrorCode::Unknown as i32,
    }
}
