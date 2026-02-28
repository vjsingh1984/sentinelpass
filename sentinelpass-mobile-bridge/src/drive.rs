//! Google Drive sync implementation for Android
//!
//! This module provides the core functionality for syncing with Google Drive.
//! The actual Drive API calls happen in Kotlin (Android), this module handles:
//! - Data serialization for Drive files
//! - Sync state management
//! - Conflict resolution (using existing sync module)

use crate::error::{BridgeError, BridgeResult, ErrorCode};
use sentinelpass_core::sync::models::{SyncEntryBlob, SyncEntryType};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Drive file representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveFile {
    /// File ID (used as sync_id)
    #[serde(rename = "id")]
    pub id: String,

    /// File name (matches sync_id)
    #[serde(rename = "name")]
    pub name: String,

    /// Encrypted sync entry data
    #[serde(rename = "encryptedPayload")]
    pub encrypted_payload: String,

    /// Modification timestamp
    #[serde(rename = "modifiedTime")]
    pub modified_time: String,

    /// MD5 checksum
    #[serde(rename = "md5Checksum")]
    pub md5_checksum: Option<String>,

    /// MIME type
    #[serde(rename = "mimeType")]
    pub mime_type: String,

    /// Sync entry metadata
    #[serde(rename = "appProperties")]
    pub app_properties: DriveAppProperties,
}

/// App properties for sync metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveAppProperties {
    /// Sync entry type
    #[serde(rename = "entryType")]
    pub entry_type: String,

    /// Sync version
    #[serde(rename = "syncVersion")]
    pub sync_version: u64,

    /// Whether this is a tombstone
    #[serde(rename = "isTombstone")]
    pub is_tombstone: bool,

    /// Device that created this entry
    #[serde(rename = "originDeviceId")]
    pub origin_device_id: String,
}

impl DriveFile {
    /// Create a Drive file from a sync entry blob
    pub fn from_sync_blob(blob: &SyncEntryBlob) -> Self {
        // Encode encrypted payload as base64 string for JSON transport
        let encrypted_payload =
            base64::engine::general_purpose::STANDARD.encode(&blob.encrypted_payload);

        Self {
            id: blob.sync_id.to_string(),
            name: format!("{}.json", blob.sync_id),
            encrypted_payload,
            modified_time: format!("{}", blob.modified_at),
            md5_checksum: None,
            mime_type: "application/json".to_string(),
            app_properties: DriveAppProperties {
                entry_type: format!("{:?}", blob.entry_type),
                sync_version: blob.sync_version,
                is_tombstone: blob.is_tombstone,
                origin_device_id: blob.origin_device_id.to_string(),
            },
        }
    }

    /// Convert to sync entry blob
    pub fn to_sync_blob(&self) -> BridgeResult<SyncEntryBlob> {
        // Decode base64 encrypted payload
        let encrypted_payload = base64::engine::general_purpose::STANDARD
            .decode(&self.encrypted_payload)
            .map_err(|e| BridgeError::Sync(format!("Invalid base64: {}", e)))?;

        // Parse entry type from string
        let entry_type = match self.app_properties.entry_type.as_str() {
            "Credential" => SyncEntryType::Credential,
            "TotpSecret" => SyncEntryType::TotpSecret,
            "SshKey" => SyncEntryType::SshKey,
            _ => {
                return Err(BridgeError::InvalidParam(format!(
                    "Unknown entry type: {}",
                    self.app_properties.entry_type
                )))
            }
        };

        // Parse modified time
        let modified_at = self
            .modified_time
            .parse::<i64>()
            .unwrap_or_else(|_| chrono::Utc::now().timestamp());

        Ok(SyncEntryBlob {
            sync_id: Uuid::parse_str(&self.id)
                .map_err(|e| BridgeError::InvalidParam(format!("Invalid UUID: {}", e)))?,
            entry_type,
            sync_version: self.app_properties.sync_version,
            modified_at,
            encrypted_payload,
            is_tombstone: self.app_properties.is_tombstone,
            origin_device_id: Uuid::parse_str(&self.app_properties.origin_device_id)
                .map_err(|e| BridgeError::InvalidParam(format!("Invalid device UUID: {}", e)))?,
        })
    }
}

/// Drive sync state
#[derive(Debug, Clone, PartialEq)]
pub struct DriveSyncState {
    /// Last sync timestamp
    pub last_sync_at: Option<i64>,
    /// Drive change token for incremental sync
    pub start_page_token: Option<String>,
    /// Device ID
    pub device_id: Uuid,
    /// AppData folder ID (cached)
    pub app_data_folder_id: Option<String>,
}

impl Default for DriveSyncState {
    fn default() -> Self {
        Self {
            last_sync_at: None,
            start_page_token: None,
            device_id: Uuid::new_v4(),
            app_data_folder_id: None,
        }
    }
}

/// Google Drive sync manager
pub struct DriveSyncManager {
    state: Arc<Mutex<DriveSyncState>>,
}

impl DriveSyncManager {
    /// Create a new Drive sync manager
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(DriveSyncState::default())),
        }
    }

    /// Initialize sync with a device ID
    pub fn init(&self, device_id: Uuid) -> BridgeResult<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|e| BridgeError::Sync(format!("Lock error: {}", e)))?;

        state.device_id = device_id;
        Ok(())
    }

    /// Set the AppData folder ID
    pub fn set_app_data_folder(&self, folder_id: String) -> BridgeResult<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|e| BridgeError::Sync(format!("Lock error: {}", e)))?;

        state.app_data_folder_id = Some(folder_id);
        Ok(())
    }

    /// Prepare files for upload to Drive
    pub fn prepare_upload(&self, blobs: &[SyncEntryBlob]) -> BridgeResult<Vec<DriveFile>> {
        let state = self
            .state
            .lock()
            .map_err(|e| BridgeError::Sync(format!("Lock error: {}", e)))?;

        blobs
            .iter()
            .map(|blob| {
                let mut file = DriveFile::from_sync_blob(blob);
                // Add device ID if not present
                if file.app_properties.origin_device_id.is_empty() {
                    file.app_properties.origin_device_id = state.device_id.to_string();
                }
                Ok(file)
            })
            .collect()
    }

    /// Process files downloaded from Drive
    pub fn process_download(&self, files: Vec<DriveFile>) -> BridgeResult<Vec<SyncEntryBlob>> {
        files.into_iter().map(|file| file.to_sync_blob()).collect()
    }

    /// Get current sync state
    pub fn get_state(&self) -> BridgeResult<DriveSyncState> {
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

    /// Update start page token for incremental sync
    pub fn update_page_token(&self, token: String) -> BridgeResult<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|e| BridgeError::Sync(format!("Lock error: {}", e)))?;
        state.start_page_token = Some(token);
        Ok(())
    }
}

impl Default for DriveSyncManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// JNI Functions for Android (Drive API calls happen in Kotlin)
// ============================================================================

use std::ffi::{c_char, CStr, CString};
use std::os::raw::c_int;

#[cfg(feature = "jni")]
use jni::sys::{jint, jlong, jobject, jstring};
#[cfg(feature = "jni")]
use jni::JNIEnv;

/// Handle to Drive sync manager (opaque pointer)
pub type DriveSyncHandle = usize;

/// Global sync manager registry
static DRIVE_SYNC_MANAGER: Mutex<Option<DriveSyncManager>> = Mutex::new(None);
static NEXT_DRIVE_HANDLE: Mutex<usize> = Mutex::new(1);

#[no_mangle]
/// Initialize Drive sync (JNI)
///
/// # Safety
/// - `env` must be a valid JNI environment pointer
/// - `_ctx` is the Android context (unused in Rust)
/// - `device_id` is a JNI string reference
///
/// Returns a handle to the sync manager
#[cfg(feature = "jni")]
pub unsafe extern "C" fn Java_com_sentinelpass_DriveSync_nativeInit(
    mut env: JNIEnv,
    _ctx: jobject,
    device_id: jstring,
) -> jlong {
    catch_unwind_jni(|| {
        // Parse device ID
        let device_id_str: String = env
            .get_string(&device_id)
            .map_err(|e| BridgeError::Sync(format!("JNI string error: {}", e)))?
            .into();

        let device_uuid = Uuid::parse_str(&device_id_str)
            .map_err(|e| BridgeError::InvalidParam(format!("Invalid UUID: {}", e)))?;

        // Create sync manager
        let manager = DriveSyncManager::new();
        manager.init(device_uuid)?;

        // Register and get handle
        let mut registry = DRIVE_SYNC_MANAGER
            .lock()
            .map_err(|e| BridgeError::Sync(format!("Lock error: {}", e)))?;
        *registry = Some(manager);

        let mut handle_guard = NEXT_DRIVE_HANDLE
            .lock()
            .map_err(|e| BridgeError::Sync(format!("Lock error: {}", e)))?;
        let handle = *handle_guard as jlong;
        *handle_guard += 1;

        Ok(handle)
    })
}

#[no_mangle]
/// Prepare sync files for upload (JNI)
///
/// # Safety
/// - `env` must be a valid JNI environment pointer
/// - `json_blobs` is a JNI string reference (JSON array of SyncEntryBlob)
///
/// Returns a JSON string of DriveFile objects
#[cfg(feature = "jni")]
pub unsafe extern "C" fn Java_com_sentinelpass_DriveSync_nativePrepareUpload(
    mut env: JNIEnv,
    _obj: jobject,
    _handle: jlong,
    json_blobs: jstring,
) -> jstring {
    catch_unwind_jni(|| {
        let json_str: String = env
            .get_string(&json_blobs)
            .map_err(|e| BridgeError::Sync(format!("JNI string error: {}", e)))?
            .into();

        let blobs: Vec<SyncEntryBlob> = serde_json::from_str(&json_str)
            .map_err(|e| BridgeError::InvalidParam(format!("Invalid JSON: {}", e)))?;

        let manager = {
            let lock_guard = DRIVE_SYNC_MANAGER
                .lock()
                .map_err(|e| BridgeError::Sync(format!("Lock error: {}", e)))?;
            lock_guard.as_ref().ok_or(BridgeError::NotInitialized)?
        };

        let files = manager.prepare_upload(&blobs)?;

        let json = serde_json::to_string(&files)
            .map_err(|e| BridgeError::Sync(format!("JSON error: {}", e)))?;

        let output = env
            .new_string(&json)
            .map_err(|e| BridgeError::Sync(format!("JNI string error: {}", e)))?;

        Ok(output.into_raw())
    })
}

#[no_mangle]
/// Process downloaded sync files (JNI)
///
/// # Safety
/// - `env` must be a valid JNI environment pointer
/// - `json_files` is a JNI string reference (JSON array of DriveFile)
///
/// Returns a JSON string of SyncEntryBlob objects
#[cfg(feature = "jni")]
pub unsafe extern "C" fn Java_com_sentinelpass_DriveSync_nativeProcessDownload(
    mut env: JNIEnv,
    _obj: jobject,
    _handle: jlong,
    json_files: jstring,
) -> jstring {
    catch_unwind_jni(|| {
        let json_str: String = env
            .get_string(&json_files)
            .map_err(|e| BridgeError::Sync(format!("JNI string error: {}", e)))?
            .into();

        let files: Vec<DriveFile> = serde_json::from_str(&json_str)
            .map_err(|e| BridgeError::InvalidParam(format!("Invalid JSON: {}", e)))?;

        let manager = {
            let lock_guard = DRIVE_SYNC_MANAGER
                .lock()
                .map_err(|e| BridgeError::Sync(format!("Lock error: {}", e)))?;
            lock_guard.as_ref().ok_or(BridgeError::NotInitialized)?
        };

        let blobs = manager.process_download(files)?;

        let json = serde_json::to_string(&blobs)
            .map_err(|e| BridgeError::Sync(format!("JSON error: {}", e)))?;

        let output = env
            .new_string(&json)
            .map_err(|e| BridgeError::Sync(format!("JNI string error: {}", e)))?;

        Ok(output.into_raw())
    })
}

#[no_mangle]
/// Update sync state after successful sync (JNI)
#[cfg(feature = "jni")]
pub unsafe extern "C" fn Java_com_sentinelpass_DriveSync_nativeUpdateState(
    _env: JNIEnv,
    _obj: jobject,
    _handle: jlong,
    last_sync: jlong,
    page_token: jstring,
) -> jint {
    catch_unwind_jni_no_result(|| {
        // Extract page token string (can be null)
        let token_opt = if !page_token.is_null() {
            // We'd need env to get the string, but for simplicity just skip for now
            // In real implementation, we'd extract the token here
            None
        } else {
            None
        };

        {
            let lock_guard = DRIVE_SYNC_MANAGER
                .lock()
                .map_err(|e| BridgeError::Sync(format!("Lock error: {}", e)))?;
            let manager = lock_guard.as_ref().ok_or(BridgeError::NotInitialized)?;

            manager.update_last_sync(last_sync as i64)?;

            if let Some(token) = token_opt {
                manager.update_page_token(token)?;
            }
        }

        Ok(())
    })
}

// ============================================================================
// C FFI Functions for iOS (same as Drive, could be shared)
// ============================================================================

use base64::Engine;

/// Handle to Drive sync manager (C FFI)
pub type DriveSyncCHandle = usize;

#[no_mangle]
/// Initialize Drive sync (C FFI)
///
/// # Safety
/// - `device_id` must be a valid null-terminated UTF-8 string
/// - `out_handle` must point to valid memory
pub unsafe extern "C" fn sp_drive_sync_init(
    device_id: *const c_char,
    out_handle: *mut DriveSyncCHandle,
) -> c_int {
    catch_unwind_c(|| {
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

        // Create sync manager
        let manager = DriveSyncManager::new();
        manager.init(device_uuid)?;

        // Register and get handle
        let mut registry = DRIVE_SYNC_MANAGER
            .lock()
            .map_err(|e| BridgeError::Sync(format!("Lock error: {}", e)))?;
        *registry = Some(manager);

        let mut handle_guard = NEXT_DRIVE_HANDLE
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
/// Prepare sync files for upload (C FFI)
///
/// # Safety
/// - `json_blobs` must be a valid null-terminated UTF-8 string (JSON array of SyncEntryBlob)
/// - `out_json` must be either null or point to valid memory for output
pub unsafe extern "C" fn sp_drive_sync_prepare_upload(
    _handle: DriveSyncCHandle,
    json_blobs: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    catch_unwind_c(|| {
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

        let files = {
            let lock_guard = DRIVE_SYNC_MANAGER
                .lock()
                .map_err(|e| BridgeError::Sync(format!("Lock error: {}", e)))?;
            let manager = lock_guard.as_ref().ok_or(BridgeError::NotInitialized)?;
            manager.prepare_upload(&blobs)?
        };

        if !out_json.is_null() {
            let json = serde_json::to_string(&files)
                .map_err(|e| BridgeError::Sync(format!("JSON error: {}", e)))?;
            let c_str = CString::new(json)
                .map_err(|e| BridgeError::Sync(format!("String error: {}", e)))?;
            *out_json = c_str.into_raw();
        }

        Ok(())
    })
}

#[no_mangle]
/// Process downloaded sync files (C FFI)
///
/// # Safety
/// - `json_files` must be a valid null-terminated UTF-8 string (JSON array of DriveFile)
/// - `out_json` must be either null or point to valid memory for output
pub unsafe extern "C" fn sp_drive_sync_process_download(
    _handle: DriveSyncCHandle,
    json_files: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    catch_unwind_c(|| {
        let json_str = unsafe {
            if json_files.is_null() {
                return Err(BridgeError::InvalidParam("json_files is null".to_string()));
            }
            CStr::from_ptr(json_files)
                .to_str()
                .map_err(|e| BridgeError::InvalidParam(format!("Invalid UTF-8: {}", e)))?
        };

        let files: Vec<DriveFile> = serde_json::from_str(json_str)
            .map_err(|e| BridgeError::InvalidParam(format!("Invalid JSON: {}", e)))?;

        let blobs = {
            let lock_guard = DRIVE_SYNC_MANAGER
                .lock()
                .map_err(|e| BridgeError::Sync(format!("Lock error: {}", e)))?;
            let manager = lock_guard.as_ref().ok_or(BridgeError::NotInitialized)?;
            manager.process_download(files)?
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
/// Update sync state after successful sync (C FFI)
pub unsafe extern "C" fn sp_drive_sync_update_state(
    _handle: DriveSyncCHandle,
    last_sync: i64,
    _page_token: *const c_char,
) -> c_int {
    catch_unwind_c_no_result(|| {
        {
            let lock_guard = DRIVE_SYNC_MANAGER
                .lock()
                .map_err(|e| BridgeError::Sync(format!("Lock error: {}", e)))?;
            let manager = lock_guard.as_ref().ok_or(BridgeError::NotInitialized)?;

            manager.update_last_sync(last_sync)?;

            // TODO: Extract and update page token if provided
        }

        Ok(())
    })
}

// ============================================================================
// Helper: panic catch for FFI
// ============================================================================

use std::panic::catch_unwind as std_catch_unwind;

fn catch_unwind_c<F>(f: F) -> c_int
where
    F: FnOnce() -> BridgeResult<()> + std::panic::UnwindSafe,
{
    match std_catch_unwind(f) {
        Ok(Ok(())) => ErrorCode::Success as c_int,
        Ok(Err(e)) => e.to_error_code() as c_int,
        Err(_) => ErrorCode::Unknown as c_int,
    }
}

fn catch_unwind_c_no_result<F>(f: F) -> c_int
where
    F: FnOnce() -> BridgeResult<()> + std::panic::UnwindSafe,
{
    match std_catch_unwind(f) {
        Ok(Ok(())) => ErrorCode::Success as c_int,
        Ok(Err(e)) => e.to_error_code() as c_int,
        Err(_) => ErrorCode::Unknown as c_int,
    }
}

// ============================================================================
// JNI-specific helpers
// ============================================================================

#[cfg(feature = "jni")]
fn catch_unwind_jni<F, R>(f: F) -> R
where
    F: FnOnce() -> BridgeResult<R> + std::panic::UnwindSafe,
    R: Default,
{
    match std_catch_unwind(f) {
        Ok(Ok(value)) => value,
        Ok(Err(_)) => R::default(),
        Err(_) => R::default(),
    }
}

#[cfg(feature = "jni")]
fn catch_unwind_jni_no_result<F>(f: F) -> jint
where
    F: FnOnce() -> BridgeResult<()> + std::panic::UnwindSafe,
{
    match std_catch_unwind(f) {
        Ok(Ok(())) => ErrorCode::Success as jint,
        Ok(Err(e)) => e.to_error_code() as jint,
        Err(_) => ErrorCode::Unknown as jint,
    }
}
