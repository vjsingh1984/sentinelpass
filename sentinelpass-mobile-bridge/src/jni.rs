// JNI exports for Android
//
// These functions are exported with JNI signatures and can be called from
// Kotlin or Java using standard Android NDK interop.

#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_mut)]

#[cfg(feature = "jni")]
use crate::bridge;
#[cfg(feature = "jni")]
use crate::error::ErrorCode;
#[cfg(feature = "jni")]
use jni::objects::{JClass, JObject, JString};
#[cfg(feature = "jni")]
use jni::sys::{jboolean, jbyteArray, jint, jlong, jobject, jsize, jstring};
#[cfg(feature = "jni")]
use jni::JNIEnv;
#[cfg(feature = "jni")]
use lazy_static::lazy_static;
#[cfg(feature = "jni")]
use std::ffi::CStr;
#[cfg(feature = "jni")]
use std::os::raw::{c_int, c_uint};
#[cfg(feature = "jni")]
use std::ptr;

/// Store vault handles for JNI
#[cfg(feature = "jni")]
lazy_static! {
    static ref JNI_VAULT_REGISTRY: std::sync::Mutex<std::collections::HashMap<jlong, u64>> =
        std::sync::Mutex::new(std::collections::HashMap::new());
}

#[cfg(feature = "jni")]
fn register_jni_handle(internal_handle: u64) -> jlong {
    let mut registry = JNI_VAULT_REGISTRY.lock().unwrap();
    let jni_handle = internal_handle as jlong;
    registry.insert(jni_handle, internal_handle);
    jni_handle
}

#[cfg(feature = "jni")]
fn get_internal_handle(jni_handle: jlong) -> Option<u64> {
    let registry = JNI_VAULT_REGISTRY.lock().unwrap();
    registry.get(&jni_handle).copied()
}

#[cfg(feature = "jni")]
fn unregister_jni_handle(jni_handle: jlong) {
    let mut registry = JNI_VAULT_REGISTRY.lock().unwrap();
    registry.remove(&jni_handle);
}

/// Convert JNI string to Rust string
#[cfg(feature = "jni")]
fn jstring_to_string(env: &mut JNIEnv, jstr: JString) -> Result<String, ErrorCode> {
    env.get_string(&jstr)
        .map(|s| s.into())
        .map_err(|_| ErrorCode::InvalidParam)
}

/// Convert Rust string to JNI string
#[cfg(feature = "jni")]
fn string_to_jstring(env: &mut JNIEnv, s: &str) -> Result<jstring, ErrorCode> {
    env.new_string(s)
        .map(|j| j.into_raw())
        .map_err(|_| ErrorCode::OutOfMemory)
}

/// Convert Result to error code
#[cfg(feature = "jni")]
fn result_to_code<T>(result: Result<T, crate::error::BridgeError>) -> jint {
    match result {
        Ok(_) => ErrorCode::Success as jint,
        Err(e) => e.to_error_code() as jint,
    }
}

// ============================================================================
// Vault Management - JNI
// ============================================================================

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultManager_nativeInit(
    mut env: JNIEnv,
    _class: JClass,
    vault_path: JString,
    master_password: JString,
) -> jlong {
    let path = match jstring_to_string(&mut env, vault_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    let password = match jstring_to_string(&mut env, master_password) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    match bridge::bridge_vault_init(&path, &password) {
        Ok(handle) => register_jni_handle(handle),
        Err(_) => 0,
    }
}

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultManager_nativeDestroy(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if let Some(_internal_handle) = get_internal_handle(handle) {
        let _ = bridge::bridge_vault_destroy(handle as u64);
        unregister_jni_handle(handle);
    }
}

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultManager_nativeIsUnlocked(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jboolean {
    if let Some(_internal_handle) = get_internal_handle(handle) {
        match bridge::bridge_vault_is_unlocked(handle as u64) {
            Ok(unlocked) => {
                if unlocked {
                    1
                } else {
                    0
                }
            }
            Err(_) => 0,
        }
    } else {
        0
    }
}

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultManager_nativeLock(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    if let Some(_internal_handle) = get_internal_handle(handle) {
        result_to_code(bridge::bridge_vault_lock(handle as u64))
    } else {
        ErrorCode::InvalidParam as jint
    }
}

// ============================================================================
// Entry Management - JNI
// ============================================================================

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultManager_nativeAddEntry(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    title: JString,
    username: JString,
    password: JString,
    url: JString,
    notes: JString,
) -> jstring {
    if let Some(_internal_handle) = get_internal_handle(handle) {
        let title_str = match jstring_to_string(&mut env, title) {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };
        let username_str = match jstring_to_string(&mut env, username) {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };
        let password_str = match jstring_to_string(&mut env, password) {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };
        let url_str = match jstring_to_string(&mut env, url) {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };
        let notes_str = match jstring_to_string(&mut env, notes) {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };

        match bridge::bridge_entry_add(
            handle as u64,
            &title_str,
            &username_str,
            &password_str,
            &url_str,
            &notes_str,
        ) {
            Ok(entry_id) => string_to_jstring(&mut env, &entry_id).unwrap_or(ptr::null_mut()),
            Err(_) => ptr::null_mut(),
        }
    } else {
        ptr::null_mut()
    }
}

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultManager_nativeGetEntry(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    entry_id: JString,
) -> jstring {
    if let Some(_internal_handle) = get_internal_handle(handle) {
        let id_str = match jstring_to_string(&mut env, entry_id) {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };

        match bridge::bridge_entry_get(handle as u64, &id_str) {
            Ok(entry) => match serde_json::to_string(&entry) {
                Ok(json) => string_to_jstring(&mut env, &json).unwrap_or(ptr::null_mut()),
                Err(_) => ptr::null_mut(),
            },
            Err(_) => ptr::null_mut(),
        }
    } else {
        ptr::null_mut()
    }
}

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultManager_nativeListEntries(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    if let Some(_internal_handle) = get_internal_handle(handle) {
        match bridge::bridge_entry_list(handle as u64) {
            Ok(summaries) => match serde_json::to_string(&summaries) {
                Ok(json) => string_to_jstring(&mut env, &json).unwrap_or(ptr::null_mut()),
                Err(_) => ptr::null_mut(),
            },
            Err(_) => ptr::null_mut(),
        }
    } else {
        ptr::null_mut()
    }
}

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultManager_nativeSearchEntries(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    query: JString,
) -> jstring {
    if let Some(_internal_handle) = get_internal_handle(handle) {
        let query_str = match jstring_to_string(&mut env, query) {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };

        match bridge::bridge_entry_search(handle as u64, &query_str) {
            Ok(summaries) => match serde_json::to_string(&summaries) {
                Ok(json) => string_to_jstring(&mut env, &json).unwrap_or(ptr::null_mut()),
                Err(_) => ptr::null_mut(),
            },
            Err(_) => ptr::null_mut(),
        }
    } else {
        ptr::null_mut()
    }
}

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultManager_nativeDeleteEntry(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    entry_id: JString,
) -> jint {
    if let Some(_internal_handle) = get_internal_handle(handle) {
        let id_str = match jstring_to_string(&mut env, entry_id) {
            Ok(s) => s,
            Err(_) => return ErrorCode::InvalidParam as jint,
        };

        result_to_code(bridge::bridge_entry_delete(handle as u64, &id_str))
    } else {
        ErrorCode::InvalidParam as jint
    }
}

// ============================================================================
// TOTP - JNI
// ============================================================================

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultManager_nativeGenerateTotp(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    entry_id: JString,
) -> jstring {
    if let Some(_internal_handle) = get_internal_handle(handle) {
        let id_str = match jstring_to_string(&mut env, entry_id) {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };

        match bridge::bridge_totp_generate_code(handle as u64, &id_str) {
            Ok(totp_info) => {
                // Return just the code as a string
                string_to_jstring(&mut env, &totp_info.code).unwrap_or(ptr::null_mut())
            }
            Err(_) => ptr::null_mut(),
        }
    } else {
        ptr::null_mut()
    }
}

// ============================================================================
// Password Generation - JNI
// ============================================================================

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultManager_nativeGeneratePassword(
    mut env: JNIEnv,
    _class: JClass,
    length: jint,
    include_symbols: jboolean,
) -> jstring {
    let length = length as usize;
    let symbols = include_symbols != 0;

    match bridge::bridge_password_generate(length, symbols) {
        Ok(password) => string_to_jstring(&mut env, &password).unwrap_or(ptr::null_mut()),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultManager_nativeCheckStrength(
    mut env: JNIEnv,
    _class: JClass,
    password: JString,
) -> jstring {
    let password_str = match jstring_to_string(&mut env, password) {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    match bridge::bridge_password_check_strength(&password_str) {
        Ok(analysis) => {
            // Return score as a simple string
            let result = format!(
                "{},{}",
                analysis.strength.score(),
                analysis.strength.as_str()
            );
            string_to_jstring(&mut env, &result).unwrap_or(ptr::null_mut())
        }
        Err(_) => ptr::null_mut(),
    }
}

// ============================================================================
// Biometric - JNI
// ============================================================================

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultManager_nativeBiometricSetKey(
    _env: JNIEnv,
    _class: JClass,
    _handle: jlong,
    _key_data: jbyteArray,
) -> jint {
    // TODO: Implement byte array conversion
    ErrorCode::Unknown as jint
}

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultManager_nativeBiometricHasKey(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jboolean {
    if let Some(_internal_handle) = get_internal_handle(handle) {
        match bridge::bridge_biometric_has_key(handle as u64) {
            Ok(has_key) => {
                if has_key {
                    1
                } else {
                    0
                }
            }
            Err(_) => 0,
        }
    } else {
        0
    }
}

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultManager_nativeBiometricRemoveKey(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    if let Some(_internal_handle) = get_internal_handle(handle) {
        result_to_code(bridge::bridge_biometric_remove_key(handle as u64))
    } else {
        ErrorCode::InvalidParam as jint
    }
}

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultManager_nativeBiometricUnlock(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    if let Some(_internal_handle) = get_internal_handle(handle) {
        result_to_code(bridge::bridge_biometric_unlock(handle as u64))
    } else {
        ErrorCode::InvalidParam as jint
    }
}

// ============================================================================
// Sync Operations - JNI
// ============================================================================

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultManager_nativeSyncGetStatus(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
    _out_status: JObject,
) -> jint {
    if let Some(_internal_handle) = get_internal_handle(handle) {
        result_to_code(bridge::bridge_sync_get_status(handle as u64).map(|_| ()))
    } else {
        ErrorCode::InvalidParam as jint
    }
}

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultManager_nativeSyncCollectPending(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    if let Some(_internal_handle) = get_internal_handle(handle) {
        match bridge::bridge_sync_collect_pending(handle as u64) {
            Ok(bytes) => {
                // Convert bytes to JSON string
                match String::from_utf8(bytes) {
                    Ok(s) => string_to_jstring(&mut env, &s).unwrap_or(ptr::null_mut()),
                    Err(_) => ptr::null_mut(),
                }
            }
            Err(_) => ptr::null_mut(),
        }
    } else {
        ptr::null_mut()
    }
}

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultManager_nativeSyncApplyEntries(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
    _entries_json: JString,
) -> jint {
    if let Some(_internal_handle) = get_internal_handle(handle) {
        // Placeholder - would need to convert JString to bytes and call bridge function
        ErrorCode::Success as jint
    } else {
        ErrorCode::InvalidParam as jint
    }
}

#[no_mangle]
#[cfg(feature = "jni")]
pub extern "system" fn Java_com_sentinelpass_VaultManager_nativeSyncPrepareDrive(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
    _device_id: JString,
) -> jstring {
    if let Some(_internal_handle) = get_internal_handle(handle) {
        // Placeholder - would call bridge_sync_prepare_drive
        ptr::null_mut()
    } else {
        ptr::null_mut()
    }
}
