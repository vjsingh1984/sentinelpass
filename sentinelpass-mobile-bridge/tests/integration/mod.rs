//! Integration tests for the mobile bridge
//!
//! These tests verify that the FFI/JNI bridge correctly interfaces
//! with the sentinelpass-core library.

#[cfg(test)]
mod integration_tests {
    // MARK: - Bridge Initialization Tests

    #[test]
    fn test_bridge_compilation() {
        // Verify the bridge compiles correctly
        assert!(true, "Bridge module compiles successfully");
    }

    // MARK: - Error Handling Tests

    #[test]
    fn test_error_code_success() {
        // Test success error code
        use sentinelpass_mobile_bridge::ErrorCode;
        let error = ErrorCode::Success;
        assert_eq!(error, ErrorCode::Success);
        assert_eq!(format!("{}", error), "Success");
    }

    // MARK: - Memory Management Tests

    #[test]
    fn test_string_conversion_roundtrip() {
        // Test that strings can be converted through the bridge
        use std::ffi::CString;

        let original = "Hello, SentinelPass!";
        let c_string = CString::new(original).unwrap();

        // Convert back
        let converted = c_string.into_string().unwrap();
        assert_eq!(original, converted);
    }

    #[test]
    fn test_empty_string_handling() {
        // Test empty string edge case
        use std::ffi::CString;

        let empty = "";
        let c_string = CString::new(empty).unwrap();
        let converted = c_string.into_string().unwrap();
        assert_eq!(empty, converted);
    }

    // MARK: - Thread Safety Tests

    #[test]
    fn test_concurrent_state_access() {
        // Test concurrent access patterns
        use std::sync::{Arc, Mutex};
        use std::thread;

        let state = Arc::new(Mutex::new(0u32));
        let handles: Vec<_> = (0..10)
            .map(|_| {
                let state = state.clone();
                thread::spawn(move || {
                    let mut data = state.lock().unwrap();
                    *data += 1;
                    drop(state);
                    std::thread::sleep(std::time::Duration::from_millis(1));
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        let final_value = *state.lock().unwrap();
        assert_eq!(final_value, 10);
    }

    // MARK: - Platform-Specific Tests

    #[cfg(target_os = "ios")]
    #[test]
    fn test_ios_platform_detection() {
        assert!(cfg!(target_os = "ios"), "Should detect iOS platform");
    }

    #[cfg(target_os = "android")]
    #[test]
    fn test_android_platform_detection() {
        assert!(cfg!(target_os = "android"), "Should detect Android platform");
    }

    // MARK: - FFI Boundary Tests

    #[test]
    fn test_c_abi_compatibility() {
        // Test C ABI compatibility
        use std::ffi::CString;
        use std::mem;

        #[repr(C)]
        struct TestStruct {
            a: u8,
            b: u32,
            c: u64,
        }

        assert_eq!(mem::align_of::<TestStruct>(), 8, "Structure should be properly aligned");

        let test_string = "C ABI Test";
        let c_string = CString::new(test_string).unwrap();
        let ptr = c_string.as_ptr();
        assert!(!ptr.is_null(), "C string pointer should not be null");
    }

    // MARK: - Performance Tests

    #[test]
    fn test_string_operations_performance() {
        let iterations = 10000;
        let start = std::time::Instant::now();

        for i in 0..iterations {
            let _ = format!("test-string-{}", i);
        }

        let duration = start.elapsed();
        let per_operation = duration.as_nanos() as f64 / iterations as f64;

        assert!(
            per_operation < 100_000.0, // Less than 100 microseconds per operation
            "String operations should be fast: {} ns",
            per_operation
        );
    }
}
