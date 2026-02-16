use super::*;
use crate::database::Database;

#[test]
fn test_vault_create_and_open() {
    let temp_path = ":memory:"; // Use in-memory database for testing

    // Create vault
    let password = b"test_password_123!";
    let vault = VaultManager::create(temp_path, password);
    assert!(vault.is_ok());
    assert!(vault.unwrap().is_unlocked());

    // Opening with :memory: creates a new database each time, so we can't test reopening
    // In a real test, we'd use a temp file
}

#[test]
fn test_vault_add_and_get_entry() {
    let temp_path = ":memory:";
    let password = b"test_password";

    let vault = VaultManager::create(temp_path, password).unwrap();

    let entry = Entry {
        entry_id: None,
        title: "Test Entry".to_string(),
        username: "user@example.com".to_string(),
        password: "secret123".to_string(),
        url: Some("https://example.com".to_string()),
        notes: Some("Test notes".to_string()),
        created_at: Utc::now(),
        modified_at: Utc::now(),
        favorite: false,
    };

    let entry_id = vault.add_entry(&entry).unwrap();
    assert!(entry_id > 0);

    let retrieved = vault.get_entry(entry_id).unwrap();
    assert_eq!(retrieved.title, "Test Entry");
    assert_eq!(retrieved.username, "user@example.com");
    assert_eq!(retrieved.password, "secret123");
    assert_eq!(retrieved.url, Some("https://example.com".to_string()));
    assert_eq!(retrieved.notes, Some("Test notes".to_string()));
}

#[test]
fn test_vault_list_entries() {
    let temp_path = ":memory:";
    let password = b"test_password";

    let vault = VaultManager::create(temp_path, password).unwrap();

    let entry1 = Entry {
        entry_id: None,
        title: "Alpha Entry".to_string(),
        username: "user1@example.com".to_string(),
        password: "pass1".to_string(),
        url: None,
        notes: None,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        favorite: false,
    };

    let entry2 = Entry {
        entry_id: None,
        title: "Zeta Entry".to_string(),
        username: "user2@example.com".to_string(),
        password: "pass2".to_string(),
        url: None,
        notes: None,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        favorite: true,
    };

    vault.add_entry(&entry1).unwrap();
    vault.add_entry(&entry2).unwrap();

    let entries = vault.list_entries().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].title, "Alpha Entry");
    assert_eq!(entries[1].title, "Zeta Entry");
}

#[test]
fn test_vault_lock() {
    let temp_path = ":memory:";
    let password = b"test_password";

    let mut vault = VaultManager::create(temp_path, password).unwrap();
    assert!(vault.is_unlocked());

    vault.lock();
    assert!(!vault.is_unlocked());
}

#[test]
fn test_vault_locked_operations_fail() {
    let temp_path = ":memory:";
    let password = b"test_password";

    let mut vault = VaultManager::create(temp_path, password).unwrap();
    vault.lock();

    assert!(vault
        .add_entry(&Entry {
            entry_id: None,
            title: "Test".to_string(),
            username: "test".to_string(),
            password: "test".to_string(),
            url: None,
            notes: None,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            favorite: false,
        })
        .is_err());

    assert!(vault.get_entry(1).is_err());
    assert!(vault.list_entries().is_err());
}

#[test]
fn test_vault_lockout_after_repeated_failed_unlocks() {
    let temp_path =
        std::env::temp_dir().join(format!("sentinelpass_lockout_{}.db", uuid::Uuid::new_v4()));
    let password = b"test_password";

    let vault = VaultManager::create(&temp_path, password).unwrap();
    drop(vault);

    for _ in 0..(DEFAULT_MAX_ATTEMPTS - 1) {
        let result = VaultManager::open(&temp_path, b"wrong_password");
        assert!(matches!(result, Err(PasswordManagerError::Crypto(_))));
    }

    let lockout_trigger = VaultManager::open(&temp_path, b"wrong_password");
    assert!(matches!(
        lockout_trigger,
        Err(PasswordManagerError::LockedOut(_))
    ));

    let still_locked_with_correct_password = VaultManager::open(&temp_path, password);
    assert!(matches!(
        still_locked_with_correct_password,
        Err(PasswordManagerError::LockedOut(_))
    ));

    let _ = std::fs::remove_file(&temp_path);
}

#[test]
fn test_totp_add_generate_remove() {
    let temp_path = ":memory:";
    let password = b"test_password";

    let vault = VaultManager::create(temp_path, password).unwrap();

    let entry = Entry {
        entry_id: None,
        title: "TOTP Entry".to_string(),
        username: "user@example.com".to_string(),
        password: "secret123".to_string(),
        url: Some("https://example.com".to_string()),
        notes: None,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        favorite: false,
    };

    let entry_id = vault.add_entry(&entry).unwrap();

    let totp_id = vault
        .add_totp_secret(
            entry_id,
            "JBSWY3DPEHPK3PXP",
            crate::totp::TotpAlgorithm::Sha1,
            6,
            30,
            Some("SentinelPass"),
            Some("user@example.com"),
        )
        .unwrap();
    assert!(totp_id > 0);

    let metadata = vault.get_totp_metadata(entry_id).unwrap();
    assert_eq!(metadata.entry_id, entry_id);
    assert_eq!(metadata.algorithm, crate::totp::TotpAlgorithm::Sha1);
    assert_eq!(metadata.digits, 6);
    assert_eq!(metadata.period, 30);

    let code = vault.generate_totp_code(entry_id).unwrap();
    assert_eq!(code.code.len(), 6);
    assert!(code.seconds_remaining >= 1 && code.seconds_remaining <= 30);

    vault.remove_totp_secret(entry_id).unwrap();
    assert!(vault.generate_totp_code(entry_id).is_err());
}

#[test]
fn test_ssh_key_encrypt_decrypt_roundtrip() {
    use crate::crypto::DataEncryptionKey;

    let dek = DataEncryptionKey::new().unwrap();
    let private_key = "-----BEGIN OPENSSH PRIVATE KEY-----\ntest private key content\n-----END OPENSSH PRIVATE KEY-----";

    // Test encryption
    let (encrypted, nonce, auth_tag) =
        crate::ssh::SshKey::encrypt_private_key(&dek, private_key).unwrap();

    assert!(!encrypted.is_empty());
    assert_eq!(nonce.len(), 12);
    assert_eq!(auth_tag.len(), 16);

    // Test decryption
    let decrypted =
        crate::ssh::SshKey::decrypt_private_key(&dek, &encrypted, &nonce, &auth_tag).unwrap();

    assert_eq!(decrypted, private_key);
}

#[test]
fn test_vault_add_and_list_ssh_keys() {
    let temp_path = ":memory:";
    let password = b"test_password";

    let vault = VaultManager::create(temp_path, password).unwrap();

    // Create an encrypted SSH key
    let dek = vault.key_hierarchy.dek().unwrap();
    let ssh_key = crate::ssh::SshKey::create_encrypted(
        dek,
        "test-key".to_string(),
        Some("test comment".to_string()),
        crate::ssh::SshKeyType::Ed25519,
        Some(256),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINCertainlyNotARealKeyButValidFormat test@example.com"
            .to_string(),
        "-----BEGIN OPENSSH PRIVATE KEY-----\ntest content\n-----END OPENSSH PRIVATE KEY-----"
            .to_string(),
        "SHA256:abcdefghijklmnopqrstuvwxyz123456=".to_string(),
    )
    .unwrap();

    // Add the key
    let key_id = vault.add_ssh_key(&ssh_key).unwrap();
    assert!(key_id > 0);

    // List keys
    let summaries = vault.list_ssh_keys().unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].name, "test-key");
    assert_eq!(summaries[0].key_type, crate::ssh::SshKeyType::Ed25519);
}

#[test]
fn test_vault_get_and_export_ssh_key() {
    let temp_path = ":memory:";
    let password = b"test_password";

    let vault = VaultManager::create(temp_path, password).unwrap();

    // Create and add an SSH key
    let dek = vault.key_hierarchy.dek().unwrap();
    let original_private_key =
        "-----BEGIN OPENSSH PRIVATE KEY-----\ntest content\n-----END OPENSSH PRIVATE KEY-----";

    let ssh_key = crate::ssh::SshKey::create_encrypted(
        dek,
        "export-test".to_string(),
        None,
        crate::ssh::SshKeyType::Rsa,
        Some(4096),
        "ssh-rsa AAAAB3NzaC1yc2E... test@example.com".to_string(),
        original_private_key.to_string(),
        "SHA256:abcdef123456=".to_string(),
    )
    .unwrap();

    let key_id = vault.add_ssh_key(&ssh_key).unwrap();

    // Get the full key
    let retrieved_key = vault.get_ssh_key(key_id).unwrap();
    assert_eq!(retrieved_key.name, "export-test");
    assert_eq!(retrieved_key.key_type, crate::ssh::SshKeyType::Rsa);

    // Export and verify private key matches
    let exported_private_key = vault.export_ssh_private_key(key_id).unwrap();
    assert_eq!(exported_private_key, original_private_key);
}

#[test]
fn test_vault_delete_ssh_key() {
    let temp_path = ":memory:";
    let password = b"test_password";

    let vault = VaultManager::create(temp_path, password).unwrap();

    // Create and add an SSH key
    let dek = vault.key_hierarchy.dek().unwrap();
    let ssh_key = crate::ssh::SshKey::create_encrypted(
        dek,
        "to-delete".to_string(),
        None,
        crate::ssh::SshKeyType::Ed25519,
        Some(256),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINCertainlyNotARealKey test@example.com".to_string(),
        "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----".to_string(),
        "SHA256:deleted=".to_string(),
    )
    .unwrap();

    let key_id = vault.add_ssh_key(&ssh_key).unwrap();

    // Verify it exists
    let keys = vault.list_ssh_keys().unwrap();
    assert_eq!(keys.len(), 1);

    // Delete the key
    vault.delete_ssh_key(key_id).unwrap();

    // Verify it's gone
    let keys = vault.list_ssh_keys().unwrap();
    assert_eq!(keys.len(), 0);

    // Trying to get it should fail
    assert!(vault.get_ssh_key(key_id).is_err());
}

#[test]
fn test_ssh_key_wrong_password_fails() {
    use crate::crypto::DataEncryptionKey;

    let dek1 = DataEncryptionKey::new().unwrap();
    let dek2 = DataEncryptionKey::new().unwrap();

    let private_key =
        "-----BEGIN OPENSSH PRIVATE KEY-----\ntest content\n-----END OPENSSH PRIVATE KEY-----";

    // Encrypt with dek1
    let (encrypted, nonce, auth_tag) =
        crate::ssh::SshKey::encrypt_private_key(&dek1, private_key).unwrap();

    // Try to decrypt with dek2 (should fail)
    let result = crate::ssh::SshKey::decrypt_private_key(&dek2, &encrypted, &nonce, &auth_tag);
    assert!(result.is_err());
}

#[test]
fn test_biometric_ref_metadata_roundtrip() {
    let db = Database::in_memory().unwrap();
    db.initialize_schema().unwrap();

    let mut key_hierarchy = KeyHierarchy::new();
    let (kdf_params, wrapped_dek) = key_hierarchy.initialize_vault(b"test_password").unwrap();
    VaultManager::store_vault_metadata(&db, &kdf_params, &wrapped_dek).unwrap();

    assert_eq!(VaultManager::load_biometric_ref(&db).unwrap(), None);

    VaultManager::set_biometric_ref(&db, Some("vault-biometric-ref")).unwrap();
    assert_eq!(
        VaultManager::load_biometric_ref(&db).unwrap().as_deref(),
        Some("vault-biometric-ref")
    );

    VaultManager::set_biometric_ref(&db, None).unwrap();
    assert_eq!(VaultManager::load_biometric_ref(&db).unwrap(), None);
}
