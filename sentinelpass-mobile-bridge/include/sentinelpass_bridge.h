#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Error codes that can be returned to mobile platforms
 *
 * These are designed to be stable across FFI boundaries and map to
 * platform-specific error types (NSError on iOS, Exception on Android).
 */
typedef enum SPErrorCode {
  /**
   * Operation completed successfully
   */
  SPErrorCode_Success = 0,
  /**
   * Invalid parameter passed to function
   */
  SPErrorCode_InvalidParam = -1,
  /**
   * Vault is currently locked
   */
  SPErrorCode_VaultLocked = -2,
  /**
   * Entry not found
   */
  SPErrorCode_NotFound = -3,
  /**
   * Cryptographic operation failed
   */
  SPErrorCode_Crypto = -4,
  /**
   * Database operation failed
   */
  SPErrorCode_Database = -5,
  /**
   * Input/Output operation failed
   */
  SPErrorCode_Io = -6,
  /**
   * Vault is already unlocked
   */
  SPErrorCode_AlreadyUnlocked = -7,
  /**
   * Invalid master password
   */
  SPErrorCode_InvalidPassword = -8,
  /**
   * Vault not initialized (run init first)
   */
  SPErrorCode_NotInitialized = -9,
  /**
   * Biometric operation failed
   */
  SPErrorCode_Biometric = -10,
  /**
   * TOTP operation failed
   */
  SPErrorCode_Totp = -11,
  /**
   * Sync operation failed
   */
  SPErrorCode_Sync = -12,
  /**
   * Out of memory
   */
  SPErrorCode_OutOfMemory = -13,
  /**
   * Unknown or internal error
   */
  SPErrorCode_Unknown = -99,
} SPErrorCode;

/**
 * Vault handle type (opaque pointer representation)
 * The actual value is a u64 handle cast to a pointer-sized type
 */
typedef uint64_t SPVaultHandle;

/**
 * FFI-safe entry representation
 */
typedef struct SPEntry {
  const char *id;
  const char *title;
  const char *username;
  const char *password;
  const char *url;
  const char *notes;
  int64_t created_at;
  int64_t modified_at;
} SPEntry;

/**
 * FFI-safe entry summary (for list views)
 */
typedef struct SPEntrySummary {
  const char *id;
  const char *title;
  const char *username;
  int64_t modified_at;
  bool favorite;
} SPEntrySummary;

/**
 * FFI-safe password analysis result
 */
typedef struct SPPasswordAnalysis {
  int score;
  double entropy_bits;
  double crack_time_seconds;
  unsigned int length;
  bool has_lower;
  bool has_upper;
  bool has_digit;
  bool has_symbol;
} SPPasswordAnalysis;

/**
 * FFI-safe TOTP code representation
 */
typedef struct SPTotpCode {
  const char *code;
  uint32_t seconds_remaining;
} SPTotpCode;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Check if biometric key is set
 *
 * # Safety
 * - out_has_key must be a valid pointer
 */
sp enum SPErrorCode sp_biometric_has_key(SPVaultHandle Handle, bool *OutHasKey);

/**
 * Remove biometric key
 */
sp enum SPErrorCode sp_biometric_remove_key(SPVaultHandle Handle);

/**
 * Set biometric key for a vault
 *
 * # Safety
 * - key_data must point to a valid buffer of key_data_len bytes
 * - The key_data should be the serialized WrappedKey from the platform keystore
 */
sp
enum SPErrorCode sp_biometric_set_key(SPVaultHandle Handle,
                                      const uint8_t *KeyData,
                                      uintptr_t KeyDataLen);

/**
 * Unlock vault using biometric authentication
 *
 * Call this after successful biometric authentication on the platform
 *
 * # Safety
 * - handle must be a valid vault handle
 */
sp enum SPErrorCode sp_biometric_unlock(SPVaultHandle Handle);

/**
 * Free bytes allocated by this library
 *
 * # Safety
 * - ptr must be a valid pointer returned from this library, or null
 */
sp void sp_bytes_free(const uint8_t *Ptr);

/**
 * Add a new entry to the vault
 *
 * # Safety
 * - All string parameters must be valid null-terminated C strings
 * - out_entry_id must be a valid pointer (will be set to newly allocated string)
 *
 * The returned entry_id must be freed with sp_string_free
 */
sp
enum SPErrorCode sp_entry_add(SPVaultHandle Handle,
                              const char *Title,
                              const char *Username,
                              const char *Password,
                              const char *Url,
                              const char *Notes,
                              const char **OutEntryId);

/**
 * Delete an entry
 *
 * # Safety
 * - entry_id must be a valid null-terminated C string
 */
sp enum SPErrorCode sp_entry_delete(SPVaultHandle Handle, const char *EntryId);

/**
 * Get a specific entry by ID
 *
 * # Safety
 * - entry_id must be a valid null-terminated C string
 * - out_entry must be a valid pointer
 *
 * The returned entry's strings must be freed with sp_string_free
 * The entire entry must be freed with sp_entry_free
 */
sp
enum SPErrorCode sp_entry_get_by_id(SPVaultHandle Handle,
                                    const char *EntryId,
                                    struct SPEntry *OutEntry);

/**
 * List all entries in the vault
 *
 * # Safety
 * - out_entries must be a valid pointer to a pointer
 * - out_count must be a valid pointer
 *
 * The returned entries array and all contained strings must be freed:
 * - First free each entry's strings with sp_string_free
 * - Then free the array with sp_bytes_free
 */
sp
enum SPErrorCode sp_entry_list_all(SPVaultHandle Handle,
                                   const struct SPEntrySummary **OutEntries,
                                   uintptr_t *OutCount);

/**
 * Search entries by query
 *
 * # Safety
 * - query must be a valid null-terminated C string
 * - out_entries must be a valid pointer
 * - out_count must be a valid pointer
 *
 * Memory management same as sp_entry_list_all
 */
sp
enum SPErrorCode sp_entry_search(SPVaultHandle Handle,
                                 const char *Query,
                                 const struct SPEntrySummary **OutEntries,
                                 uintptr_t *OutCount);

/**
 * Update an existing entry
 *
 * # Safety
 * - entry_id must be a valid null-terminated C string
 * - All other string parameters can be null (meaning no change)
 */
sp
enum SPErrorCode sp_entry_update(SPVaultHandle Handle,
                                 const char *EntryId,
                                 const char *Title,
                                 const char *Username,
                                 const char *Password,
                                 const char *Url,
                                 const char *Notes);

/**
 * Check password strength
 *
 * # Safety
 * - password must be a valid null-terminated C string
 * - out_analysis must be a valid pointer
 */
sp
enum SPErrorCode sp_password_check_strength(const char *Password,
                                            struct SPPasswordAnalysis *OutAnalysis);

/**
 * Generate a random password
 *
 * # Safety
 * - out_password must be a valid pointer
 *
 * The returned password string must be freed with sp_string_free
 */
sp
enum SPErrorCode sp_password_generate(uintptr_t Length,
                                      bool IncludeSymbols,
                                      const char **OutPassword);

/**
 * Free a string allocated by this library
 *
 * # Safety
 * - ptr must be a valid pointer returned from this library, or null
 */
sp void sp_string_free(const char *Ptr);

/**
 * Generate TOTP code for an entry
 *
 * # Safety
 * - entry_id must be a valid null-terminated C string
 * - out_code must be a valid pointer
 *
 * The returned code string must be freed with sp_string_free
 */
sp
enum SPErrorCode sp_totp_generate_code(SPVaultHandle Handle,
                                       const char *EntryId,
                                       struct SPTotpCode *OutCode);

/**
 * Destroy a vault and free resources
 *
 * # Safety
 * - handle must be a valid vault handle returned from sp_vault_init
 */
sp enum SPErrorCode sp_vault_destroy(SPVaultHandle Handle);

/**
 * Initialize or unlock a vault
 *
 * # Safety
 * - vault_path must be a valid null-terminated C string
 * - master_password must be a valid null-terminated C string
 * - out_handle must be a valid pointer to a VaultHandle
 *
 * # Arguments
 * * vault_path - Path to vault database file
 * * master_password - Master password for encryption
 * * out_handle - Output parameter for vault handle
 *
 * # Returns
 * ErrorCode::Success on success, error code otherwise
 */
sp
enum SPErrorCode sp_vault_init(const char *VaultPath,
                               const char *MasterPassword,
                               SPVaultHandle *OutHandle);

/**
 * Check if vault is currently unlocked
 *
 * # Safety
 * - handle must be a valid vault handle
 * - out_unlocked must be a valid pointer to a bool
 */
sp enum SPErrorCode sp_vault_is_unlocked(SPVaultHandle Handle, bool *OutUnlocked);

/**
 * Lock the vault
 *
 * # Safety
 * - handle must be a valid vault handle
 */
sp enum SPErrorCode sp_vault_lock(SPVaultHandle Handle);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
