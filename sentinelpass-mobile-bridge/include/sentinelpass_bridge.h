#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Error codes that can be returned to mobile platforms
 */
typedef enum SPErrorCode {
  SPErrorCode_Success = 0,
  SPErrorCode_InvalidParam = -1,
  SPErrorCode_VaultLocked = -2,
  SPErrorCode_NotFound = -3,
  SPErrorCode_Crypto = -4,
  SPErrorCode_Database = -5,
  SPErrorCode_Io = -6,
  SPErrorCode_AlreadyUnlocked = -7,
  SPErrorCode_InvalidPassword = -8,
  SPErrorCode_NotInitialized = -9,
  SPErrorCode_Biometric = -10,
  SPErrorCode_Totp = -11,
  SPErrorCode_Sync = -12,
  SPErrorCode_OutOfMemory = -13,
  SPErrorCode_Unknown = -99,
} SPErrorCode;

/**
 * Vault handle type (opaque u64)
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
  bool favorite;
} SPEntry;

/**
 * FFI-safe entry summary (for list views)
 */
typedef struct SPEntrySummary {
  const char *id;
  const char *title;
  const char *username;
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

sp enum SPErrorCode sp_biometric_has_key(SPVaultHandle Handle, bool *OutHasKey);

sp enum SPErrorCode sp_biometric_remove_key(SPVaultHandle Handle);

sp
enum SPErrorCode sp_biometric_set_key(SPVaultHandle Handle,
                                      const uint8_t *KeyData,
                                      uintptr_t KeyDataLen);

sp enum SPErrorCode sp_biometric_unlock(SPVaultHandle Handle);

sp void sp_bytes_free(const uint8_t *Ptr, uintptr_t Len);

/**
 * Add a new entry
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
 * Delete entry
 */
sp enum SPErrorCode sp_entry_delete(SPVaultHandle Handle, const char *EntryId);

/**
 * Get entry by ID
 */
sp
enum SPErrorCode sp_entry_get_by_id(SPVaultHandle Handle,
                                    const char *EntryId,
                                    struct SPEntry *OutEntry);

/**
 * List all entries
 */
sp
enum SPErrorCode sp_entry_list_all(SPVaultHandle Handle,
                                   const struct SPEntrySummary **OutEntries,
                                   uintptr_t *OutCount);

/**
 * Search entries
 */
sp
enum SPErrorCode sp_entry_search(SPVaultHandle Handle,
                                 const char *Query,
                                 const struct SPEntrySummary **OutEntries,
                                 uintptr_t *OutCount);

/**
 * Check password strength
 */
sp
enum SPErrorCode sp_password_check_strength(const char *Password,
                                            struct SPPasswordAnalysis *OutAnalysis);

/**
 * Generate password
 */
sp
enum SPErrorCode sp_password_generate(uintptr_t Length,
                                      bool IncludeSymbols,
                                      const char **OutPassword);

sp void sp_string_free(const char *Ptr);

/**
 * Generate TOTP code
 */
sp
enum SPErrorCode sp_totp_generate_code(SPVaultHandle Handle,
                                       const char *EntryId,
                                       struct SPTotpCode *OutCode);

/**
 * Destroy a vault
 */
sp enum SPErrorCode sp_vault_destroy(SPVaultHandle Handle);

/**
 * Initialize or unlock a vault
 */
sp
enum SPErrorCode sp_vault_init(const char *VaultPath,
                               const char *MasterPassword,
                               SPVaultHandle *OutHandle);

/**
 * Check if vault is unlocked
 */
sp enum SPErrorCode sp_vault_is_unlocked(SPVaultHandle Handle, bool *OutUnlocked);

/**
 * Lock the vault
 */
sp enum SPErrorCode sp_vault_lock(SPVaultHandle Handle);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
