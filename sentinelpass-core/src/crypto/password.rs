//! Secure random password generator

use crate::crypto::{Result, CryptoError};
use rand::seq::SliceRandom;

/// Character sets for password generation
pub struct CharacterSets {
    /// Lowercase letters (a-z)
    pub lowercase: &'static [u8],
    /// Uppercase letters (A-Z)
    pub uppercase: &'static [u8],
    /// Digits (0-9)
    pub digits: &'static [u8],
    /// Symbols/special characters
    pub symbols: &'static [u8],
    /// All letters (upper + lower case)
    pub letters: &'static [u8],
    /// Alphanumeric (letters + digits)
    pub alphanumeric: &'static [u8],
    /// All printable ASCII characters
    pub all: &'static [u8],
}

impl CharacterSets {
    const LOWERCASE: &'static [u8] = b"abcdefghijklmnopqrstuvwxyz";
    const UPPERCASE: &'static [u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGITS: &'static [u8] = b"0123456789";
    const SYMBOLS: &'static [u8] = b"!@#$%^&*()_+-=[]{}|;:,.<>?";

    pub const fn get() -> &'static CharacterSets {
        &CharacterSets {
            lowercase: Self::LOWERCASE,
            uppercase: Self::UPPERCASE,
            digits: Self::DIGITS,
            symbols: Self::SYMBOLS,
            letters: Self::LETTERS,
            alphanumeric: Self::ALPHANUMERIC,
            all: Self::ALL,
        }
    }

    const LETTERS: &'static [u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const ALPHANUMERIC: &'static [u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const ALL: &'static [u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
}

/// Configuration for password generation
#[derive(Debug, Clone, Copy)]
pub struct PasswordGeneratorConfig {
    /// Length of the password to generate
    pub length: usize,
    /// Include lowercase letters
    pub include_lowercase: bool,
    /// Include uppercase letters
    pub include_uppercase: bool,
    /// Include digits
    pub include_digits: bool,
    /// Include symbols
    pub include_symbols: bool,
    /// Exclude ambiguous characters (like l, 1, I, O, 0)
    pub exclude_ambiguous: bool,
}

impl Default for PasswordGeneratorConfig {
    fn default() -> Self {
        Self {
            length: 16,
            include_lowercase: true,
            include_uppercase: true,
            include_digits: true,
            include_symbols: true,
            exclude_ambiguous: true,
        }
    }
}

impl PasswordGeneratorConfig {
    /// Create a new password generator config
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the password length
    pub fn length(mut self, length: usize) -> Self {
        self.length = length;
        self
    }

    /// Include lowercase letters
    pub fn with_lowercase(mut self, include: bool) -> Self {
        self.include_lowercase = include;
        self
    }

    /// Include uppercase letters
    pub fn with_uppercase(mut self, include: bool) -> Self {
        self.include_uppercase = include;
        self
    }

    /// Include digits
    pub fn with_digits(mut self, include: bool) -> Self {
        self.include_digits = include;
        self
    }

    /// Include symbols
    pub fn with_symbols(mut self, include: bool) -> Self {
        self.include_symbols = include;
        self
    }

    /// Exclude ambiguous characters (l, 1, I, O, 0, etc.)
    pub fn exclude_ambiguous(mut self, exclude: bool) -> Self {
        self.exclude_ambiguous = exclude;
        self
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        if self.length < 4 {
            return Err(CryptoError::EncryptionFailed(
                "Password length must be at least 4 characters".to_string()
            ));
        }

        if !self.include_lowercase && !self.include_uppercase && !self.include_digits && !self.include_symbols {
            return Err(CryptoError::EncryptionFailed(
                "At least one character type must be enabled".to_string()
            ));
        }

        Ok(())
    }
}

/// Generate a secure random password
pub fn generate_password(config: &PasswordGeneratorConfig) -> Result<String> {
    config.validate()?;

    let charset = CharacterSets::get();
    let mut rng = rand::thread_rng();

    // Build the character pool
    let mut pool = Vec::new();

    if config.include_lowercase {
        pool.extend(charset.lowercase);
    }
    if config.include_uppercase {
        pool.extend(charset.uppercase);
    }
    if config.include_digits {
        pool.extend(charset.digits);
    }
    if config.include_symbols {
        pool.extend(charset.symbols);
    }

    // Remove ambiguous characters if requested
    if config.exclude_ambiguous {
        pool.retain(|&c| !matches!(c, b'l' | b'1' | b'I' | b'O' | b'0'));
    }

    // Ensure pool is not empty
    if pool.is_empty() {
        return Err(CryptoError::RandomFailed(
            "Character pool is empty after applying filters".to_string()
        ));
    }

    // Ensure at least one character from each requested type
    let mut password = Vec::with_capacity(config.length);
    let mut position = 0;

    if config.include_lowercase {
        let chars = if config.exclude_ambiguous {
            charset.lowercase.iter().copied().filter(|&c| !matches!(c, b'l')).collect::<Vec<_>>()
        } else {
            charset.lowercase.to_vec()
        };
        if !chars.is_empty() {
            password.push(chars.choose(&mut rng).copied().unwrap());
            position += 1;
        }
    }

    if config.include_uppercase {
        let chars = if config.exclude_ambiguous {
            charset.uppercase.iter().copied().filter(|&c| !matches!(c, b'I' | b'O')).collect::<Vec<_>>()
        } else {
            charset.uppercase.to_vec()
        };
        if !chars.is_empty() {
            password.push(chars.choose(&mut rng).copied().unwrap());
            position += 1;
        }
    }

    if config.include_digits {
        let chars = if config.exclude_ambiguous {
            charset.digits.iter().copied().filter(|&c| !matches!(c, b'0' | b'1')).collect::<Vec<_>>()
        } else {
            charset.digits.to_vec()
        };
        if !chars.is_empty() {
            password.push(chars.choose(&mut rng).copied().unwrap());
            position += 1;
        }
    }

    if config.include_symbols {
        password.push(pool.choose(&mut rng).copied().unwrap());
        position += 1;
    }

    // Fill the rest with random characters from the pool
    while position < config.length {
        password.push(pool.choose(&mut rng).copied().unwrap());
        position += 1;
    }

    // Shuffle the password to avoid predictable patterns
    let mut password_vec: Vec<char> = password.into_iter().map(|b| b as char).collect();
    password_vec.shuffle(&mut rng);

    Ok(password_vec.into_iter().collect())
}

/// Generate a simple alphanumeric password
pub fn generate_simple_password(length: usize) -> Result<String> {
    let config = PasswordGeneratorConfig {
        length,
        include_lowercase: true,
        include_uppercase: true,
        include_digits: true,
        include_symbols: false,
        exclude_ambiguous: true,
    };
    generate_password(&config)
}

/// Generate a passphrase from a word list
///
/// Note: This is a placeholder implementation. In production, use a proper word list.
pub fn generate_passphrase(word_count: usize, separator: &str) -> Result<String> {
    if word_count == 0 {
        return Err(CryptoError::EncryptionFailed(
            "Word count must be at least 1".to_string()
        ));
    }

    // Simple word list for demonstration
    const WORDS: &[&str] = &[
        "correct", "horse", "battery", "staple", "cloud", "mountain", "river", "forest",
        "ocean", "star", "moon", "sun", "wind", "rain", "snow", "fire", "earth", "water",
        "bridge", "castle", "dragon", "eagle", "flower", "garden", "house", "island", "journey",
    ];

    let mut rng = rand::thread_rng();
    let words: Vec<&str> = (0..word_count)
        .map(|_| WORDS.choose(&mut rng).copied().unwrap())
        .collect();

    Ok(words.join(separator))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_default_password() {
        let config = PasswordGeneratorConfig::default();
        let password = generate_password(&config).unwrap();
        assert_eq!(password.len(), 16);
    }

    #[test]
    fn test_generate_custom_length() {
        let config = PasswordGeneratorConfig::default().length(32);
        let password = generate_password(&config).unwrap();
        assert_eq!(password.len(), 32);
    }

    #[test]
    fn test_generate_letters_only() {
        let config = PasswordGeneratorConfig::default()
            .with_digits(false)
            .with_symbols(false)
            .length(12);
        let password = generate_password(&config).unwrap();
        assert_eq!(password.len(), 12);
        assert!(password.chars().all(|c| c.is_alphabetic()));
    }

    #[test]
    fn test_generate_no_ambiguous() {
        let config = PasswordGeneratorConfig::default()
            .exclude_ambiguous(true)
            .length(20);
        let password = generate_password(&config).unwrap();
        assert_eq!(password.len(), 20);
        assert!(!password.chars().any(|c| matches!(c, 'l' | '1' | 'I' | 'O' | '0')));
    }

    #[test]
    fn test_simple_password() {
        let password = generate_simple_password(12).unwrap();
        assert_eq!(password.len(), 12);
        assert!(password.chars().all(|c| c.is_alphanumeric()));
    }

    #[test]
    fn test_passphrase() {
        let passphrase = generate_passphrase(4, "-").unwrap();
        let parts: Vec<&str> = passphrase.split('-').collect();
        assert_eq!(parts.len(), 4);
    }

    #[test]
    fn test_validate_length_too_short() {
        let config = PasswordGeneratorConfig::default().length(2);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_no_char_types() {
        let config = PasswordGeneratorConfig {
            length: 16,
            include_lowercase: false,
            include_uppercase: false,
            include_digits: false,
            include_symbols: false,
            exclude_ambiguous: false,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_passwords_are_unique() {
        let config = PasswordGeneratorConfig::default();
        let p1 = generate_password(&config).unwrap();
        let p2 = generate_password(&config).unwrap();
        assert_ne!(p1, p2);
    }
}
