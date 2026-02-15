//! Password strength analysis and entropy calculation

use crate::crypto::Result;

/// Strength rating for a password
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PasswordStrength {
    /// Very weak - high risk of cracking
    VeryWeak,
    /// Weak - moderate risk
    Weak,
    /// Fair - some protection
    Fair,
    /// Good - strong password
    Good,
    /// Strong - very strong password
    Strong,
    /// Very strong - excellent password
    VeryStrong,
}

impl PasswordStrength {
    /// Get the strength as a numeric score (0-5)
    pub fn score(&self) -> u8 {
        match self {
            PasswordStrength::VeryWeak => 0,
            PasswordStrength::Weak => 1,
            PasswordStrength::Fair => 2,
            PasswordStrength::Good => 3,
            PasswordStrength::Strong => 4,
            PasswordStrength::VeryStrong => 5,
        }
    }

    /// Get the strength as a display string
    pub fn as_str(&self) -> &'static str {
        match self {
            PasswordStrength::VeryWeak => "Very Weak",
            PasswordStrength::Weak => "Weak",
            PasswordStrength::Fair => "Fair",
            PasswordStrength::Good => "Good",
            PasswordStrength::Strong => "Strong",
            PasswordStrength::VeryStrong => "Very Strong",
        }
    }

    /// Get the color code for UI display
    pub fn color_code(&self) -> &'static str {
        match self {
            PasswordStrength::VeryWeak => "\x1b[31m",   // Red
            PasswordStrength::Weak => "\x1b[33m",       // Orange/Yellow
            PasswordStrength::Fair => "\x1b[93m",       // Bright Yellow
            PasswordStrength::Good => "\x1b[32m",       // Green
            PasswordStrength::Strong => "\x1b[36m",     // Cyan
            PasswordStrength::VeryStrong => "\x1b[34m", // Blue
        }
    }
}

/// Password analysis result
#[derive(Debug, Clone)]
pub struct PasswordAnalysis {
    /// Overall strength rating
    pub strength: PasswordStrength,
    /// Estimated entropy in bits
    pub entropy_bits: f64,
    /// Estimated time to crack (in seconds, assuming 10 billion guesses/sec)
    pub crack_time_seconds: f64,
    /// Password length
    pub length: usize,
    /// Whether password contains lowercase letters
    pub has_lowercase: bool,
    /// Whether password contains uppercase letters
    pub has_uppercase: bool,
    /// Whether password contains digits
    pub has_digits: bool,
    /// Whether password contains symbols
    pub has_symbols: bool,
    /// Warnings about the password
    pub warnings: Vec<String>,
    /// Suggestions for improvement
    pub suggestions: Vec<String>,
}

impl PasswordAnalysis {
    /// Get a human-readable crack time
    pub fn crack_time_human(&self) -> String {
        let seconds = self.crack_time_seconds;

        if seconds < 1.0 {
            "Instantly".to_string()
        } else if seconds < 60.0 {
            format!("{} seconds", seconds.floor())
        } else if seconds < 3600.0 {
            format!("{} minutes", (seconds / 60.0).floor())
        } else if seconds < 86400.0 {
            format!("{} hours", (seconds / 3600.0).floor())
        } else if seconds < 31536000.0 {
            format!("{} days", (seconds / 86400.0).floor())
        } else if seconds < 315360000.0 {
            format!("{} years", (seconds / 31536000.0).floor())
        } else if seconds < 3153600000.0 {
            format!("{} decades", (seconds / 315360000.0).floor())
        } else {
            "Centuries".to_string()
        }
    }
}

/// Analyze password strength
pub fn analyze_password(password: &str) -> Result<PasswordAnalysis> {
    let length = password.len();
    let mut warnings = Vec::new();
    let mut suggestions = Vec::new();

    // Check character types
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_digits = password.chars().any(|c| c.is_ascii_digit());
    let has_symbols = password
        .chars()
        .any(|c| c.is_ascii_punctuation() || c.is_ascii_graphic() && !c.is_alphanumeric());

    // Calculate character set size
    let mut charset_size = 0;
    if has_lowercase {
        charset_size += 26;
    }
    if has_uppercase {
        charset_size += 26;
    }
    if has_digits {
        charset_size += 10;
    }
    if has_symbols {
        charset_size += 32; // Approximate for common symbols
    }

    // Calculate entropy: E = L * log2(R)
    // where L is length and R is charset size
    let entropy_bits = if charset_size > 0 {
        (length as f64) * (charset_size as f64).log2()
    } else {
        0.0
    };

    // Estimate crack time (assuming 10 billion guesses/second)
    // Time = 2^entropy / guesses_per_second
    let guesses_per_second = 10_000_000_000.0;
    let crack_time_seconds = if entropy_bits > 0.0 {
        2_f64.powf(entropy_bits) / guesses_per_second
    } else {
        0.0
    };

    // Determine strength based on entropy
    let strength = if entropy_bits < 28.0 {
        PasswordStrength::VeryWeak
    } else if entropy_bits < 36.0 {
        PasswordStrength::Weak
    } else if entropy_bits < 60.0 {
        PasswordStrength::Fair
    } else if entropy_bits < 80.0 {
        PasswordStrength::Good
    } else if entropy_bits < 100.0 {
        PasswordStrength::Strong
    } else {
        PasswordStrength::VeryStrong
    };

    // Generate warnings and suggestions
    if length < 8 {
        warnings.push("Password is too short".to_string());
        suggestions.push("Use at least 8 characters".to_string());
    } else if length < 12 {
        warnings.push("Password could be longer".to_string());
        suggestions.push("Consider using 12+ characters for better security".to_string());
    }

    if !has_lowercase {
        warnings.push("Missing lowercase letters".to_string());
        suggestions.push("Add lowercase letters (a-z)".to_string());
    }
    if !has_uppercase {
        warnings.push("Missing uppercase letters".to_string());
        suggestions.push("Add uppercase letters (A-Z)".to_string());
    }
    if !has_digits {
        warnings.push("Missing numbers".to_string());
        suggestions.push("Add numbers (0-9)".to_string());
    }
    if !has_symbols {
        warnings.push("Missing special characters".to_string());
        suggestions.push("Add special characters (!@#$%, etc.)".to_string());
    }

    // Check for common patterns
    if password.to_lowercase().contains("password") {
        warnings.push("Contains the word 'password'".to_string());
        suggestions.push("Avoid using dictionary words".to_string());
    }

    // Check for repeating characters
    if password
        .chars()
        .collect::<Vec<char>>()
        .windows(3)
        .any(|w| w[0] == w[1] && w[1] == w[2])
    {
        warnings.push("Contains repeating characters".to_string());
        suggestions.push("Avoid repeating characters".to_string());
    }

    // Check for sequential characters
    let sequential = password.chars().collect::<Vec<char>>().windows(3).any(|w| {
        let (a, b, c) = (w[0] as u8, w[1] as u8, w[2] as u8);
        (a + 1 == b && b + 1 == c) || (a == b + 1 && b == c + 1)
    });
    if sequential {
        warnings.push("Contains sequential characters (like 'abc' or '123')".to_string());
        suggestions.push("Avoid sequential patterns".to_string());
    }

    Ok(PasswordAnalysis {
        strength,
        entropy_bits,
        crack_time_seconds,
        length,
        has_lowercase,
        has_uppercase,
        has_digits,
        has_symbols,
        warnings,
        suggestions,
    })
}

/// Calculate Shannon entropy of a string
pub fn calculate_shannon_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }

    let len = text.len() as f64;
    let mut freq = std::collections::HashMap::new();

    for c in text.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }

    let mut entropy = 0.0;
    for &count in freq.values() {
        let p = count as f64 / len;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_very_weak_password() {
        let analysis = analyze_password("123").unwrap();
        assert_eq!(analysis.strength, PasswordStrength::VeryWeak);
        assert!(analysis.entropy_bits < 28.0);
    }

    #[test]
    fn test_weak_password() {
        let analysis = analyze_password("password").unwrap();
        // "password" has reasonable entropy but should trigger a warning
        assert!(analysis.warnings.iter().any(|w| w.contains("password")));
        assert!(analysis.entropy_bits < 40.0);
    }

    #[test]
    fn test_fair_password() {
        let analysis = analyze_password("Pass123!").unwrap();
        assert_eq!(analysis.strength, PasswordStrength::Fair);
        assert!(analysis.has_lowercase);
        assert!(analysis.has_uppercase);
        assert!(analysis.has_digits);
        assert!(analysis.has_symbols);
    }

    #[test]
    fn test_good_password() {
        let analysis = analyze_password("MyP@ssw0rd!23").unwrap();
        assert!(matches!(
            analysis.strength,
            PasswordStrength::Good | PasswordStrength::Strong
        ));
    }

    #[test]
    fn test_strong_password() {
        let analysis = analyze_password("Tr0ub4dor&3St!le#P@ssw0rd").unwrap();
        assert!(matches!(
            analysis.strength,
            PasswordStrength::Strong | PasswordStrength::VeryStrong
        ));
        assert!(analysis.entropy_bits > 80.0);
    }

    #[test]
    fn test_shannon_entropy() {
        let entropy = calculate_shannon_entropy("aaaa");
        assert_eq!(entropy, 0.0); // All same characters

        let entropy = calculate_shannon_entropy("abcd");
        assert!(entropy > 0.0); // All different
    }

    #[test]
    fn test_repeating_characters() {
        let analysis = analyze_password("Passs111").unwrap();
        assert!(analysis.warnings.iter().any(|w| w.contains("repeating")));
    }

    #[test]
    fn test_sequential_characters() {
        let analysis = analyze_password("Pass123abc").unwrap();
        assert!(analysis.warnings.iter().any(|w| w.contains("sequential")));
    }

    #[test]
    fn test_crack_time_formatting() {
        let analysis = PasswordAnalysis {
            strength: PasswordStrength::Good,
            entropy_bits: 60.0,
            crack_time_seconds: 30.0,
            length: 12,
            has_lowercase: true,
            has_uppercase: true,
            has_digits: true,
            has_symbols: true,
            warnings: vec![],
            suggestions: vec![],
        };
        assert_eq!(analysis.crack_time_human(), "30 seconds");
    }
}
