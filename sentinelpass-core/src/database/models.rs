//! Database models for password entries.

use chrono::{DateTime, Utc};

/// A password entry stored in the database
#[derive(Debug, Clone)]
pub struct Entry {
    pub entry_id: Option<i64>,
    pub vault_id: i64,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
    pub favorite: bool,
}

/// A domain mapping for autofill lookup
#[derive(Debug, Clone)]
pub struct DomainMapping {
    pub mapping_id: Option<i64>,
    pub entry_id: i64,
    pub domain: String,
    pub is_primary: bool,
}
