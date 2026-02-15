//! Database layer for the password manager.
//!
//! This module handles all database operations including schema management,
//! migrations, and encrypted data persistence.

pub mod migrations;
pub mod models;
pub mod schema;

pub use models::{DomainMapping, Entry, TotpSecret};
pub use schema::Database;
