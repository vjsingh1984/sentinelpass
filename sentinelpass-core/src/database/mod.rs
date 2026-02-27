//! Database layer for the password manager.
//!
//! This module handles all database operations including schema management,
//! migrations, and encrypted data persistence.

pub mod migrations;
pub mod models;
pub mod repository;
pub mod schema;

pub use models::{DomainMapping, Entry, TotpSecret};
pub use repository::{
    EntryFilter, EntryRepository, NewEntryParams, RawEntryRow, SqliteEntryRepository,
    UpdateEntryParams,
};
pub use schema::Database;
