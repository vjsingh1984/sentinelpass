//! Database layer for the password manager.
//!
//! This module handles all database operations including schema management,
//! migrations, and encrypted data persistence.

pub mod schema;
pub mod models;
pub mod migrations;

pub use schema::Database;
pub use models::{Entry, DomainMapping};
