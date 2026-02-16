//! Database migrations for schema versioning.
//!
//! Schema version is tracked via `db_metadata.version` and validated on vault
//! open in `schema::Database::validate_schema_version()`. When future schema
//! changes are needed, add migration logic here and bump
//! `schema::CURRENT_SCHEMA_VERSION`.
