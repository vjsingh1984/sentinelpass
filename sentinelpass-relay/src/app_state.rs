//! Shared relay application state.

use crate::config::RelayConfig;
use crate::rate_limit::RateLimiter;
use crate::storage::RelayStorage;
use std::sync::Arc;

/// Shared state for handlers and middleware.
#[derive(Clone)]
pub struct RelayAppState {
    pub storage: RelayStorage,
    pub config: Arc<RelayConfig>,
    pub rate_limiter: RateLimiter,
}

impl RelayAppState {
    pub fn new(storage: RelayStorage, config: RelayConfig) -> Self {
        let rate_limiter = RateLimiter::new(config.rate_limit_per_minute);
        Self {
            storage,
            config: Arc::new(config),
            rate_limiter,
        }
    }
}
