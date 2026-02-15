//! Auto-lock functionality for vault security.

use std::time::{Duration, Instant};

/// Auto-lock manager for vault security
pub struct AutoLockManager {
    last_activity: Instant,
    timeout: Duration,
    enabled: bool,
}

impl AutoLockManager {
    /// Create a new auto-lock manager
    pub fn new(timeout: Duration) -> Self {
        Self {
            last_activity: Instant::now(),
            timeout,
            enabled: true,
        }
    }

    /// Update the last activity timestamp
    pub fn record_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Check if the vault should be locked
    pub fn should_lock(&self) -> bool {
        if !self.enabled {
            return false;
        }
        self.last_activity.elapsed() > self.timeout
    }

    /// Enable auto-lock
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable auto-lock
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Set the timeout duration
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Get the time until lock
    pub fn time_until_lock(&self) -> Option<Duration> {
        if !self.enabled {
            return None;
        }
        self.timeout.checked_sub(self.last_activity.elapsed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_auto_lock_timeout() {
        let manager = AutoLockManager::new(Duration::from_millis(100));

        // Should not lock immediately
        assert!(!manager.should_lock());

        // Wait for timeout
        thread::sleep(Duration::from_millis(150));

        // Should lock now
        assert!(manager.should_lock());
    }

    #[test]
    fn test_activity_resets_timer() {
        // Use wider timing margins to avoid flaky behavior on slow CI runners.
        let mut manager = AutoLockManager::new(Duration::from_millis(250));

        thread::sleep(Duration::from_millis(40));
        manager.record_activity();

        thread::sleep(Duration::from_millis(60));
        // Should not lock because activity reset the timer
        assert!(!manager.should_lock());

        thread::sleep(Duration::from_millis(220));
        // Should lock after enough time has passed since last activity
        assert!(manager.should_lock());
    }

    #[test]
    fn test_disabled_auto_lock() {
        let mut manager = AutoLockManager::new(Duration::from_millis(50));

        manager.disable();

        thread::sleep(Duration::from_millis(100));

        // Should not lock when disabled
        assert!(!manager.should_lock());
    }

    #[test]
    fn test_time_until_lock() {
        let manager = AutoLockManager::new(Duration::from_secs(5));

        let remaining = manager.time_until_lock();
        assert!(remaining.is_some());
        assert!(remaining.unwrap().as_secs() <= 5);
    }

    #[test]
    fn test_time_until_lock_when_disabled() {
        let mut manager = AutoLockManager::new(Duration::from_secs(5));
        manager.disable();

        assert!(manager.time_until_lock().is_none());
    }
}
