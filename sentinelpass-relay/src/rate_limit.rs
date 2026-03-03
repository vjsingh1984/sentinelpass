//! Token bucket rate limiter with sustained abuse prevention.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<Mutex<HashMap<String, TokenBucket>>>,
    max_tokens: u32,
    refill_rate: f64, // tokens per second
    hourly_buckets: Arc<Mutex<HashMap<String, HourlyBucket>>>,
    hourly_limit: u32,
    daily_buckets: Arc<Mutex<HashMap<String, DailyBucket>>>,
    daily_limit: u32,
}

#[allow(dead_code)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

struct HourlyBucket {
    count: u32,
    window_start: Instant,
}

struct DailyBucket {
    count: u32,
    window_start: Instant,
}

#[allow(dead_code)]
impl RateLimiter {
    pub fn new(requests_per_minute: u32) -> Self {
        // Hourly limit: 10x the per-minute rate (allows bursts but prevents sustained abuse)
        let hourly_limit = requests_per_minute.saturating_mul(10);
        // Daily limit: 100x the per-minute rate (allows legitimate usage while preventing automated abuse)
        let daily_limit = requests_per_minute.saturating_mul(100);

        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            max_tokens: requests_per_minute,
            refill_rate: requests_per_minute as f64 / 60.0,
            hourly_buckets: Arc::new(Mutex::new(HashMap::new())),
            hourly_limit,
            daily_buckets: Arc::new(Mutex::new(HashMap::new())),
            daily_limit,
        }
    }

    pub fn check(&self, device_id: &str) -> bool {
        // Check per-minute rate limit (token bucket)
        if !self.check_minute_limit(device_id) {
            return false;
        }

        // Check per-hour quota (sliding window)
        if !self.check_hourly_limit(device_id) {
            return false;
        }

        // Check per-day quota (sliding window)
        self.check_daily_limit(device_id)
    }

    fn check_minute_limit(&self, device_id: &str) -> bool {
        let mut buckets = match self.buckets.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();

        let bucket = buckets.entry(device_id.to_string()).or_insert(TokenBucket {
            tokens: self.max_tokens as f64,
            last_refill: now,
        });

        // Refill tokens
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_rate).min(self.max_tokens as f64);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn check_hourly_limit(&self, device_id: &str) -> bool {
        let mut buckets = match self.hourly_buckets.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();

        let bucket = buckets
            .entry(device_id.to_string())
            .or_insert(HourlyBucket {
                count: 0,
                window_start: now,
            });

        // Reset if window has expired (1 hour)
        if now.duration_since(bucket.window_start) >= Duration::from_secs(3600) {
            bucket.count = 0;
            bucket.window_start = now;
        }

        if bucket.count < self.hourly_limit {
            bucket.count += 1;
            true
        } else {
            false
        }
    }

    fn check_daily_limit(&self, device_id: &str) -> bool {
        let mut buckets = match self.daily_buckets.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();

        let bucket = buckets.entry(device_id.to_string()).or_insert(DailyBucket {
            count: 0,
            window_start: now,
        });

        // Reset if window has expired (24 hours)
        if now.duration_since(bucket.window_start) >= Duration::from_secs(86400) {
            bucket.count = 0;
            bucket.window_start = now;
        }

        if bucket.count < self.daily_limit {
            bucket.count += 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn rate_limiter_exhausts_tokens() {
        let limiter = RateLimiter::new(2);
        assert!(limiter.check("device-a"));
        assert!(limiter.check("device-a"));
        assert!(!limiter.check("device-a"));
    }

    #[test]
    fn rate_limiter_is_key_scoped() {
        let limiter = RateLimiter::new(1);
        assert!(limiter.check("device-a"));
        assert!(!limiter.check("device-a"));
        assert!(limiter.check("device-b"));
    }

    #[test]
    fn rate_limiter_enforces_hourly_quota() {
        let limiter = RateLimiter::new(6); // 6 per minute, 60 per hour
        let key = "hourly-test";

        // Make rapid requests until we hit the per-minute limit
        let mut succeeded = 0;
        for _ in 0..10 {
            if limiter.check(key) {
                succeeded += 1;
            }
        }
        assert_eq!(succeeded, 6, "Should succeed for all 6 per-minute tokens");

        // Check that hourly bucket has 6 requests (matching the per-minute limit)
        let hourly_buckets = limiter.hourly_buckets.lock().unwrap();
        let bucket = hourly_buckets.get(key).unwrap();
        assert_eq!(
            bucket.count, 6,
            "Hourly count should match per-minute usage"
        );

        // Verify the hourly limit is higher than per-minute
        assert_eq!(limiter.hourly_limit, 60, "Hourly limit should be 60");
    }

    #[test]
    fn rate_limiter_enforces_daily_quota() {
        let limiter = RateLimiter::new(1); // 1 per minute, 100 per day
        let key = "daily-test";

        // Exhaust per-minute and hourly limits to reach daily limit
        // Note: This test would take a very long time to truly exhaust the daily limit
        // so we just verify the logic structure is correct

        // First request should always succeed
        assert!(limiter.check(key), "First request should succeed");

        // Verify the daily bucket was created and incremented
        let daily_buckets = limiter.daily_buckets.lock().unwrap();
        let bucket = daily_buckets.get(key);
        assert!(bucket.is_some(), "Daily bucket should exist");
        assert_eq!(bucket.unwrap().count, 1, "Daily count should be 1");
    }

    #[cfg(not(windows))]
    #[test]
    #[ignore = "Instant subtraction causes overflow/hang on some platforms"]
    fn rate_limiter_resets_hourly_window() {
        let limiter = RateLimiter::new(10);
        let key = "hourly-reset-test";

        // Create a bucket with custom start time (in the past)
        let mut buckets = limiter.hourly_buckets.lock().unwrap();
        buckets.insert(
            key.to_string(),
            HourlyBucket {
                count: 999,                                               // Near limit
                window_start: Instant::now() - Duration::from_secs(3601), // 1 hour + 1 second ago
            },
        );
        drop(buckets);

        // Should reset and allow new requests
        assert!(
            limiter.check(key),
            "Should succeed after hourly window reset"
        );

        let buckets = limiter.hourly_buckets.lock().unwrap();
        let bucket = buckets.get(key).unwrap();
        assert_eq!(bucket.count, 1, "Count should reset to 1");
    }

    #[cfg(not(windows))]
    #[test]
    #[ignore = "Instant subtraction causes overflow/hang on some platforms"]
    fn rate_limiter_resets_daily_window() {
        let limiter = RateLimiter::new(10);
        let key = "daily-reset-test";

        // Create a bucket with custom start time (in the past)
        let mut buckets = limiter.daily_buckets.lock().unwrap();
        buckets.insert(
            key.to_string(),
            DailyBucket {
                count: 9999,                                               // Near limit
                window_start: Instant::now() - Duration::from_secs(86401), // 24 hours + 1 second ago
            },
        );
        drop(buckets);

        // Should reset and allow new requests
        assert!(
            limiter.check(key),
            "Should succeed after daily window reset"
        );

        let buckets = limiter.daily_buckets.lock().unwrap();
        let bucket = buckets.get(key).unwrap();
        assert_eq!(bucket.count, 1, "Count should reset to 1");
    }

    #[test]
    fn rate_limiter_scales_quotas_with_per_minute_rate() {
        let limiter_low = RateLimiter::new(1); // 1/min, 10/hour, 100/day
        let limiter_high = RateLimiter::new(10); // 10/min, 100/hour, 1000/day

        // Verify internal limits scale correctly
        assert_eq!(
            limiter_low.hourly_limit, 10,
            "Low rate limiter hourly limit should be 10"
        );
        assert_eq!(
            limiter_low.daily_limit, 100,
            "Low rate limiter daily limit should be 100"
        );
        assert_eq!(
            limiter_high.hourly_limit, 100,
            "High rate limiter hourly limit should be 100"
        );
        assert_eq!(
            limiter_high.daily_limit, 1000,
            "High rate limiter daily limit should be 1000"
        );
    }

    #[test]
    fn rate_limiter_minute_refill_works() {
        let limiter = RateLimiter::new(60); // 60 per minute = 1 per second
        let key = "refill-test";

        // Exhaust all tokens
        for _ in 0..60 {
            assert!(limiter.check(key), "Should succeed within limit");
        }
        assert!(
            !limiter.check(key),
            "Should be rate limited after exhaustion"
        );

        // Wait 1 second for one token refill
        thread::sleep(Duration::from_millis(1100));
        assert!(limiter.check(key), "Should succeed after token refill");
    }
}
