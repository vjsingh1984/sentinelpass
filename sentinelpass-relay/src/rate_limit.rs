//! Token bucket rate limiter per device.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[allow(dead_code)]
#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<Mutex<HashMap<String, TokenBucket>>>,
    max_tokens: u32,
    refill_rate: f64, // tokens per second
}

#[allow(dead_code)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

#[allow(dead_code)]
impl RateLimiter {
    pub fn new(requests_per_minute: u32) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            max_tokens: requests_per_minute,
            refill_rate: requests_per_minute as f64 / 60.0,
        }
    }

    pub fn check(&self, device_id: &str) -> bool {
        let mut buckets = self.buckets.lock().unwrap();
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
}
