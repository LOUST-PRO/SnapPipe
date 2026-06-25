//! Token-bucket rate limiter for SnapPipe.
//!
//! Each [`crate::NodeId`] owns an independent [`TokenBucket`] refilled at
//! `capacity / refill_period`. The default period is 60 seconds; per-node
//! overrides (from the trust store) override this. The limiter is safe for
//! concurrent use via a single `Mutex<HashMap>`.
//!
//! Behaviour:
//! - First call to [`RateLimiter::try_consume`] on a node initializes a full
//!   bucket sized to `default_per_min`.
//! - Bursts up to `capacity` are allowed after a quiet period.
//! - Time is supplied by the caller (`now_unix` seconds, fractional allowed)
//!   to keep tests deterministic.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::NodeId;

/// Default per-node rate when the trust store has no override (req/min).
pub const DEFAULT_RATE_PER_MIN: u32 = 100;

/// One token bucket sized in requests-per-minute.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TokenBucket {
    pub tokens: f64,
    pub last_refill_unix: f64,
    pub capacity: f64,
    pub refill_per_sec: f64,
}

impl TokenBucket {
    /// Construct a bucket sized to `per_min`, fully refilled, anchored at
    /// `now_unix`.
    pub fn full(per_min: u32, now_unix: f64) -> Self {
        let capacity = per_min as f64;
        Self {
            tokens: capacity,
            last_refill_unix: now_unix,
            capacity,
            refill_per_sec: capacity / 60.0,
        }
    }

    /// Refill `self` based on elapsed seconds since `last_refill_unix`,
    /// capped at `capacity`. Mutates in place and returns the new token count.
    pub fn refill(&mut self, now_unix: f64) -> f64 {
        if now_unix <= self.last_refill_unix {
            return self.tokens;
        }
        let elapsed = now_unix - self.last_refill_unix;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        self.last_refill_unix = now_unix;
        self.tokens
    }

    /// Try to consume one token at `now_unix`. Returns `true` if allowed.
    pub fn try_consume(&mut self, now_unix: f64) -> bool {
        self.refill(now_unix);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Update the bucket's capacity and refill rate to a new per-minute
    /// target, preserving the current token count (clamped if `capacity`
    /// shrinks).
    pub fn retune(&mut self, per_min: u32, now_unix: f64) {
        self.refill(now_unix);
        self.capacity = per_min as f64;
        self.refill_per_sec = self.capacity / 60.0;
        self.tokens = self.tokens.min(self.capacity);
    }
}

/// Thread-safe, per-node rate limiter.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<NodeId, TokenBucket>>>,
    default_per_min: u32,
}

impl RateLimiter {
    /// Construct a limiter with the given default per-minute budget.
    /// `default_per_min == 0` is clamped to [`DEFAULT_RATE_PER_MIN`].
    pub fn new(default_per_min: u32) -> Self {
        let default = if default_per_min == 0 {
            DEFAULT_RATE_PER_MIN
        } else {
            default_per_min
        };
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            default_per_min: default,
        }
    }

    /// Default per-minute budget for new nodes.
    pub fn default_per_min(&self) -> u32 {
        self.default_per_min
    }

    /// Number of tracked nodes (snapshot).
    pub fn tracked_nodes(&self) -> usize {
        self.inner.lock().expect("rate limiter poisoned").len()
    }

    /// Try to consume one token for `node_id` at `now_unix`. The bucket is
    /// lazily initialized on first call.
    pub fn try_consume(&self, node_id: &NodeId, now_unix: f64) -> bool {
        let mut guard = self.inner.lock().expect("rate limiter poisoned");
        let bucket = guard
            .entry(node_id.clone())
            .or_insert_with(|| TokenBucket::full(self.default_per_min, now_unix));
        bucket.try_consume(now_unix)
    }

    /// Override the per-minute budget for a single node.
    pub fn set_limit(&self, node_id: &NodeId, per_min: u32, now_unix: f64) {
        let mut guard = self.inner.lock().expect("rate limiter poisoned");
        let bucket = guard
            .entry(node_id.clone())
            .or_insert_with(|| TokenBucket::full(self.default_per_min, now_unix));
        bucket.retune(per_min, now_unix);
    }

    /// Read-only snapshot of a node's bucket (returns `None` if untracked).
    pub fn snapshot(&self, node_id: &NodeId) -> Option<TokenBucket> {
        self.inner
            .lock()
            .expect("rate limiter poisoned")
            .get(node_id)
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_signing_key;

    fn node_a() -> NodeId {
        NodeId::from_verifying_key(&generate_signing_key().verifying_key())
    }

    fn node_b() -> NodeId {
        NodeId::from_verifying_key(&generate_signing_key().verifying_key())
    }

    #[test]
    fn allows_burst_up_to_capacity_then_denies() {
        let limiter = RateLimiter::new(5); // 5 req/min -> 1 token / 12s
        let node = node_a();

        // 5 immediate attempts succeed (full bucket).
        for _ in 0..5 {
            assert!(limiter.try_consume(&node, 1_000.0));
        }
        // 6th is denied.
        assert!(!limiter.try_consume(&node, 1_000.0));
    }

    #[test]
    fn refills_proportional_to_elapsed_time() {
        let limiter = RateLimiter::new(60); // 1 token per second
        let node = node_a();

        // Drain the bucket.
        for _ in 0..60 {
            assert!(limiter.try_consume(&node, 1_000.0));
        }
        assert!(!limiter.try_consume(&node, 1_000.0));

        // Half a second elapsed: ~0.5 tokens accumulated, still not enough.
        assert!(!limiter.try_consume(&node, 1_000.5));

        // One full second elapsed: 1 token available.
        assert!(limiter.try_consume(&node, 1_001.0));
        assert!(!limiter.try_consume(&node, 1_001.0));
    }

    #[test]
    fn per_node_override_retunes_capacity() {
        let limiter = RateLimiter::new(2);
        let node = node_a();

        // Drain at the default (capacity 2).
        assert!(limiter.try_consume(&node, 1_000.0));
        assert!(limiter.try_consume(&node, 1_000.0));
        assert!(!limiter.try_consume(&node, 1_000.0));

        // Retune to a much larger budget and jump forward enough seconds
        // for the new bucket to fully refill to its new capacity.
        limiter.set_limit(&node, 10, 1_001.0);
        let snap = limiter.snapshot(&node).expect("tracked");
        assert_eq!(snap.capacity, 10.0);
        assert!(snap.refill_per_sec > 0.0);

        // 10/min = 1 token per 6s. 60s of elapsed time fully refills the bucket.
        assert!(limiter.try_consume(&node, 1_001.0 + 60.0));
        assert!(limiter.try_consume(&node, 1_001.0 + 60.0));
    }

    #[test]
    fn buckets_are_isolated_per_node() {
        let limiter = RateLimiter::new(2);
        let a = node_a();
        let b = node_b();

        assert!(limiter.try_consume(&a, 1_000.0));
        assert!(limiter.try_consume(&a, 1_000.0));
        assert!(!limiter.try_consume(&a, 1_000.0));

        // `b` still has a full bucket.
        assert!(limiter.try_consume(&b, 1_000.0));
        assert!(limiter.try_consume(&b, 1_000.0));
        assert!(!limiter.try_consume(&b, 1_000.0));

        assert_eq!(limiter.tracked_nodes(), 2);
    }

    #[test]
    fn zero_default_clamps_to_fallback() {
        let limiter = RateLimiter::new(0);
        assert_eq!(limiter.default_per_min(), DEFAULT_RATE_PER_MIN);
    }
}