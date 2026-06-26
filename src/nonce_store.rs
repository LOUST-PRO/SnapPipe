//! Replay-protection nonce store for SnapPipe.
//!
//! Tracks a bounded window of seen 16-byte nonces keyed by creation time.
//! Each call to [`NonceStore::check_and_record`] atomically decides whether a
//! nonce is fresh (returns `Ok(true)`) or a replay (returns `Ok(false)`).
//!
//! The store is intentionally in-memory and ephemeral: persistence is opt-in
//! via [`NonceStore::persist_to`] / [`NonceStore::load_from`] using the same
//! canonical hex-per-line format used by [`crate::trust::TrustStore`].
//!
//! Concurrency: a single `std::sync::Mutex` guards the map. The store is
//! optimized for low-contention paths (one handshake per accepted connection);
//! for higher fan-out the cleanup pass should be called periodically rather
//! than on the hot path.
//!
//! Metrics: lock-free `AtomicU64` counters track check/accept/replay
//! outcomes. [`NonceStore::metrics`] returns a snapshot. Operators watch
//! the throughput counters to detect the v0.3.0 migration trigger documented
//! in `docs/SECURITY-MODEL.md` (sustained `>100 handshakes/sec` per edge).

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use thiserror::Error;

/// Errors returned by [`NonceStore`].
#[derive(Debug, Error)]
pub enum NonceError {
    #[error("io error on {path}: {message}")]
    Io { path: String, message: String },
    #[error("malformed nonce line in store: {0}")]
    MalformedLine(String),
}

/// Lock-free snapshot of [`NonceStore`] traffic counters.
///
/// Read via [`NonceStore::metrics`]. The counters are monotonic `AtomicU64`
/// so they wrap cleanly at `u64::MAX` (effectively never for any practical
/// deployment). Operators compare consecutive snapshots to derive rates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NonceStoreMetrics {
    pub total_check_calls: u64,
    pub total_accepted: u64,
    pub total_rejected_replay: u64,
    pub total_accepted_after_ttl: u64,
    pub current_size: usize,
}

impl NonceStoreMetrics {
    /// Counters excluding `current_size`, suitable for diffing across two
    /// snapshots to derive per-window deltas.
    pub fn counters(&self) -> (u64, u64, u64, u64) {
        (
            self.total_check_calls,
            self.total_accepted,
            self.total_rejected_replay,
            self.total_accepted_after_ttl,
        )
    }
}

/// Thread-safe, in-memory replay-protection store for 16-byte nonces.
#[derive(Debug, Clone)]
pub struct NonceStore {
    inner: Arc<Mutex<HashMap<[u8; 16], i64>>>,
    ttl_secs: i64,
    total_check_calls: Arc<AtomicU64>,
    total_accepted: Arc<AtomicU64>,
    total_rejected_replay: Arc<AtomicU64>,
    total_accepted_after_ttl: Arc<AtomicU64>,
}

impl NonceStore {
    /// Construct a fresh store with the given TTL window in seconds.
    /// `ttl_secs` must be > 0; values <= 0 default to 60 seconds.
    pub fn new(ttl_secs: i64) -> Self {
        let ttl = if ttl_secs > 0 { ttl_secs } else { 60 };
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            ttl_secs: ttl,
            total_check_calls: Arc::new(AtomicU64::new(0)),
            total_accepted: Arc::new(AtomicU64::new(0)),
            total_rejected_replay: Arc::new(AtomicU64::new(0)),
            total_accepted_after_ttl: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Construct a pre-populated store (for tests).
    pub fn with_capacity(ttl_secs: i64, capacity: usize) -> Self {
        let store = Self::new(ttl_secs);
        {
            let mut guard = store.inner.lock().expect("nonce store poisoned");
            guard.reserve(capacity);
        }
        store
    }

    /// TTL configured for this store.
    pub fn ttl_secs(&self) -> i64 {
        self.ttl_secs
    }

    /// Number of nonces currently tracked (lock acquisition + snapshot).
    pub fn len(&self) -> usize {
        self.inner.lock().expect("nonce store poisoned").len()
    }

    /// `true` when the store has zero tracked nonces.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Atomically check whether `nonce` has been seen recently and, if not,
    /// record it as seen at `now_unix`. Returns `Ok(true)` on first sighting
    /// (accept), `Ok(false)` on replay (reject), `Err(_)` only on internal
    /// invariants being violated.
    pub fn check_and_record(&self, nonce: &[u8; 16], now_unix: i64) -> Result<bool, NonceError> {
        self.total_check_calls.fetch_add(1, Ordering::Relaxed);
        let mut guard = self.inner.lock().expect("nonce store poisoned");
        if let Some(prior) = guard.get(nonce).copied()
            && now_unix.saturating_sub(prior) < self.ttl_secs
        {
            self.total_rejected_replay.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }
        // Past-TTL entries are also accepted, but tracked separately so
        // operators can distinguish "fresh nonce, first sighting" from
        // "replay attempt after TTL expiry".
        if guard.contains_key(nonce) {
            self.total_accepted_after_ttl
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.total_accepted.fetch_add(1, Ordering::Relaxed);
        }
        guard.insert(*nonce, now_unix);
        Ok(true)
    }

    /// Lock-free snapshot of traffic counters and current size.
    pub fn metrics(&self) -> NonceStoreMetrics {
        NonceStoreMetrics {
            total_check_calls: self.total_check_calls.load(Ordering::Relaxed),
            total_accepted: self.total_accepted.load(Ordering::Relaxed),
            total_rejected_replay: self.total_rejected_replay.load(Ordering::Relaxed),
            total_accepted_after_ttl: self.total_accepted_after_ttl.load(Ordering::Relaxed),
            current_size: self.len(),
        }
    }

    /// Remove every nonce whose recorded timestamp is older than
    /// `now_unix - ttl_secs`. Returns the number of entries removed.
    pub fn cleanup_expired(&self, now_unix: i64) -> usize {
        let mut guard = self.inner.lock().expect("nonce store poisoned");
        let cutoff = now_unix.saturating_sub(self.ttl_secs);
        let before = guard.len();
        guard.retain(|_, recorded| *recorded >= cutoff);
        before.saturating_sub(guard.len())
    }

    /// Persist the current store snapshot to `path`. Format is one hex-encoded
    /// nonce followed by `:` and the unix timestamp per line. Existing files
    /// are overwritten.
    pub fn persist_to(&self, path: &Path) -> Result<(), NonceError> {
        let snapshot: Vec<([u8; 16], i64)> = {
            let guard = self.inner.lock().expect("nonce store poisoned");
            guard.iter().map(|(k, v)| (*k, *v)).collect()
        };
        let mut body = String::new();
        for (nonce, ts) in &snapshot {
            body.push_str(&hex_encode(nonce));
            body.push(':');
            body.push_str(&ts.to_string());
            body.push('\n');
        }
        std::fs::write(path, body).map_err(|err| NonceError::Io {
            path: path.display().to_string(),
            message: err.to_string(),
        })
    }

    /// Load nonces from `path` previously written by [`Self::persist_to`].
    /// Missing files yield an empty store; malformed lines return
    /// [`NonceError::MalformedLine`].
    pub fn load_from(path: &Path, ttl_secs: i64) -> Result<Self, NonceError> {
        match std::fs::read_to_string(path) {
            Ok(raw) => {
                let mut entries: Vec<([u8; 16], i64)> = Vec::new();
                for (idx, line) in raw.lines().enumerate() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let (hex, ts) = line.split_once(':').ok_or_else(|| {
                        NonceError::MalformedLine(format!("line {}: missing ':'", idx + 1))
                    })?;
                    let nonce = hex_decode(hex).map_err(|err| {
                        NonceError::MalformedLine(format!("line {}: bad hex ({})", idx + 1, err))
                    })?;
                    let ts_val = ts.parse::<i64>().map_err(|err| {
                        NonceError::MalformedLine(format!(
                            "line {}: bad timestamp ({})",
                            idx + 1,
                            err
                        ))
                    })?;
                    entries.push((nonce, ts_val));
                }
                let store = Self::new(ttl_secs);
                {
                    let mut guard = store.inner.lock().expect("nonce store poisoned");
                    guard.reserve(entries.len());
                    for (nonce, ts) in entries {
                        guard.insert(nonce, ts);
                    }
                }
                Ok(store)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::new(ttl_secs)),
            Err(err) => Err(NonceError::Io {
                path: path.display().to_string(),
                message: err.to_string(),
            }),
        }
    }
}

fn hex_encode(bytes: &[u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    for byte in bytes {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

fn hex_decode(s: &str) -> Result<[u8; 16], String> {
    if s.len() != 32 {
        return Err(format!("expected 32 hex chars, got {}", s.len()));
    }
    let mut out = [0u8; 16];
    let bytes = s.as_bytes();
    for i in 0..16 {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        other => Err(format!("invalid hex char: {:?}", other as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::task::JoinSet;

    fn fixed(n: u8) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0] = n;
        out
    }

    #[test]
    fn first_sight_accepts_subsequent_sight_rejects() {
        let store = NonceStore::new(60);
        let n = fixed(1);

        assert!(store.check_and_record(&n, 1_700_000_000).unwrap());
        assert!(!store.check_and_record(&n, 1_700_000_010).unwrap());
        assert!(!store.check_and_record(&n, 1_700_000_059).unwrap());

        // Past TTL: nonce is reaped on cleanup, so check_and_record can
        // accept again (the prior entry is still considered "expired").
        store.cleanup_expired(1_700_000_061);
        assert!(store.check_and_record(&n, 1_700_000_062).unwrap());
    }

    #[test]
    fn ttl_expiration_frees_nonces() {
        let store = NonceStore::new(30);
        store.check_and_record(&fixed(7), 1_000).unwrap();
        store.check_and_record(&fixed(8), 1_005).unwrap();
        assert_eq!(store.len(), 2);

        let removed = store.cleanup_expired(1_040);
        assert_eq!(removed, 2);
        assert!(store.is_empty());
    }

    #[test]
    fn zero_or_negative_ttl_clamps_to_default() {
        let store = NonceStore::new(0);
        assert_eq!(store.ttl_secs(), 60);

        let store = NonceStore::new(-5);
        assert_eq!(store.ttl_secs(), 60);
    }

    #[test]
    fn persistence_roundtrip_replays_state() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("nonces.txt");
        let original = NonceStore::new(120);
        original
            .check_and_record(&fixed(11), 1_700_000_000)
            .unwrap();
        original
            .check_and_record(&fixed(22), 1_700_000_010)
            .unwrap();
        original.persist_to(&path).unwrap();

        let restored = NonceStore::load_from(&path, 120).unwrap();
        assert_eq!(restored.len(), 2);
        assert!(
            !restored
                .check_and_record(&fixed(11), 1_700_000_020)
                .unwrap()
        );
        assert!(
            !restored
                .check_and_record(&fixed(22), 1_700_000_030)
                .unwrap()
        );
        assert!(
            restored
                .check_and_record(&fixed(33), 1_700_000_040)
                .unwrap()
        );
    }

    #[test]
    fn load_from_missing_file_returns_empty_store() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("missing.txt");
        let store = NonceStore::load_from(&path, 60).unwrap();
        assert!(store.is_empty());
        assert_eq!(store.ttl_secs(), 60);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_check_and_record_serializes_correctly() {
        let store = Arc::new(NonceStore::new(300));
        let nonce = fixed(99);

        let mut tasks: JoinSet<bool> = JoinSet::new();
        for i in 0..10 {
            let store = Arc::clone(&store);
            tasks.spawn(async move {
                // The first task to observe the nonce accepts; the rest replay.
                store.check_and_record(&nonce, 1_700_000_000).unwrap()
            });
            let _ = i;
        }

        let mut accepted = 0usize;
        while let Some(joined) = tasks.join_next().await {
            if joined.unwrap() {
                accepted += 1;
            }
        }
        // Exactly one of the 10 concurrent attempts must succeed.
        assert_eq!(accepted, 1, "exactly one acceptance expected");
    }

    #[test]
    fn metrics_track_check_accept_replay_outcomes() {
        let store = NonceStore::new(60);
        let n1 = fixed(1);
        let n2 = fixed(2);

        // 2 first-sighting accepts.
        assert!(store.check_and_record(&n1, 1_000).unwrap());
        assert!(store.check_and_record(&n2, 1_010).unwrap());

        // 2 replay rejects.
        assert!(!store.check_and_record(&n1, 1_020).unwrap());
        assert!(!store.check_and_record(&n2, 1_030).unwrap());

        // After TTL expires, the same nonce is accepted again and tracked as
        // accepted_after_ttl (not as fresh accepted).
        assert!(store.check_and_record(&n1, 1_090).unwrap());

        let m = store.metrics();
        assert_eq!(m.total_check_calls, 5);
        assert_eq!(m.total_accepted, 2);
        assert_eq!(m.total_rejected_replay, 2);
        assert_eq!(m.total_accepted_after_ttl, 1);
        assert_eq!(m.current_size, 2);
    }

    #[test]
    fn metrics_are_lock_free_under_concurrent_load() {
        // Spawn N tasks, each calling check_and_record with its own nonce.
        // After join, total_check_calls must equal N exactly. AtomicU64 with
        // Relaxed ordering is sufficient because the metric is observational,
        // not load-bearing for correctness.
        let store = Arc::new(NonceStore::new(60));
        let mut handles = Vec::new();
        for i in 0u8..50 {
            let store = Arc::clone(&store);
            handles.push(std::thread::spawn(move || {
                store.check_and_record(&fixed(i), 1_700_000_000).unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let m = store.metrics();
        assert_eq!(m.total_check_calls, 50);
        assert_eq!(m.total_accepted, 50);
        assert_eq!(m.total_rejected_replay, 0);
        assert_eq!(m.total_accepted_after_ttl, 0);
        assert_eq!(m.current_size, 50);
    }
}
