//! End-to-end integration test for the trust + sync plane.
//!
//! Exercises the public API across multiple modules in one workflow:
//!
//! 1. Generate signing keys for two issuers.
//! 2. Build a `TrustStore` populated with both issuers.
//! 3. Issue a `SignedTicket` for each issuer against a common subject.
//! 4. Verify each ticket against the trust store.
//! 5. Walk a temp directory, mutate a file at sub-second intervals, walk
//!    again, and verify the diff engine identifies the modification.
//! 6. Use `NonceStore` to verify replay protection (accept first, reject
//!    replay inside TTL).
//! 7. Use `RateLimiter` to verify per-issuer throttling (allow burst, deny
//!    after capacity).
//! 8. Read `NonceStore::metrics()` and `RateLimiter::metrics()` and assert
//!    counters reflect every operation above.
//!
//! No mocks. The full crate API is exercised end-to-end.

use std::fs;
use std::path::Path;

use filetime::FileTime;
use snappipe::nonce_store::NonceStore;
use snappipe::rate_limit::{DEFAULT_RATE_PER_MIN, RateLimiter, RateLimiterMetrics};
use snappipe::sync::{FileEntry, Mtime, apply_mtime, diff_entries, walk_dir};
use snappipe::trust::TrustStore;
use snappipe::{NodeId, RelayConfig, generate_signing_key, issue_ticket, verify_ticket};
use tempfile::tempdir;

fn write_file(dir: &Path, rel: &str, body: &[u8]) -> std::path::PathBuf {
    let path = dir.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&path, body).unwrap();
    path
}

#[test]
fn trust_and_sync_plane_round_trip() {
    // --- Setup: two issuers, one subject.
    let issuer_a_key = generate_signing_key();
    let issuer_b_key = generate_signing_key();
    let subject_key = generate_signing_key();

    let issuer_a_id = NodeId::from_verifying_key(&issuer_a_key.verifying_key());
    let issuer_b_id = NodeId::from_verifying_key(&issuer_b_key.verifying_key());
    let subject_id = NodeId::from_verifying_key(&subject_key.verifying_key());

    // --- TrustStore: both issuers registered with distinct rate budgets.
    let store = TrustStore::new();
    store.add(issuer_a_id.clone(), "relay-a", 50);
    store.add(issuer_b_id.clone(), "relay-b", 200);

    assert!(store.is_trusted(&issuer_a_id));
    assert!(store.is_trusted(&issuer_b_id));
    assert_eq!(store.len(), 2);
    assert_eq!(store.get(&issuer_a_id).unwrap().rate_limit_per_min, 50);
    assert_eq!(store.get(&issuer_b_id).unwrap().rate_limit_per_min, 200);

    // --- Tickets: each issuer issues a ticket for the same subject.
    let relay_url = "quic://relay.example.net:4433";
    let now = 1_700_000_000_i64;
    let ticket_a = issue_ticket(
        &issuer_a_key,
        Some(&subject_key.verifying_key()),
        relay_url,
        "/snappipe/0",
        300,
        now,
    )
    .unwrap();
    let ticket_b = issue_ticket(
        &issuer_b_key,
        Some(&subject_key.verifying_key()),
        relay_url,
        "/snappipe/0",
        300,
        now,
    )
    .unwrap();

    // --- Verify: each ticket is accepted when the trust check passes.
    assert!(
        verify_ticket(&ticket_a, &issuer_a_key.verifying_key(), now + 10).is_ok(),
        "ticket A must verify against issuer A's VK"
    );
    assert!(
        verify_ticket(&ticket_b, &issuer_b_key.verifying_key(), now + 10).is_ok(),
        "ticket B must verify against issuer B's VK"
    );
    // Cross-verification (issuer A's ticket with issuer B's VK) must fail.
    assert!(
        verify_ticket(&ticket_a, &issuer_b_key.verifying_key(), now + 10).is_err(),
        "ticket A must NOT verify against issuer B's VK"
    );

    // --- Sync plane: write, walk, mutate sub-second, walk again, diff.
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "shared.txt", b"hello");
    write_file(root, "removed.txt", b"bye");
    write_file(root, "sub/nested.txt", b"deep");

    let before: Vec<FileEntry> = walk_dir(root).unwrap();
    assert_eq!(before.len(), 3);

    // Mutate shared.txt within the same wall-clock second to exercise the
    // sub-second mtime preservation added in v0.2.1.
    let shared = root.join("shared.txt");
    let bumped = FileTime::from_unix_time(
        before
            .iter()
            .find(|e| e.path == "shared.txt")
            .unwrap()
            .mtime
            .secs,
        999_999_999,
    );
    filetime::set_file_mtime(&shared, bumped).unwrap();

    // Add a new file; remove another.
    write_file(root, "added.txt", b"new");
    fs::remove_file(root.join("removed.txt")).unwrap();

    let after: Vec<FileEntry> = walk_dir(root).unwrap();
    assert_eq!(after.len(), 3);

    let (added, removed, modified) = diff_entries(&before, &after);
    assert_eq!(added.len(), 1);
    assert_eq!(added[0].path, "added.txt");
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].path, "removed.txt");
    assert_eq!(modified.len(), 1);
    assert_eq!(modified[0].0.path, "shared.txt");
    // Sub-second diff must register as a modification, not a no-op.
    assert_eq!(modified[0].1.mtime.nanos, 999_999_999);

    // apply_mtime round-trip: write a known mtime, walk, restore, walk.
    let target = write_file(root, "rt.txt", b"x");
    let mtime = Mtime {
        secs: 1_700_000_000,
        nanos: 123_456_789,
    };
    apply_mtime(&target, mtime).unwrap();
    let entries = walk_dir(root).unwrap();
    let captured = entries.iter().find(|e| e.path == "rt.txt").unwrap().mtime;
    assert_eq!(captured, mtime);

    // --- NonceStore: accept first, reject replay, accept-after-TTL.
    let nonces = NonceStore::new(60);
    let n: [u8; 16] = [7; 16];
    assert!(nonces.check_and_record(&n, 1_000).unwrap());
    assert!(!nonces.check_and_record(&n, 1_020).unwrap()); // inside TTL
    assert!(nonces.check_and_record(&n, 1_090).unwrap()); // past TTL

    let nm = nonces.metrics();
    assert_eq!(nm.total_check_calls, 3);
    assert_eq!(nm.total_accepted, 1);
    assert_eq!(nm.total_rejected_replay, 1);
    assert_eq!(nm.total_accepted_after_ttl, 1);

    // --- RateLimiter: per-issuer budget from trust store, mirrors it.
    let limiter = RateLimiter::new(DEFAULT_RATE_PER_MIN);
    limiter.set_limit(
        &issuer_a_id,
        store.get(&issuer_a_id).unwrap().rate_limit_per_min,
        1_000.0,
    );
    limiter.set_limit(
        &issuer_b_id,
        store.get(&issuer_b_id).unwrap().rate_limit_per_min,
        1_000.0,
    );

    // Drain issuer A's bucket (capacity 50). 50 must pass, 51st must fail.
    let mut allowed_a = 0;
    for _ in 0..60 {
        if limiter.try_consume(&issuer_a_id, 1_000.0) {
            allowed_a += 1;
        }
    }
    assert_eq!(allowed_a, 50, "issuer A must hit its 50-req ceiling");

    // Issuer B has capacity 200; first 200 must pass.
    let mut allowed_b = 0;
    for _ in 0..250 {
        if limiter.try_consume(&issuer_b_id, 1_000.0) {
            allowed_b += 1;
        }
    }
    assert_eq!(allowed_b, 200, "issuer B must hit its 200-req ceiling");

    let rm: RateLimiterMetrics = limiter.metrics();
    assert_eq!(rm.total_try_consume_calls, 60 + 250);
    assert_eq!(rm.total_allowed, 50 + 200);
    assert_eq!(rm.total_denied, 10 + 50);
    assert_eq!(rm.total_set_limit_calls, 2);
    assert_eq!(rm.tracked_nodes, 2);

    // --- End-to-end invariant: trust check + ticket verification +
    //     sync plane + nonce/rate-limit observability all agree on the
    //     identities. No silent failures.
    assert_eq!(ticket_a.claims.issuer, issuer_a_id);
    assert_eq!(ticket_b.claims.issuer, issuer_b_id);
    assert_eq!(ticket_a.claims.subject, subject_id);
    assert_eq!(ticket_b.claims.subject, subject_id);
    assert_eq!(ticket_a.claims.relay_url, relay_url);
    let sample = RelayConfig::sample();
    assert!(!sample.node_name.is_empty());
    assert!(!sample.default_alpn.is_empty());
}
