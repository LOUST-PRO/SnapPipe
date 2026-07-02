# Changelog

All notable changes to SnapPipe are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/).

## [0.2.1] - 2026-06-25

The hardening release. No breaking changes to the public API. Six
follow-up PRs applied audit-driven fixes across the trust store,
sync plane, rate limiter, QUIC transport, CI workflow, and security
disclosure process. One additional PR added lock-free observability
counters (the v0.3.0 migration trigger), and one added an integration
test that uncovered a latent lazy-seed bug in `RateLimiter::set_limit`.

### Added

- `NonceStore::metrics()` returns `NonceStoreMetrics { total_check_calls,
  total_accepted, total_rejected_replay, total_accepted_after_ttl,
  current_size }`. Lock-free `AtomicU64` counters with `Ordering::Relaxed`.
  Operators diff two consecutive snapshots to derive per-window
  throughput; the documented v0.3.0 migration trigger is
  `>100 try_consume_calls / sec` per edge.
- `RateLimiter::metrics()` returns `RateLimiterMetrics {
  total_try_consume_calls, total_allowed, total_denied,
  total_set_limit_calls, tracked_nodes }`. Same observability surface as
  `NonceStore`.
- `Mtime { secs: i64, nanos: u32 }` in the `sync` module, replacing the
  second-precision `mtime_unix: i64`. Helpers: `from_system_time`,
  `from_metadata`, `is_known`.
- `apply_mtime(path, mtime)` public helper for restoring sub-second mtime
  on the destination.
- `diff_entries(before, after) -> (Vec<added>, Vec<removed>, Vec<modified>)`
  for explicit classification of file changes.
- `default_alpn_bytes()` helper deriving from the `DEFAULT_ALPN`
  constant. Single source of truth for both client and server endpoints.
- `SECURITY.md` (project root) with disclosure channel, 48-hour SLA,
  90-day coordinated disclosure preferred.
- `docs/SECURITY-MODEL.md` — threat model, hardening posture table,
  deferred `Mutex` contention rationale with v0.3.0 trigger.

### Changed

- `TrustStore::load_or_default` returns `Result<Self, TrustStoreError>`.
  I/O errors propagate instead of silently returning an empty store. An
  empty store is **not** a default-allow state — handshake fails for
  unknown issuers. Pre-v0.2.1, a corrupted `~/.config/snappipe/trust.toml`
  would have silently allowed all issuers.
- `RateLimiter::set_limit(node_id, per_min, now)`:
  - `per_min == 0` is clamped to `DEFAULT_RATE_PER_MIN`, mirroring the
    constructor's zero-clamp.
  - Lazy-seed bug fix: when a bucket is created lazily inside `set_limit`,
    it is now seeded at the **effective `per_min`** instead of
    `self.default_per_min`, then retuned. This fixes the case where
    `set_limit(&id, 200, _)` on a fresh limiter granted only 100 initial
    tokens (the default) instead of 200.
- `Mtime` in `FileEntry` — sub-second precision preserved end-to-end.
- `walk_dir_with` phase 1 propagates walkdir errors via
  `SyncError::Walk` instead of silently dropping them via
  `.filter_map(|e| e.ok())`.

### Hardening (CI)

- `.github/workflows/ci.yml`:
  - `actions/checkout` pinned to `11bd71901bbe5b1630ceea73d27597364c9af683`
    (v4.2.2).
  - `actions/cache` pinned to `0c907a75c2c80ebcb7f088228285e798b750cf8f`
    (v4.2.1).
  - `dtolnay/rust-toolchain` pinned to `29eef336d9b2848a0b548edc03f92a220660cdb8`
    (stable HEAD).
  - Added `persist-credentials: false` so a leaked runner cannot pivot
    via the post-action token file.
  - Added `concurrency.cancel-in-progress` so stale PR runs do not burn
    runner minutes.
  - Added explicit `permissions: contents: read` to minimize default
    GITHUB_TOKEN privileges.
  - `cargo test --locked` so `Cargo.lock` is the source of truth — no
    floating dependencies.

### Tests

- 58 → 63 passing (lib + integration + quic_e2e).
- New: `tests/integration_trust_sync.rs` — end-to-end round-trip across
  `trust`, `sync`, `nonce_store`, `rate_limit` in a single workflow.
  Exposed the lazy-seed bug in `RateLimiter::set_limit`.
- New: `metrics_track_try_consume_allow_deny_outcomes`,
  `metrics_are_lock_free_under_concurrent_load`,
  `mtime_roundtrip_via_apply_mtime`,
  `mtime_distinguishes_two_writes_within_same_second`,
  `mtime_unknown_is_noop`, `walk_dir_propagates_permission_errors`,
  `client_and_server_alpn_match`.

### PRs

- #3 `hardening(trust)`: load_or_default now propagates I/O errors instead
  of failing open.
- #4 `hardening(sync)`: sub-second mtime precision + walkdir error
  propagation.
- #5 `hardening(rate-limit)`: set_limit(0) now clamps to
  `DEFAULT_RATE_PER_MIN`.
- #6 `hardening(quic)`: ALPN now derives from `DEFAULT_ALPN` — single
  source of truth.
- #7 `hardening(ci)`: SHA-pinned actions + persist-credentials false +
  concurrency + permissions.
- #8 `docs(security)`: SECURITY.md disclosure channel + SECURITY-MODEL.md
  threat model.
- #9 `feat(metrics)`: lock-free v0.3.0 trigger counters in `NonceStore`
  and `RateLimiter`.
- #10 `test(integration)`: trust + sync plane round-trip + set_limit
  lazy-seed bug fix.

## [0.1.0] - 2026-06

Initial release of the identity-based transport toolkit:

- Ed25519 identity generation + stable NodeId derivation.
- Signed session tickets with explicit issuer and subject identities.
- Offline ticket verification.
- Quinn-based QUIC transport profiles.
- Sample relay configuration scaffold.
- CLI for issuing, inspecting, and verifying tickets.

[0.2.1]: https://github.com/LOUST-PRO/SnapPipe/compare/v0.1.0...v0.2.1
[0.1.0]: https://github.com/LOUST-PRO/SnapPipe/releases/tag/v0.1.0