# SnapPipe Security Model

This document describes the threat model, current hardening posture, and
known technical debt for the `snappipe` crate. It is meant for operators
auditing the transport layer before deploying SnapPipe in production.

## Trust boundaries

- **Issuer trust**: Ed25519 `VerifyingKey` registered in the
  [`TrustStore`](src/trust.rs). Trust is added by operator action, persisted
  to `~/.config/snappipe/trust.toml`. An empty store is NOT a default-allow
  state — handshake fails for unknown issuers.
- **Ticket gating**: A server endpoint accepts a QUIC stream only after the
  client presents a `SignedTicket` whose `issuer` matches a trusted NodeId
  and whose signature verifies against the issuer's `VerifyingKey`.
- **Replay protection**: A 16-byte nonce with TTL=60s is recorded on first
  sighting; replays inside the window are rejected by
  [`NonceStore::check_and_record`](src/nonce_store.rs).
- **Rate limiting**: Token-bucket per NodeId in
  [`RateLimiter`](src/rate_limit.rs). Default 100 req/min; per-node override
  via trust entry. `set_limit(0)` is clamped to the default to prevent
  accidental disable.

## Hardening posture (2026-06-25)

| Concern | Status | Notes |
|---|---|---|
| TrustStore load fails closed | ✅ | `load_or_default` returns `Result`, I/O errors propagate |
| Sync mtime precision | ✅ | `Mtime { secs, nanos }`, subsecond diffs preserved |
| Sync walkdir errors | ✅ | Permission/IO errors propagate, not silently dropped |
| RateLimit `set_limit(0)` clamp | ✅ | Zero clamped to `DEFAULT_RATE_PER_MIN` |
| ALPN source-of-truth | ✅ | Both client and server derive from `DEFAULT_ALPN` constant |
| CI actions SHA pinned | ✅ | `actions/checkout@v4.2.2`, `actions/cache@v4.2.1`, `dtolnay/rust-toolchain@stable` |
| CI `persist-credentials: false` | ✅ | Leaked runner cannot pivot via post-action token file |
| CI `concurrency.cancel-in-progress` | ✅ | Stale PR runs don't burn runner minutes |
| CI explicit `permissions: contents: read` | ✅ | Default GITHUB_TOKEN privileges minimized |
| CI `cargo test --locked` | ✅ | Cargo.lock is the source of truth; no floating deps |

## Known technical debt

### Mutex contention on hot path (deferred to v0.3.0)

**Files**: `src/nonce_store.rs`, `src/rate_limit.rs`,
`src/sync.rs` (`walk_dir_with` parallel phase).

**Current state**: `std::sync::Mutex<HashMap<_, _>>` guards the state in
`NonceStore` and `RateLimiter`. Each handshake acquires the lock briefly
(no `.await` is held across the critical section), and the post-handshake
work runs without the lock.

**Why this is acceptable today**: At the target scale (laptop ↔ VPS, 1-2
handshakes/sec peak; relay backhaul ≤ 50 concurrent connections), the
contention window is measured in microseconds and the throughput is far
below the Mutex contention knee.

**Migration trigger for v0.3.0**: When the relay observes sustained
`>100 handshakes/sec` from a single edge OR when profiling identifies the
`HashMap` lookup as a hot spot, migrate to:

- `dashmap::DashMap<NodeId, TokenBucket>` for `RateLimiter`
- A sharded nonce store (16 shards keyed by `nonce[0]`) for `NonceStore`
- A bounded `parking_lot::Mutex` (no poison handling, faster uncontended
  path) if profiling shows `std::sync::Mutex::lock()` itself is hot.

**Why documented, not fixed now**: dashmap adds ~300 KB to the binary and
~250 LOC of refactor across `nonce_store.rs`, `rate_limit.rs`, and their
test modules. That refactor is justified when a real workload demands it;
optimizing speculatively violates "evidence-first" hardening.

### Self-signed dev cert in production paths

The `self_signed_dev_cert` helper exists for tests and CI. Production
deployments MUST replace it with a real cert chain loaded from disk or a
secret manager. There is no operator-visible flag to disable the helper —
the integration tests guard against accidentally shipping the dev path, but
the runtime invariant is "operator discipline + code review".

## Reporting a vulnerability

Email `opensource@loust.pro` with the subject `SnapPipe security`. PGP key
fingerprint is published at https://loust.pro/pgp. Expect a 48-hour
acknowledgment SLA; coordinated disclosure is preferred.