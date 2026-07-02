# Release notes — v0.2.1

> **Tag**: [`v0.2.1`](https://github.com/LOUST-PRO/SnapPipe/releases/tag/v0.2.1)
> **Manifest**: [Cargo.toml @ v0.2.1](https://github.com/LOUST-PRO/SnapPipe/blob/v0.2.1/Cargo.toml)
> **Released**: 2026-06-25

## What changed

This is a hardening release — no breaking changes to the public API. The
eight PRs that make up v0.2.1 bring the crate from "the first serious
layer" (the `v0.1.0` README framing) to "audit-ready infrastructure
primitive".

### Highlights

**Identity hardening.** `TrustStore::load_or_default` now propagates
I/O errors instead of silently returning an empty store. An empty store
is **not** a default-allow state — handshake fails for unknown issuers.
Pre-v0.2.1, a corrupted `~/.config/snappipe/trust.toml` would have
silently allowed every issuer. This was the highest-priority finding in
the audit that triggered this batch.

**Sub-second mtime.** `Mtime { secs, nanos }` replaces the
second-precision `mtime_unix`. The bare-metal hardening synchronizer
(which uses `scp -p` to preserve mtime for `lzt-hub sync`) can now
distinguish two writes that fall inside the same wall-clock second. The
regression guard is the integration test
`mtime_distinguishes_two_writes_within_same_second`.

**Lock-free v0.3.0 trigger metrics.** `NonceStore::metrics()` and
`RateLimiter::metrics()` expose monotonic counters via `AtomicU64` with
`Ordering::Relaxed`. Operators diff consecutive snapshots at a known
interval (e.g. 1 second) to derive throughput. The v0.3.0 migration
trigger is `>100 try_consume_calls / sec` per edge — see
[`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md) for the rationale and
the targeted `dashmap` / `parking_lot::Mutex` migration plan.

**Lazy-seed bug fix in `RateLimiter::set_limit`.** When a per-node bucket
is created lazily inside `set_limit` (i.e. before any `try_consume` call
has happened for that node), it was being seeded at
`self.default_per_min` and then immediately retuned. A node whose
override `per_min > default_per_min` therefore received only
`default_per_min` initial tokens, not `per_min`. Fix: seed new buckets at
the effective `per_min` instead of the limiter default. Existing buckets
are retuned in place so the in-flight token count is preserved. The bug
was latent since `v0.1.0` and was uncovered by the new
`tests/integration_trust_sync.rs` end-to-end round-trip.

**CI hardening.** GitHub Actions SHAs pinned to specific commit SHAs
(not mutable `v4.x.y` tags). `persist-credentials: false` so a leaked
runner cannot pivot via the post-action token file.
`concurrency.cancel-in-progress` so stale PR runs do not burn runner
minutes. Explicit `permissions: contents: read` minimizes default
GITHUB_TOKEN privileges. `cargo test --locked` ensures `Cargo.lock` is
the source of truth — no floating dependencies.

**Disclosure channel.** `SECURITY.md` documents the disclosure process
(`opensource@loust.pro`, 48-hour acknowledgment SLA, 90-day coordinated
disclosure preferred).

### Deferred to v0.3.0

The Mutex contention migration to `dashmap` / `parking_lot::Mutex` is
explicitly deferred until the in-code metrics show sustained
`>100 handshakes/sec` per edge. The migration plan is in
[`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md) under "Mutex contention
on hot path (deferred to v0.3.0)".

### Acknowledgements

The hardening batch was triggered by an SRE peer audit of the v0.2.0
transport layer. The audit report covered 4 concerns + 3 immediate
actions; one claim was audited and rejected as already-covered, one was
deferred to v0.3.0 with the documented trigger, and one latent bug was
uncovered by the integration test written in response to the audit.