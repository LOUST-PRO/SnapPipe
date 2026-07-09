# Operational Deployment

> **Audience**: operators deploying SnapPipe in production. Assumes familiarity
> with QUIC, TLS certificates, and UNIX networking. This is a technical
> reference, not a tutorial.

## What SnapPipe is

SnapPipe is an **identity-based QUIC transport library** — a crate you
depend on from `Cargo.toml`, not a daemon you install. It provides:

- **Signed ticket handshake** — peers exchange Ed25519-signed tickets
  instead of shared secrets or pre-shared keys.
- **Replay protection** — a 16-byte nonce store rejects duplicate tickets
  within a configurable TTL window (default 60 s).
- **Per-peer rate limiting** — configurable requests-per-minute per NodeId.
- **Relay scaffolding** — a `ByteStream` trait and `Relay::handle_connection`
  let you embed the relay in any Tokio async context.

SnapPipe does **not** provide: connectivity (how packets reach the peer),
certificate management (use `rcgen` or your PKI), or persistence (all state
is in-memory by default).

## Deployment topologies

### 1 — Client ↔ Server (direct)

The simplest pattern. A server exposes a QUIC endpoint; clients connect
directly. Suitable when both ends have routable addresses or are on the
same private network.

```
[ client ] --QUIC--> [ server ]
                     ├── TrustStore (client NodeId)
                     └── NonceStore (replay protection)
```

### 2 — Self-hosted relay (bounce)

For NAT traversal or when peers cannot reach each other directly. The
relay runs on a VPS or any always-on host. Peers connect to the relay
instead of to each other.

```
[ peer-A ] --QUIC--> [ relay ] <--QUIC-- [ peer-B ]
                          ├── TrustStore (both NodeIds)
                          ├── NonceStore (replay protection)
                          └── RateLimiter (per-node quotas)
```

### 3 — Mesh (multi-node)

For team infrastructure. Each node runs a relay; trust stores are shared
out-of-band (ssh key distribution, Vault, etc.).

## Running the relay

The relay is embedded in your Tokio application. Minimal example:

```rust
use snappipe::relay::{run_listener, Relay, RelayConfig};
use snappipe::trust::TrustStore;
use snappipe::rate_limit::RateLimiter;
use snappipe::quic::{build_server_endpoint, QuicEndpointConfig};
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let trust = Arc::new(TrustStore::new());
    // trust.add(node_id, "display-name", 100); // req/min override

    let limiter = Arc::new(RateLimiter::new(100)); // default 100 req/min

    let relay = Arc::new(Relay::new(RelayConfig::new(
        "0.0.0.0:0".parse()?,
        trust,
        limiter,
    )));

    let endpoint = build_server_endpoint(&QuicEndpointConfig::server(
        "0.0.0.0:7777".parse()?,
    ))?;

    let cancel = Arc::new(Mutex::new(false));
    let stats = run_listener(endpoint, relay, cancel).await?;
    println!("relay stats: {:?}", stats.counts);
    Ok(())
}
```

The relay listener uses **stream 0** for the SnapPipe ticket handshake.
Application data flows on streams 1 … N. This matches how the QUIC multi-stream
model works: stream 0 is reserved for the handshake, subsequent streams are
bidi or uni and carry your payload.

## Configuration reference

### TrustStore (`trust/`)

Plain-text file, one line per trusted NodeId:

```
# node_id display_name rate_limit_override
7f4e... MyLaptop 150
3a2b... BackupServer 50
```

- Lines starting with `#` are comments.
- `rate_limit_override` is optional; omit for the daemon default (100 req/min).
- Empty store = **deny-all** (secure default).

### RateLimiter

Token-bucket with per-node overrides from the trust store. The global
default is set at construction. Zero-override is clamped to the default
(not disabled).

### NonceStore

In-memory LRU-style dedup. TTL is fixed at 60 seconds. Size limit is
fixed at 65 536 entries. Both are compile-time constants in the crate.

## Certificate setup

For development, `self_signed_dev_cert()` generates a localhost cert.
**Do not use dev certificates in production.** Instead:

1. Obtain a real certificate (Let's Encrypt, your CA, etc.)
2. Load the certificate chain and private key into a `rustls::ServerConfig`
3. Pass it to `quinn::ServerConfig::with_cert_chain()`

See `src/quic/endpoint.rs` for the dev helper.

## Observability

`RelayStats` exposes:

| Field | Meaning |
|---|---|
| `counts["closed"]` | Connections that ended cleanly |
| `counts["rate_limited"]` | Connections cut by rate limiter |
| `counts["trust_rejected"]` | Connections rejected by trust store |
| `counts["error"]` | Connections that errored mid-stream |

`NonceStore::metrics()` and `RateLimiter::metrics()` expose lock-free
counters for the hot path. Call `metrics()` from your admin HTTP server or
tracing span on an interval.

## Limitations

- **In-memory state** — `NonceStore` and `RateLimiter` do not persist.
  Multi-replica deployments need a shared Redis or similar.
- **Single-process** — the relay is a library, not a daemon. Embed it in
  your own Tokio runtime.
- **No mTLS** — identity gating is at the application layer (tickets), not
  the TLS layer. Layer mTLS on top via `rustls::ClientConfig` if required.

## See also

- [`README.md`](../README.md) — overview, CLI reference, installation.
- [`RELEASES.md`](../RELEASES.md) — changelog and version history.
- [`SECURITY.md`](../SECURITY.md) — disclosure process.
- [`docs/SECURITY-MODEL.md`](SECURITY-MODEL.md) — threat model and
  hardening posture.
