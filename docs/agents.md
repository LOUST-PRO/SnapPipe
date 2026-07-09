# Agents — SnapPipe

> Internal guide for Claude Code agents working in this repo.
> **Public content goes in `OPERATIONAL-DEPLOYMENT.md`.**
> This file is gitignored — contains private operational context.

## Project type

**Public OSS library** (Apache-2.0). All content in this repo is public once
merged to `main`. Do not commit credentials, internal hostnames, private IP
addresses, or operator-specific infrastructure details.

## Architecture

```
snappipe/
├── src/
│   ├── lib.rs          # Core types: NodeId, TicketClaims, SignedTicket, issue_ticket, verify_ticket
│   ├── main.rs         # CLI: keygen, ticket {issue,inspect,verify}, relay sample-config
│   ├── relay.rs        # (moved to relay/mod.rs) — ByteStream trait, Relay, MemoryStream
│   ├── relay/
│   │   ├── mod.rs      # Relay core + ByteStream + MemoryStream
│   │   └── listener.rs # run_listener — production QUIC accept loop
│   ├── quic/
│   │   ├── mod.rs      # QuicTransportProfile, QuicProfileError
│   │   └── endpoint.rs  # build_server_endpoint, build_client_endpoint, self_signed_dev_cert
│   ├── trust.rs        # TrustStore — plain-text NodeId allowlist
│   ├── rate_limit.rs   # RateLimiter — token bucket per NodeId
│   ├── session.rs      # server_handshake, ClientNode, HandshakeSummary
│   └── nonce_store.rs # NonceStore — in-memory replay protection
├── tests/              # Integration tests (quic_e2e.rs, relay_listener_e2e.rs)
├── examples/           # Usage examples
└── docs/
    ├── OPERATIONAL-DEPLOYMENT.md  # PUBLIC — generic deployment guide
    ├── SECURITY-MODEL.md         # PUBLIC — threat model
    ├── agents.md                 # THIS FILE — gitignored
    └── .gitignore               # Ignores agents.md
```

## Contribution rules

1. **One concern per PR** — no mixed fix+refactor+docs in the same PR.
2. **Validation before commit** — all four must pass:
   ```bash
   cargo test --locked
   cargo clippy --locked --all-targets -- -D warnings
   cargo fmt --all -- --check
   ```
3. **PR title format** — conventional commits: `feat/`, `fix/`, `docs/`, `chore/`.
4. **Scope boundary required** — every PR body must state what it does NOT change.
5. **No secret content** — no API keys, tokens, hostnames, IPs, or private infra.

## Key APIs

### Ticket lifecycle

```rust
// Issue a ticket (client side)
let ticket = issue_ticket(&signing_key, subject, issuer, relay_url, alpn, now, ttl)?;

// Verify a ticket (server side)
let claims = verify_ticket(&ticket, &issuer_verifying_key, now)?;
```

### Relay

```rust
// Embed the relay in your Tokio application
use snappipe::relay::{run_listener, Relay, RelayConfig};

let relay = Arc::new(Relay::new(RelayConfig::new(listen_addr, trust, limiter)));
let cancel = Arc::new(Mutex::new(false));
let stats = run_listener(endpoint, relay, cancel).await?;
```

### QUIC endpoint

```rust
use snappipe::quic::{build_server_endpoint, QuicEndpointConfig};

let endpoint = build_server_endpoint(&QuicEndpointConfig::server("0.0.0.0:7777".parse()?))?;
```

## Internal operational context (private — never commit)

This section describes Lou's specific deployment. **Do not reference in public docs.**

### Lou's deployment

- **Laptop ↔ VPS relay pattern**: Laptop connects to VPS relay via `ssh-proxy`
  5-tier fallback (QUIC → Hysteria2 → gost → tls-direct → direct-ssh).
- **Layer 0**: The SnapPipe relay (`run_listener`) is the entry point on the
  VPS side for the 5-tier fallback chain.
- **5-tier chain gist** (private): `https://gist.github.com/louzt/3991f144c7d67726045af3cefc60f42a`
- **Internal sync**: `lzt-hub sync` uses SnapPipe for transport; trust store
  is managed out-of-band via `ssh`.

### What's gitignored in docs/

- `agents.md` — this file. Contains private deployment context.

### What's public in docs/

- `OPERATIONAL-DEPLOYMENT.md` — generic SnapPipe deployment guide, no
  operator-specific infra.
- `SECURITY-MODEL.md` — threat model, applicable to any SnapPipe deployment.

## Testing locally

```bash
cargo test --locked
cargo test --test relay_listener_e2e -- --nocapture  # e2e smoke
cargo clippy --locked --all-targets -- -D warnings
```

## When stuck

- **QUIC connection fails**: check that both sides use the same ALPN (`/snappipe/0`).
- **Handshake rejected**: verify the issuer's `VerifyingKey` is in the trust store.
- **Replay error**: check that the `NonceStore` TTL hasn't expired (default 60 s).
- **Rate limited**: check the per-node override in the trust store vs global default.
