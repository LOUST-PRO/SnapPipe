# Introduction

**SnapPipe** is an identity-gated QUIC transport toolkit for Rust
applications and operators who need signed-ticket gating, replay
protection, per-peer rate limiting, and a self-hosted relay that
doesn't depend on a third-party SaaS. v0.3.0 adds a TCP-over-QUIC
tunnel for shipping legacy TCP protocols (RDP, raw SSH, private DB
wire protocols) over the same identity-gated transport.

## TL;DR

```text
┌────────────────────────────────────────────────────────────────────┐
│  cargo add snappipe                                                 │
│                                                                    │
│  snappipe keygen --out ./keys/relay.secret                          │
│  snappipe relay serve --bind 0.0.0.0:4443 --key ./keys/relay.secret │
│                                                                    │
│  # on the client:                                                  │
│  snappipe ticket issue --issuer ./keys/relay.secret \\              │
│      --peer-id <client-node-id> --ttl-seconds 3600                  │
│  snappipe sync push --ticket peer.ticket.json --target ./local      │
└────────────────────────────────────────────────────────────────────┘
```

## What it is

SnapPipe provides a thin, auditable QUIC transport with three layers
of identity gating:

1. **Trust store**: an empty store is NOT a default-allow state.
   Every accepted peer must have an Ed25519 `VerifyingKey` registered
   in [`TrustStore`](https://docs.rs/snappipe/latest/snappipe/struct.TrustStore.html).
2. **Signed tickets**: short-lived bearer tokens signed by a trusted
   issuer. Replay protection is enforced via a 16-byte nonce with
   60-second TTL inside [`NonceStore`](https://docs.rs/snappipe/latest/snappipe/struct.NonceStore.html).
3. **Per-peer rate limit**: token-bucket per `NodeId` with a default
   budget of 100 req/min. A misconfigured `set_limit(&id, 0, _)` is
   clamped to the default, never silently disabled.

v0.3.0 layers on a **TCP-over-QUIC tunnel** that reuses all three
gating layers and adds a dedicated ALPN (`/snappipe/tunnel/0`) so
tunnel traffic stays on its own wire — there is no second auth
surface.

## Why it exists

Most "QUIC + identity" stacks in the wild delegate either transport
to a SaaS (Cloudflare, ngrok) or identity to a centralised auth
provider (Auth0, Clerk). SnapPipe is for operators who want both
layers under their own control: a self-hosted relay they can audit,
keys they can rotate on their own schedule, and a transport that
survives the kinds of network conditions that drop SaaS-hosted
QUIC connections (UDP blackholes, aggressive DPI, residential NAT).

The crate was extracted from an operator-side deployment that runs
the relay on a single 1 Gbps VPS and has been in production since
mid-2025. The v0.3.0 tunnel layer is the same one the canonical
operator stack uses for RDP-over-QUIC for remote dev work.

## At a glance

| Property | Value |
|---|---|
| Language | Rust (edition 2024) |
| Transport | QUIC via `quinn` 0.11 + `rustls` 0.23 (ring crypto) |
| Identity | Ed25519 via `ed25519-dalek` 2.x |
| CLI size | single binary, ~8 MiB stripped |
| Async runtime | `tokio` (multi-thread) |
| Runtime deps | 16 (all `Cargo.toml`-pinned via `Cargo.lock`) |
| Default rate limit | 100 req/min per NodeId (clamp on `set_limit(0)`) |
| Nonce TTL | 60 seconds |
| Ticket default TTL | 300 seconds |
| Tunnel ALPN | `/snappipe/tunnel/0` |
| Relay default port | 4443/udp |
| License | Apache-2.0 |

## Where to next

- [Installation](./installation.md) — `cargo install snappipe` and the
  first-run identity bootstrap.
- [How it works](./how-it-works.md) — the trust store + ticket +
  nonce + rate-limit gating chain, with the operator-stack
  diagram.
- [Operations](./operations.md) — three deployment patterns (single
  relay, direct, mesh) plus the v0.3.0 TCP-over-QUIC tunnel.
- [Security model](./security-model.md) — threat model and
  hardening posture table.
- [Reference](./reference.md) — CLI flags, env vars, exit codes.
- [License](./license.md) — Apache-2.0 + the fork hardening addendum.
