# Security model

This page documents SnapPipe's threat model, the trust boundaries
in scope, the hardening posture taken by the reference
deployment, and the known technical debt an operator should
understand before scaling v0.3.0+ workloads.

## What SnapPipe is and isn't

**SnapPipe is identity-gated transport.** It guarantees that bytes
flowing across the QUIC stream were authored by a peer the
operator has explicitly trusted, that no peer can replay an
authentication, and that no peer can exceed its per-minute budget.

**SnapPipe is not:**

- A general-purpose VPN. It does not impersonate a network
  interface; it's a per-stream gate.
- A SaaS. There is no third party in the auth path; the relay is
  operator-controlled.
- A firewall. SnapPipe does not block traffic at the IP layer; it
  rejects streams at the application layer.
- Anonymity-preserving. The relay sees both peers' source IPs in
  the QUIC handshake metadata.
- Carrier-traversal. If the carrier blocks UDP/4443, SnapPipe
  cannot route around it; that's a connectivity concern, not a
  transport one (see [Operations](./operations.md#pattern-3-mesh-multi-relay)).

## Trust boundaries

Three trust boundaries separate SnapPipe's components:

| Boundary | In scope | Out of scope |
|---|---|---|
| **Trust store file** | The `~/.config/snappipe/trust.toml` file, its on-disk permissions, its integrity against tamper | The host kernel (a root user can rewrite the file; SnapPipe runs as non-root but the file's protection is the OS layer's responsibility) |
| **Ed25519 keys** | Secret key storage (file permissions + umask), `keygen` output entropy, signature verification | Hardware tokens (YubiKey etc. are not integrated; a future version may add `ed25519-dalek` PKCS#11 support) |
| **QUIC session** | Transport encryption (rustls + ring crypto), replay protection (nonce store), rate limit | Operator-side rate-limit decisions (the operator chooses the budget; v0.3.0 default is 100 req/min per NodeId) |

### What the relay operator trusts

The relay operator trusts:

1. The OS to keep the relay secret key file readable only to the
   relay process (the `install -m 0600` convention is the
   reference).
2. The host clock to be roughly monotonic (the 60-second nonce
   TTL depends on wall time; a clock skew of >60s between peers
   can cause legitimate nonces to be flagged as replays).
3. The trust.toml file to be the canonical source of truth (a
   missing or corrupt file fails-closed; the daemon refuses to
   start, not start in a degraded allow-all mode).

### What the peer trusts

The peer trusts:

1. The relay to enforce the rate limit honestly (the relay can
   bypass any peer's rate limit trivially, but the operator
   reputation cost is high).
2. The relay to forward application bytes promptly (the
   v0.3.0+ performance claim is documented in [Operations](./operations.md#pattern-1-single-relay-canonical)).
3. The trust store on the relay to be the canonical source of
   peer allow-list.

## Hardening posture

The reference deployment sets the following hardening posture:

| Concern | Posture |
|---|---|
| Process privilege | Runs as `snappipe` user (UID/GID created at install), never root |
| File system access | `~/.config/snappipe/` is mode 0700 owned by `snappipe` |
| Trust file | mode 0600, owned by `snappipe`, no other readable bits |
| Secret keys | mode 0600, owned by `snappipe`, never logged |
| Network surface | UDP/4443 only (TCP is closed at the firewall layer); HTTP metrics endpoint bound to 127.0.0.1:9090 |
| systemd integration | `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=true`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectControlGroups=yes` |
| Memory ceiling | `MemoryMax=128M` (relay) / `MemoryMax=64M` (tunnel client) |
| Restart policy | `Restart=on-failure`, `RestartSec=5`, `StartLimitBurst=5` per `StartLimitIntervalSec=300` |
| Log volume | stdout + journald only; no file logging by default; `journalctl -u snappipe-relay` is the audit trail |
| Audit trail | relay's metrics endpoint exposes `total_accepted`, `total_rejected_replay`, `total_denied` for manual diff |

These are the reference values. Operators with different
deployment requirements may adjust; the crate does not enforce
any of the above at runtime. The hardening posture is a deployment
concern, not a library concern.

## Threat model — explicit failure modes

The following scenarios are explicitly enumerated and the
expected behaviour documented:

| Threat | Expected behaviour |
|---|---|
| Attacker presents a forged ticket | `Error::InvalidSig`; stream torn down; metrics counter `total_rejected_replay` increments; the attacker's NodeId is denied for the rate-limit window |
| Attacker replays a legitimate ticket | `Error::NonceReplay`; same as above |
| Attacker floods with new tickets from a trusted issuer | Token bucket denies after the first 100/min; metrics counter `total_denied` increments |
| Attacker floods with new tickets from an untrusted issuer | `Error::TrustStoreMiss`; stream torn down; no further cost beyond the QUIC handshake |
| Attacker compromises the relay host's filesystem | Game over — the secret key is on disk. The mitigation is OS-level: file permissions, full-disk encryption, host intrusion detection |
| Attacker compromises the peer's trust.toml file | Game over — the attacker can add themselves as a trusted peer. The mitigation is OS-level |
| Clock skew >60s between peers | Legitimate nonces flagged as replays. The mitigation is NTP or chrony on both hosts |
| Replay after the 60-second nonce TTL | **Allowed by design** — tickets are short-lived credentials, not permanent authorisations |

## Known technical debt

v0.3.0 ships with two deliberate deferrals. Both are documented so
operators can size their workloads accordingly.

### NonceStore and RateLimiter Mutex contention

Both `NonceStore::check_and_record` and `RateLimiter::try_consume`
are protected by a `std::sync::Mutex<HashMap<_, _>>`. The lock is
held briefly (no `.await` across it), but it IS a single global
mutex per peer.

**Trigger for migration**: >100 `try_consume` calls / second / edge.
At that point the per-NodeId Mutex becomes the bottleneck and v0.4
will migrate to either a sharded map (16-way sharding by NodeId
hash prefix) or a lock-free skiplist.

### Single trust.toml load

`TrustStore::load_or_default` reads the entire file at start-up
and on every `add_peer` call. There is no incremental update path.

**Trigger for migration**: >1000 peers per trust store, or
>1 add/second sustained rate. At that point the file-based store
will be replaced with a daemon-managed in-memory store + a
sidecar protocol for incremental updates.

## Disclosure

Security issues should be reported via the GitHub Security tab,
following the [SECURITY.md](https://github.com/LOUST-PRO/SnapPipe/blob/main/SECURITY.md)
policy. The maintainer team responds within 72 hours and aims to
land a fix within 30 days for high-severity issues.