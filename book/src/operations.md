# Operations

This page covers the three deployment patterns the relay supports
(single relay, direct, mesh) and the v0.3.0 TCP-over-QUIC tunnel.
Pick the pattern that matches your topology; the gating chain stays
the same across all three.

## Pattern 1 — Single relay (canonical)

The simplest topology: one relay host, N clients, all peers
register the relay's public key in their trust store.

```text
   ┌─────────────────┐
   │  Relay (VPS)    │
   │  UDP/4443       │
   │  trust: peers   │
   └─────────────────┘
           ▲
     ┌─────┴─────┐
     │           │
   laptop-1   laptop-2
```

This is the canonical pattern used by the original operator
deployment. The relay has a single trust store (`trust.toml`) that
lists every peer allowed to connect. Tickets are issued on-demand
when a peer needs access — typically by an admin script running on
the relay host.

When to use this pattern:

- N clients ≤ 20 (the relay's trust store is read on every handshake
  but cheap; the rate-limit bookkeeping is the bottleneck)
- All clients are stable (not churning in/out)
- UDP/4443 reachable from every peer

When NOT to use this pattern:

- Clients behind a corporate firewall that blocks UDP/4443 (use
  Pattern 3 with a tunnel)
- >20 clients per second of new connections (the single Mutex on
  `NonceStore` and `RateLimiter` becomes the bottleneck — see
  [Security model](./security-model.md#known-technical-debt))

## Pattern 2 — Direct (peer-to-peer)

No relay at all. Two peers connect directly via QUIC, with one
acting as the server side and the other as the client. The trust
store is duplicated between both sides.

```text
   laptop-A   <─────QUIC──────>   laptop-B
   trust: B                         trust: A
```

When to use this pattern:

- Two specific laptops that already share SSH keys (the trust store
  is just one more configuration file to copy)
- The relay would only ever relay between the same two peers (the
  relay adds zero value here)

When NOT to use this pattern:

- Either peer is behind a NAT you can't punch (NAT traversal is not
  in scope for v0.3.0 — Pattern 3 covers that case)
- More than 2 peers (the trust store becomes N×N entries)

## Pattern 3 — Mesh (multi-relay)

Two or more relays, each with their own trust store, federating
peers. The pattern is mostly used to survive carrier-level UDP
blackholes by having relays in different geographic regions.

```text
   ┌──────────────────┐    ┌──────────────────┐
   │  Relay US-East   │    │  Relay EU-West   │
   │  trust: clients  │    │  trust: clients  │
   └──────────────────┘    └──────────────────┘
        ▲   ▲                  ▲   ▲
        │   │                  │   │
     laptop-1  laptop-2     laptop-3  laptop-4
```

Tickets issued by relay US-East are valid for relay EU-West only
if EU-West's trust store has the same issuer registered. This is
the operationally correct default: each relay decides which issuers
to honour. A peer wanting to traverse both relays needs two
tickets.

When to use this pattern:

- Your peers are in different geographic regions
- Some carriers block UDP/4443 (route around via the relay in the
  unaffected region)
- You want failover when one relay is down

When NOT to use this pattern:

- You're a single-region operator (Pattern 1 is simpler and has the
  same security guarantees)
- Your peer count is small enough that a single relay handles the
  load easily

## TCP-over-QUIC tunnel (deployment v0.3.0)

The tunnel layer wraps legacy TCP protocols (RDP, raw SSH, private
DB wire protocols) inside the same QUIC transport. The gating
chain (trust store + signed ticket + nonce + rate limit) applies
to the tunnel ALPN exactly as it does to the sync ALPN. There is
no second authentication surface.

### Architecture

```text
   laptop                               vps
   ┌─────────────────────┐             ┌─────────────────────┐
   │ client.tcp (RDP)    │             │                     │
   │       │             │             │                     │
   │       ▼             │             │                     │
   │ snappipe-tunnel-    │             │ snappipe relay      │
   │   client            │   QUIC      │   4443/udp          │
   │   (forwards)        │ ──────────► │   (tunnel ALPN)     │
   │                     │             │       │             │
   │                     │             │       ▼             │
   │                     │             │ snappipe-tunnel-    │
   │                     │             │   server            │
   │                     │             │   (relays TCP)      │
   │                     │             │       │             │
   │                     │             │       ▼             │
   │                     │             │ upstream.tcp (RDP)  │
   └─────────────────────┘             └─────────────────────┘
```

The client opens a local TCP listener, takes any incoming
connection, and pipes it through the QUIC tunnel. The relay's
tunnel server side terminates the QUIC tunnel and opens a new TCP
connection to the upstream service.

### Configuration

`examples/relay.sample.toml` ships the canonical configuration:

```toml
[relay]
bind = "0.0.0.0:4443"
key_path = "/var/lib/snappipe/relay.secret"
trust_path = "/etc/snappipe/trust.toml"

[tunnel]
enabled = true
alpn = "/snappipe/tunnel/0"
max_concurrent_streams = 100
```

The `[tunnel]` block enables the tunnel layer. With it disabled,
the relay only accepts the sync ALPN.

### systemd unit (client side)

`examples/snappipe-tunnel-client.service` ships a drop-in unit:

```ini
[Unit]
Description=SnapPipe tunnel client (RDP over QUIC)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment="AUTOSSH_GATETIME=0"
ExecStart=/usr/local/bin/snappipe-tunnel-client \
    --ticket /etc/snappipe/peer.ticket.json \
    --relay relay.example.com:4443 \
    --upstream rdp.example.com:3389 \
    --local-listen 127.0.0.1:13389
Restart=always
RestartSec=10
MemoryMax=64M
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/log/snappipe
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

`MemoryMax=64M` caps the cgroup RSS; the QUIC stack + tokio runtime
stays well under that. The strict `ProtectSystem` + `ProtectHome`
sandboxes the process.

### Verify the tunnel

Once the client systemd unit is active:

```bash
systemctl status snappipe-tunnel-client.service
# expected: Active: active (running)

# Test from the laptop:
nc -zv 127.0.0.1 13389
# expected: succeeded

# Now any RDP client pointed at 127.0.0.1:13389 will go via QUIC
# to relay.example.com:4443 and end up at rdp.example.com:3389
```

A handshake failure surfaces in the journal as
`Error::TrustStoreMiss` or `Error::NonceReplay`. Both are
operator-actionable; the unit does not auto-restart on these
errors (no thrash).

## Metrics endpoints

Both the relay and the tunnel expose metrics via the JSON endpoint
`GET /metrics` on the listen socket (default 127.0.0.1:9090). The
endpoint is HTTP, unauthenticated, and intended for scraping by
Prometheus or diffing manually.

```bash
curl -s http://127.0.0.1:9090/metrics | jq .
# expected output: { "trust_store_size": 5,
#                     "nonce_store": { ... },
#                     "rate_limiter": { ... } }
```

Snapshot the metrics, wait 60 seconds, snapshot again. Diff the
`total_accepted` / `total_rejected_replay` / `total_denied`
counters — large deltas are signals of either a peer under attack
or a misconfigured trust store.