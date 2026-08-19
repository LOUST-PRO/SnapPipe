# Installation

This page covers installing the `snappipe` crate (library use), the
`snappipe` binary (CLI), and the canonical first-run identity
bootstrap. Library users should jump straight to the
[API documentation on docs.rs](https://docs.rs/snappipe).

## As a library

Add `snappipe` to your `Cargo.toml`:

```toml
[dependencies]
snappipe = "0.3"
```

For minimum-dependency builds (no CLI features), add the crate with
the default features:

```toml
[dependencies]
snappipe = { version = "0.3", default-features = false }
```

The default feature set pulls in `tokio`, `quinn`, and `rustls`. If
your project already pins compatible versions, the build shares the
single dependency graph; if not, expect a one-time compile of ~60
seconds on a modern laptop.

## As a CLI

The CLI is the same crate built as a binary. Two install paths:

### Via `cargo install`

```bash
cargo install snappipe --locked
```

This places the binary at `~/.cargo/bin/snappipe`. The `--locked`
flag pins the install to the lockfile shipped in the published
crate, ensuring reproducibility.

### From source (for local development)

```bash
git clone https://github.com/LOUST-PRO/SnapPipe
cd SnapPipe
cargo build --release --bin snappipe
install -m 0755 target/release/snappipe /usr/local/bin/
```

## First-run identity bootstrap

Before any relay or client can accept a peer, the operator must
generate an Ed25519 identity and register the corresponding public
key in the trust store of any peer that should accept this node.

### 1. Generate the relay identity

```bash
mkdir -p ~/.config/snappipe
snappipe keygen \
    --out ~/.config/snappipe/relay.secret \
    --public-out ~/.config/snappipe/relay.public
```

The `.secret` file is Ed25519 secret key material (base64url, single
line). **Treat it like an SSH private key** — never commit it, never
paste it in chat, never log it. The `.public` file is the matching
`VerifyingKey`, safe to share with peers.

### 2. Distribute the public key to trusted peers

For each peer that should be allowed to connect to this relay, copy
the relay's `.public` file (or just the contents) into the peer's
trust store:

```bash
# on the peer host:
mkdir -p ~/.config/snappipe
# append or create trust.toml:
cat >> ~/.config/snappipe/trust.toml <<EOF
[[peer]]
node_id = "relay-prod-1"
public_key = "<paste contents of relay.public here>"
rate_limit_per_min = 200
EOF
```

Empty `trust.toml` is a deny-all state — no peer is accepted until
an entry exists. This is intentional: an operator who hasn't
populated the trust store has not yet decided to trust anyone.

### 3. Start the relay

```bash
snappipe relay serve \
    --bind 0.0.0.0:4443 \
    --key ~/.config/snappipe/relay.secret
```

The relay listens on UDP/4443 by default. v0.3.0 adds the TCP-over-
QUIC tunnel on the same port but with the `/snappipe/tunnel/0`
ALPN — see [Operations](./operations.md#tcp-over-quic-tunnel-deployment-v030).

### 4. Issue a signed ticket to a peer

```bash
snappipe ticket issue \
    --issuer ~/.config/snappipe/relay.secret \
    --peer-id laptop-prod-1 \
    --ttl-seconds 3600 \
    --out peer.ticket.json
```

The ticket is a single JSON file that the peer presents when
connecting. Tickets are short-lived by default (300s); the
`--ttl-seconds` flag here overrides to 3600s for a longer-lived
session.

### 5. Push from the peer

```bash
snappipe sync push \
    --ticket peer.ticket.json \
    --target ./local-copy \
    --relay relay.example.com:4443
```

If the trust store on the relay does not contain the peer's
`VerifyingKey`, the handshake fails with
`Error::TrustStoreMiss(peer_id)`. If the ticket's nonce has been
seen inside the 60-second TTL, the handshake fails with
`Error::NonceReplay`. Both errors are operator-actionable and do
not crash the daemon.

## Verifying the install

Two sanity checks confirm the install is alive.

### CLI responds

```bash
snappipe --version
# expected: snappipe 0.3.0
```

### Trust store load works

```bash
snappipe trust list
# expected: lists all registered peers (or empty if none registered)
```

If `trust list` returns `Error::Io` reading the trust.toml file,
the file path in `~/.config/snappipe/trust.toml` is wrong — fix the
path or create the file.

## Uninstalling

```bash
cargo uninstall snappipe
rm -rf ~/.config/snappipe
```

The relay has no global state beyond `~/.config/snappipe/`. Removal
is fully reversible.
