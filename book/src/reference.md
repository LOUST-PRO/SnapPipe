# Reference

This page enumerates the CLI surface (commands, flags, env vars,
exit codes) and the public library API. For the full rustdoc
rendering, see [docs.rs/snappipe](https://docs.rs/snappipe).

## CLI commands

| Command | Purpose |
|---|---|
| `snappipe keygen` | Generate a new Ed25519 identity pair |
| `snappipe relay serve` | Start the relay daemon |
| `snappipe relay stop` | Graceful shutdown of a running relay |
| `snappipe ticket issue` | Issue a signed ticket to a peer |
| `snappipe ticket verify` | Verify a ticket locally without sending it |
| `snappipe trust list` | List registered peers in the local trust store |
| `snappipe trust add` | Add a peer to the local trust store |
| `snappipe trust remove` | Remove a peer from the local trust store |
| `snappipe sync push` | Push a local snapshot to a remote relay |
| `snappipe sync pull` | Pull a remote snapshot from a relay |
| `snappipe tunnel client` | Run the TCP-over-QUIC tunnel client (v0.3.0+) |
| `snappipe tunnel relay` | Run the tunnel server side (v0.3.0+) |
| `snappipe --version` | Print version and exit |

## `snappipe keygen`

```text
Usage: snappipe keygen [OPTIONS]

Options:
  -o, --out <FILE>            Path to write the secret key (base64url)
      --public-out <FILE>     Path to write the public key (base64url)
      --force                 Overwrite an existing key file
      --umask <UMASK>         Umask for the new key file [default: 0077]
  -h, --help                  Print help
```

## `snappipe relay serve`

```text
Usage: snappipe relay serve [OPTIONS]

Options:
  -b, --bind <ADDR>           Bind address [default: 0.0.0.0:4443]
  -k, --key <FILE>            Path to the relay's Ed25519 secret key
      --trust <FILE>          Path to the trust.toml file [default: ~/.config/snappipe/trust.toml]
      --metrics-bind <ADDR>   Bind address for the metrics endpoint [default: 127.0.0.1:9090]
      --max-concurrent <N>    Max concurrent QUIC connections [default: 1000]
      --config <FILE>         Optional config file (TOML) overriding defaults
  -h, --help                  Print help
```

## `snappipe ticket issue`

```text
Usage: snappipe ticket issue [OPTIONS]

Options:
      --issuer <FILE>         Path to the issuer's secret key file
      --peer-id <NODE_ID>     The peer NodeId this ticket authorises
      --ttl-seconds <N>       Ticket lifetime [default: 300]
      --rate-limit-override <N>  Optional per-ticket rate limit override
      --out <FILE>            Path to write the JSON ticket
      --force                 Overwrite an existing ticket file
  -h, --help                  Print help
```

## `snappipe ticket verify`

```text
Usage: snappipe ticket verify [OPTIONS]

Options:
      --ticket <FILE>         Path to the ticket JSON file
      --issuer <FILE>         Path to the issuer's public key
      --trust-store <FILE>    Optional trust.toml for issuer check
      --no-nonce-check        Skip the 60-second nonce window check
  -h, --help                  Print help

Exits 0 if valid; 1 if signature invalid; 2 if issuer unknown; 3 if nonce replay.
```

## `snappipe trust {list,add,remove}`

```text
Usage: snappipe trust list [--trust <FILE>]
Usage: snappipe trust add --node-id <ID> --public-key <KEY> [--trust <FILE>]
Usage: snappipe trust remove --node-id <ID> [--trust <FILE>]
```

## `snappipe sync {push,pull}`

```text
Usage: snappipe sync push --ticket <FILE> --relay <ADDR> --target <DIR>
Usage: snappipe sync pull --ticket <FILE> --relay <ADDR> --target <DIR>

Options common:
      --ticket <FILE>     Path to the ticket JSON file
      --relay <HOST:PORT>  The relay's QUIC address
      --target <DIR>      Local directory to push from / pull to
      --max-bytes <N>     Maximum transfer size in bytes [default: 1073741824]
      --resume            Try resume on partial transfer
  -h, --help              Print help
```

## `snappipe tunnel {client,relay}` (v0.3.0+)

```text
Usage: snappipe tunnel client --ticket <FILE> --relay <HOST:PORT> \
    --upstream <HOST:PORT> --local-listen <ADDR>

Usage: snappipe tunnel relay --relay-bind <ADDR> --upstream <HOST:PORT>

Options (client):
      --ticket <FILE>        Path to the ticket JSON file
      --relay <HOST:PORT>    The relay's QUIC address
      --upstream <HOST:PORT> The upstream TCP service to tunnel to
      --local-listen <ADDR>  Local TCP listener (e.g. 127.0.0.1:13389)
      --max-concurrent <N>   Max concurrent TCP connections [default: 16]
  -h, --help                 Print help

Options (relay):
      --relay-bind <ADDR>    QUIC bind address (e.g. 0.0.0.0:4443)
      --upstream <HOST:PORT> Upstream TCP service to terminate to
      --key <FILE>           Relay's Ed25519 secret key
  -h, --help                 Print help
```

## Environment variables

| Variable | Effect |
|---|---|
| `SNAPPIPE_LOG` | Log level: `error`, `warn`, `info`, `debug`, `trace` [default: `info`] |
| `SNAPPIPE_TRUST_PATH` | Override the trust.toml path |
| `SNAPPIPE_KEY_PATH` | Override the key file path |
| `SNAPPIPE_METRICS_BIND` | Override the metrics endpoint bind address |
| `SNAPPIPE_QUIC_IDLE_TIMEOUT_MS` | QUIC idle timeout in milliseconds [default: 30000] |
| `SNAPPIPE_QUIC_KEEPALIVE_MS` | QUIC keepalive interval in milliseconds [default: 10000] |

Environment variables override command-line flags. Flags override
the config file. The precedence is:

```
flags > env vars > config file > defaults
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | I/O error (file not found, permission denied, etc.) |
| 2 | Argument parse error (invalid flag value, missing required argument) |
| 3 | Signature verification failed |
| 4 | Issuer not in trust store |
| 5 | Nonce replay detected |
| 6 | Rate limit exceeded |
| 7 | Tunnel ALPN mismatch (v0.3.0+) |
| 100 | Unhandled internal error (likely a bug; please file an issue) |
| 101 | Panic recovered; a bug report is the right next step |

## Library API

The library surface is documented in full at
[docs.rs/snappipe](https://docs.rs/snappipe). The five primary
types are:

- [`TrustStore`](https://docs.rs/snappipe/latest/snappipe/struct.TrustStore.html)
  — peer allow-list with persistence
- [`SignedTicket`](https://docs.rs/snappipe/latest/snappipe/struct.SignedTicket.html)
  — short-lived bearer token
- [`NonceStore`](https://docs.rs/snappipe/latest/snappipe/struct.NonceStore.html)
  — replay protection with 60-second TTL
- [`RateLimiter`](https://docs.rs/snappipe/latest/snappipe/struct.RateLimiter.html)
  — per-NodeId token bucket
- [`Relay`](https://docs.rs/snappipe/latest/snappipe/struct.Relay.html)
  — the relay daemon (v0.3.0+)

Library users typically construct a `TrustStore` from a path,
hand a `SignedTicket` to a peer, and call `NonceStore::check_and_record`
plus `RateLimiter::try_consume` on inbound requests. The
`Relay::serve` method is for the relay binary; library code that
wants to act as a peer does not need `Relay`.