use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use snappipe::{
    DEFAULT_ALPN, DEFAULT_TICKET_TTL_SECS, NodeId, RelayConfig, SignedTicket, decode_public_key,
    decode_secret_key, encode_public_key, encode_secret_key, generate_signing_key, issue_ticket,
    nonce_store::{NonceStore, NonceStoreMetrics},
    now_unix_seconds,
    quic::QuicTransportProfile,
    rate_limit::{RateLimiter, RateLimiterMetrics},
    session::{TrustCheck, allow_all_trust},
    to_pretty_json,
    transport::tunnel,
    verify_ticket,
};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "snappipe")]
#[command(about = "Identity-based ticket and relay toolkit for self-hosted QUIC transport")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Keygen(KeygenArgs),
    Ticket {
        #[command(subcommand)]
        command: TicketCommand,
    },
    Relay {
        #[command(subcommand)]
        command: RelayCommand,
    },
    Quic {
        #[command(subcommand)]
        command: QuicCommand,
    },
    Tunnel {
        #[command(subcommand)]
        command: TunnelCommand,
    },
    Metrics(MetricsArgs),
}

#[derive(Args, Debug)]
struct KeygenArgs {
    #[arg(long, default_value = "identity.secret")]
    out: PathBuf,
    #[arg(long, default_value = "identity.public")]
    public_out: PathBuf,
}

#[derive(Subcommand, Debug)]
enum TicketCommand {
    Issue(TicketIssueArgs),
    Inspect(TicketInspectArgs),
    Verify(TicketVerifyArgs),
}

#[derive(Args, Debug)]
struct TicketIssueArgs {
    #[arg(long)]
    secret_key: PathBuf,
    #[arg(long)]
    subject_public_key: Option<PathBuf>,
    #[arg(long)]
    relay_url: String,
    #[arg(long, default_value = DEFAULT_ALPN)]
    alpn: String,
    #[arg(long, default_value_t = DEFAULT_TICKET_TTL_SECS)]
    ttl_seconds: i64,
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct TicketInspectArgs {
    #[arg(long)]
    ticket: PathBuf,
}

#[derive(Args, Debug)]
struct TicketVerifyArgs {
    #[arg(long)]
    ticket: PathBuf,
    #[arg(long)]
    public_key: PathBuf,
    #[arg(long)]
    now: Option<i64>,
}

#[derive(Subcommand, Debug)]
enum RelayCommand {
    SampleConfig(RelaySampleConfigArgs),
}

#[derive(Subcommand, Debug)]
enum QuicCommand {
    Profile(QuicProfileArgs),
}

/// TCP-over-QUIC tunnel subcommands.
///
/// `tunnel serve` runs on the operator's edge (e.g. the LZT relay VPS)
/// and forwards every QUIC stream to a fixed local TCP backend.
/// `tunnel connect` runs on the friend/customer side: it binds a local
/// TCP port (e.g. 127.0.0.1:25566) and tunnels each accepted
/// connection through a single long-lived QUIC connection to the
/// remote `serve`.
///
/// Both ends reuse the existing ticket-gated handshake and trust
/// store; only the application ALPN (`/snappipe/tunnel/0`) is new.
#[derive(Subcommand, Debug)]
enum TunnelCommand {
    Serve(TunnelServeArgs),
    Connect(TunnelConnectArgs),
}

#[derive(Args, Debug)]
struct TunnelServeArgs {
    /// Path to the operator's secret key (Ed25519, base64url). Used
    /// to verify the signed ticket presented by the client.
    #[arg(long)]
    secret_key: PathBuf,
    /// Path to the operator's public key (Ed25519, base64url). The
    /// ticket's `subject` claim MUST equal this key's NodeId.
    #[arg(long)]
    public_key: PathBuf,
    /// Path to the trust store. New issuers are added with
    /// `snappipe trust add <node-id>`; absent store = allow_all.
    ///
    /// NOTE: this flag is RESERVED for the upcoming trust-store
    /// loader. The current `tunnel serve` falls back to
    /// `allow_all_trust()` regardless of whether this path is
    /// supplied, so a `Some(_)` value here is accepted for
    /// forward-compatibility but does NOT tighten the issuer
    /// allowlist yet. Do not rely on this flag in production until
    /// trust-store loading is implemented in a follow-up PR.
    #[arg(long)]
    trust_store: Option<PathBuf>,
    /// QUIC bind address (e.g. `0.0.0.0:4443`).
    #[arg(long, default_value = "0.0.0.0:4443")]
    quic_bind: String,
    /// Local TCP backend to proxy to (e.g. `127.0.0.1:25565`).
    #[arg(long)]
    target: String,
    /// Tunnel ALPN override (rarely changed).
    #[arg(long, default_value = tunnel::TUNNEL_ALPN)]
    alpn: String,
}

#[derive(Args, Debug)]
struct TunnelConnectArgs {
    /// Path to the client's secret key. Currently used only to
    /// derive the local subject NodeId when self-issuing tickets
    /// during dev/testing; production deployments ship a separate
    /// peer key.
    #[arg(long)]
    secret_key: PathBuf,
    /// Path to a JSON file containing the signed [`SignedTicket`]
    /// issued by the operator.
    #[arg(long)]
    ticket: PathBuf,
    /// Path to the OPERATOR's public key (Ed25519, base64url). This
    /// is the key that signed the ticket; the client uses it to
    /// verify the ticket locally before presenting it on the wire.
    /// Required: the client cannot trust a ticket whose issuer it
    /// does not know.
    #[arg(long)]
    issuer_public_key: PathBuf,
    /// Path to the relay's DER-encoded leaf certificate. Pinned
    /// into the client trust store before the QUIC handshake so
    /// the connection cannot succeed against an unrelated peer.
    /// Required for production deployments.
    #[arg(long)]
    server_cert: PathBuf,
    /// Remote relay host:port (e.g. `127.0.0.1:4443`).
    #[arg(long)]
    relay: String,
    /// Local TCP listener address to expose (e.g. `127.0.0.1:25566`).
    #[arg(long)]
    listen: String,
    /// Tunnel ALPN override (must match the server side).
    #[arg(long, default_value = tunnel::TUNNEL_ALPN)]
    alpn: String,
}

#[derive(Args, Debug)]
struct RelaySampleConfigArgs {
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct QuicProfileArgs {
    #[arg(long, default_value = "low-latency-interactive")]
    preset: String,
    #[arg(long, default_value = DEFAULT_ALPN)]
    alpn: String,
    #[arg(long)]
    output: Option<PathBuf>,
}

/// Arguments for the `metrics` subcommand.
///
/// Runs a small reproducible workload against fresh `NonceStore` and
/// `RateLimiter` instances, then prints both metric snapshots as a single
/// JSON document. Use it as a smoke test, as a live reference of the
/// metrics schema, and as the input shape for operators diffing two
/// consecutive snapshots to derive throughput (the v0.3.0 migration
/// trigger is documented in `docs/SECURITY-MODEL.md`).
#[derive(Args, Debug)]
struct MetricsArgs {
    /// TTL (seconds) used for the demo `NonceStore`.
    #[arg(long, default_value_t = 60)]
    nonce_ttl_secs: i64,
    /// Default per-minute budget for the demo `RateLimiter`.
    #[arg(long, default_value_t = 100)]
    rate_default_per_min: u32,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen(args) => keygen(args),
        Command::Ticket { command } => match command {
            TicketCommand::Issue(args) => issue(args),
            TicketCommand::Inspect(args) => inspect(args),
            TicketCommand::Verify(args) => verify(args),
        },
        Command::Relay { command } => match command {
            RelayCommand::SampleConfig(args) => sample_config(args),
        },
        Command::Quic { command } => match command {
            QuicCommand::Profile(args) => quic_profile(args),
        },
        Command::Tunnel { command } => match command {
            TunnelCommand::Serve(args) => tunnel_serve(args),
            TunnelCommand::Connect(args) => tunnel_connect(args),
        },
        Command::Metrics(args) => metrics_cmd(args),
    }
}

fn keygen(args: KeygenArgs) -> Result<()> {
    let signing_key = generate_signing_key();
    let secret = encode_secret_key(&signing_key);
    let public = encode_public_key(&signing_key.verifying_key());

    fs::write(&args.out, format!("{}\n", secret))
        .with_context(|| format!("failed to write {}", args.out.display()))?;
    fs::write(&args.public_out, format!("{}\n", public))
        .with_context(|| format!("failed to write {}", args.public_out.display()))?;

    println!("secret_key_path={}", args.out.display());
    println!("public_key_path={}", args.public_out.display());
    println!("node_id={public}");
    Ok(())
}

fn issue(args: TicketIssueArgs) -> Result<()> {
    let secret_key = fs::read_to_string(&args.secret_key)
        .with_context(|| format!("failed to read {}", args.secret_key.display()))?;
    let signing_key = decode_secret_key(secret_key.trim())?;
    let subject_key = args
        .subject_public_key
        .as_ref()
        .map(|path| {
            fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))
                .and_then(|raw| decode_public_key(raw.trim()).map_err(anyhow::Error::from))
        })
        .transpose()?;
    let now = now_unix_seconds();
    let ticket = issue_ticket(
        &signing_key,
        subject_key.as_ref(),
        args.relay_url,
        args.alpn,
        args.ttl_seconds,
        now,
    )?;
    let json = to_pretty_json(&ticket)?;

    if let Some(path) = args.output {
        fs::write(&path, format!("{}\n", json))
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!("ticket_path={}", path.display());
    } else {
        println!("{json}");
    }

    Ok(())
}

fn inspect(args: TicketInspectArgs) -> Result<()> {
    let ticket = load_ticket(&args.ticket)?;
    println!("{}", to_pretty_json(&ticket.claims)?);
    Ok(())
}

fn verify(args: TicketVerifyArgs) -> Result<()> {
    let ticket = load_ticket(&args.ticket)?;
    let public_key = fs::read_to_string(&args.public_key)
        .with_context(|| format!("failed to read {}", args.public_key.display()))?;
    let verifying_key = decode_public_key(public_key.trim())?;
    let now = args.now.unwrap_or_else(now_unix_seconds);
    let claims = verify_ticket(&ticket, &verifying_key, now)?;
    println!("verified=true");
    println!("issuer={}", claims.issuer);
    println!("subject={}", claims.subject);
    println!("relay_url={}", claims.relay_url);
    println!("alpn={}", claims.alpn);
    println!("expires_at={}", claims.expires_at);
    Ok(())
}

fn sample_config(args: RelaySampleConfigArgs) -> Result<()> {
    let config = RelayConfig::sample().to_toml_like();
    if let Some(path) = args.output {
        fs::write(&path, &config).with_context(|| format!("failed to write {}", path.display()))?;
        println!("sample_config_path={}", path.display());
    } else {
        println!("{config}");
    }
    Ok(())
}

fn quic_profile(args: QuicProfileArgs) -> Result<()> {
    let profile = match args.preset.as_str() {
        "low-latency-interactive" => QuicTransportProfile::low_latency_interactive(args.alpn),
        "relay-backhaul" => QuicTransportProfile::relay_backhaul(args.alpn),
        other => anyhow::bail!(
            "unknown quic preset: {other}. expected one of: low-latency-interactive, relay-backhaul"
        ),
    };
    let json = to_pretty_json(&profile)?;

    if let Some(path) = args.output {
        fs::write(&path, format!("{}\n", json))
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!("quic_profile_path={}", path.display());
    } else {
        println!("{json}");
    }

    Ok(())
}

fn load_ticket(path: &PathBuf) -> Result<SignedTicket> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let ticket = serde_json::from_str::<SignedTicket>(raw.trim())
        .with_context(|| format!("failed to parse {} as SignedTicket JSON", path.display()))?;
    Ok(ticket)
}

/// Operator-facing entry point for `snappipe tunnel serve`.
///
/// Builds a tunnel-flavored QUIC server endpoint (shared `quic_bind`,
/// ALPN `/snappipe/tunnel/0`), reads the trust store from disk (or
/// falls back to `allow_all` when no path is supplied), and runs the
/// tunnel accept loop against `target`.
fn tunnel_serve(args: TunnelServeArgs) -> Result<()> {
    use tokio::sync::Mutex;

    let issuer_secret = fs::read_to_string(&args.secret_key)
        .with_context(|| format!("read secret key {}", args.secret_key.display()))?;
    let issuer_key = decode_secret_key(issuer_secret.trim())
        .map_err(|err| anyhow::anyhow!("decode secret key: {}", err))?;

    let pub_key_text = fs::read_to_string(&args.public_key)
        .with_context(|| format!("read public key {}", args.public_key.display()))?;
    let expected_subject = decode_public_key(pub_key_text.trim())
        .map_err(|err| anyhow::anyhow!("decode public key: {}", err))?;

    let trust: Arc<dyn TrustCheck> = allow_all_trust();

    if let Some(path) = &args.trust_store {
        eprintln!(
            "WARNING: --trust-store={} is currently a no-op in tunnel serve. \
             Issuer allowlist is allow_all until TrustStore loading is wired \
             in a follow-up PR. Do not rely on this flag to restrict issuers \
             in production.",
            path.display()
        );
    }

    let bind: std::net::SocketAddr = args.quic_bind.parse()?;
    let target: std::net::SocketAddr = args.target.parse()?;

    // Build a tuned server config using the tunnel profile (ALPN =
    // /snappipe/tunnel/0).
    let cert = snappipe::quic::self_signed_dev_cert(&[])?;
    let mut server_cfg = snappipe::quic::default_server_config(&cert)?;
    let profile = QuicTransportProfile::relay_backhaul(args.alpn.clone());
    let transport = Arc::new(profile.build_transport_config()?);
    server_cfg.transport_config(transport);
    let endpoint = quinn::Endpoint::server(server_cfg, bind)
        .map_err(|err| anyhow::anyhow!("bind {}: {}", bind, err))?;

    eprintln!(
        "tunnel-serve: listening on {} (ALPN {}) -> target {}",
        bind, args.alpn, target
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let cancel = Arc::new(Mutex::new(false));
    let issuer_arc = Arc::new(issuer_key.verifying_key());
    let subject_arc = Arc::new(expected_subject);
    runtime.block_on(async move {
        tunnel::serve(endpoint, target, trust, issuer_arc, subject_arc, cancel).await
    })
}

/// Friend/customer entry point for `snappipe tunnel connect`.
///
/// Loads the signed ticket, re-verifies it locally, builds a tunnel
/// QUIC client, performs the handshake, and serves a local TCP
/// listener that proxies each accepted connection through the
/// tunnel.
fn tunnel_connect(args: TunnelConnectArgs) -> Result<()> {
    use std::net::SocketAddr;

    // Read client secret key. The handshake layer uses it only when
    // the ticket is self-issued (dev/test); production deployments
    // ship a separate peer key.
    let secret_raw = fs::read_to_string(&args.secret_key)
        .with_context(|| format!("read secret key {}", args.secret_key.display()))?;
    let _signing_key = decode_secret_key(secret_raw.trim())
        .map_err(|err| anyhow::anyhow!("decode secret key: {}", err))?;

    // Read the operator's issuing public key. The client uses it to
    // verify the ticket signature before presenting it on the wire.
    let issuer_pub_text = fs::read_to_string(&args.issuer_public_key).with_context(|| {
        format!(
            "read issuer public key {}",
            args.issuer_public_key.display()
        )
    })?;
    let issuer_public_key = decode_public_key(issuer_pub_text.trim())
        .map_err(|err| anyhow::anyhow!("decode issuer public key: {}", err))?;

    // Read + DER-decode the server cert. Pinned into the client
    // trust store before the QUIC handshake.
    let server_cert_der = fs::read(&args.server_cert)
        .with_context(|| format!("read server cert {}", args.server_cert.display()))?;

    let cfg = tunnel::TunnelConfig {
        quic_bind: "0.0.0.0:0".parse().unwrap(),
        target_addr: "127.0.0.1:0".parse().unwrap(),
        listen_addr: args.listen.parse::<SocketAddr>()?,
        relay_addr: args.relay.parse::<SocketAddr>()?,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        tunnel::connect(
            cfg,
            &args.ticket,
            &args.secret_key,
            &server_cert_der,
            &issuer_public_key,
        )
        .await?;
        // `tunnel::connect` never returns Ok normally (it runs the
        // listener forever).
        std::future::pending::<()>().await;
        Ok(())
    })
}

/// JSON-serialisable bundle of metrics from both hot-path stores plus
/// the v0.3.0 migration-trigger reminder.
///
/// Operators diff two consecutive snapshots over a known interval to
/// derive throughput; a `try_consume_calls` delta exceeding 100 in a
/// 1-second window is the migration trigger documented in
/// `docs/SECURITY-MODEL.md`.
#[derive(Debug, Serialize)]
struct MetricsSnapshot {
    nonce_store: NonceStoreMetrics,
    rate_limiter: RateLimiterMetrics,
    v0_3_0_trigger: V03Trigger,
}

#[derive(Debug, Serialize)]
struct V03Trigger {
    description: &'static str,
    note: &'static str,
}

fn metrics_cmd(args: MetricsArgs) -> Result<()> {
    // Reproducible workload on fresh stores. The numbers below are small
    // enough to fit comfortably in a single bucket but exercise every
    // counter so the JSON output is non-trivial.
    let nonce_store = NonceStore::new(args.nonce_ttl_secs);
    let rate_limiter = RateLimiter::new(args.rate_default_per_min);

    // 50 fresh nonces -> all accepted.
    for i in 0u8..50 {
        let mut nonce = [0u8; 16];
        nonce[0] = i;
        nonce_store.check_and_record(&nonce, 1_700_000_000).ok();
    }
    // 30 replays -> all rejected as replays within the TTL window.
    for i in 0u8..30 {
        let mut nonce = [0u8; 16];
        nonce[0] = i;
        nonce_store.check_and_record(&nonce, 1_700_000_010).ok();
    }

    // 20 rate-limit allows + 5 denies on a node with a 25/min budget.
    let rate_node = NodeId::from_verifying_key(&generate_signing_key().verifying_key());
    rate_limiter.set_limit(&rate_node, 25, 1_700_000_000.0);
    for _ in 0..25 {
        rate_limiter.try_consume(&rate_node, 1_700_000_000.0);
    }
    // 5 of those 25 succeed; force 5 more attempts at the same instant so
    // they all deny (bucket is empty and no time has elapsed).
    for _ in 0..5 {
        rate_limiter.try_consume(&rate_node, 1_700_000_000.0);
    }

    // Touch a second node so `tracked_nodes` reflects >1, then drain it.
    let second_node = NodeId::from_verifying_key(&generate_signing_key().verifying_key());
    for _ in 0..3 {
        rate_limiter.try_consume(&second_node, 1_700_000_000.0);
    }

    let snapshot = MetricsSnapshot {
        nonce_store: nonce_store.metrics(),
        rate_limiter: rate_limiter.metrics(),
        v0_3_0_trigger: V03Trigger {
            description: "Sustained >100 try_consume_calls / sec per edge triggers \
                migration to sharded RateLimiter/NonceStore. See docs/SECURITY-MODEL.md.",
            note: "Single snapshot only — diff two consecutive snapshots over a \
                known interval to derive throughput.",
        },
    };
    println!("{}", to_pretty_json(&snapshot)?);
    Ok(())
}
