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
    to_pretty_json, verify_ticket,
};
use std::fs;
use std::path::PathBuf;

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
