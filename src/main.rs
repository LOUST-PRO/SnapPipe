use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use snappipe::{
    decode_public_key, decode_secret_key, encode_public_key, encode_secret_key,
    generate_signing_key, issue_ticket, now_unix_seconds, to_pretty_json, verify_ticket,
    RelayConfig, SignedTicket, DEFAULT_ALPN, DEFAULT_TICKET_TTL_SECS,
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

#[derive(Args, Debug)]
struct RelaySampleConfigArgs {
    #[arg(long)]
    output: Option<PathBuf>,
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
        fs::write(&path, &config)
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!("sample_config_path={}", path.display());
    } else {
        println!("{config}");
    }
    Ok(())
}

fn load_ticket(path: &PathBuf) -> Result<SignedTicket> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let ticket = serde_json::from_str::<SignedTicket>(raw.trim())
        .with_context(|| format!("failed to parse {} as SignedTicket JSON", path.display()))?;
    Ok(ticket)
}
