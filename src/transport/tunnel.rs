//! TCP-over-QUIC tunneling for SnapPipe.
//!
//! This module adds a thin "tunnel" layer on top of the existing QUIC
//! relay stack. Two CLI subcommands are exposed by [`crate::main`]:
//!
//! - `tunnel serve` — runs on the operator's edge host, accepts QUIC
//!   tunnel connections gated by signed tickets, and forwards every
//!   incoming bidirectional stream to a single local TCP target
//!   (e.g. `127.0.0.1:5432` for an internal Postgres). All per-stream
//!   bytes are byte-pumped both ways.
//! - `tunnel connect` — runs on the trusted-peer host, binds a local
//!   TCP port (e.g. `127.0.0.1:25566`), performs the ticket-gated
//!   handshake on a single long-lived QUIC connection, and for every
//!   accepted TCP connection opens a new bidirectional QUIC stream
//!   that the server side bridges to the backend.
//!
//! The design stays close to the existing `relay` listener to avoid
//! inventing new ALPN constants or hand-off conventions: the same
//! ticket handshake is reused, only the application protocol differs.
//!
//! ## Wire model
//!
//! Stream 0 of each QUIC connection carries a SnapPipe ticket handshake
//! (see [`crate::session::server_handshake`]). Once the handshake
//! succeeds, the server accepts bidirectional streams 1..N. Each
//! such stream represents one proxied TCP connection: the server
//! dials the local target TCP socket and pumps bytes in both
//! directions; the client, on the matching end, opens a new QUIC
//! stream whenever a local TCP client connects and pumps bytes
//! through the same channel.
//!
//! ## Threat model notes
//!
//! - The server side authenticates the peer by verifying the signed
//!   ticket. Without a valid ticket (signed by the operator's
//!   issuance key) the QUIC connection is closed at handshake time.
//! - Each accepted stream consumes server resources; the
//!   `RateLimiter` and `TrustStore` gates are NOT yet wired into
//!   `tunnel::serve` — they apply to the relay listener but not
//!   to the tunnel endpoint specifically. Operators expecting
//!   per-peer rate caps at the tunnel layer must layer them on
//!   externally (e.g. via iptables connlimit or an haproxy in
//!   front) until a follow-up PR threads the existing
//!   `RateLimiter` through `tunnel::serve`.
//! - The transport does NOT add encryption or confidentiality
//!   guarantees beyond what the underlying QUIC stack already
//!   provides.
//!
//! ## Why this lives next to `relay`
//!
//! Reusing the same ALPN and handshake would break existing relay
//! deployments. The tunnel uses a separate ALPN (`/snappipe/tunnel/0`)
//! to preserve the wire-level separation between relay traffic and
//! tunnel traffic. The choice is documented in
//! `docs/OPERATIONAL-DEPLOYMENT.md`.
//!
//! ## Production caveats
//!
//! The current implementation dials the target TCP once per stream.
//! This is intentional: it keeps the failure semantics simple and
//! matches what most low-latency TCP workloads expect. Operators
//! that need connection pooling or persistent backends should
//! revisit this when scaling beyond a handful of concurrent peers.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::{Connection, Endpoint};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::session::{self, TrustCheck, server_handshake};
use crate::{SignedTicket, TicketError, decode_secret_key, quic, verify_ticket};

/// ALPN identifier reserved for TCP-over-QUIC tunnels. Kept distinct
/// from [`crate::DEFAULT_ALPN`] so existing relay deployments do not
/// silently start routing tunnel traffic.
pub const TUNNEL_ALPN: &str = "/snappipe/tunnel/0";

/// Common configuration shared by both server and client sides.
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    /// QUIC bind address for the server side. Ignored on the client.
    pub quic_bind: SocketAddr,
    /// Local TCP address the server proxies connections to
    /// (e.g. `127.0.0.1:25565`). Ignored on the client.
    pub target_addr: SocketAddr,
    /// Local TCP address the client listens on for application
    /// connections (e.g. `127.0.0.1:25566`). Ignored on the server.
    pub listen_addr: SocketAddr,
    /// Remote QUIC endpoint address (server's relay). Ignored on the
    /// server.
    pub relay_addr: SocketAddr,
}

impl TunnelConfig {
    /// Strict top-level sanity check: fail if any of the four
    /// addresses has a zero port. Use this in callers that have not
    /// yet decided which role they will play, or as a defensive
    /// check before constructing the role-aware helpers.
    pub fn validate(&self) -> Result<()> {
        if self.quic_bind.port() == 0 {
            anyhow::bail!("TunnelConfig.quic_bind port is 0");
        }
        if self.target_addr.port() == 0 {
            anyhow::bail!("TunnelConfig.target_addr port is 0");
        }
        if self.listen_addr.port() == 0 {
            anyhow::bail!("TunnelConfig.listen_addr port is 0");
        }
        if self.relay_addr.port() == 0 {
            anyhow::bail!("TunnelConfig.relay_addr port is 0");
        }
        Ok(())
    }

    /// Validate that the addresses relevant to a SERVER (`serve`)
    /// are populated. The client-side fields (`listen_addr`,
    /// `relay_addr`) are allowed to be `0.0.0.0:0` because the
    /// server-side code never reads them; the converse applies to
    /// `connect`.
    pub fn validate_server(&self) -> Result<()> {
        if self.quic_bind.port() == 0 {
            anyhow::bail!("TunnelConfig.quic_bind is required for the server role");
        }
        if self.target_addr.port() == 0 {
            anyhow::bail!("TunnelConfig.target_addr is required for the server role");
        }
        Ok(())
    }

    /// Validate that the addresses relevant to a CLIENT (`connect`)
    /// are populated. The server-side fields are allowed to be
    /// `0.0.0.0:0` because the client never reads them.
    pub fn validate_client(&self) -> Result<()> {
        if self.listen_addr.port() == 0 {
            anyhow::bail!("TunnelConfig.listen_addr is required for the client role");
        }
        if self.relay_addr.port() == 0 {
            anyhow::bail!("TunnelConfig.relay_addr is required for the client role");
        }
        Ok(())
    }
}

/// Run the tunnel server: accept QUIC connections on `endpoint`,
/// verify tickets via `trust`, and forward every incoming stream to
/// `target_addr`. Returns when `cancel` flips to `true` (cooperative
/// shutdown).
///
/// `issuer_verifying_key` is the key used to verify the ticket's
/// signature. `expected_subject` should be the operator's
/// pre-registered public key (the ticket binds itself to a subject).
pub async fn serve(
    endpoint: Endpoint,
    target_addr: SocketAddr,
    trust: Arc<dyn TrustCheck>,
    issuer_verifying_key: Arc<ed25519_dalek::VerifyingKey>,
    expected_subject: Arc<ed25519_dalek::VerifyingKey>,
    cancel: Arc<Mutex<bool>>,
) -> Result<()> {
    loop {
        // Check cancellation flag cooperatively.
        if *cancel.lock().await {
            break;
        }

        // Accept the next incoming connection.
        let incoming = endpoint.accept().await;

        let incoming = match incoming {
            Some(i) => i,
            None => {
                // Endpoint permanently closed; exit gracefully.
                break;
            }
        };

        // Complete the QUIC handshake for this incoming connection.
        let conn = match incoming.accept() {
            Ok(connecting) => match connecting.await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!(
                        "tunnel: incoming connection failed during QUIC handshake: {}",
                        e
                    );
                    continue;
                }
            },
            Err(e) => {
                eprintln!("tunnel: incoming.accept() failed: {}", e);
                continue;
            }
        };

        let target = target_addr;
        let trust = Arc::clone(&trust);
        let issuer = Arc::clone(&issuer_verifying_key);
        let subject = Arc::clone(&expected_subject);
        let cancel = Arc::clone(&cancel);

        tokio::spawn(async move {
            if let Err(err) =
                handle_tunnel_connection(conn, target, trust, issuer, subject, cancel).await
            {
                eprintln!("tunnel: connection ended with error: {}", err);
            }
        });
    }
    Ok(())
}

async fn handle_tunnel_connection(
    conn: Connection,
    target_addr: SocketAddr,
    trust: Arc<dyn TrustCheck>,
    issuer_key: Arc<ed25519_dalek::VerifyingKey>,
    expected_subject: Arc<ed25519_dalek::VerifyingKey>,
    cancel: Arc<Mutex<bool>>,
) -> Result<()> {
    // Accept the handshake stream opened by the client.
    let (hs_send, hs_recv) = conn
        .accept_bi()
        .await
        .map_err(|err| anyhow::anyhow!("accept handshake stream: {}", err))?;

    let now = crate::now_unix_seconds();
    let summary = match server_handshake(
        hs_send,
        hs_recv,
        &issuer_key,
        &expected_subject,
        trust,
        now,
    )
    .await
    {
        Ok(summary) => summary,
        Err(err) => {
            eprintln!("tunnel: handshake failed: {}", err);
            conn.close(0u8.into(), b"handshake failed");
            return Ok(());
        }
    };

    eprintln!(
        "tunnel: accepted peer={} for target={}",
        summary.subject, target_addr
    );

    // Pump streams 1..N
    loop {
        if *cancel.lock().await {
            break;
        }
        let (qs_send, qs_recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            Err(_) => break,
        };

        let target = target_addr;
        tokio::spawn(async move {
            // Dial the local TCP target and bridge.
            let (mut qs_send_for_bridge, qs_recv_for_bridge) = (qs_send, qs_recv);
            let tcp = match TcpStream::connect(target).await {
                Ok(s) => s,
                Err(err) => {
                    eprintln!("tunnel: dial target {} failed: {}", target, err);
                    let _ = qs_send_for_bridge.finish();
                    return;
                }
            };
            if let Err(err) = bridge_quic_to_tcp(qs_send_for_bridge, qs_recv_for_bridge, tcp).await
            {
                eprintln!("tunnel: bridge ended: {}", err);
            }
        });
    }
    Ok(())
}

/// Bidirectional copy between a QUIC stream pair and a TCP socket.
/// Returns when either side observes EOF or a fatal error.
async fn bridge_quic_to_tcp(
    mut qs_send: quinn::SendStream,
    mut qs_recv: quinn::RecvStream,
    tcp: TcpStream,
) -> Result<()> {
    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    let qs_to_tcp = async {
        let mut buf = [0u8; 8192];
        loop {
            match qs_recv.read(&mut buf).await {
                Ok(Some(0)) => break,
                Ok(Some(n)) => {
                    if let Err(err) = tcp_write.write_all(&buf[..n]).await {
                        eprintln!("tunnel: tcp_write error: {}", err);
                        break;
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    eprintln!("tunnel: qs_recv error: {}", err);
                    break;
                }
            }
        }
        // Half-close so the target TCP sees EOF on its read side.
        let _ = tcp_write.shutdown().await;
    };

    let tcp_to_qs = async {
        let mut buf = [0u8; 8192];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(err) = qs_send.write_all(&buf[..n]).await {
                        eprintln!("tunnel: qs_send error: {}", err);
                        break;
                    }
                }
                Err(err) => {
                    eprintln!("tunnel: tcp_read error: {}", err);
                    break;
                }
            }
        }
        let _ = qs_send.finish();
    };

    tokio::join!(qs_to_tcp, tcp_to_qs);
    Ok(())
}

/// Run the tunnel client. Takes a pre-configured QUIC client endpoint
/// (`endpoint`) — typically built with the same certificate chain the
/// server presents — and a `listener` already bound at the local TCP
/// port the application will dial.
///
/// `ticket_path` points to a JSON file containing the signed
/// [`SignedTicket`] the server will verify against the issuer key.
///
/// `issuer_public_key` is the operator's issuing VerifyingKey. It is
/// used to verify the ticket locally before presenting it on the
/// wire (defense in depth: a peer that somehow obtained a
/// self-issued ticket would still fail this check).
///
/// `client_secret_key_path` is read for compatibility with the CLI
/// surface (the secret is needed when the ticket issuer equals the
/// client key, i.e. self-issued tickets during dev/testing). The
/// server side, in production, will reject self-issued tickets
/// unless that is the explicit operator policy.
pub async fn connect_with(
    endpoint: Endpoint,
    listener: TcpListener,
    relay_addr: SocketAddr,
    ticket_path: &Path,
    issuer_public_key: &ed25519_dalek::VerifyingKey,
    client_secret_key_path: &Path,
) -> Result<()> {
    // Read and parse ticket.
    let ticket_raw = tokio::fs::read_to_string(ticket_path)
        .await
        .with_context(|| format!("read ticket {}", ticket_path.display()))?;
    let ticket: SignedTicket = serde_json::from_str(ticket_raw.trim())
        .with_context(|| format!("parse ticket {}", ticket_path.display()))?;

    // Optional client secret (for self-issued tickets during
    // dev/tests only; production clients use a separate peer key
    // that is NOT the issuer).
    let secret_raw = tokio::fs::read_to_string(client_secret_key_path)
        .await
        .with_context(|| format!("read secret key {}", client_secret_key_path.display()))?;
    let _signing_key = decode_secret_key(secret_raw.trim())
        .map_err(|err| anyhow::anyhow!("decode secret key: {}", err))?;

    // Connect to server (single long-lived QUIC connection).
    //
    // The server name MUST match the SAN the certificate was issued
    // for (e.g. `localhost` for self-signed dev certs); production
    // deployments using real PKI should override this with the
    // operator's hostname.
    let conn = endpoint
        .connect(relay_addr, "localhost")
        .map_err(|err| anyhow::anyhow!("connect to relay: {}", err))?
        .await
        .map_err(|err| anyhow::anyhow!("handshake with relay failed: {}", err))?;

    // Verify the ticket locally before sending it (defense-in-depth).
    // The ticket signature MUST be checked against the OPERATOR's
    // issuing key, not the client's key — a self-issued ticket is
    // only valid in dev/test scenarios.
    let _ =
        verify_ticket(&ticket, issuer_public_key, crate::now_unix_seconds()).map_err(|err| {
            anyhow::anyhow!(
                "ticket failed local verification ({}). Re-issue from operator.",
                ticket_error_label(&err)
            )
        })?;

    // Perform ticket handshake over stream 0.
    let _summary = session::client_handshake(&conn, &ticket)
        .await
        .map_err(|err| anyhow::anyhow!("server rejected ticket: {}", err))?;
    eprintln!("tunnel: handshake OK with {}", relay_addr);

    // Accept loop: each new TCP connection gets its own QUIC bidi stream.
    loop {
        let (tcp, peer_addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                eprintln!("tunnel: accept failed: {}", err);
                continue;
            }
        };

        let conn = conn.clone();
        tokio::spawn(async move {
            let (qs_send, qs_recv) = match conn.open_bi().await {
                Ok(pair) => pair,
                Err(err) => {
                    eprintln!("tunnel: open_bi to {} failed: {}", peer_addr, err);
                    return;
                }
            };
            if let Err(err) = bridge_quic_to_tcp(qs_send, qs_recv, tcp).await {
                eprintln!("tunnel: bridge for {} ended: {}", peer_addr, err);
            }
        });
    }
}

/// Convenience wrapper that builds the QUIC endpoint with the server's
/// certificate pinned into the client trust store. Production
/// deployments should use [`connect_with`] with a real PKI bundle
/// obtained out-of-band from the operator.
///
/// `server_cert_der` is the DER-encoded leaf certificate the server
/// presents; it is pinned into the client's root store so the TLS
/// handshake cannot succeed against an unrelated peer.
///
/// `issuer_public_key` is the operator's issuing VerifyingKey (see
/// [`connect_with`]).
///
/// `alpn` overrides the protocol identifier used during the QUIC
/// handshake; it MUST match the server's configured ALPN or the
/// handshake fails cleanly.
pub async fn connect(
    cfg: TunnelConfig,
    ticket_path: &Path,
    client_secret_key_path: &Path,
    server_cert_der: &[u8],
    issuer_public_key: &ed25519_dalek::VerifyingKey,
    alpn: &str,
) -> Result<()> {
    let listener = TcpListener::bind(cfg.listen_addr)
        .await
        .with_context(|| format!("bind local TCP {}", cfg.listen_addr))?;
    eprintln!("tunnel: client listening on TCP {}", cfg.listen_addr);

    // Build a client QUIC endpoint that pins the server's cert into
    // the trust store. This is the production path; the self-signed
    // dev cert helper is only used by the e2e test which constructs
    // both sides explicitly via `connect_with`.
    let listen_any: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut endpoint = Endpoint::client(listen_any)?;
    let client_config = quic::pinned_client_config_with_alpn(server_cert_der, alpn)?;
    endpoint.set_default_client_config(client_config);

    connect_with(
        endpoint,
        listener,
        cfg.relay_addr,
        ticket_path,
        issuer_public_key,
        client_secret_key_path,
    )
    .await
}

fn ticket_error_label(err: &TicketError) -> &'static str {
    match err {
        TicketError::Expired => "expired",
        TicketError::InvalidKeyEncoding => "invalid_key_encoding",
        TicketError::InvalidSignatureEncoding => "invalid_signature_encoding",
        TicketError::InvalidSignature => "invalid_signature",
        TicketError::UnsupportedVersion(_) => "unsupported_version",
        TicketError::Serialization(_) => "serialization",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_config_rejects_fully_empty_population() {
        // A default config with all zeros must fail all three
        // validation helpers to catch misconfiguration early in
        // `tunnel serve` / `tunnel connect`. The strict
        // `validate()` fails on any zero port; the role-aware
        // helpers fail only on the ports relevant to that role.
        let cfg = TunnelConfig {
            quic_bind: "0.0.0.0:0".parse().unwrap(),
            target_addr: "127.0.0.1:0".parse().unwrap(),
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            relay_addr: "0.0.0.0:0".parse().unwrap(),
        };
        assert!(
            cfg.validate().is_err(),
            "validate should fail when any port is zero"
        );
        assert!(
            cfg.validate_server().is_err(),
            "validate_server should fail when quic_bind and target_addr are zero"
        );
        assert!(
            cfg.validate_client().is_err(),
            "validate_client should fail when listen_addr and relay_addr are zero"
        );
    }

    #[test]
    fn tunnel_alpn_is_distinct_from_default_alpn() {
        assert_ne!(TUNNEL_ALPN, crate::DEFAULT_ALPN);
        assert!(TUNNEL_ALPN.starts_with("/snappipe/"));
    }

    #[test]
    fn ticket_error_label_covers_all_variants() {
        let cases = vec![
            (TicketError::Expired, "expired"),
            (TicketError::InvalidKeyEncoding, "invalid_key_encoding"),
            (
                TicketError::InvalidSignatureEncoding,
                "invalid_signature_encoding",
            ),
            (TicketError::InvalidSignature, "invalid_signature"),
            (TicketError::UnsupportedVersion(7), "unsupported_version"),
            (TicketError::Serialization("x".into()), "serialization"),
        ];
        for (err, label) in cases {
            assert_eq!(ticket_error_label(&err), label);
        }
    }
}
