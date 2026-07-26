//! End-to-end smoke test for the TCP-over-QUIC tunnel.
//!
//! Spins up:
//! 1. A trivial TCP echo server bound on `127.0.0.1`.
//! 2. A tunnel server pointing its QUIC ALPN `/snappipe/tunnel/0` at the
//!    echo backend.
//! 3. A tunnel client connecting to the QUIC relay and exposing a
//!    local TCP listener.
//! 4. A plain TCP client connecting to the local listener; the payload
//!    must round-trip via QUIC and back.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use snappipe::decode_public_key;
use snappipe::encode_public_key;
use snappipe::encode_secret_key;
use snappipe::generate_signing_key;
use snappipe::issue_ticket;
use snappipe::now_unix_seconds;
use snappipe::quic::{QuicTransportProfile, default_server_config, self_signed_dev_cert};
use snappipe::session::{TrustCheck, allow_all_trust};
use snappipe::transport::tunnel;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const TUNNEL_PAYLOAD: &[u8; 11] = b"hello-quic!";

#[tokio::test(flavor = "multi_thread")]
async fn tunnel_round_trip_over_quic() {
    // -- Generate the operator keypair and issue a ticket ---------------------
    // Self-issued ticket: issuer == subject. This mirrors the simplest
    // end-to-end case where one operator key both signs and consumes
    // tickets (the friend's secret key IS the issuer's secret).
    let issuer = generate_signing_key();
    let subject = &issuer;
    let now = now_unix_seconds();
    let ticket = issue_ticket(
        &issuer,
        None,
        "quic://127.0.0.1:4443",
        tunnel::TUNNEL_ALPN,
        300,
        now,
    )
    .expect("ticket");

    // Persist ticket + keys to temp files (the public API of `tunnel::connect`
    // requires disk paths).
    let tmp = std::env::temp_dir().join(format!("snappipe-tunnel-{}", now));
    std::fs::create_dir_all(&tmp).expect("mkdir");
    let issuer_secret_path = tmp.join("issuer.secret");
    let issuer_public_path = tmp.join("issuer.public");
    let subject_secret_path = tmp.join("subject.secret");
    let ticket_path = tmp.join("ticket.json");
    std::fs::write(
        &issuer_secret_path,
        format!("{}\n", encode_secret_key(&issuer)),
    )
    .expect("write issuer secret");
    std::fs::write(
        &issuer_public_path,
        format!("{}\n", encode_public_key(&issuer.verifying_key())),
    )
    .expect("write issuer public");
    std::fs::write(
        &subject_secret_path,
        format!("{}\n", encode_secret_key(subject)),
    )
    .expect("write subject secret");
    let ticket_json = serde_json::to_string(&ticket).expect("ticket json");
    std::fs::write(&ticket_path, format!("{}\n", ticket_json)).expect("write ticket");

    // Decode the public key on disk to mirror the operator-side verification.
    let pub_key_text = std::fs::read_to_string(&issuer_public_path).expect("read issuer public");
    let expected_subject = decode_public_key(pub_key_text.trim()).expect("decode public");

    // -- Spin up an in-process TCP echo backend -------------------------------
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
    let echo_addr = echo_listener.local_addr().expect("echo local addr");
    let echo_handle = tokio::spawn(async move {
        if let Ok((mut tcp, _)) = echo_listener.accept().await {
            let mut buf = [0u8; 1024];
            if let Ok(n) = tcp.read(&mut buf).await {
                let _ = tcp.write_all(&buf[..n]).await;
            }
        }
    });

    // -- Build the tunnel server endpoint -------------------------------------
    let dev_cert = self_signed_dev_cert(&["localhost"]).expect("dev cert");
    let server_ep = {
        let server_cfg = default_server_config(&dev_cert).expect("server config");
        let transport = Arc::new(
            QuicTransportProfile::relay_backhaul(tunnel::TUNNEL_ALPN)
                .build_transport_config()
                .expect("transport config"),
        );
        let mut cfg = server_cfg;
        cfg.transport_config(transport);
        quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap()).expect("server endpoint")
    };
    let server_addr: SocketAddr = server_ep.local_addr().expect("server local addr");

    let trust: Arc<dyn TrustCheck> = allow_all_trust();
    let issuer_arc = Arc::new(issuer.verifying_key());
    let subject_arc = Arc::new(expected_subject);
    let cancel = Arc::new(Mutex::new(false));

    let serve_handle = {
        let cancel = Arc::clone(&cancel);
        let trust = Arc::clone(&trust);
        let issuer = Arc::clone(&issuer_arc);
        let subject = Arc::clone(&subject_arc);
        tokio::spawn(async move {
            tunnel::serve(server_ep, echo_addr, trust, issuer, subject, cancel).await
        })
    };

    // -- Build the tunnel client (local listener on a random port) -----------
    let client_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("client tcp bind");
    let listen_addr = client_listener.local_addr().expect("client local addr");

    // Build the QUIC client endpoint trusting the *same* dev cert as the
    // server. `tunnel::connect_with` is the test-friendly variant that
    // accepts pre-built endpoints. Issuer key == subject key (self-issued
    // ticket) so we pass the issuer's verifying key as the ticket signer.
    let mut client_endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client quic endpoint");
    let client_quic_cfg = snappipe::quic::default_client_config(&dev_cert).expect("client cfg");
    client_endpoint.set_default_client_config(client_quic_cfg);

    let client_handle = {
        let ticket_path = ticket_path.clone();
        let subject_secret_path = subject_secret_path.clone();
        let issuer_vk = issuer.verifying_key();
        tokio::spawn(async move {
            tunnel::connect_with(
                client_endpoint,
                client_listener,
                server_addr,
                &ticket_path,
                &issuer_vk,
                &subject_secret_path,
            )
            .await
        })
    };

    // Give the client a moment to open its QUIC connection.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // -- Connect a plain TCP client and round-trip a payload ------------------
    let mut client = TcpStream::connect(listen_addr).await.expect("tcp connect");
    client
        .write_all(TUNNEL_PAYLOAD)
        .await
        .expect("write payload");
    let mut received = [0u8; 64];
    let n = client.read(&mut received).await.expect("read payload");
    assert_eq!(
        &received[..n],
        TUNNEL_PAYLOAD,
        "echoed bytes must match the request"
    );

    // -- Teardown -------------------------------------------------------------
    *cancel.lock().await = true;
    drop(client); // close the TCP connection so the tunnel stream sees EOF.

    // Cancel propagation is not strict; allow up to 2 seconds for graceful
    // unwind so the test does not flap under CI load.
    let _ = tokio::time::timeout(Duration::from_secs(2), serve_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), client_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), echo_handle).await;

    let _ = std::fs::remove_dir_all(&tmp);
}

/// Confirm that `TunnelConfig::validate()` rejects an all-zero config.
///
/// This catches future refactors that might relax the early-fail
/// semantics.
#[test]
fn tunnel_config_rejects_all_zero_addresses() {
    use snappipe::transport::tunnel::TunnelConfig;
    let cfg = TunnelConfig {
        quic_bind: "0.0.0.0:0".parse().unwrap(),
        target_addr: "127.0.0.1:0".parse().unwrap(),
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        relay_addr: "0.0.0.0:0".parse().unwrap(),
    };
    assert!(cfg.validate().is_err());
}

/// Confirm the tunnel ALPN is distinct from the relay ALPN so existing
/// relay deployments do not start routing tunnel traffic silently.
#[test]
fn tunnel_alpn_is_distinct_from_default_alpn() {
    assert_ne!(tunnel::TUNNEL_ALPN, snappipe::DEFAULT_ALPN);
    assert!(tunnel::TUNNEL_ALPN.starts_with("/snappipe/"));
}
