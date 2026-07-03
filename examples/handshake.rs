//! End-to-end client-to-client handshake demo.
//!
//! Run it with:
//!
//! ```bash
//! cargo run --example handshake
//! ```
//!
//! The program generates two identities (Alice and Bob), Alice issues a
//! signed ticket for Bob, Bob's server trusts only Alice's `NodeId`, and
//! the two endpoints complete the production handshake path on loopback.
//! After the handshake Alice sends a short payload and Bob echoes it
//! back, proving the gated stream is fully bidirectional.
//!
//! The point is to show the **identity-based** essence of SnapPipe in
//! one self-contained example:
//!
//! - the ALPN comes from `DEFAULT_ALPN` (no magic strings)
//! - the ticket carries an explicit issuer and subject
//! - Bob's trust store contains exactly Alice's `NodeId`; an empty
//!   store is *not* a default-allow (`NonNullIssuer`)
//! - the nonce check, the trust check, and the signature verification
//!   all run on the hot path
//!
//! There is **no relay** in this example — the connection is direct,
//! which is the simplest possible deployment of SnapPipe and the
//! recommended starting point for new operators. See
//! `docs/OPERATIONAL-DEPLOYMENT.md` for the multi-hop patterns.

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use snappipe::quic::{
    QuicEndpointConfig, build_client_endpoint, default_server_config, self_signed_dev_cert,
};
use snappipe::session::{TrustCheck, client_handshake, server_handshake};
use snappipe::{DEFAULT_ALPN, NodeId, generate_signing_key, issue_ticket, now_unix_seconds};
use tokio::time::timeout;

/// Trust check that accepts exactly one issuer.
struct AllowOne {
    allowed: NodeId,
}

impl TrustCheck for AllowOne {
    fn is_trusted(&self, issuer: &NodeId) -> bool {
        issuer == &self.allowed
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    // 1. Two fresh identities.
    let alice_key = generate_signing_key();
    let bob_key = generate_signing_key();
    let alice_id = NodeId::from_verifying_key(&alice_key.verifying_key());
    let bob_id = NodeId::from_verifying_key(&bob_key.verifying_key());

    println!("alice_node_id={alice_id}");
    println!("bob_node_id={bob_id}");
    println!("alpn={DEFAULT_ALPN}");

    // 2. Alice issues a ticket for Bob, valid for 5 minutes.
    let now = now_unix_seconds();
    let ticket = issue_ticket(
        &alice_key,
        Some(&bob_key.verifying_key()),
        "quic://direct", // informational: no relay in this example
        DEFAULT_ALPN,
        300,
        now,
    )?;

    // 3. Self-signed dev cert for loopback testing only; production
    //    deployments should use a real CA-issued cert. Both endpoints
    //    share this cert so the client's trust anchor matches what the
    //    server presents during the QUIC handshake.
    let cert = self_signed_dev_cert(&[])?;
    let server_cfg = default_server_config(&cert)?;

    let bind: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let server =
        quinn::Endpoint::server(server_cfg, bind).map_err(|e| anyhow!("server bind: {e}"))?;
    let client = build_client_endpoint(&QuicEndpointConfig::client(bind), &cert)?;
    let server_addr = server.local_addr()?;
    println!("server_listen={server_addr}");

    // 4. Bob's trust store: only Alice is allowed.
    let trust: Arc<dyn TrustCheck> = Arc::new(AllowOne {
        allowed: alice_id.clone(),
    });

    // 5. Bob's accept loop in a background task.
    let alice_vk = alice_key.verifying_key();
    let bob_vk = bob_key.verifying_key();
    let server_task =
        tokio::spawn(async move { run_bob(server, trust, alice_vk, bob_vk, now + 300).await });

    // 6. Alice connects, completes the handshake, exchanges a payload.
    let connect = client
        .connect(server_addr, "localhost")
        .map_err(|e| anyhow!("connect attempt: {e}"))?;
    let conn = timeout(Duration::from_secs(5), connect)
        .await
        .map_err(|_| anyhow!("client connect timeout"))?
        .map_err(|e| anyhow!("client connect failed: {e}"))?;

    let summary = client_handshake(&conn, &ticket)
        .await
        .map_err(|e| anyhow!("client handshake failed: {e}"))?;
    println!(
        "client_handshake_ok issuer={} subject={}",
        summary.issuer, summary.subject
    );

    let payload = b"hello from alice";
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(payload).await?;
    send.finish()?;

    let mut buf = vec![0u8; payload.len()];
    recv.read_exact(&mut buf).await?;
    println!("client_received={:?}", String::from_utf8_lossy(&buf));

    if buf != payload {
        return Err(anyhow!(
            "echo mismatch: sent={:?} got={:?}",
            String::from_utf8_lossy(payload),
            String::from_utf8_lossy(&buf)
        ));
    }

    conn.close(0u32.into(), b"demo done");

    // 7. Drain Bob's task so the example exits cleanly.
    let bob_result = timeout(Duration::from_secs(2), server_task)
        .await
        .map_err(|_| anyhow!("server task timeout"))?
        .map_err(|e| anyhow!("server join failed: {e}"))?;
    bob_result.map_err(|e| anyhow!("bob failed: {}", source(&*e)))?;

    println!("done: identity-gated client-to-client handshake + payload echo OK");
    Ok(())
}

async fn run_bob(
    server: quinn::Endpoint,
    trust: Arc<dyn TrustCheck>,
    alice_vk: ed25519_dalek::VerifyingKey,
    bob_vk: ed25519_dalek::VerifyingKey,
    expires_at: i64,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let incoming = server
        .accept()
        .await
        .ok_or_else(|| anyhow!("no incoming"))?;
    let conn = incoming.await.map_err(|e| anyhow!("incoming await: {e}"))?;

    let (hs_send, hs_recv) = conn
        .accept_bi()
        .await
        .map_err(|e| anyhow!("accept_bi: {e}"))?;
    let summary = server_handshake(hs_send, hs_recv, &alice_vk, &bob_vk, trust, expires_at)
        .await
        .map_err(|e| anyhow!("server handshake failed: {e}"))?;
    println!(
        "server_handshake_ok issuer={} subject={}",
        summary.issuer, summary.subject
    );

    // Echo back whatever Alice sends.
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .map_err(|e| anyhow!("accept_bi: {e}"))?;
    let mut buf = vec![0u8; 4096];
    let n = recv.read(&mut buf).await?.ok_or_else(|| anyhow!("eof"))?;
    send.write_all(&buf[..n]).await?;
    send.finish()?;
    println!("server_echoed_bytes={n}");
    // Brief grace period so the client's read_exact completes before
    // the task ends and the connection is torn down.
    tokio::time::sleep(Duration::from_millis(50)).await;
    conn.close(0u32.into(), b"echo done");
    Ok(())
}

fn source(err: &(dyn Error + Send + Sync + 'static)) -> String {
    let mut chain = String::new();
    chain.push_str(&err.to_string());
    let mut next = err.source();
    while let Some(e) = next {
        chain.push_str(": ");
        chain.push_str(&e.to_string());
        next = e.source();
    }
    chain
}
