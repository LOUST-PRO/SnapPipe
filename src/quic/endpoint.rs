//! QUIC endpoint construction for SnapPipe.
//!
//! Provides:
//! - Self-signed certificate generation for development and tests
//! - rustls-backed server and client configurations using ALPN `/snappipe/0`
//! - Quinn endpoint builders with profile-aware transport tuning
//!
//! In production, the self-signed helper must NOT be used. Operators should
//! wire in their own PKI (real cert chain + private key) and pin trusted roots
//! out-of-band.

use quinn::{ClientConfig, Endpoint, ServerConfig};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;

use super::{QuicProfileError, QuicTransportProfile};
use crate::DEFAULT_ALPN;

/// Default ALPN byte sequence advertised by both client and server configs.
/// Sourced from [`crate::DEFAULT_ALPN`] so the wire protocol identifier lives
/// in exactly one place — the lib.rs constant.
fn default_alpn_bytes() -> Vec<u8> {
    DEFAULT_ALPN.as_bytes().to_vec()
}

/// Default SAN list used by the dev self-signed cert generator.
pub const DEFAULT_DEV_SAN: &str = "localhost";

/// Roles a SnapPipe QUIC endpoint can play.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointRole {
    /// Client-only endpoint, no incoming connections.
    Client,
    /// Server endpoint, listens for incoming connections.
    Server,
    /// Combined client + server (peer role, both connect and accept).
    Peer,
}

/// User-facing knobs to spin up a QUIC endpoint with a chosen profile.
#[derive(Debug, Clone)]
pub struct QuicEndpointConfig {
    pub bind: SocketAddr,
    pub profile: QuicTransportProfile,
    pub role: EndpointRole,
}

impl QuicEndpointConfig {
    pub fn peer(bind: SocketAddr) -> Self {
        Self {
            bind,
            profile: QuicTransportProfile::low_latency_interactive(DEFAULT_ALPN),
            role: EndpointRole::Peer,
        }
    }

    pub fn server(bind: SocketAddr) -> Self {
        Self {
            bind,
            profile: QuicTransportProfile::relay_backhaul(DEFAULT_ALPN),
            role: EndpointRole::Server,
        }
    }

    pub fn client(bind: SocketAddr) -> Self {
        Self {
            bind,
            profile: QuicTransportProfile::low_latency_interactive(DEFAULT_ALPN),
            role: EndpointRole::Client,
        }
    }
}

/// Self-signed certificate and matching private key, both DER-encoded.
///
/// Convenience struct for tests, dev, and CI. Production code must replace
/// this with a real cert chain + private key loaded from disk or a secret
/// manager.
#[derive(Debug)]
pub struct DevCert {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
}

/// Errors that can arise while constructing a QUIC endpoint.
#[derive(Debug, Error)]
pub enum QuicEndpointError {
    #[error("rustls config failed: {0}")]
    Rustls(String),
    #[error("rcgen failed: {0}")]
    Rcgen(String),
    #[error("endpoint bind failed for {0}: {1}")]
    Bind(SocketAddr, String),
    #[error("profile invalid: {0}")]
    Profile(#[from] QuicProfileError),
}

/// Generate a self-signed dev certificate. SAN entries default to
/// [`DEFAULT_DEV_SAN`] (localhost) plus any extra SANs the caller passes.
pub fn self_signed_dev_cert(extra_sans: &[&str]) -> Result<DevCert, QuicEndpointError> {
    let mut sans = vec![DEFAULT_DEV_SAN.to_owned()];
    for san in extra_sans {
        sans.push((*san).to_owned());
    }

    let certified = generate_simple_self_signed(sans)
        .map_err(|err| QuicEndpointError::Rcgen(err.to_string()))?;
    let cert_der: CertificateDer<'static> = certified.cert.der().clone();
    let key_pkcs8 = PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());
    let key_der = PrivateKeyDer::from(key_pkcs8);

    Ok(DevCert {
        cert_chain: vec![cert_der],
        private_key: key_der,
    })
}

/// Build a rustls `ServerConfig` for SnapPipe, with ALPN `/snappipe/0`.
fn rustls_server_config(
    dev_cert: &DevCert,
) -> Result<Arc<rustls::ServerConfig>, QuicEndpointError> {
    let provider = rustls::crypto::ring::default_provider();
    let provider_arc = Arc::new(provider);
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider_arc)
        .with_safe_default_protocol_versions()
        .map_err(|err| QuicEndpointError::Rustls(err.to_string()))?
        .with_no_client_auth()
        .with_single_cert(
            dev_cert.cert_chain.clone(),
            dev_cert.private_key.clone_key(),
        )
        .map_err(|err| QuicEndpointError::Rustls(err.to_string()))?;
    server_crypto.alpn_protocols = vec![default_alpn_bytes()];
    Ok(Arc::new(server_crypto))
}

/// Build a rustls-backed `ClientConfig` that trusts the given dev cert as a root.
fn rustls_client_config(
    dev_cert: &DevCert,
) -> Result<Arc<rustls::ClientConfig>, QuicEndpointError> {
    let mut roots = rustls::RootCertStore::empty();
    let cert = dev_cert
        .cert_chain
        .first()
        .ok_or_else(|| QuicEndpointError::Rustls("empty cert chain".into()))?;
    roots
        .add(cert.clone())
        .map_err(|err| QuicEndpointError::Rustls(err.to_string()))?;

    let provider = rustls::crypto::ring::default_provider();
    let provider_arc = Arc::new(provider);
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider_arc)
        .with_safe_default_protocol_versions()
        .map_err(|err| QuicEndpointError::Rustls(err.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![default_alpn_bytes()];
    Ok(Arc::new(client_crypto))
}

/// Build a Quinn `ServerConfig` from a dev cert + the supplied profile.
pub fn default_server_config(dev_cert: &DevCert) -> Result<ServerConfig, QuicEndpointError> {
    let rustls_cfg = rustls_server_config(dev_cert)?;
    let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_cfg)
        .map_err(|err| QuicEndpointError::Rustls(err.to_string()))?;
    Ok(ServerConfig::with_crypto(Arc::new(quic_server_config)))
}

/// Build a Quinn `ClientConfig` that trusts the given dev cert as a root.
pub fn default_client_config(dev_cert: &DevCert) -> Result<ClientConfig, QuicEndpointError> {
    let rustls_cfg = rustls_client_config(dev_cert)?;
    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg)
        .map_err(|err| QuicEndpointError::Rustls(err.to_string()))?;
    Ok(ClientConfig::new(Arc::new(quic_client_config)))
}

/// Build a server-only Quinn endpoint bound to `cfg.bind`, using
/// `cfg.profile` for transport tuning and a self-signed dev cert.
pub fn build_server_endpoint(cfg: &QuicEndpointConfig) -> Result<Endpoint, QuicEndpointError> {
    let dev_cert = self_signed_dev_cert(&[])?;
    let mut server_config = default_server_config(&dev_cert)?;
    let transport = Arc::new(cfg.profile.build_transport_config()?);
    server_config.transport_config(transport);

    let endpoint = Endpoint::server(server_config, cfg.bind)
        .map_err(|err| QuicEndpointError::Bind(cfg.bind, err.to_string()))?;
    Ok(endpoint)
}

/// Build a client-only Quinn endpoint bound to `cfg.bind`, trusting the
/// supplied dev cert as a root.
pub fn build_client_endpoint(
    cfg: &QuicEndpointConfig,
    trust: &DevCert,
) -> Result<Endpoint, QuicEndpointError> {
    let mut client_config = default_client_config(trust)?;
    let transport = Arc::new(cfg.profile.build_transport_config()?);
    client_config.transport_config(transport);

    let mut endpoint = Endpoint::client(cfg.bind)
        .map_err(|err| QuicEndpointError::Bind(cfg.bind, err.to_string()))?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn dev_bind() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
    }

    #[test]
    fn self_signed_dev_cert_has_distinguished_chain_and_key() {
        let cert = self_signed_dev_cert(&["snap.test"]).unwrap();
        assert_eq!(cert.cert_chain.len(), 1);
        assert!(!cert.private_key.secret_der().is_empty());
    }

    #[test]
    fn rustls_server_config_advertises_snappipe_alpn() {
        let cert = self_signed_dev_cert(&[]).unwrap();
        let server_cfg = rustls_server_config(&cert).unwrap();
        let alpn: Vec<String> = server_cfg
            .alpn_protocols
            .iter()
            .map(|bytes| String::from_utf8_lossy(bytes).to_string())
            .collect();
        assert_eq!(alpn, vec![DEFAULT_ALPN.to_string()]);
        // Wire-format must match DEFAULT_ALPN exactly. If the lib.rs
        // constant ever changes, this assertion is the safety net that the
        // wire identifier stays in sync with the documented constant.
        assert_eq!(server_cfg.alpn_protocols.len(), 1);
        assert_eq!(
            server_cfg.alpn_protocols[0],
            DEFAULT_ALPN.as_bytes(),
            "ALPN wire bytes must equal DEFAULT_ALPN exactly"
        );
    }

    #[test]
    fn rustls_client_config_advertises_snappipe_alpn() {
        let cert = self_signed_dev_cert(&[]).unwrap();
        let client_cfg = rustls_client_config(&cert).unwrap();
        let alpn: Vec<String> = client_cfg
            .alpn_protocols
            .iter()
            .map(|bytes| String::from_utf8_lossy(bytes).to_string())
            .collect();
        assert_eq!(alpn, vec![DEFAULT_ALPN.to_string()]);
        assert_eq!(client_cfg.alpn_protocols.len(), 1);
        assert_eq!(
            client_cfg.alpn_protocols[0],
            DEFAULT_ALPN.as_bytes(),
            "ALPN wire bytes must equal DEFAULT_ALPN exactly"
        );
    }

    #[test]
    fn client_and_server_alpn_match() {
        // A client talking to a server with mismatched ALPN would see the
        // handshake fail with NO_APPLICATION_PROTOCOL — guard against the
        // two configs diverging by asserting equality end-to-end.
        let cert = self_signed_dev_cert(&[]).unwrap();
        let server_cfg = rustls_server_config(&cert).unwrap();
        let client_cfg = rustls_client_config(&cert).unwrap();
        assert_eq!(server_cfg.alpn_protocols, client_cfg.alpn_protocols);
    }

    #[tokio::test]
    async fn build_server_endpoint_succeeds_for_loopback() {
        let cfg = QuicEndpointConfig::server(dev_bind());
        let endpoint = build_server_endpoint(&cfg).expect("server endpoint");
        let local = endpoint.local_addr().expect("bound");
        assert!(local.ip().is_loopback());
        endpoint.close(0u32.into(), b"test done");
    }

    #[tokio::test]
    async fn build_client_endpoint_succeeds_for_loopback() {
        let trust = self_signed_dev_cert(&[]).unwrap();
        let cfg = QuicEndpointConfig::client(dev_bind());
        let endpoint = build_client_endpoint(&cfg, &trust).expect("client endpoint");
        let local = endpoint.local_addr().expect("bound");
        assert!(local.ip().is_loopback());
        endpoint.close(0u32.into(), b"test done");
    }
}
