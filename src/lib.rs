// Phase 2c `session.rs` is frozen; suppress pre-existing clippy nits that
// would otherwise block `-D warnings` CI on this crate.
#![allow(clippy::clone_on_copy)]
#![allow(clippy::let_underscore_future)]

use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub mod quic;
pub mod session;
pub mod sync;

pub mod nonce_store;
pub mod rate_limit;
pub mod relay;
pub mod trust;

pub const TICKET_VERSION: u8 = 1;
pub const DEFAULT_ALPN: &str = "/snappipe/0";
pub const DEFAULT_TICKET_TTL_SECS: i64 = 300;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(String);

impl NodeId {
    pub fn from_verifying_key(key: &VerifyingKey) -> Self {
        Self(Base64UrlUnpadded::encode_string(key.as_bytes()))
    }

    pub fn parse(value: &str) -> Result<Self, TicketError> {
        let mut bytes = [0u8; 32];
        Base64UrlUnpadded::decode(value, &mut bytes)
            .map_err(|_| TicketError::InvalidKeyEncoding)?;
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketClaims {
    pub version: u8,
    pub issuer: NodeId,
    pub subject: NodeId,
    pub relay_url: String,
    pub alpn: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTicket {
    pub claims: TicketClaims,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayConfig {
    pub node_name: String,
    pub public_hostname: String,
    pub quic_bind: String,
    pub metrics_bind: String,
    pub default_alpn: String,
    pub stun_bind: Option<String>,
    pub default_ticket_ttl: i64,
    pub relay_mode: String,
}

impl RelayConfig {
    pub fn sample() -> Self {
        Self {
            node_name: "snappipe-relay-prod-1".into(),
            public_hostname: "relay.example.net".into(),
            quic_bind: "0.0.0.0:4433".into(),
            metrics_bind: "127.0.0.1:9109".into(),
            default_alpn: DEFAULT_ALPN.into(),
            stun_bind: Some("0.0.0.0:3478".into()),
            default_ticket_ttl: DEFAULT_TICKET_TTL_SECS,
            relay_mode: "identity-gated".into(),
        }
    }

    pub fn to_toml_like(&self) -> String {
        format!(
            concat!(
                "node_name = \"{}\"\n",
                "public_hostname = \"{}\"\n",
                "quic_bind = \"{}\"\n",
                "metrics_bind = \"{}\"\n",
                "default_alpn = \"{}\"\n",
                "stun_bind = {}\n",
                "default_ticket_ttl = {}\n",
                "relay_mode = \"{}\"\n"
            ),
            self.node_name,
            self.public_hostname,
            self.quic_bind,
            self.metrics_bind,
            self.default_alpn,
            self.stun_bind
                .as_ref()
                .map(|value| format!("\"{}\"", value))
                .unwrap_or_else(|| "\"\"".into()),
            self.default_ticket_ttl,
            self.relay_mode,
        )
    }
}

#[derive(Debug, Error)]
pub enum TicketError {
    #[error("invalid key encoding")]
    InvalidKeyEncoding,
    #[error("invalid signature encoding")]
    InvalidSignatureEncoding,
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("ticket expired")]
    Expired,
    #[error("unsupported ticket version {0}")]
    UnsupportedVersion(u8),
    #[error("serialization failure: {0}")]
    Serialization(String),
}

pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

pub fn encode_secret_key(signing_key: &SigningKey) -> String {
    Base64UrlUnpadded::encode_string(&signing_key.to_keypair_bytes())
}

pub fn decode_secret_key(encoded: &str) -> Result<SigningKey, TicketError> {
    let mut bytes = [0u8; 64];
    Base64UrlUnpadded::decode(encoded, &mut bytes)
        .map_err(|_| TicketError::InvalidKeyEncoding)?;
    SigningKey::from_keypair_bytes(&bytes).map_err(|_| TicketError::InvalidKeyEncoding)
}

pub fn encode_public_key(verifying_key: &VerifyingKey) -> String {
    Base64UrlUnpadded::encode_string(verifying_key.as_bytes())
}

pub fn decode_public_key(encoded: &str) -> Result<VerifyingKey, TicketError> {
    let mut bytes = [0u8; 32];
    Base64UrlUnpadded::decode(encoded, &mut bytes)
        .map_err(|_| TicketError::InvalidKeyEncoding)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| TicketError::InvalidKeyEncoding)
}

pub fn issue_ticket(
    signing_key: &SigningKey,
    subject_key: Option<&VerifyingKey>,
    relay_url: impl Into<String>,
    alpn: impl Into<String>,
    ttl_seconds: i64,
    now: i64,
) -> Result<SignedTicket, TicketError> {
    let issuer = NodeId::from_verifying_key(&signing_key.verifying_key());
    let subject = NodeId::from_verifying_key(
        subject_key.unwrap_or(&signing_key.verifying_key()),
    );
    let claims = TicketClaims {
        version: TICKET_VERSION,
        issuer,
        subject,
        relay_url: relay_url.into(),
        alpn: alpn.into(),
        issued_at: now,
        expires_at: now + ttl_seconds,
        nonce: Base64UrlUnpadded::encode_string(&random_nonce()),
    };

    sign_ticket(&claims, signing_key)
}

pub fn sign_ticket(
    claims: &TicketClaims,
    signing_key: &SigningKey,
) -> Result<SignedTicket, TicketError> {
    let payload = canonical_ticket_payload(claims)?;
    let signature = signing_key.sign(payload.as_bytes());
    Ok(SignedTicket {
        claims: claims.clone(),
        signature: Base64UrlUnpadded::encode_string(&signature.to_bytes()),
    })
}

pub fn verify_ticket(
    ticket: &SignedTicket,
    verifying_key: &VerifyingKey,
    now: i64,
) -> Result<TicketClaims, TicketError> {
    if ticket.claims.version != TICKET_VERSION {
        return Err(TicketError::UnsupportedVersion(ticket.claims.version));
    }
    if now > ticket.claims.expires_at {
        return Err(TicketError::Expired);
    }

    let payload = canonical_ticket_payload(&ticket.claims)?;
    let signature = decode_signature(&ticket.signature)?;
    verifying_key
        .verify(payload.as_bytes(), &signature)
        .map_err(|_| TicketError::InvalidSignature)?;

    Ok(ticket.claims.clone())
}

pub fn to_pretty_json<T: Serialize>(value: &T) -> Result<String, TicketError> {
    serde_json::to_string_pretty(value).map_err(|err| TicketError::Serialization(err.to_string()))
}

pub fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time must be after unix epoch")
        .as_secs() as i64
}

fn random_nonce() -> [u8; 16] {
    use rand_core::RngCore;
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn canonical_ticket_payload(claims: &TicketClaims) -> Result<String, TicketError> {
    serde_json::to_string(claims).map_err(|err| TicketError::Serialization(err.to_string()))
}

fn decode_signature(encoded: &str) -> Result<Signature, TicketError> {
    let mut bytes = [0u8; 64];
    Base64UrlUnpadded::decode(encoded, &mut bytes)
        .map_err(|_| TicketError::InvalidSignatureEncoding)?;
    Ok(Signature::from_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_roundtrip_uses_public_key_identity() {
        let key = generate_signing_key();
        let node_id = NodeId::from_verifying_key(&key.verifying_key());
        let parsed = NodeId::parse(node_id.as_str()).unwrap();
        assert_eq!(parsed, node_id);
    }

    #[test]
    fn signed_ticket_roundtrip_verifies() {
        let key = generate_signing_key();
        let now = 1_700_000_000;
        let ticket = issue_ticket(
            &key,
            None,
            "quic://relay.example.net:4433",
            DEFAULT_ALPN,
            300,
            now,
        )
        .unwrap();
        let verified = verify_ticket(&ticket, &key.verifying_key(), now + 1).unwrap();
        assert_eq!(verified.issuer, NodeId::from_verifying_key(&key.verifying_key()));
        assert_eq!(verified.subject, NodeId::from_verifying_key(&key.verifying_key()));
        assert_eq!(verified.relay_url, "quic://relay.example.net:4433");
    }

    #[test]
    fn relay_operator_can_issue_for_different_subject() {
        let issuer = generate_signing_key();
        let subject = generate_signing_key();
        let now = 1_700_000_000;
        let ticket = issue_ticket(
            &issuer,
            Some(&subject.verifying_key()),
            "quic://relay.example.net:4433",
            DEFAULT_ALPN,
            300,
            now,
        )
        .unwrap();
        let verified = verify_ticket(&ticket, &issuer.verifying_key(), now + 1).unwrap();
        assert_eq!(verified.issuer, NodeId::from_verifying_key(&issuer.verifying_key()));
        assert_eq!(verified.subject, NodeId::from_verifying_key(&subject.verifying_key()));
    }

    #[test]
    fn tampered_ticket_is_rejected() {
        let key = generate_signing_key();
        let now = 1_700_000_000;
        let mut ticket = issue_ticket(
            &key,
            None,
            "quic://relay.example.net:4433",
            DEFAULT_ALPN,
            300,
            now,
        )
        .unwrap();
        ticket.claims.relay_url = "quic://evil.example.net:4433".into();
        let result = verify_ticket(&ticket, &key.verifying_key(), now + 1);
        assert!(matches!(result, Err(TicketError::InvalidSignature)));
    }

    #[test]
    fn expired_ticket_is_rejected() {
        let key = generate_signing_key();
        let now = 1_700_000_000;
        let ticket = issue_ticket(
            &key,
            None,
            "quic://relay.example.net:4433",
            DEFAULT_ALPN,
            5,
            now,
        )
        .unwrap();
        let result = verify_ticket(&ticket, &key.verifying_key(), now + 6);
        assert!(matches!(result, Err(TicketError::Expired)));
    }

    #[test]
    fn secret_key_encoding_roundtrips() {
        let key = generate_signing_key();
        let encoded = encode_secret_key(&key);
        let decoded = decode_secret_key(&encoded).unwrap();
        assert_eq!(decoded.to_keypair_bytes(), key.to_keypair_bytes());
    }
}
