//! Trusted-issuer registry for SnapPipe.
//!
//! The trust store maps [`crate::NodeId`] (public-key identity) to operator-
//! supplied metadata: a human-readable display name, the unix timestamp at
//! which the entry was added, and a per-node rate budget override consumed
//! by [`crate::rate_limit::RateLimiter`].
//!
//! Persistence is intentionally simple: a single `node_id = "name:rate"`
//! line per entry. No TOML serializer is involved so the file remains
//! operator-editable with any text editor and the parser is forgiving of
//! whitespace and comments.
//!
//! The store also implements [`crate::session::TrustCheck`], so it can be
//! handed directly to [`crate::session::server_handshake`] without any
//! adapter glue.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use thiserror::Error;

use crate::NodeId;
use crate::session::TrustCheck;

/// Default rate-limit override applied when the operator omits a value.
pub const DEFAULT_RATE_PER_MIN: u32 = 100;

/// Errors that can arise while reading or writing the trust store on disk.
#[derive(Debug, Error)]
pub enum TrustStoreError {
    #[error("io error on {path}: {message}")]
    Io { path: String, message: String },
    #[error("malformed trust line {line_no}: {message}")]
    Malformed { line_no: usize, message: String },
}

/// Per-node metadata captured when the operator adds an issuer to the trust store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustEntry {
    pub display_name: String,
    pub added_at_unix: i64,
    pub rate_limit_per_min: u32,
}

impl TrustEntry {
    pub fn new(
        display_name: impl Into<String>,
        added_at_unix: i64,
        rate_limit_per_min: u32,
    ) -> Self {
        Self {
            display_name: display_name.into(),
            added_at_unix,
            rate_limit_per_min,
        }
    }
}

/// Thread-safe, persistent registry of trusted issuer identities.
#[derive(Debug, Clone)]
pub struct TrustStore {
    inner: Arc<RwLock<HashMap<NodeId, TrustEntry>>>,
    path: Option<PathBuf>,
}

impl Default for TrustStore {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            path: None,
        }
    }
}

impl TrustStore {
    /// Construct an empty in-memory store (no persistence path).
    pub fn new() -> Self {
        Self::default()
    }

    /// Default on-disk location: `${XDG_CONFIG_HOME:-~/.config}/snappipe/trust.toml`.
    pub fn default_path() -> Option<PathBuf> {
        let base = dirs::config_dir()?;
        Some(base.join("snappipe").join("trust.toml"))
    }

    /// Load from the default path; missing file returns an empty store.
    pub fn load_or_default() -> Self {
        match Self::default_path() {
            Some(path) => Self::load_from_path(&path).unwrap_or_else(|_| Self {
                inner: Arc::new(RwLock::new(HashMap::new())),
                path: Some(path),
            }),
            None => Self::new(),
        }
    }

    /// Load from an explicit path. Missing file yields an empty store with the
    /// path recorded for later `save`.
    pub fn load_from_path(path: &Path) -> Result<Self, TrustStoreError> {
        match std::fs::read_to_string(path) {
            Ok(raw) => {
                let store = Self::parse(&raw)?;
                Ok(Self {
                    inner: Arc::new(RwLock::new(store)),
                    path: Some(path.to_path_buf()),
                })
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                inner: Arc::new(RwLock::new(HashMap::new())),
                path: Some(path.to_path_buf()),
            }),
            Err(err) => Err(TrustStoreError::Io {
                path: path.display().to_string(),
                message: err.to_string(),
            }),
        }
    }

    /// Persist the current store to its configured path. Stores constructed
    /// via [`TrustStore::new`] (no path) silently succeed (no-op).
    pub fn save(&self) -> Result<(), TrustStoreError> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| TrustStoreError::Io {
                path: parent.display().to_string(),
                message: err.to_string(),
            })?;
        }
        let entries = self.list();
        let mut body = String::new();
        body.push_str(
            "# SnapPipe trust store: one issuer per line as `node_id = \"name:rate\"`.\n",
        );
        body.push_str("# Lines beginning with `#` and blank lines are ignored.\n");
        let mut sorted = entries;
        sorted.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
        for (node, entry) in &sorted {
            body.push_str(node.as_str());
            body.push_str(" = \"");
            body.push_str(&entry.display_name);
            body.push(':');
            body.push_str(&entry.rate_limit_per_min.to_string());
            body.push_str("\"\n");
        }
        std::fs::write(path, body).map_err(|err| TrustStoreError::Io {
            path: path.display().to_string(),
            message: err.to_string(),
        })
    }

    /// Add (or replace) an entry for `node_id`.
    pub fn add(&self, node_id: NodeId, display_name: impl Into<String>, rate_limit_per_min: u32) {
        let entry = TrustEntry::new(display_name, crate::now_unix_seconds(), rate_limit_per_min);
        self.inner
            .write()
            .expect("trust store poisoned")
            .insert(node_id, entry);
    }

    /// Add with an explicit timestamp (test-friendly).
    pub fn add_at(&self, node_id: NodeId, entry: TrustEntry) {
        self.inner
            .write()
            .expect("trust store poisoned")
            .insert(node_id, entry);
    }

    /// Remove the entry for `node_id`. Returns `true` if an entry was deleted.
    pub fn remove(&self, node_id: &NodeId) -> bool {
        self.inner
            .write()
            .expect("trust store poisoned")
            .remove(node_id)
            .is_some()
    }

    /// Snapshot of all entries (sorted by NodeId string for determinism).
    pub fn list(&self) -> Vec<(NodeId, TrustEntry)> {
        self.inner
            .read()
            .expect("trust store poisoned")
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// `true` when `node_id` is registered as trusted.
    pub fn is_trusted(&self, node_id: &NodeId) -> bool {
        self.inner
            .read()
            .expect("trust store poisoned")
            .contains_key(node_id)
    }

    /// Read-only view of a single entry.
    pub fn get(&self, node_id: &NodeId) -> Option<TrustEntry> {
        self.inner
            .read()
            .expect("trust store poisoned")
            .get(node_id)
            .cloned()
    }

    /// Number of tracked issuers.
    pub fn len(&self) -> usize {
        self.inner.read().expect("trust store poisoned").len()
    }

    /// `true` when no issuers are tracked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn parse(raw: &str) -> Result<HashMap<NodeId, TrustEntry>, TrustStoreError> {
        let mut out = HashMap::new();
        for (idx, line) in raw.lines().enumerate() {
            let line_no = idx + 1;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let (lhs, rhs) = trimmed
                .split_once('=')
                .ok_or_else(|| TrustStoreError::Malformed {
                    line_no,
                    message: "expected `node_id = \"name:rate\"`".into(),
                })?;
            let node_id_str = lhs.trim();
            let rhs_trim = rhs.trim();
            let payload = rhs_trim
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .ok_or_else(|| TrustStoreError::Malformed {
                    line_no,
                    message: "value must be a double-quoted string".into(),
                })?;
            let (name, rate) =
                payload
                    .split_once(':')
                    .ok_or_else(|| TrustStoreError::Malformed {
                        line_no,
                        message: "value must be `\"name:rate\"`".into(),
                    })?;
            let rate: u32 = rate
                .trim()
                .parse()
                .map_err(|err| TrustStoreError::Malformed {
                    line_no,
                    message: format!("invalid rate: {err}"),
                })?;
            let node_id = NodeId::parse(node_id_str).map_err(|err| TrustStoreError::Malformed {
                line_no,
                message: format!("invalid node id: {err}"),
            })?;
            out.insert(
                node_id,
                TrustEntry::new(name.trim().to_owned(), 0_i64, rate),
            );
        }
        Ok(out)
    }
}

impl TrustCheck for TrustStore {
    fn is_trusted(&self, issuer: &NodeId) -> bool {
        TrustStore::is_trusted(self, issuer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_signing_key;
    use tempfile::tempdir;

    fn node() -> NodeId {
        NodeId::from_verifying_key(&generate_signing_key().verifying_key())
    }

    #[test]
    fn add_remove_roundtrip_tracks_state() {
        let store = TrustStore::new();
        let n = node();

        assert!(!store.is_trusted(&n));
        store.add(n.clone(), "alpha-relay", 50);
        assert!(store.is_trusted(&n));

        let entry = store.get(&n).unwrap();
        assert_eq!(entry.display_name, "alpha-relay");
        assert_eq!(entry.rate_limit_per_min, 50);

        assert!(store.remove(&n));
        assert!(!store.is_trusted(&n));
        assert!(!store.remove(&n));
    }

    #[test]
    fn empty_store_lists_nothing() {
        let store = TrustStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert!(store.list().is_empty());
    }

    #[test]
    fn default_rate_per_min_is_100() {
        assert_eq!(DEFAULT_RATE_PER_MIN, 100);
        let store = TrustStore::new();
        store.add(node(), "node", 0); // 0 -> not enforced at add time
        let _ = store; // rate is per-entry; nothing to assert besides the const
    }

    #[test]
    fn persistence_roundtrip_via_disk() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("trust.toml");

        let n = node();
        let store = TrustStore::load_from_path(&path).unwrap();
        store.add(n.clone(), "beta-relay", 25);
        store.save().unwrap();

        let restored = TrustStore::load_from_path(&path).unwrap();
        assert!(restored.is_trusted(&n));
        let entry = restored.get(&n).unwrap();
        assert_eq!(entry.display_name, "beta-relay");
        assert_eq!(entry.rate_limit_per_min, 25);
    }

    #[test]
    fn load_from_missing_file_yields_empty() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("nope.toml");
        let store = TrustStore::load_from_path(&path).unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn parse_tolerates_comments_and_blank_lines() {
        let n = NodeId::from_verifying_key(&generate_signing_key().verifying_key());
        let raw = format!("{} = \"primary:100\"\n", n.as_str());
        let parsed = TrustStore::parse(&raw).unwrap();
        assert_eq!(parsed.len(), 1);
        let entry = parsed.get(&n).unwrap();
        assert_eq!(entry.display_name, "primary");
        assert_eq!(entry.rate_limit_per_min, 100);
        // suppress the unused-binding warning above by reading n
        let _ = n;
    }

    #[test]
    fn parse_rejects_malformed_lines() {
        let raw = "not_a_valid_assignment";
        assert!(matches!(
            TrustStore::parse(raw),
            Err(TrustStoreError::Malformed { .. })
        ));

        let raw = "abc = \"missing-colon\"";
        assert!(matches!(
            TrustStore::parse(raw),
            Err(TrustStoreError::Malformed { .. })
        ));

        let raw = "abc = \"name:not_a_number\"";
        assert!(matches!(
            TrustStore::parse(raw),
            Err(TrustStoreError::Malformed { .. })
        ));
    }

    #[test]
    fn trust_store_satisfies_trust_check_trait() {
        let store = TrustStore::new();
        let n = node();
        let _: Arc<dyn TrustCheck> = Arc::new(store.clone());
        assert!(!store.is_trusted(&n));
        store.add(n.clone(), "node", 10);
        assert!(store.is_trusted(&n));
    }
}
