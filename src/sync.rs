//! Directory walker and mtime preservation for the SnapPipe sync plane.
//!
//! Walks a directory recursively and emits canonical [`FileEntry`] records
//! that can be serialized, diffed between hosts, and replayed to disk with
//! [`apply_mtime`] restoring POSIX mtime exactly.
//!
//! - Walks are parallel above [`PARALLEL_THRESHOLD`] entries via Rayon.
//! - Hidden dotfiles and the `.git` directory are skipped by default.
//! - Symlinks are NOT followed (security: never descend through untrusted
//!   symlinks during a sync).

use filetime::FileTime;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use thiserror::Error;
use walkdir::WalkDir;

/// Number of files above which the walk switches to a parallel collect.
pub const PARALLEL_THRESHOLD: usize = 100;

/// Canonical record describing a single regular file on disk.
///
/// `path` is always relative to the walk root and uses forward slashes.
/// `mtime_unix` is the file's POSIX mtime in seconds since the unix epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub mtime_unix: i64,
    pub executable: bool,
    pub mode: u32,
}

/// Errors that can occur while walking or applying metadata.
#[derive(Debug, Error)]
pub enum SyncError {
    #[error("path is not a directory: {0}")]
    NotADirectory(PathBuf),
    #[error("io error walking {path}: {message}")]
    Walk { path: PathBuf, message: String },
    #[error("io error setting mtime on {path}: {message}")]
    Mtime { path: PathBuf, message: String },
    #[error("entry path escapes root: {0}")]
    PathEscape(String),
}

/// Predicate applied during walk to decide whether an entry is kept.
///
/// Returning `false` excludes both the entry and its descendants.
pub trait WalkPredicate: Send + Sync {
    fn keep(&self, relative_path: &str, is_dir: bool) -> bool;
}

impl<F> WalkPredicate for F
where
    F: Fn(&str, bool) -> bool + Send + Sync,
{
    fn keep(&self, relative_path: &str, is_dir: bool) -> bool {
        (self)(relative_path, is_dir)
    }
}

/// Default predicate: skip dotfiles and `.git` to avoid syncing noise.
pub fn default_predicate() -> impl WalkPredicate {
    |rel: &str, _is_dir: bool| {
        !(rel.starts_with('.') || rel == ".git" || rel.contains("/.") || rel.starts_with("./.git"))
    }
}

/// Walk `root` recursively, returning canonical file entries sorted by path.
///
/// Entries with `path == ""` (the root itself) are excluded.
pub fn walk_dir(root: &Path) -> Result<Vec<FileEntry>, SyncError> {
    walk_dir_with(root, default_predicate())
}

/// Walk `root` recursively with a custom predicate.
pub fn walk_dir_with<P: WalkPredicate>(
    root: &Path,
    predicate: P,
) -> Result<Vec<FileEntry>, SyncError> {
    let meta = std::fs::metadata(root)
        .map_err(|err| SyncError::Walk {
            path: root.to_path_buf(),
            message: err.to_string(),
        })?;
    if !meta.is_dir() {
        return Err(SyncError::NotADirectory(root.to_path_buf()));
    }

    let collected: Mutex<Vec<FileEntry>> = Mutex::new(Vec::new());

    let iter = WalkDir::new(root).follow_links(false).into_iter();
    let entries: Vec<_> = iter
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let rel = match entry.path().strip_prefix(root) {
                Ok(p) => p.to_string_lossy().replace('\\', "/"),
                Err(_) => return false,
            };
            let rel_for_predicate = if rel.is_empty() {
                String::new()
            } else {
                rel.clone()
            };
            predicate.keep(&rel_for_predicate, entry.file_type().is_dir())
        })
        .collect();

    if entries.len() > PARALLEL_THRESHOLD {
        entries.par_iter().try_for_each(|entry| -> Result<(), SyncError> {
            if entry.file_type().is_dir() {
                return Ok(());
            }
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .map_err(|_| SyncError::PathEscape(path.to_string_lossy().to_string()))?
                .to_string_lossy()
                .replace('\\', "/");
            if rel.is_empty() {
                return Ok(());
            }
            let entry_meta = std::fs::metadata(path).map_err(|err| SyncError::Walk {
                path: path.to_path_buf(),
                message: err.to_string(),
            })?;
            let record = build_entry(&rel, &entry_meta);
            collected.lock().expect("poisoned").push(record);
            Ok(())
        })?;
    } else {
        for entry in &entries {
            if entry.file_type().is_dir() {
                continue;
            }
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .map_err(|_| SyncError::PathEscape(path.to_string_lossy().to_string()))?
                .to_string_lossy()
                .replace('\\', "/");
            if rel.is_empty() {
                continue;
            }
            let entry_meta = std::fs::metadata(path).map_err(|err| SyncError::Walk {
                path: path.to_path_buf(),
                message: err.to_string(),
            })?;
            collected
                .lock()
                .expect("poisoned")
                .push(build_entry(&rel, &entry_meta));
        }
    }

    let mut out = collected.into_inner().expect("poisoned");
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

fn build_entry(rel: &str, meta: &std::fs::Metadata) -> FileEntry {
    let mtime = meta.modified().ok().and_then(|t| {
        t.duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs() as i64)
    });
    let mode = unix_mode(meta);
    let executable = (mode & 0o111) != 0;
    FileEntry {
        path: rel.to_owned(),
        size: meta.len(),
        mtime_unix: mtime.unwrap_or(0),
        executable,
        mode,
    }
}

#[cfg(unix)]
fn unix_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode()
}

#[cfg(not(unix))]
fn unix_mode(_meta: &std::fs::Metadata) -> u32 {
    0
}

/// Apply POSIX mtime to `path` exactly as recorded in `target_unix`.
///
/// No-op when `target_unix` is `0` (treated as "unknown").
pub fn apply_mtime(path: &Path, target_unix: i64) -> Result<(), SyncError> {
    if target_unix <= 0 {
        return Ok(());
    }
    let ft = FileTime::from_unix_time(target_unix, 0);
    filetime::set_file_mtime(path, ft).map_err(|err| SyncError::Mtime {
        path: path.to_path_buf(),
        message: err.to_string(),
    })
}

/// Compute the difference between two file entry lists as `(added, removed, modified)`.
///
/// `added` are present in `target` but not in `source`.
/// `removed` are present in `source` but not in `target`.
/// `modified` are present in both but with different `(size, mtime_unix, mode)`.
pub fn diff_entries(
    source: &[FileEntry],
    target: &[FileEntry],
) -> (Vec<FileEntry>, Vec<FileEntry>, Vec<(FileEntry, FileEntry)>) {
    use std::collections::HashMap;
    let source_map: HashMap<&str, &FileEntry> =
        source.iter().map(|e| (e.path.as_str(), e)).collect();
    let target_map: HashMap<&str, &FileEntry> =
        target.iter().map(|e| (e.path.as_str(), e)).collect();

    let mut added: Vec<FileEntry> = Vec::new();
    let mut modified: Vec<(FileEntry, FileEntry)> = Vec::new();
    for (path, entry) in &target_map {
        match source_map.get(path) {
            None => added.push((*entry).clone()),
            Some(prev) if signature_changed(prev, entry) => {
                modified.push(((*prev).clone(), (*entry).clone()));
            }
            _ => {}
        }
    }

    let mut removed: Vec<FileEntry> = Vec::new();
    for (path, entry) in &source_map {
        if !target_map.contains_key(path) {
            removed.push((*entry).clone());
        }
    }

    added.sort_by(|a, b| a.path.cmp(&b.path));
    removed.sort_by(|a, b| a.path.cmp(&b.path));
    modified.sort_by(|a, b| a.0.path.cmp(&b.0.path));
    (added, removed, modified)
}

fn signature_changed(a: &FileEntry, b: &FileEntry) -> bool {
    a.size != b.size || a.mtime_unix != b.mtime_unix || a.mode != b.mode
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write_file(dir: &Path, rel: &str, body: &[u8]) -> PathBuf {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn walk_dir_returns_sorted_canonical_entries() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        write_file(root, "b.txt", b"second");
        write_file(root, "a.txt", b"first");
        write_file(root, "sub/c.txt", b"third");

        let entries = walk_dir(root).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].path, "a.txt");
        assert_eq!(entries[1].path, "b.txt");
        assert_eq!(entries[2].path, "sub/c.txt");
        assert_eq!(entries[0].size, 5);
        assert!(entries[0].mtime_unix > 0);
    }

    #[test]
    fn walk_dir_skips_dotfiles_and_git() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        write_file(root, "keep.txt", b"k");
        write_file(root, ".hidden", b"h");
        write_file(root, ".git/HEAD", b"ref: refs/heads/main");
        write_file(root, "ok/.dotfile", b"d");

        let entries = walk_dir(root).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert!(paths.contains(&"keep.txt"));
        assert!(!paths.iter().any(|p| p.starts_with(".git")));
        assert!(!paths.iter().any(|p| p.starts_with(".")));
    }

    #[test]
    fn mtime_roundtrip_via_apply_mtime() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        let target = write_file(root, "f.txt", b"hello");
        let original = FileTime::from_unix_time(1_700_000_000, 0);
        filetime::set_file_mtime(&target, original).unwrap();

        let entries = walk_dir(root).unwrap();
        assert_eq!(entries[0].mtime_unix, 1_700_000_000);

        // Change mtime, walk again, restore via apply_mtime, walk again.
        let bumped = FileTime::from_unix_time(1_800_000_000, 0);
        filetime::set_file_mtime(&target, bumped).unwrap();
        let after_bump = walk_dir(root).unwrap();
        assert_eq!(after_bump[0].mtime_unix, 1_800_000_000);

        apply_mtime(&target, entries[0].mtime_unix).unwrap();
        let restored = walk_dir(root).unwrap();
        assert_eq!(restored[0].mtime_unix, entries[0].mtime_unix);
    }

    #[test]
    fn diff_entries_detects_added_removed_modified() {
        let make = |path: &str, size: u64, mtime: i64| FileEntry {
            path: path.into(),
            size,
            mtime_unix: mtime,
            executable: false,
            mode: 0o644,
        };

        let source = vec![
            make("shared.txt", 10, 1000),
            make("gone.txt", 5, 1100),
            make("edit.txt", 7, 1200),
        ];
        let target = vec![
            make("shared.txt", 10, 1000),
            make("edit.txt", 8, 1201),
            make("new.txt", 4, 1300),
        ];

        let (added, removed, modified) = diff_entries(&source, &target);
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].path, "new.txt");
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].path, "gone.txt");
        assert_eq!(modified.len(), 1);
        assert_eq!(modified[0].0.path, "edit.txt");
        assert_eq!(modified[0].1.size, 8);
    }
}