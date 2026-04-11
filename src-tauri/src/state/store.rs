//! Atomic BypassState persistence.
//!
//! All writes go through `write_atomic`: write to `state.json.tmp`,
//! `fsync`, then `rename` over `state.json`. This guarantees the on-disk
//! file is never observed in a half-written state, even if the process
//! crashes or loses power mid-write.
//!
//! This module is deliberately synchronous — BypassState writes are tiny
//! (kilobytes) and happen at well-defined lifecycle boundaries, not in
//! hot paths. Making them sync simplifies crash-safety reasoning.

use super::{BypassState, STATE_SCHEMA_VERSION};
use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// File name used inside the Tauri `app_data_dir()` directory.
pub const STATE_FILE_NAME: &str = "state.json";

/// Handle to the on-disk state file. Cheap to clone (it's just a path).
#[derive(Debug, Clone)]
pub struct StateStore {
    path: PathBuf,
}

impl StateStore {
    /// Build a store rooted at an arbitrary directory. The directory is
    /// created on demand on first write. Tests use this with a `tempfile::TempDir`.
    pub fn new(dir: impl AsRef<Path>) -> Self {
        Self {
            path: dir.as_ref().join(STATE_FILE_NAME),
        }
    }

    /// Absolute path to the on-disk state file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load the current state. Returns `Ok(None)` if the file does not exist.
    ///
    /// Version check: if the on-disk schema is newer than we know, returns
    /// an error so the app can warn the user rather than corrupt data.
    pub fn load(&self) -> Result<Option<BypassState>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&self.path)
            .with_context(|| format!("read state file {}", self.path.display()))?;
        if bytes.is_empty() {
            return Ok(None);
        }
        let state: BypassState = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse state file {}", self.path.display()))?;
        if state.version > STATE_SCHEMA_VERSION {
            anyhow::bail!(
                "state file version {} is newer than supported {}",
                state.version,
                STATE_SCHEMA_VERSION
            );
        }
        Ok(Some(state))
    }

    /// Atomically persist `state` to disk.
    pub fn save(&self, state: &BypassState) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create state dir {}", parent.display()))?;
        }
        let json = serde_json::to_vec_pretty(state).context("serialize state")?;
        write_atomic(&self.path, &json)
            .with_context(|| format!("atomic write state file {}", self.path.display()))?;
        Ok(())
    }

    /// Load → mutate → save pattern. Safe to use from the state_writer task.
    /// Callers that only hold a reference (for read-only inspection) should
    /// use `load()` directly.
    pub fn update<F>(&self, f: F) -> Result<BypassState>
    where
        F: FnOnce(&mut BypassState),
    {
        let mut state = self.load()?.unwrap_or_else(BypassState::idle);
        f(&mut state);
        self.save(&state)?;
        Ok(state)
    }

    /// Remove the state file. No-op if it doesn't exist.
    pub fn delete(&self) -> Result<()> {
        if self.path.exists() {
            fs::remove_file(&self.path)
                .with_context(|| format!("delete state file {}", self.path.display()))?;
        }
        Ok(())
    }

    /// Move the current file aside as `state.json.bak`. Used by reconcile
    /// when a host-fingerprint mismatch is detected — we don't want to
    /// lose the user's data, but we can't trust it either.
    pub fn move_aside(&self) -> Result<()> {
        if !self.path.exists() {
            return Ok(());
        }
        let bak = self.path.with_extension("json.bak");
        fs::rename(&self.path, &bak).with_context(|| {
            format!(
                "move state aside {} → {}",
                self.path.display(),
                bak.display()
            )
        })?;
        Ok(())
    }
}

/// Write `bytes` to `target` atomically.
///
/// Steps: create `target.tmp` → write → fsync → rename `tmp` → `target`.
/// The rename is atomic on all supported platforms for files on the same
/// filesystem.
fn write_atomic(target: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp_path = target.with_extension("json.tmp");
    // Clean any leftover tmp from a previous crash.
    let _ = fs::remove_file(&tmp_path);

    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    // Rename overwrites target atomically.
    fs::rename(&tmp_path, target)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::BypassStatus;
    use tempfile::TempDir;

    #[test]
    fn load_missing_file_returns_none() {
        let dir = TempDir::new().unwrap();
        let store = StateStore::new(dir.path());
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn save_then_load_round_trip() {
        let dir = TempDir::new().unwrap();
        let store = StateStore::new(dir.path());
        let state = BypassState::idle();
        store.save(&state).unwrap();
        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.status, BypassStatus::Idle);
        assert_eq!(loaded.version, STATE_SCHEMA_VERSION);
    }

    #[test]
    fn save_creates_parent_dir() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("a").join("b");
        let store = StateStore::new(&nested);
        store.save(&BypassState::idle()).unwrap();
        assert!(nested.join(STATE_FILE_NAME).exists());
    }

    #[test]
    fn update_mutates_and_persists() {
        let dir = TempDir::new().unwrap();
        let store = StateStore::new(dir.path());
        store
            .update(|s| {
                s.status = BypassStatus::Applying;
                s.last_error = Some("boom".into());
            })
            .unwrap();
        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.status, BypassStatus::Applying);
        assert_eq!(loaded.last_error.as_deref(), Some("boom"));
    }

    #[test]
    fn delete_removes_file() {
        let dir = TempDir::new().unwrap();
        let store = StateStore::new(dir.path());
        store.save(&BypassState::idle()).unwrap();
        assert!(store.path().exists());
        store.delete().unwrap();
        assert!(!store.path().exists());
    }

    #[test]
    fn delete_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let store = StateStore::new(dir.path());
        store.delete().unwrap();
        store.delete().unwrap();
    }

    #[test]
    fn move_aside_renames_to_bak() {
        let dir = TempDir::new().unwrap();
        let store = StateStore::new(dir.path());
        store.save(&BypassState::idle()).unwrap();
        store.move_aside().unwrap();
        assert!(!store.path().exists());
        assert!(dir.path().join("state.json.bak").exists());
    }

    #[test]
    fn move_aside_missing_is_noop() {
        let dir = TempDir::new().unwrap();
        let store = StateStore::new(dir.path());
        store.move_aside().unwrap();
        // no error, no file created
        assert!(!dir.path().join("state.json.bak").exists());
    }

    #[test]
    fn load_rejects_future_schema_version() {
        let dir = TempDir::new().unwrap();
        let store = StateStore::new(dir.path());
        let mut state = BypassState::idle();
        state.version = STATE_SCHEMA_VERSION + 1;
        store.save(&state).unwrap();
        let result = store.load();
        assert!(result.is_err(), "should reject future schema version");
    }

    #[test]
    fn load_empty_file_returns_none() {
        let dir = TempDir::new().unwrap();
        let store = StateStore::new(dir.path());
        fs::write(store.path(), b"").unwrap();
        assert!(store.load().unwrap().is_none());
    }
}
