//! Layer 3 — Platform-agnostic persistent state.
//!
//! Stores the current bypass state (idle, applying, active, removing, error)
//! to disk via Tauri's `app_data_dir()`. Enables crash-safe reconcile:
//! if the app dies mid-apply, the next launch can clean up orphaned
//! mechanisms (routes, PF anchors, networksetup entries, etc.).
//!
//! See `docs: plans/zany-wandering-parrot.md` for schema details.

pub mod store;
pub mod reconcile;

use crate::engine::reporter::MechanismPayload;
use crate::engine::types::{ApplyPlan, MechanismTag, NetworkSnapshot, Strategy, VerifyReport};
use serde::{Deserialize, Serialize};

/// Current schema version. Bump on any backwards-incompatible change.
/// Reconcile refuses to load states with a higher version than it knows.
pub const STATE_SCHEMA_VERSION: u32 = 1;

/// Top-level bypass state persisted to `state.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassState {
    pub version: u32,
    pub status: BypassStatus,
    pub strategy: Option<Strategy>,
    /// Unix seconds when Aç started. Used to age out stale states
    /// (> 12h → treat as crashed).
    pub started_at: Option<u64>,
    pub snapshot: Option<NetworkSnapshot>,
    pub plan: Option<ApplyPlan>,
    /// Committed mechanisms, in the order they were applied.
    /// Kapa walks this list IN REVERSE and invokes the matching undo.
    pub mechanisms: Vec<AppliedMechanism>,
    pub last_verify: Option<VerifyReport>,
    pub last_error: Option<String>,
    /// Host identity — reject state files that came from a different machine
    /// (e.g. Time Machine restore).
    pub host_fingerprint: HostFingerprint,
}

impl BypassState {
    /// Fresh idle state with current host fingerprint.
    pub fn idle() -> Self {
        Self {
            version: STATE_SCHEMA_VERSION,
            status: BypassStatus::Idle,
            strategy: None,
            started_at: None,
            snapshot: None,
            plan: None,
            mechanisms: Vec::new(),
            last_verify: None,
            last_error: None,
            host_fingerprint: HostFingerprint::current(),
        }
    }

    /// Is this state file from the same machine that wrote it?
    pub fn host_matches(&self) -> bool {
        self.host_fingerprint == HostFingerprint::current()
    }

    /// True when there's anything on disk / system that Kapa would need to undo.
    pub fn has_committed_mechanisms(&self) -> bool {
        !self.mechanisms.is_empty()
    }
}

/// Lifecycle status. Drives startup reconcile decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BypassStatus {
    /// No bypass active, no mechanisms committed.
    Idle,
    /// Discovery + Plan done, Apply about to start. If we find a state file
    /// in this status it means a crash between Phase 2 and Phase 3 — there
    /// should be no mechanisms to undo.
    Armed,
    /// Phase 3 Apply in progress. Crash here means partial mechanisms are
    /// committed — reconcile must run Phase 6 Rollback.
    Applying,
    /// Phase 5 Commit done. Everything is live. Watchdog running (if the
    /// process is alive).
    Active,
    /// Phase 6 Rollback in progress. Crash here means partial undo — next
    /// launch must keep rolling back.
    Removing,
    /// Something failed and the state may be inconsistent. UI surfaces this
    /// and user can retry Kapa. Reconcile will also try Rollback again.
    Error,
}

impl BypassStatus {
    /// Startup should run Rollback on these statuses.
    pub fn needs_reconcile_rollback(&self) -> bool {
        matches!(
            self,
            BypassStatus::Applying | BypassStatus::Removing | BypassStatus::Error
        )
    }
}

/// One committed mechanism. Contains enough information for Kapa to
/// produce the exact reverse operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedMechanism {
    pub tag: MechanismTag,
    pub applied_at: u64,
    pub payload: MechanismPayload,
    /// Human-readable one-liner for logs ("route -n delete 8.8.8.8/32 x3").
    pub undo_hint: String,
}

/// Identifies the machine that wrote this state file. Simple tuple;
/// comparison is all-or-nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostFingerprint {
    pub os: String,
    pub hostname: String,
    pub user: String,
}

impl HostFingerprint {
    pub fn current() -> Self {
        Self {
            os: std::env::consts::OS.to_string(),
            hostname: hostname_lookup(),
            user: username_lookup(),
        }
    }
}

fn hostname_lookup() -> String {
    // Tauri is happy with any stable string; native hostname via libc/sysinfo
    // is overkill for fingerprinting. Environment fallback is stable per login.
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn username_lookup() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_state_has_no_mechanisms() {
        let s = BypassState::idle();
        assert_eq!(s.status, BypassStatus::Idle);
        assert!(!s.has_committed_mechanisms());
        assert_eq!(s.version, STATE_SCHEMA_VERSION);
    }

    #[test]
    fn host_fingerprint_current_self_matches() {
        let s = BypassState::idle();
        assert!(s.host_matches());
    }

    #[test]
    fn status_reconcile_rules() {
        assert!(!BypassStatus::Idle.needs_reconcile_rollback());
        assert!(!BypassStatus::Active.needs_reconcile_rollback());
        assert!(!BypassStatus::Armed.needs_reconcile_rollback());
        assert!(BypassStatus::Applying.needs_reconcile_rollback());
        assert!(BypassStatus::Removing.needs_reconcile_rollback());
        assert!(BypassStatus::Error.needs_reconcile_rollback());
    }

    #[test]
    fn state_serde_round_trip() {
        let s = BypassState::idle();
        let json = serde_json::to_string(&s).unwrap();
        let back: BypassState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status, BypassStatus::Idle);
        assert_eq!(back.version, STATE_SCHEMA_VERSION);
    }
}
