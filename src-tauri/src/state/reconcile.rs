//! Startup reconciliation for crashed sessions.
//!
//! Called once at app startup before the user sees any UI. Loads the
//! persisted `BypassState`, decides whether it is still valid, and either
//! reuses it, rolls it back, or moves it aside.
//!
//! ## Decision tree
//!
//! ```text
//!                   ┌─────────────────────────┐
//!                   │ state.json exists?      │
//!                   └───┬────────────┬────────┘
//!                    No │            │ Yes
//!                       ▼            ▼
//!                 Fresh()      ┌───────────────┐
//!                              │ host matches? │
//!                              └──┬─────────┬──┘
//!                              No│         │Yes
//!                                ▼         ▼
//!                           MovedAside   ┌─────────────┐
//!                                        │ status?     │
//!                                        └┬────────┬───┘
//!                                         │        │
//!                                         │        └─▶ Idle          → Fresh
//!                                         │
//!                                         ├─▶ Active && < 12h old
//!                                         │    verify_active() →
//!                                         │      Pass/Unknown → Reused
//!                                         │      Fail          → CleanedUp
//!                                         │
//!                                         ├─▶ Applying/Removing/Error → CleanedUp
//!                                         │
//!                                         └─▶ Anything else → CleanedUp
//! ```
//!
//! `CleanedUp` runs `engine.remove(&state, reporter)` over the recorded
//! mechanisms, then deletes the state file. This is the fix for the macOS
//! orphaned-networksetup bug: even if the app died during Apply, the next
//! launch cleans it up before the user notices anything is wrong.

use crate::engine::reporter::MechanismReporter;
use crate::engine::BypassEngine;
use crate::state::store::StateStore;
use crate::state::{BypassState, BypassStatus};
use crate::lifecycle::log_bridge;
use anyhow::Result;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::AppHandle;

/// How old an Active state may be before reconcile treats it as stale.
/// 12 hours is long enough for a typical workday, short enough that a
/// stale state definitely reflects a crashed or abandoned session.
const STALE_ACTIVE_SECONDS: u64 = 12 * 3600;

/// Outcome of a reconcile run. Used only for logging/tests.
#[derive(Debug, PartialEq, Eq)]
pub enum ReconcileOutcome {
    /// No state file existed — nothing to reconcile.
    Fresh,
    /// State was from a different host and got moved aside to `state.json.bak`.
    MovedAside,
    /// Active state was still valid; left on disk as-is.
    Reused,
    /// Some mechanisms were rolled back and the state file was deleted.
    CleanedUp,
}

/// Run the reconciliation decision tree against a given store and engine.
///
/// This function is intentionally synchronous — it's called from the Tauri
/// `.setup()` closure before any windows are visible. All engine calls
/// use the existing sync trait methods; the caller can wrap the entire
/// reconcile in `tauri::async_runtime::spawn` if it wants to run async.
pub fn reconcile(
    app: &AppHandle,
    engine: &'static dyn BypassEngine,
    store: &StateStore,
) -> Result<ReconcileOutcome> {
    let Some(state) = store.load()? else {
        return Ok(ReconcileOutcome::Fresh);
    };

    if !state.host_matches() {
        log_bridge::emit_line(
            app,
            "[reconcile] state farklı bir makineden, bak dosyasına taşındı",
        );
        store.move_aside()?;
        return Ok(ReconcileOutcome::MovedAside);
    }

    // Stale check: any state older than STALE_ACTIVE_SECONDS gets cleaned
    // up regardless of status. This catches the case where the user quit
    // last night and woke up on a completely different network.
    if is_stale(&state) {
        log_bridge::emit_line(
            app,
            "[reconcile] 12 saatten eski state tespit edildi, temizleniyor",
        );
        return rollback_and_clear(app, engine, store, state);
    }

    match state.status {
        BypassStatus::Idle => {
            // Committed clean shutdown. Just leave it.
            Ok(ReconcileOutcome::Reused)
        }
        BypassStatus::Active => {
            if !state.has_committed_mechanisms() {
                // Active with nothing committed is nonsense — treat as idle.
                log_bridge::emit_line(
                    app,
                    "[reconcile] Active state mekanizmasız, idle'a düşürülüyor",
                );
                store.delete()?;
                return Ok(ReconcileOutcome::CleanedUp);
            }
            // LegacyEngine returns Unknown (no verification). Step 6+ gives
            // real verdicts; reconcile will then catch drift automatically.
            let report = engine.verify_active(&state);
            use crate::engine::types::VerifyOutcome;
            match report.overall {
                VerifyOutcome::Fail => {
                    log_bridge::emit_line(
                        app,
                        "[reconcile] doğrulama başarısız, eski state rollback ediliyor",
                    );
                    rollback_and_clear(app, engine, store, state)
                }
                _ => {
                    // Pass / Degraded / Unknown — trust existing state.
                    log_bridge::emit_line(
                        app,
                        "[reconcile] önceki session hâlâ geçerli, state korundu",
                    );
                    Ok(ReconcileOutcome::Reused)
                }
            }
        }
        _ => {
            // Applying, Removing, Armed, Error — transaction was interrupted.
            // Always roll back whatever mechanisms are recorded.
            log_bridge::emit_line(
                app,
                format!(
                    "[reconcile] kesilmiş transaction ({:?}) tespit edildi, rollback",
                    state.status
                ),
            );
            rollback_and_clear(app, engine, store, state)
        }
    }
}

fn rollback_and_clear(
    app: &AppHandle,
    engine: &'static dyn BypassEngine,
    store: &StateStore,
    state: BypassState,
) -> Result<ReconcileOutcome> {
    // Create a reporter wired to a local drain so the events land in the
    // UI log. We don't need the state_writer pattern here — reconcile is
    // synchronous and the events are purely informational.
    let (reporter, mut rx) = MechanismReporter::new();

    if let Err(e) = engine.remove(&state, &reporter) {
        log_bridge::emit_line(app, format!("[reconcile] rollback hatası: {}", e));
    }
    drop(reporter);

    // Drain events synchronously — the channel is now closed.
    while let Ok(event) = rx.try_recv() {
        if !event.detail.is_empty() {
            log_bridge::emit_line(app, event.detail);
        }
    }

    store.delete()?;
    Ok(ReconcileOutcome::CleanedUp)
}

fn is_stale(state: &BypassState) -> bool {
    let Some(ts) = state.started_at else {
        // No timestamp — treat as stale to be safe.
        return true;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now.saturating_sub(ts) > STALE_ACTIVE_SECONDS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::BypassState;

    #[test]
    fn stale_check_no_timestamp_is_stale() {
        let s = BypassState::idle();
        assert!(is_stale(&s));
    }

    #[test]
    fn stale_check_recent_is_not_stale() {
        let mut s = BypassState::idle();
        s.started_at = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - 10,
        );
        assert!(!is_stale(&s));
    }

    #[test]
    fn stale_check_old_is_stale() {
        let mut s = BypassState::idle();
        s.started_at = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .saturating_sub(STALE_ACTIVE_SECONDS + 60),
        );
        assert!(is_stale(&s));
    }
}
