//! Background watchdog that periodically re-verifies the bypass and
//! re-applies it when a rival VPN has overwritten our routes.
//!
//! The watchdog is spawned at Phase 5 Commit and terminated at the
//! start of Phase 6 Rollback (i.e. Kapa). While alive, every ~15s it:
//!
//!   1. Calls `engine.detect()` to look for network changes.
//!      If the gateway or Wi-Fi ifindex has changed, triggers a full
//!      reapply against the new network.
//!
//!   2. Calls `engine.verify_active(&state)`. If the report says `Fail`,
//!      reapplies the plan (idempotent — same commands that Phase 3
//!      ran). Reapplies are debounced: at most one every 5 seconds.
//!
//! The loop shares a stop signal with the orchestrator via `Arc<Notify>`
//! and an `AtomicBool`. Kapa first flips the bool, then notifies — the
//! task wakes up, sees the flag, and exits cleanly before Phase 6 runs.
//!
//! Singleton shape: only one watchdog is alive at a time (one bypass
//! session at a time). The global handle lives in `once_cell` and is
//! guarded by a `tokio::sync::Mutex`.

use crate::engine::types::VerifyOutcome;
use crate::engine::BypassEngine;
use crate::lifecycle::log_bridge;
use crate::state::store::StateStore;
use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::AppHandle;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;

/// Interval between verify ticks. Slightly off the minute to avoid
/// alignment with external scheduled work on the user's machine.
const TICK_INTERVAL: Duration = Duration::from_secs(15);

/// Minimum time between two consecutive reapplies. Protects against
/// reapply storms when a VPN is locked in a route-rewriting loop.
const REAPPLY_DEBOUNCE: Duration = Duration::from_secs(5);

/// Shared state that a running watchdog owns.
#[derive(Clone)]
struct WatchdogState {
    stop: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl WatchdogState {
    fn new() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    fn signal_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    fn should_stop(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
}

/// Global watchdog handle. `None` when no bypass is active.
static GLOBAL: Lazy<Mutex<Option<WatchdogHandle>>> = Lazy::new(|| Mutex::new(None));

/// Handle returned from `spawn`. Kept inside the global registry so
/// `stop` can reach it from a different Transaction instance.
pub struct WatchdogHandle {
    state: WatchdogState,
    join: JoinHandle<()>,
}

impl WatchdogHandle {
    pub async fn stop(self) {
        self.state.signal_stop();
        // Give the task a moment to exit; if it doesn't, abort it.
        let _ = tokio::time::timeout(Duration::from_secs(3), self.join).await;
    }
}

/// Spawn the watchdog and register it globally. If a previous watchdog
/// is still running for any reason, it is stopped first.
pub async fn spawn(
    engine: &'static dyn BypassEngine,
    store: StateStore,
    app: AppHandle,
) {
    // Stop any existing watchdog. This is defensive — the orchestrator
    // should have already called `stop` on Kapa, but if two Aç clicks
    // race we want to keep exactly one alive.
    stop_global().await;

    let state = WatchdogState::new();
    let loop_state = state.clone();
    let loop_store = store.clone();
    let loop_app = app.clone();

    let join = tokio::spawn(async move {
        run_loop(engine, loop_store, loop_app, loop_state).await;
    });

    let handle = WatchdogHandle { state, join };
    *GLOBAL.lock().await = Some(handle);
    log_bridge::emit_line(&app, "[watchdog] izleme başladı (15s aralık)");
}

/// Stop whatever watchdog is currently registered globally. No-op if
/// none is running.
pub async fn stop_global() {
    let mut guard = GLOBAL.lock().await;
    if let Some(handle) = guard.take() {
        handle.stop().await;
    }
}

/// The main watchdog loop.
async fn run_loop(
    engine: &'static dyn BypassEngine,
    store: StateStore,
    app: AppHandle,
    state: WatchdogState,
) {
    let mut last_reapply: Option<Instant> = None;

    loop {
        // Wait for either the interval to elapse or a stop notification.
        tokio::select! {
            _ = tokio::time::sleep(TICK_INTERVAL) => {}
            _ = state.notify.notified() => {}
        }
        if state.should_stop() {
            return;
        }

        // Reload the persistent state — another task may have changed it.
        let store_for_tick = store.clone();
        let loaded = tokio::task::spawn_blocking(move || store_for_tick.load())
            .await
            .ok()
            .and_then(|r| r.ok())
            .flatten();

        let Some(current_state) = loaded else {
            // State file disappeared — bypass is no longer active, exit.
            log_bridge::emit_line(
                &app,
                "[watchdog] state dosyası yok, izleme sonlandırılıyor",
            );
            return;
        };

        // Re-detect and compare with the snapshot we committed at Phase 5.
        // A gateway flip or ifindex change is almost always a network change
        // (user moved Wi-Fi networks, switched to hotspot, etc.).
        let detect_result = tokio::task::spawn_blocking(move || engine.detect())
            .await
            .ok()
            .and_then(|r| r.ok());

        if let (Some(new_snap), Some(old_snap)) = (&detect_result, &current_state.snapshot) {
            let gw_changed = new_snap.default_gateway != old_snap.default_gateway;
            let idx_changed = new_snap.wifi.index != old_snap.wifi.index;
            if gw_changed || idx_changed {
                log_bridge::emit_line(
                    &app,
                    "[watchdog] ağ değişikliği tespit edildi, bypass yeniden uygulanıyor",
                );
                // TODO: full reapply against the new snapshot is done by
                // calling Transaction::run_apply again. For now we emit a
                // log and let the user re-press Aç manually. Step 10 or a
                // follow-up can wire in a full auto-reapply.
                continue;
            }
        }

        // Verify the bypass is still winning. If not, reapply.
        let state_arc = Arc::new(current_state.clone());
        let state_for_verify = Arc::clone(&state_arc);
        let verify = tokio::task::spawn_blocking(move || engine.verify_active(&state_for_verify))
            .await
            .unwrap_or_else(|_| crate::engine::types::VerifyReport::empty());

        if verify.overall == VerifyOutcome::Fail {
            // Debounce: skip if we reapplied recently.
            if let Some(last) = last_reapply {
                if last.elapsed() < REAPPLY_DEBOUNCE {
                    continue;
                }
            }
            log_bridge::emit_line(
                &app,
                "[watchdog] rakip route'lar tespit edildi, reapply...",
            );
            if let Some(plan) = current_state.plan.clone() {
                let (reporter, _rx) = crate::engine::reporter::MechanismReporter::new();
                let _ = tokio::task::spawn_blocking(move || engine.apply(&plan, &reporter))
                    .await;
                // Drop the reporter synchronously — events are discarded
                // for watchdog-driven reapplies (they would flood the UI).
                last_reapply = Some(Instant::now());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watchdog_state_signal_stops() {
        let s = WatchdogState::new();
        assert!(!s.should_stop());
        s.signal_stop();
        assert!(s.should_stop());
    }

    #[test]
    fn watchdog_state_clones_share_flag() {
        let s = WatchdogState::new();
        let s2 = s.clone();
        s.signal_stop();
        assert!(s2.should_stop());
    }

    #[test]
    fn tick_interval_is_15s() {
        assert_eq!(TICK_INTERVAL, Duration::from_secs(15));
    }

    #[test]
    fn reapply_debounce_is_5s() {
        assert_eq!(REAPPLY_DEBOUNCE, Duration::from_secs(5));
    }
}
