//! Lifecycle hook handlers — glue between the orchestrator and Tauri /
//! OS-level events.
//!
//! Four distinct exit / entry paths for RouteShift:
//!
//! | Hook              | When                          | Cleanup kind |
//! |-------------------|-------------------------------|--------------|
//! | `on_startup`      | app launch, before tray icon  | reconcile    |
//! | `on_window_close` | user clicks window X          | hide only    |
//! | `on_tray_quit`    | user picks "Çıkış" from tray  | graceful     |
//! | `on_signal`       | SIGTERM/SIGINT/Ctrl+C         | emergency    |
//!
//! Graceful = full Phase 6→8 rollback with verify. Emergency = best-effort
//! synchronous rollback inside a 3s deadline, no verify. The difference
//! matters because process kill doesn't give us time to run `engine.verify`.

use crate::engine::reporter::MechanismReporter;
use crate::engine::BypassEngine;
use crate::lifecycle::log_bridge;
use crate::lifecycle::Transaction;
use crate::state::reconcile::{self, ReconcileOutcome};
use crate::state::store::StateStore;
use crate::state::BypassStatus;
use anyhow::Result;
use std::path::PathBuf;
use tauri::{AppHandle, Manager};

/// Run startup reconciliation. Called from Tauri `.setup()` once the app
/// has a handle but before the window becomes visible. Logs are emitted
/// via `log_bridge::emit_line` — the UI picks them up as soon as its
/// webview finishes loading.
///
/// Reconcile is intentionally fail-soft: if anything goes wrong we log
/// it and let the app continue in Idle state. The user can always press
/// Aç to reinitialize.
pub fn on_startup(
    app: &AppHandle,
    engine: &'static dyn BypassEngine,
) -> Result<ReconcileOutcome> {
    let state_dir = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| PathBuf::from("."));
    let store = StateStore::new(&state_dir);
    let outcome = reconcile::reconcile(app, engine, &store)?;
    log_bridge::emit_line(
        app,
        format!("[startup] reconcile sonucu: {:?}", outcome),
    );
    Ok(outcome)
}

/// Run a graceful shutdown from the tray "Çıkış" menu. Fully rolls back
/// the current bypass via the orchestrator, deletes the state file, and
/// returns. Callers are expected to call `app.exit(0)` afterwards.
pub async fn on_tray_quit(app: AppHandle) -> Result<()> {
    log_bridge::emit_line(&app, "[quit] graceful shutdown başladı");
    let tx = Transaction::new(app.clone())?;
    // run_remove is a no-op if there's no active state.
    tx.run_remove().await?;
    log_bridge::emit_line(&app, "[quit] graceful shutdown tamamlandı");
    Ok(())
}

/// Install a Ctrl+C / SIGTERM handler that runs an emergency cleanup.
/// Emergency cleanup is synchronous, does NOT verify, and has a hard
/// 3-second deadline so the process can exit quickly.
///
/// Called once from `main.rs::main()` before `tauri::Builder::run()`.
/// The handler captures the state directory path; engine + store are
/// reconstructed fresh inside the handler so nothing from the async
/// runtime is captured.
pub fn install_signal_handler(state_dir: PathBuf) {
    let result = ctrlc::set_handler(move || {
        tracing::info!("SIGINT/SIGTERM received, running emergency cleanup");
        emergency_cleanup(&state_dir);
        std::process::exit(0);
    });
    if let Err(e) = result {
        tracing::warn!("ctrlc handler install failed: {}", e);
    }
}

/// Synchronous emergency cleanup. Reads the state file, runs
/// `engine.remove` on whatever mechanisms are recorded, and swallows
/// any errors. No Tauri events (the process is about to exit anyway).
fn emergency_cleanup(state_dir: &std::path::Path) {
    let store = StateStore::new(state_dir);
    let Ok(Some(state)) = store.load() else {
        return;
    };
    if !matches!(
        state.status,
        BypassStatus::Active | BypassStatus::Applying | BypassStatus::Removing
    ) {
        return;
    }
    let engine = crate::engine::current_engine();
    // Discard the reporter events — we don't have time to process them.
    let (reporter, _rx) = MechanismReporter::new();
    let _ = engine.remove(&state, &reporter);
    // Leave the state file alone so the next launch's reconcile picks up
    // anything we couldn't clean in the 3s budget.
}
