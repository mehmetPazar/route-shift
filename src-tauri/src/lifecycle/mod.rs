//! Layer 3 — Lifecycle orchestrator.
//!
//! Drives the 8-phase bypass state machine:
//!
//! ```text
//! Phase 1 DISCOVERY   (parallel: state load, detect, DNS, probe, proxy)
//! Phase 2 PLAN        (sync: strategy select, ApplyPlan assembly)
//! Phase 3 APPLY       (parallel per-mechanism, batched per-type)
//! Phase 4 VERIFY      (parallel per-target: route_lookup + traceroute + TLS)
//! Phase 5 COMMIT      (sync: persist Active, spawn watchdog)
//! Phase 6 ROLLBACK    (reverse undo on failure)
//! Phase 7 VERIFY RM   (parallel per-target: VPN regained control?)
//! Phase 8 COMMIT RM   (sync: delete state, run-done)
//! ```
//!
//! See `docs: plans/zany-wandering-parrot.md`.

pub mod hooks;
pub mod log_bridge;
pub mod phases;
pub mod strategy;
pub mod watchdog;

use crate::engine::reporter::MechanismReporter;
use crate::engine::types::VerifyOutcome;
use crate::engine::{self, BypassEngine};
use crate::state::store::StateStore;
use crate::state::{BypassState, BypassStatus};
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use tauri::{AppHandle, Manager};
use tokio::task::spawn_blocking;

/// Owns the context needed to run a bypass transaction.
pub struct Transaction {
    pub engine: &'static dyn BypassEngine,
    pub app: AppHandle,
    pub store: StateStore,
}

impl Transaction {
    /// Construct a transaction using the current platform engine and the
    /// Tauri-provided `app_data_dir` as the state root.
    pub fn new(app: AppHandle) -> Result<Self> {
        let state_dir = resolve_state_dir(&app)?;
        let store = StateStore::new(&state_dir);
        Ok(Self {
            engine: engine::current_engine(),
            app,
            store,
        })
    }

    /// Execute the full Aç flow (Phases 1–5, with rollback to Phase 6 on
    /// failure).
    pub async fn run_apply(&self, domains: Vec<String>) -> Result<()> {
        // --- Phase 1: Discovery ---
        let disco = phases::phase1_discovery(self.engine, self.store.clone(), domains, &self.app)
            .await
            .context("phase1 discovery")?;

        // --- Phase 2: Plan ---
        let dns_servers = crate::network::DNS_SERVERS;
        let plan = phases::phase2_plan(&disco, dns_servers);
        let plan_arc = Arc::new(plan.clone());

        let store_clone = self.store.clone();
        let plan_for_disk = plan.clone();
        let _applying_state = spawn_blocking(move || {
            store_clone.update(|s| {
                s.status = BypassStatus::Applying;
                s.strategy = Some(plan_for_disk.strategy);
                s.snapshot = Some(plan_for_disk.snapshot.clone());
                s.plan = Some(plan_for_disk.clone());
                s.mechanisms.clear();
                s.last_error = None;
            })
        })
        .await
        .context("phase2 state flush task join")??;

        // --- Phase 3: Apply ---
        let (reporter, rx) = MechanismReporter::new();
        let writer_handle = phases::spawn_state_writer(rx, self.app.clone());

        let apply_result =
            phases::phase3_apply(self.engine, Arc::clone(&plan_arc), reporter, &self.app).await;

        // Wait for the state writer to drain all events emitted during
        // Phase 3 before we proceed. The writer exits when all reporter
        // clones are dropped — the clone held by `phase3_apply` is already
        // gone by this point because it was consumed in the spawn_blocking
        // closure.
        let mechanisms = writer_handle
            .await
            .context("state writer join")
            .unwrap_or_default();

        if let Err(apply_err) = apply_result {
            log_bridge::emit_line(
                &self.app,
                format!("HATA: apply başarısız: {}", apply_err),
            );
            // Build a transient state containing whatever mechanisms did
            // commit and roll them back.
            let rollback_state = BypassState {
                mechanisms: mechanisms.clone(),
                snapshot: Some(plan_arc.snapshot.clone()),
                ..BypassState::idle()
            };
            self.run_rollback_inner(Arc::new(rollback_state)).await.ok();
            let store_clone = self.store.clone();
            let err_msg = apply_err.to_string();
            spawn_blocking(move || {
                store_clone.update(|s| {
                    s.status = BypassStatus::Error;
                    s.last_error = Some(err_msg);
                })
            })
            .await
            .ok();
            return Err(apply_err);
        }

        // --- Phase 4: Verify Active ---
        // Build a transient state to feed verify. It includes whatever
        // mechanisms committed so verify_active can know which targets
        // to check.
        let verify_state = BypassState {
            status: BypassStatus::Active,
            strategy: Some(plan.strategy),
            snapshot: Some(plan.snapshot.clone()),
            plan: Some(plan.clone()),
            mechanisms: mechanisms.clone(),
            ..BypassState::idle()
        };
        let verify_state_arc = Arc::new(verify_state);
        let verify = phases::phase4_verify(self.engine, verify_state_arc, &self.app).await;

        if verify.overall == VerifyOutcome::Fail {
            log_bridge::emit_line(&self.app, "HATA: Verify başarısız, rollback...");
            let rollback_state = BypassState {
                mechanisms: mechanisms.clone(),
                snapshot: Some(plan.snapshot.clone()),
                ..BypassState::idle()
            };
            self.run_rollback_inner(Arc::new(rollback_state)).await.ok();
            let store_clone = self.store.clone();
            spawn_blocking(move || {
                store_clone.update(|s| {
                    s.status = BypassStatus::Error;
                    s.last_error = Some("verification failed".into());
                })
            })
            .await
            .ok();
            return Err(anyhow::anyhow!("verification failed"));
        }

        // --- Phase 5: Commit ---
        phases::phase5_commit(
            self.store.clone(),
            plan.snapshot.clone(),
            plan.clone(),
            plan.strategy,
            mechanisms,
            verify,
            &self.app,
        )
        .await?;

        // Spawn the watchdog after Commit so it only runs against a
        // fully-committed state. It stays alive until Kapa calls
        // `watchdog::stop_global` at the start of run_remove.
        watchdog::spawn(self.engine, self.store.clone(), self.app.clone()).await;

        Ok(())
    }

    /// Execute the full Kapa flow (Phases 6–8). Reads the on-disk state
    /// and undoes whatever mechanisms were recorded.
    pub async fn run_remove(&self) -> Result<()> {
        // Stop the watchdog first so it can't race with our rollback.
        watchdog::stop_global().await;

        let store_clone = self.store.clone();
        let loaded = spawn_blocking(move || store_clone.load())
            .await
            .context("load task join")??;

        let Some(state) = loaded else {
            log_bridge::emit_line(&self.app, "  Aktif bypass bulunamadı.");
            return Ok(());
        };

        // Mark Removing so a crash mid-rollback is reconcilable.
        let store_clone = self.store.clone();
        let _ = spawn_blocking(move || {
            store_clone.update(|s| {
                s.status = BypassStatus::Removing;
            })
        })
        .await;

        self.run_rollback_inner(Arc::new(state.clone())).await?;

        // Phase 7 Verify Removal (best-effort for Step 4; LegacyEngine returns Unknown).
        let _verify = phases::phase7_verify_removal(self.engine, Arc::new(state), &self.app).await;

        // Phase 8 Commit Removal
        phases::phase8_commit_removal(self.store.clone(), &self.app).await?;

        Ok(())
    }

    async fn run_rollback_inner(&self, state: Arc<BypassState>) -> Result<()> {
        let (reporter, rx) = MechanismReporter::new();
        let writer_handle = phases::spawn_state_writer(rx, self.app.clone());

        let rollback_res =
            phases::phase6_rollback(self.engine, state, reporter, &self.app).await;

        // Drain state writer after rollback reporter is dropped.
        let _ = writer_handle.await;

        rollback_res
    }
}

/// Resolve the directory where state.json should live. Uses Tauri's
/// `app_data_dir` resolver (macOS: `~/Library/Application Support/<id>`,
/// Windows: `%APPDATA%\<id>`, Linux: `$XDG_CONFIG_HOME/<id>`).
fn resolve_state_dir(app: &AppHandle) -> Result<PathBuf> {
    app.path()
        .app_data_dir()
        .context("resolve app_data_dir")
}

// ============================================================
// Public entry points used by Tauri commands (behind feature flag).
// ============================================================

/// Run the Aç path via the new orchestrator. Used by `#[tauri::command]
/// bypass_run` when the `new_lifecycle` feature is enabled.
pub async fn run_add(app: AppHandle, domains: Vec<String>) -> Result<(), String> {
    let tx = Transaction::new(app.clone()).map_err(|e| e.to_string())?;
    match tx.run_apply(domains).await {
        Ok(()) => {
            log_bridge::emit_done_ok(&app, "add");
            Ok(())
        }
        Err(e) => {
            // Emit the full anyhow error chain to the log so the user sees the
            // underlying cause, not just the top-level wrapper. The short
            // message goes to `run-done` for the UI banner.
            let full = format!("{:#}", e);
            log_bridge::emit_line(&app, format!("HATA: {}", full));
            let msg = e.to_string();
            log_bridge::emit_done_err(&app, "add", msg.clone());
            Err(msg)
        }
    }
}

/// Run the Kapa path via the new orchestrator.
pub async fn run_remove(app: AppHandle) -> Result<(), String> {
    let tx = Transaction::new(app.clone()).map_err(|e| e.to_string())?;
    match tx.run_remove().await {
        Ok(()) => {
            log_bridge::emit_done_ok(&app, "remove");
            Ok(())
        }
        Err(e) => {
            let full = format!("{:#}", e);
            log_bridge::emit_line(&app, format!("HATA: {}", full));
            let msg = e.to_string();
            log_bridge::emit_done_err(&app, "remove", msg.clone());
            Err(msg)
        }
    }
}
