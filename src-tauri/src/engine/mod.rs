//! Layer 2 — BypassEngine trait and supporting types.
//!
//! This module defines the platform-agnostic contract that each OS-specific
//! engine (Windows, macOS, Linux) must implement. The lifecycle orchestrator
//! in `crate::lifecycle` drives engines through the 8-phase state machine.
//!
//! The trait is synchronous — callers (the orchestrator) are expected to
//! invoke engine methods from `tokio::task::spawn_blocking` when they need
//! to interleave with other async work.
//!
//! See `docs: plans/zany-wandering-parrot.md` for the full architecture.

pub mod adapter;
pub mod reporter;
pub mod types;

use crate::state::BypassState;
use reporter::MechanismReporter;
use std::net::IpAddr;
use types::{ApplyPlan, NetworkSnapshot, RivalMap, VerifyReport};

/// Platform-agnostic bypass contract.
///
/// Implementations are stateless — all the state they need to undo an
/// apply is passed back to them via `BypassState`. This keeps reconcile
/// simple: the orchestrator loads state, hands it to whichever engine
/// is current for this platform, and the engine does the right thing.
pub trait BypassEngine: Send + Sync + 'static {
    /// Phase 1a: inspect the current network and return an immutable snapshot.
    /// No mutations. No fallback defaults — if Wi-Fi is not present or has
    /// no gateway, this returns an error.
    fn detect(&self) -> anyhow::Result<NetworkSnapshot>;

    /// Phase 1b: for each target IP, determine which route entry currently
    /// owns it (gateway, interface, prefix length). The lifecycle
    /// strategy selector uses this to choose Coexistence vs Aggressive.
    ///
    /// An empty `RivalMap` is equivalent to "no known rivals" which steers
    /// the selector toward Coexistence (the safe default).
    fn probe_rivals(&self, targets: &[IpAddr]) -> anyhow::Result<RivalMap>;

    /// Phase 3: apply the plan. Each committed mechanism should be reported
    /// via `reporter.emit(MechanismEvent::ok(...))` with a populated
    /// `MechanismPayload` so Kapa / reconcile can undo it later.
    ///
    /// Parallelism within a single engine is at the engine's discretion,
    /// but it MUST be safe to call `apply` from a single-threaded caller —
    /// the orchestrator handles cross-mechanism parallelism at the phase
    /// level.
    fn apply(&self, plan: &ApplyPlan, reporter: &MechanismReporter) -> anyhow::Result<()>;

    /// Phase 4: confirm the plan actually took effect. For each target,
    /// determine which interface the kernel would use and compare to the
    /// expected Wi-Fi interface. Optionally probe TLS.
    fn verify_active(&self, state: &BypassState) -> VerifyReport;

    /// Phase 6: undo everything recorded in `state.mechanisms`, in reverse
    /// order. Safe to call on any `BypassState` regardless of current status.
    /// Mechanisms that fail to undo should be logged via `reporter` but must
    /// not stop other undos from running.
    fn remove(&self, state: &BypassState, reporter: &MechanismReporter) -> anyhow::Result<()>;

    /// Phase 7: confirm that removal actually restored VPN control. For each
    /// target, the winning interface should NOT be Wi-Fi anymore.
    fn verify_removed(&self, state: &BypassState) -> VerifyReport;
}

/// Singleton accessor for the engine appropriate to the current platform.
///
/// At Step 3 this always returns the `LegacyEngine` adapter which delegates
/// to the existing `PlatformNetwork` static methods. Later steps will
/// replace this with native implementations (`WinEngine`, `MacEngine`, etc.).
pub fn current_engine() -> &'static dyn BypassEngine {
    use once_cell::sync::Lazy;
    static ENGINE: Lazy<adapter::LegacyEngine> = Lazy::new(adapter::LegacyEngine::new);
    &*ENGINE
}
