//! The 8-phase bypass state machine.
//!
//! This module is the heart of the refactor. Each phase is a small async
//! function that takes the current engine + context and either advances
//! the state machine or falls back to rollback. Parallelism is expressed
//! via `tokio::join!` inside each phase.
//!
//! At Step 4 the phases call into `LegacyEngine` so runtime behavior stays
//! identical to the pre-refactor code. Steps 6–8 swap in native engine
//! implementations one platform at a time without touching this file.

use crate::dns::{self, DnsResult};
use crate::engine::reporter::{MechanismEvent, MechanismReporter, MechanismStatus, Phase};
use crate::engine::types::{
    ApplyPlan, Ipv4Net, MechanismTag, NetworkSnapshot, RivalMap, Strategy, VerifyReport,
};
use crate::engine::BypassEngine;
use crate::lifecycle::log_bridge;
use crate::lifecycle::strategy;
use crate::state::store::StateStore;
use crate::state::{AppliedMechanism, BypassState, BypassStatus};
use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::AppHandle;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::task::spawn_blocking;

// ===== Phase 1 — Discovery =====

pub struct DiscoveryResult {
    pub snapshot: NetworkSnapshot,
    pub dns: DnsResult,
    pub rivals: RivalMap,
    pub prior_state: Option<BypassState>,
}

/// Run Phase 1 tasks in parallel via `tokio::join!`.
///
/// Independent tasks:
///   - state::load    (blocking, disk I/O)
///   - engine.detect  (blocking, native API)
///   - dns::resolve_domains (async)
///   - engine.probe_rivals  (blocking, depends on DNS result)
///
/// The dns → probe dependency is expressed with sequential awaits inside
/// one branch of the join; the other branches run in parallel.
pub async fn phase1_discovery(
    engine: &'static dyn BypassEngine,
    store: StateStore,
    domains: Vec<String>,
    app: &AppHandle,
) -> Result<DiscoveryResult> {
    log_bridge::emit_line(app, "\n  [1/4] Keşif fazı (paralel)...\n");

    let detect_task = spawn_blocking(move || engine.detect());
    let store_for_load = store.clone();
    let load_task = spawn_blocking(move || store_for_load.load());
    let dns_task = dns::resolve_domains(&domains);

    // Run the three independent tasks concurrently.
    let (detect_res, load_res, dns_result) = tokio::join!(detect_task, load_task, dns_task);

    let snapshot = detect_res
        .context("detect task join")?
        .map_err(|e| anyhow::anyhow!("detect: {}", e))?;

    let prior_state = load_res.context("load task join")?.context("state load")?;

    for line in &dns_result.logs {
        log_bridge::emit_line(app, line.clone());
    }

    // DNS → probe_rivals dependency.
    let targets: Vec<IpAddr> = dns_result
        .exact_ips
        .iter()
        .map(|ip| IpAddr::V4(*ip))
        .collect();
    let probe_targets = targets.clone();
    let rivals = spawn_blocking(move || engine.probe_rivals(&probe_targets))
        .await
        .context("probe_rivals task join")?
        .unwrap_or_default();

    log_bridge::emit_line(
        app,
        format!(
            "    Keşif tamam: {} hedef IP, {} rakip",
            targets.len(),
            rivals.entries.len()
        ),
    );

    Ok(DiscoveryResult {
        snapshot,
        dns: dns_result,
        rivals,
        prior_state,
    })
}

// ===== Phase 2 — Plan =====

/// Produce an `ApplyPlan` from the discovery results.
///
/// Pure function (no I/O), fully testable. Strategy selection also happens
/// here via `strategy::select`.
pub fn phase2_plan(disco: &DiscoveryResult, dns_servers: &[&str]) -> ApplyPlan {
    let strategy = strategy::select(&disco.snapshot, &disco.rivals);

    // Legacy mapping:
    //   targets_host   = DNS_SERVERS (8.8.8.8, 8.8.4.4, 1.1.1.1) + exact IPs from DNS
    //   targets_subnet = /24 blocks from DnsResult.subnets
    let mut targets_host: Vec<IpAddr> = dns_servers
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .collect();
    for ip in &disco.dns.exact_ips {
        targets_host.push(IpAddr::V4(*ip));
    }
    // Dedup host IPs.
    targets_host.sort();
    targets_host.dedup();

    let targets_subnet: Vec<Ipv4Net> = disco
        .dns
        .subnets
        .iter()
        .filter_map(|s| s.parse::<Ipv4Addr>().ok())
        .map(|net| Ipv4Net::new(net, 24))
        .collect();

    let mechanisms = plan_mechanisms_for_platform(strategy);

    ApplyPlan {
        strategy,
        snapshot: disco.snapshot.clone(),
        targets_host,
        targets_subnet,
        mechanisms,
    }
}

fn plan_mechanisms_for_platform(strategy: Strategy) -> Vec<MechanismTag> {
    let mut mechs = vec![MechanismTag::KernelRoute];

    #[cfg(target_os = "macos")]
    {
        mechs.push(MechanismTag::NetworksetupRoute);
        mechs.push(MechanismTag::PfAnchor);
    }

    #[cfg(target_os = "windows")]
    {
        if strategy == Strategy::Aggressive {
            mechs.push(MechanismTag::InterfaceMetric);
        }
    }

    let _ = strategy; // silence unused on non-windows
    mechs
}

// ===== Phase 3 — Apply =====

/// Execute the plan. Runs inside `spawn_blocking` because the legacy engine
/// makes synchronous `Command::new` calls. Mechanism-type parallelism is
/// the engine's responsibility for now; the orchestrator-level parallelism
/// of Phase 3 (batched route add || PF anchor || networksetup || metric)
/// will land in Step 7/8 when the engines split into real tasks.
pub async fn phase3_apply(
    engine: &'static dyn BypassEngine,
    plan: Arc<ApplyPlan>,
    reporter: MechanismReporter,
    app: &AppHandle,
) -> Result<()> {
    log_bridge::emit_line(app, "\n  [2/4] Apply fazı...\n");
    let plan_clone = Arc::clone(&plan);
    spawn_blocking(move || engine.apply(&plan_clone, &reporter))
        .await
        .context("apply task join")?
}

// ===== Phase 4 — Verify Active =====

pub async fn phase4_verify(
    engine: &'static dyn BypassEngine,
    state: Arc<BypassState>,
    app: &AppHandle,
) -> VerifyReport {
    log_bridge::emit_line(app, "\n  [3/4] Doğrulama fazı...\n");
    let state_clone = Arc::clone(&state);
    spawn_blocking(move || engine.verify_active(&state_clone))
        .await
        .unwrap_or_else(|_| VerifyReport::empty())
}

// ===== Phase 5 — Commit =====

pub async fn phase5_commit(
    store: StateStore,
    snapshot: NetworkSnapshot,
    plan: ApplyPlan,
    strategy: Strategy,
    mechanisms: Vec<AppliedMechanism>,
    verify: VerifyReport,
    app: &AppHandle,
) -> Result<()> {
    let store_clone = store.clone();
    let state = spawn_blocking(move || {
        store_clone.update(|s| {
            s.status = BypassStatus::Active;
            s.strategy = Some(strategy);
            s.started_at = Some(now_secs());
            s.snapshot = Some(snapshot.clone());
            s.plan = Some(plan.clone());
            s.mechanisms = mechanisms.clone();
            s.last_verify = Some(verify.clone());
            s.last_error = None;
        })
    })
    .await
    .context("commit task join")??;
    let _ = state;
    log_bridge::emit_line(app, "  [4/4] Commit: bypass aktif ✓");
    Ok(())
}

// ===== Phase 6 — Rollback =====

pub async fn phase6_rollback(
    engine: &'static dyn BypassEngine,
    state: Arc<BypassState>,
    reporter: MechanismReporter,
    app: &AppHandle,
) -> Result<()> {
    log_bridge::emit_line(app, "\n  [Rollback] Mekanizmalar geri alınıyor...\n");
    let state_clone = Arc::clone(&state);
    spawn_blocking(move || engine.remove(&state_clone, &reporter))
        .await
        .context("rollback task join")?
}

// ===== Phase 7 — Verify Removal =====

pub async fn phase7_verify_removal(
    engine: &'static dyn BypassEngine,
    state: Arc<BypassState>,
    app: &AppHandle,
) -> VerifyReport {
    log_bridge::emit_line(app, "\n  [Verify] Kaldırma doğrulanıyor...\n");
    let state_clone = Arc::clone(&state);
    spawn_blocking(move || engine.verify_removed(&state_clone))
        .await
        .unwrap_or_else(|_| VerifyReport::empty())
}

// ===== Phase 8 — Commit Removal =====

pub async fn phase8_commit_removal(store: StateStore, app: &AppHandle) -> Result<()> {
    let store_clone = store.clone();
    spawn_blocking(move || store_clone.delete())
        .await
        .context("delete task join")??;
    log_bridge::emit_line(app, "  Bypass kapatıldı, state.json silindi ✓");
    Ok(())
}

// ===== State writer task =====

/// Spawns the single state_writer task that serializes all state mutations.
///
/// Returns a `JoinHandle` that completes once the channel is closed (all
/// reporters dropped). The handle resolves to the final list of applied
/// mechanisms so the orchestrator can feed it into Phase 5 Commit.
pub fn spawn_state_writer(
    mut rx: UnboundedReceiver<MechanismEvent>,
    app: AppHandle,
) -> tokio::task::JoinHandle<Vec<AppliedMechanism>> {
    tokio::spawn(async move {
        let mut applied: Vec<AppliedMechanism> = Vec::new();
        while let Some(event) = rx.recv().await {
            // Always forward detail to the UI as a log line — this preserves
            // the scrolling log feel of the old implementation.
            if !event.detail.is_empty() {
                log_bridge::emit_line(&app, event.detail.clone());
            }
            if event.status == MechanismStatus::Ok {
                if let Some(payload) = event.payload {
                    let undo_hint = match event.phase {
                        Phase::Apply => format!("{:?}", event.tag),
                        _ => format!("undo {:?}", event.tag),
                    };
                    applied.push(AppliedMechanism {
                        tag: event.tag,
                        applied_at: now_secs(),
                        payload,
                        undo_hint,
                    });
                }
            }
        }
        applied
    })
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::types::{ProxyState, WifiInterface};

    fn snap() -> NetworkSnapshot {
        NetworkSnapshot {
            wifi: WifiInterface {
                index: 0,
                name: "en0".into(),
                mac: None,
                ipv4: None,
                is_virtual: false,
                is_up: true,
                default_metric: None,
            },
            default_gateway: "192.168.1.1".parse().unwrap(),
            primary_service_name: "Wi-Fi".into(),
            proxy: ProxyState::Unknown,
            ipv6_enabled: true,
            detected_at: 0,
        }
    }

    #[test]
    fn phase2_plan_dedupes_host_targets() {
        let disco = DiscoveryResult {
            snapshot: snap(),
            dns: DnsResult {
                subnets: vec!["160.79.104.0".to_string()],
                exact_ips: vec!["8.8.8.8".parse().unwrap(), "160.79.104.10".parse().unwrap()],
                logs: vec![],
            },
            rivals: RivalMap::default(),
            prior_state: None,
        };
        let plan = phase2_plan(&disco, &["8.8.8.8", "1.1.1.1"]);
        // "8.8.8.8" comes from both DNS_SERVERS and exact_ips → dedupe.
        let count = plan
            .targets_host
            .iter()
            .filter(|ip| ip.to_string() == "8.8.8.8")
            .count();
        assert_eq!(count, 1);
        // Subnet is always /24 in legacy mode.
        assert_eq!(plan.targets_subnet[0].prefix_len, 24);
    }

    #[test]
    fn phase2_plan_defaults_to_coexistence_without_rivals() {
        let disco = DiscoveryResult {
            snapshot: snap(),
            dns: DnsResult {
                subnets: vec![],
                exact_ips: vec![],
                logs: vec![],
            },
            rivals: RivalMap::default(),
            prior_state: None,
        };
        let plan = phase2_plan(&disco, &[]);
        assert_eq!(plan.strategy, Strategy::Coexistence);
        assert!(plan.mechanisms.contains(&MechanismTag::KernelRoute));
    }
}
