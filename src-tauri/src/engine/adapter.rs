//! Legacy engine adapter — implements `BypassEngine` by delegating to the
//! existing `PlatformNetwork` static methods and the inline route-command
//! builders that currently live in `main.rs`.
//!
//! **Purpose:** This adapter exists so the new lifecycle orchestrator can
//! drive the old execution paths through the new trait interface without
//! rewriting any platform code. At Step 3 nothing actually calls it yet;
//! Step 4 wires it into `lifecycle::phases`. Steps 6–8 replace it with
//! native implementations one platform at a time.
//!
//! The adapter deliberately re-emits the same log strings the legacy code
//! produced so the UI console output is byte-identical to before the
//! refactor.

use super::reporter::{MechanismEvent, MechanismPayload, MechanismReporter, Phase};
use super::types::{
    ApplyPlan, MechanismTag, NetworkSnapshot, ProxyState, RivalMap, Strategy, VerifyReport,
    WifiInterface,
};
use super::BypassEngine;
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
use crate::network::NetworkOps;
use crate::network::{NetworkConfig, PlatformNetwork, DNS_SERVERS};
use crate::state::BypassState;
use anyhow::{anyhow, Context, Result};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Thin adapter that wraps the existing platform modules.
pub struct LegacyEngine;

impl LegacyEngine {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LegacyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BypassEngine for LegacyEngine {
    fn detect(&self) -> Result<NetworkSnapshot> {
        // On Windows, prefer the native GetAdaptersAddresses path (Step 6).
        // Fixes Turkish-locale and multi-virtual-adapter detection bugs.
        #[cfg(target_os = "windows")]
        {
            return crate::network::windows::detect::detect_primary_adapter()
                .map_err(|e| anyhow!("native detect: {}", e));
        }
        // On macOS, prefer the scutil + ipconfig path (Step 8).
        // Language-independent, no `.1` gateway fallback.
        #[cfg(target_os = "macos")]
        {
            return crate::network::macos::detect::detect_primary_interface()
                .map_err(|e| anyhow!("macos detect: {}", e));
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            let logs = log_buffer();
            let cb = make_cb(&logs);
            let config = PlatformNetwork::detect_network_config(&cb)
                .map_err(|e| anyhow!("detect_network_config: {}", e))?;
            drop_logs(&logs);
            Ok(snapshot_from_config(&config))
        }
    }

    fn probe_rivals(&self, targets: &[IpAddr]) -> Result<RivalMap> {
        // On Windows, use the native GetIpForwardTable2 path (Step 6).
        // The strategy selector uses this to decide Coexistence vs
        // Aggressive. On other platforms, an empty map defaults to
        // Coexistence which is the safe choice.
        #[cfg(target_os = "windows")]
        {
            // We need the Wi-Fi ifIndex to correctly classify "rivals"
            // versus "already ours". Re-detect the primary adapter so
            // the probe has a reference.
            let snapshot = crate::network::windows::detect::detect_primary_adapter()?;
            return crate::network::windows::probe::probe_targets(
                targets,
                snapshot.wifi.index,
            );
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = targets;
            Ok(RivalMap::default())
        }
    }

    fn apply(&self, plan: &ApplyPlan, reporter: &MechanismReporter) -> Result<()> {
        apply_plan_legacy(plan, reporter)
    }

    fn verify_active(&self, _state: &BypassState) -> VerifyReport {
        // Legacy engine has no structured verification. Returning an empty
        // report (overall = Unknown) preserves existing behavior where the
        // app commits after apply without gating on verify. Steps 6–8 will
        // provide real Find-NetRoute / route-n-get-based verdicts.
        VerifyReport::empty()
    }

    fn remove(&self, state: &BypassState, reporter: &MechanismReporter) -> Result<()> {
        remove_plan_legacy(state, reporter)
    }

    fn verify_removed(&self, _state: &BypassState) -> VerifyReport {
        VerifyReport::empty()
    }
}

// ========== Helpers ==========

type SharedLog = Arc<Mutex<Vec<String>>>;

fn log_buffer() -> SharedLog {
    Arc::new(Mutex::new(Vec::new()))
}

fn make_cb(buf: &SharedLog) -> impl Fn(&str) + '_ {
    let buf = buf.clone();
    move |msg: &str| {
        if let Ok(mut guard) = buf.lock() {
            guard.push(msg.to_string());
        }
    }
}

fn drop_logs(_buf: &SharedLog) {
    // Logs are intentionally discarded here — the orchestrator captures
    // logs through MechanismReporter.emit(...) events instead. This helper
    // exists so callers can drain and discard in one place if needed.
}

fn drain_logs(buf: &SharedLog) -> Vec<String> {
    let mut guard = buf.lock().unwrap_or_else(|p| p.into_inner());
    std::mem::take(&mut *guard)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn snapshot_from_config(cfg: &NetworkConfig) -> NetworkSnapshot {
    let gateway: IpAddr = cfg
        .gateway
        .parse()
        .unwrap_or_else(|_| "0.0.0.0".parse().unwrap());

    // interface_name is the IfIndex string on Windows and the device name
    // (e.g. "en0") on macOS/Linux. Try to parse as u32 first.
    let (index, name) = match cfg.interface_name.parse::<u32>() {
        Ok(idx) => (idx, String::new()),
        Err(_) => (0, cfg.interface_name.clone()),
    };

    NetworkSnapshot {
        wifi: WifiInterface {
            index,
            name,
            mac: None,
            ipv4: None,
            is_virtual: false,
            is_up: true,
            default_metric: None,
        },
        default_gateway: gateway,
        primary_service_name: cfg.service_name.clone(),
        proxy: ProxyState::Unknown,
        ipv6_enabled: true,
        detected_at: now_secs(),
    }
}

/// Build the add-route commands for the current platform.
///
/// Windows (Step 7): uses the new `network::windows::routes` builder
/// which drops the `IF` parameter — the Ivanti bug fix. Metric 1 is
/// passed through here; Aggressive strategy additionally lowers the
/// Wi-Fi interface metric via `metric.rs` (wired at the call site).
///
/// macOS / Linux still use the legacy inline shell strings. Steps 8+
/// will replace those with their own native implementations.
#[allow(unused_variables)]
fn build_add_route_commands(
    subnets: &[String],
    exact_ips: &[String],
    gateway: &str,
    iface: &str,
) -> Vec<String> {
    let mut commands = Vec::new();

    #[cfg(target_os = "macos")]
    {
        for ip in exact_ips {
            commands.push(format!(
                "route -n delete -host {} 2>/dev/null ; route -n add -host {} {}",
                ip, ip, gateway
            ));
        }
        for subnet in subnets {
            commands.push(format!(
                "route -n delete -net {}/24 2>/dev/null ; route -n add -net {}/24 {}",
                subnet, subnet, gateway
            ));
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Use the IF-less builder from Step 7.
        use crate::network::windows::routes;
        use std::net::{IpAddr, Ipv4Addr};

        let gw_ip: IpAddr = gateway.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let exact_parsed: Vec<Ipv4Addr> =
            exact_ips.iter().filter_map(|s| s.parse().ok()).collect();
        let subnet_parsed: Vec<Ipv4Addr> =
            subnets.iter().filter_map(|s| s.parse().ok()).collect();

        commands.extend(routes::build_add_commands(
            &exact_parsed,
            &subnet_parsed,
            gw_ip,
            1, // always metric=1; Strategy decides whether to also set InterfaceMetric
        ));
    }

    #[cfg(target_os = "linux")]
    {
        for ip in exact_ips {
            commands.push(format!(
                "ip route del {}/32 2>/dev/null ; ip route add {}/32 via {} dev {}",
                ip, ip, gateway, iface
            ));
        }
        for subnet in subnets {
            commands.push(format!(
                "ip route del {}/24 2>/dev/null ; ip route add {}/24 via {} dev {}",
                subnet, subnet, gateway, iface
            ));
        }
    }

    commands
}

#[allow(unused_variables)]
fn build_remove_route_commands(subnets: &[String], exact_ips: &[String], iface: &str) -> Vec<String> {
    let mut commands = Vec::new();

    #[cfg(target_os = "macos")]
    {
        for ip in exact_ips {
            commands.push(format!(
                "route -n delete -host {} 2>/dev/null ; route -n delete -ifscope {} -host {} 2>/dev/null",
                ip, iface, ip
            ));
        }
        for subnet in subnets {
            commands.push(format!(
                "route -n delete -net {}/24 2>/dev/null ; route -n delete -ifscope {} -net {}/24 2>/dev/null",
                subnet, iface, subnet
            ));
        }
    }

    #[cfg(target_os = "windows")]
    {
        use crate::network::windows::routes;
        use std::net::Ipv4Addr;
        let exact_parsed: Vec<Ipv4Addr> =
            exact_ips.iter().filter_map(|s| s.parse().ok()).collect();
        let subnet_parsed: Vec<Ipv4Addr> =
            subnets.iter().filter_map(|s| s.parse().ok()).collect();
        commands.extend(routes::build_delete_commands(&exact_parsed, &subnet_parsed));
    }

    #[cfg(target_os = "linux")]
    {
        for ip in exact_ips {
            commands.push(format!("ip route del {}/32 2>/dev/null", ip));
        }
        for subnet in subnets {
            commands.push(format!("ip route del {}/24 2>/dev/null", subnet));
        }
    }

    commands
}

/// Extract dotted-quad strings from the ApplyPlan's typed targets. The
/// legacy command builders operate on strings so we convert here.
fn plan_to_string_targets(plan: &ApplyPlan) -> (Vec<String>, Vec<String>) {
    let exact_ips: Vec<String> = plan.targets_host.iter().map(|ip| ip.to_string()).collect();
    let subnets: Vec<String> = plan
        .targets_subnet
        .iter()
        .map(|net| net.network.to_string())
        .collect();
    (exact_ips, subnets)
}

/// Phase 3 Apply, delegating to the legacy PlatformNetwork methods.
fn apply_plan_legacy(plan: &ApplyPlan, reporter: &MechanismReporter) -> Result<()> {
    let gateway = plan.snapshot.default_gateway.to_string();
    let iface = if plan.snapshot.wifi.name.is_empty() {
        plan.snapshot.wifi.index.to_string()
    } else {
        plan.snapshot.wifi.name.clone()
    };
    let service = plan.snapshot.primary_service_name.clone();

    let (exact_ips, subnets) = plan_to_string_targets(plan);

    // ---- Windows: InterfaceMetric mechanism (Aggressive strategy only) ----
    // When Strategy is Aggressive, our /32 host routes tie specificity with
    // the VPN's own /32 rivals. Tie-break uses effective metric, which is
    // `route_metric + interface_metric`. Lowering Wi-Fi's InterfaceMetric
    // to 1 makes our total (1+1=2) beat Ivanti's typical tunnel metric.
    //
    // Save the original metric into the payload so Kapa can restore it.
    #[cfg(target_os = "windows")]
    {
        if plan.strategy == Strategy::Aggressive || plan.strategy == Strategy::Hybrid {
            apply_windows_interface_metric(plan, reporter)?;
        }
    }

    // ---- KernelRoute mechanism (all platforms) ----
    reporter.emit(MechanismEvent::started(
        MechanismTag::KernelRoute,
        Phase::Apply,
        "Route komutları çalıştırılıyor...",
    ));

    let route_logs = log_buffer();
    let cb = make_cb(&route_logs);
    let commands = build_add_route_commands(&subnets, &exact_ips, &gateway, &iface);
    let route_result = PlatformNetwork::exec_routes_elevated(&commands, &cb);
    let captured = drain_logs(&route_logs);

    match route_result {
        Ok(()) => {
            let mut cidrs: Vec<String> = Vec::new();
            for ip in &exact_ips {
                cidrs.push(format!("{}/32", ip));
            }
            for subnet in &subnets {
                cidrs.push(format!("{}/24", subnet));
            }
            reporter.emit(MechanismEvent::ok(
                MechanismTag::KernelRoute,
                Phase::Apply,
                format!("{} route eklendi", cidrs.len()),
                MechanismPayload::KernelRoutes { cidrs },
            ));
            for line in captured {
                reporter.emit(MechanismEvent::started(
                    MechanismTag::KernelRoute,
                    Phase::Apply,
                    line,
                ));
            }
        }
        Err(e) => {
            reporter.emit(MechanismEvent::failed(
                MechanismTag::KernelRoute,
                Phase::Apply,
                format!("Route ekleme hatası: {}", e),
            ));
            for line in captured {
                reporter.emit(MechanismEvent::started(
                    MechanismTag::KernelRoute,
                    Phase::Apply,
                    line,
                ));
            }
            return Err(anyhow!("kernel route apply failed: {}", e));
        }
    }

    // ---- macOS-specific mechanisms ----
    #[cfg(target_os = "macos")]
    {
        apply_macos_networksetup(&service, &gateway, &exact_ips, &subnets, reporter)?;
        apply_macos_pf(
            &iface,
            &gateway,
            &exact_ips,
            &subnets,
            &plan.strategy,
            reporter,
        )?;
    }

    // Strategy hint only — real strategy-specific behavior is wired in Step 7.
    let _ = plan.strategy;

    Ok(())
}

#[cfg(target_os = "windows")]
fn apply_windows_interface_metric(
    plan: &ApplyPlan,
    reporter: &MechanismReporter,
) -> Result<()> {
    use crate::network::windows::metric;
    let if_index = plan.snapshot.wifi.index;

    reporter.emit(MechanismEvent::started(
        MechanismTag::InterfaceMetric,
        Phase::Apply,
        format!("Wi-Fi interface metric ayarlanıyor (iface={})", if_index),
    ));

    // Read current metric so Kapa can restore it. If the read fails, fall
    // back to `None` which triggers `restore_automatic` on Kapa.
    let original = metric::read_current_metric(if_index).ok();
    let new_metric: u32 = 1;

    match metric::set_metric(if_index, new_metric) {
        Ok(()) => {
            reporter.emit(MechanismEvent::ok(
                MechanismTag::InterfaceMetric,
                Phase::Apply,
                format!(
                    "Wi-Fi interface metric {} -> {} ✓",
                    original
                        .map(|m| m.to_string())
                        .unwrap_or_else(|| "auto".into()),
                    new_metric
                ),
                MechanismPayload::InterfaceMetric {
                    index: if_index,
                    original,
                    new_metric,
                },
            ));
            Ok(())
        }
        Err(e) => {
            reporter.emit(MechanismEvent::failed(
                MechanismTag::InterfaceMetric,
                Phase::Apply,
                format!("metric ayarlanamadı: {}", e),
            ));
            Err(e)
        }
    }
}

#[cfg(target_os = "macos")]
fn apply_macos_networksetup(
    service: &str,
    gateway: &str,
    exact_ips: &[String],
    subnets: &[String],
    reporter: &MechanismReporter,
) -> Result<()> {
    reporter.emit(MechanismEvent::started(
        MechanismTag::NetworksetupRoute,
        Phase::Apply,
        "networksetup additional routes yükleniyor...",
    ));
    let logs = log_buffer();
    let cb = make_cb(&logs);

    // exec_routes_networksetup expects a &[&str] of dns ip strings; we
    // pass our exact_ips as the DNS slot and subnets as the subnet slot
    // to preserve the legacy behavior.
    let dns_refs: Vec<&str> = exact_ips.iter().map(|s| s.as_str()).collect();
    let result = PlatformNetwork::exec_routes_networksetup(&dns_refs, subnets, gateway, service, &cb);
    let captured = drain_logs(&logs);

    match result {
        Ok(()) => {
            let entries: Vec<(String, String, String)> = exact_ips
                .iter()
                .map(|ip| (ip.clone(), "255.255.255.255".to_string(), gateway.to_string()))
                .chain(subnets.iter().map(|s| {
                    (s.clone(), "255.255.255.0".to_string(), gateway.to_string())
                }))
                .collect();
            reporter.emit(MechanismEvent::ok(
                MechanismTag::NetworksetupRoute,
                Phase::Apply,
                "networksetup additional routes yüklendi",
                MechanismPayload::NetworksetupRoutes {
                    service: service.to_string(),
                    entries,
                },
            ));
            for line in captured {
                reporter.emit(MechanismEvent::started(
                    MechanismTag::NetworksetupRoute,
                    Phase::Apply,
                    line,
                ));
            }
            Ok(())
        }
        Err(e) => {
            reporter.emit(MechanismEvent::failed(
                MechanismTag::NetworksetupRoute,
                Phase::Apply,
                format!("networksetup hatası: {}", e),
            ));
            Err(anyhow!("networksetup apply failed: {}", e)).context("macos networksetup")
        }
    }
}

#[cfg(target_os = "macos")]
fn apply_macos_pf(
    iface: &str,
    gateway: &str,
    exact_ips: &[String],
    subnets: &[String],
    _strategy: &Strategy,
    reporter: &MechanismReporter,
) -> Result<()> {
    reporter.emit(MechanismEvent::started(
        MechanismTag::PfAnchor,
        Phase::Apply,
        "PF anchor yükleniyor...",
    ));
    let logs = log_buffer();
    let cb = make_cb(&logs);

    let dns_refs: Vec<&str> = exact_ips.iter().map(|s| s.as_str()).collect();
    let result = PlatformNetwork::add_pf_bypass(&dns_refs, subnets, gateway, iface, &cb);
    let captured = drain_logs(&logs);

    match result {
        Ok(()) => {
            reporter.emit(MechanismEvent::ok(
                MechanismTag::PfAnchor,
                Phase::Apply,
                "PF route-to kuralları yüklendi",
                MechanismPayload::PfAnchor {
                    anchor: "com.routeshift".to_string(),
                    // LegacyEngine does not modify /etc/pf.conf — Step 8 will
                    // start tracking this honestly. For now assume false.
                    pf_conf_line_added: false,
                },
            ));
            for line in captured {
                reporter.emit(MechanismEvent::started(
                    MechanismTag::PfAnchor,
                    Phase::Apply,
                    line,
                ));
            }
            Ok(())
        }
        Err(e) => {
            // Non-fatal: the legacy code treats PF failures as warnings.
            reporter.emit(MechanismEvent::warn(
                MechanismTag::PfAnchor,
                Phase::Apply,
                format!("PF anchor yüklenemedi (uyarı): {}", e),
            ));
            Ok(())
        }
    }
}

/// Phase 6 Rollback, delegating to the legacy PlatformNetwork methods.
fn remove_plan_legacy(state: &BypassState, reporter: &MechanismReporter) -> Result<()> {
    let Some(snapshot) = state.snapshot.clone() else {
        reporter.emit(MechanismEvent::warn(
            MechanismTag::KernelRoute,
            Phase::Rollback,
            "state.snapshot yok, rollback atlanıyor",
        ));
        return Ok(());
    };

    let gateway = snapshot.default_gateway.to_string();
    let iface = if snapshot.wifi.name.is_empty() {
        snapshot.wifi.index.to_string()
    } else {
        snapshot.wifi.name.clone()
    };
    let service = snapshot.primary_service_name.clone();
    let _ = gateway; // used on some platforms below

    // Collect the set of CIDRs / entries from recorded mechanisms so we
    // undo exactly what we applied. Mechanisms run in reverse order.
    //
    // NOTE: InterfaceMetric is restored LAST (after routes are deleted)
    // so that ongoing connections don't swing to VPN mid-teardown while
    // the metric is still low. On Windows this is handled by a second
    // pass below.
    let mut kernel_cidrs: Vec<String> = Vec::new();
    let mut pf_present = false;
    let mut netsetup_present = false;
    #[cfg(target_os = "windows")]
    let mut pending_metric_restore: Option<(u32, Option<u32>)> = None;

    for mech in state.mechanisms.iter().rev() {
        match &mech.payload {
            MechanismPayload::KernelRoutes { cidrs } => kernel_cidrs.extend(cidrs.clone()),
            MechanismPayload::NetworksetupRoutes { .. } => netsetup_present = true,
            MechanismPayload::PfAnchor { .. } => pf_present = true,
            #[cfg(target_os = "windows")]
            MechanismPayload::InterfaceMetric {
                index, original, ..
            } => {
                pending_metric_restore = Some((*index, *original));
            }
            _ => {}
        }
    }

    // ---- Kernel routes ----
    if !kernel_cidrs.is_empty() {
        let (exact_ips, subnets) = split_cidrs(&kernel_cidrs);
        reporter.emit(MechanismEvent::started(
            MechanismTag::KernelRoute,
            Phase::Rollback,
            "Route komutları kaldırılıyor...",
        ));
        let logs = log_buffer();
        let cb = make_cb(&logs);
        let commands = build_remove_route_commands(&subnets, &exact_ips, &iface);
        let result = PlatformNetwork::exec_routes_elevated(&commands, &cb);
        let captured = drain_logs(&logs);
        match result {
            Ok(()) => {
                reporter.emit(MechanismEvent::ok(
                    MechanismTag::KernelRoute,
                    Phase::Rollback,
                    format!("{} route kaldırıldı", kernel_cidrs.len()),
                    MechanismPayload::KernelRoutes { cidrs: Vec::new() },
                ));
            }
            Err(e) => {
                reporter.emit(MechanismEvent::warn(
                    MechanismTag::KernelRoute,
                    Phase::Rollback,
                    format!("Route silme uyarısı: {}", e),
                ));
            }
        }
        for line in captured {
            reporter.emit(MechanismEvent::started(
                MechanismTag::KernelRoute,
                Phase::Rollback,
                line,
            ));
        }
    }

    // ---- macOS mechanisms ----
    #[cfg(target_os = "macos")]
    {
        if netsetup_present {
            reporter.emit(MechanismEvent::started(
                MechanismTag::NetworksetupRoute,
                Phase::Rollback,
                "networksetup additional routes temizleniyor...",
            ));
            let logs = log_buffer();
            let cb = make_cb(&logs);
            PlatformNetwork::clear_routes_networksetup(&service, &cb);
            drop(cb);
            let _ = drain_logs(&logs);
            reporter.emit(MechanismEvent::ok(
                MechanismTag::NetworksetupRoute,
                Phase::Rollback,
                "networksetup temizlendi",
                MechanismPayload::NetworksetupRoutes {
                    service: service.clone(),
                    entries: Vec::new(),
                },
            ));
        }
        if pf_present {
            reporter.emit(MechanismEvent::started(
                MechanismTag::PfAnchor,
                Phase::Rollback,
                "PF anchor temizleniyor...",
            ));
            let logs = log_buffer();
            let cb = make_cb(&logs);
            PlatformNetwork::remove_pf_bypass(&cb);
            drop(cb);
            let _ = drain_logs(&logs);
            reporter.emit(MechanismEvent::ok(
                MechanismTag::PfAnchor,
                Phase::Rollback,
                "PF anchor temizlendi",
                MechanismPayload::PfAnchor {
                    anchor: "com.routeshift".to_string(),
                    pf_conf_line_added: false,
                },
            ));
        }
    }

    // ---- Windows: restore InterfaceMetric LAST ----
    // Ordering matters: we deleted the /32 routes above, so the kernel
    // has already re-picked the VPN route for ongoing connections. NOW
    // we can safely restore the Wi-Fi interface metric without causing
    // an in-flight connection to hop interfaces.
    #[cfg(target_os = "windows")]
    {
        if let Some((if_index, original)) = pending_metric_restore {
            use crate::network::windows::metric;
            reporter.emit(MechanismEvent::started(
                MechanismTag::InterfaceMetric,
                Phase::Rollback,
                format!("Wi-Fi interface metric geri yükleniyor (iface={})", if_index),
            ));
            let restore_result = match original {
                Some(orig) => metric::set_metric(if_index, orig),
                None => metric::restore_automatic(if_index),
            };
            match restore_result {
                Ok(()) => {
                    reporter.emit(MechanismEvent::ok(
                        MechanismTag::InterfaceMetric,
                        Phase::Rollback,
                        "Wi-Fi metric restored ✓",
                        MechanismPayload::InterfaceMetric {
                            index: if_index,
                            original,
                            new_metric: original.unwrap_or(0),
                        },
                    ));
                }
                Err(e) => {
                    reporter.emit(MechanismEvent::warn(
                        MechanismTag::InterfaceMetric,
                        Phase::Rollback,
                        format!("metric restore uyarısı: {}", e),
                    ));
                }
            }
        }
    }

    // On non-macOS platforms these flags are set-but-unused; silence the lint.
    let _ = pf_present;
    let _ = netsetup_present;
    let _ = service;

    Ok(())
}

/// Split a list of CIDRs into (exact_ips, subnet_networks).
/// Input strings like "8.8.8.8/32" → exact_ips, "160.79.104.0/24" → subnets.
fn split_cidrs(cidrs: &[String]) -> (Vec<String>, Vec<String>) {
    let mut exact_ips = Vec::new();
    let mut subnets = Vec::new();
    for cidr in cidrs {
        if let Some((addr, prefix)) = cidr.split_once('/') {
            if prefix == "32" {
                exact_ips.push(addr.to_string());
            } else {
                subnets.push(addr.to_string());
            }
        } else {
            exact_ips.push(cidr.clone());
        }
    }
    (exact_ips, subnets)
}

/// Placeholder: the legacy engine does not actually use DNS_SERVERS directly,
/// but keeping the import alive documents the intent for Step 4. Step 10 drops it.
#[allow(dead_code)]
fn legacy_dns_servers() -> &'static [&'static str] {
    DNS_SERVERS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_cidrs_separates_by_prefix() {
        let cidrs = vec![
            "8.8.8.8/32".to_string(),
            "160.79.104.0/24".to_string(),
            "1.1.1.1/32".to_string(),
            "104.18.32.0/24".to_string(),
        ];
        let (ips, subnets) = split_cidrs(&cidrs);
        assert_eq!(ips, vec!["8.8.8.8", "1.1.1.1"]);
        assert_eq!(subnets, vec!["160.79.104.0", "104.18.32.0"]);
    }

    #[test]
    fn split_cidrs_handles_missing_prefix() {
        let cidrs = vec!["8.8.8.8".to_string()];
        let (ips, subnets) = split_cidrs(&cidrs);
        assert_eq!(ips, vec!["8.8.8.8"]);
        assert!(subnets.is_empty());
    }

    #[test]
    fn plan_to_string_targets_roundtrip() {
        use crate::engine::types::{Ipv4Net, NetworkSnapshot, Strategy, WifiInterface};
        use std::net::Ipv4Addr;
        let plan = ApplyPlan {
            strategy: Strategy::Coexistence,
            snapshot: NetworkSnapshot {
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
            },
            targets_host: vec!["8.8.8.8".parse().unwrap()],
            targets_subnet: vec![Ipv4Net::new(Ipv4Addr::new(160, 79, 104, 0), 24)],
            mechanisms: vec![MechanismTag::KernelRoute],
        };
        let (ips, subnets) = plan_to_string_targets(&plan);
        assert_eq!(ips, vec!["8.8.8.8"]);
        assert_eq!(subnets, vec!["160.79.104.0"]);
    }

    #[test]
    fn legacy_engine_default_probe_returns_empty_rivals() {
        let engine = LegacyEngine::new();
        let rivals = engine
            .probe_rivals(&["8.8.8.8".parse().unwrap()])
            .expect("probe should not fail");
        assert!(rivals.entries.is_empty());
    }
}
