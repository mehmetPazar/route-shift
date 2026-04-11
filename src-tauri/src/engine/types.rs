//! Layer 2 type definitions.
//!
//! These types are the contract between the lifecycle orchestrator and
//! platform-specific BypassEngine implementations. All are `Serialize +
//! Deserialize` so they can be persisted to disk as part of `BypassState`.
//!
//! See `docs: plans/zany-wandering-parrot.md` for the architectural rationale.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

// ===== Phase 1 Discovery output =====

/// Immutable snapshot of the network at a point in time.
///
/// Produced by `BypassEngine::detect()` during Phase 1. Used by strategy
/// selection and by the watchdog to detect network changes (gateway flip,
/// Wi-Fi reassociation, etc).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSnapshot {
    pub wifi: WifiInterface,
    pub default_gateway: IpAddr,
    /// macOS networksetup service name (e.g. "Wi-Fi"). Empty on other OSes.
    pub primary_service_name: String,
    pub proxy: ProxyState,
    pub ipv6_enabled: bool,
    /// Unix seconds — used for drift detection during reconcile.
    pub detected_at: u64,
}

/// Physical Wi-Fi adapter details, as returned by native OS APIs
/// (GetAdaptersAddresses on Windows, scutil+ipconfig on macOS).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiInterface {
    /// OS-level interface index (IfIndex on Windows, kernel ifindex elsewhere).
    pub index: u32,
    /// Friendly / device name ("Wi-Fi", "en0", "wlp2s0").
    pub name: String,
    pub mac: Option<String>,
    pub ipv4: Option<Ipv4Addr>,
    /// True if this adapter is a virtual adapter (Wi-Fi Direct, Hyper-V vNIC, etc.).
    /// Engines must filter these out before returning a snapshot.
    pub is_virtual: bool,
    pub is_up: bool,
    /// Original interface metric before we touched it. Captured so Kapa can
    /// restore it on aggressive-strategy rollback. `None` on macOS/Linux where
    /// we don't mutate interface metric.
    pub default_metric: Option<u32>,
}

/// System proxy configuration observed at discovery time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProxyState {
    Disabled,
    SystemProxy { server: String },
    PacUrl(String),
    Unknown,
}

// ===== Phase 1 Probe output =====

/// Maps each target IP to the route that currently serves it.
/// Used by strategy selection to decide Coexistence vs Aggressive.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RivalMap {
    pub entries: Vec<RivalEntry>,
}

/// Current routing-table owner of a target IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RivalEntry {
    pub target: IpAddr,
    pub current_gateway: Option<IpAddr>,
    pub current_interface: Option<u32>,
    /// Longest matching prefix length: 0 (default route), 24, 32, etc.
    /// Rivals with prefix_len == 32 are "strong" — they tie specificity
    /// with our /32 host routes and force Aggressive strategy.
    pub current_prefix_len: u8,
    /// Heuristic: interface name matches known VPN patterns
    /// (pulse, juniper, cisco, tun, tap, utun, ppp, ...).
    pub likely_vpn: bool,
}

// ===== Phase 2 Plan output =====

/// Fully declarative description of what Phase 3 Apply will do.
/// Produced by the strategy selector from (snapshot, rivals, dns_result).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyPlan {
    pub strategy: Strategy,
    pub snapshot: NetworkSnapshot,
    /// /32 host routes — individual IPs (DNS servers + resolved domain IPs).
    /// More specific than /24, so they win via longest-prefix-match unless
    /// a rival also has a /32.
    pub targets_host: Vec<IpAddr>,
    /// /24 subnet routes — CIDR blocks derived from resolved IPs.
    pub targets_subnet: Vec<Ipv4Net>,
    /// Mechanism types this plan will invoke, in dependency order.
    /// The engine uses this to know which mechanisms to spawn in parallel
    /// during Phase 3.
    pub mechanisms: Vec<MechanismTag>,
}

/// Strategy selected by `lifecycle::strategy::select()`. See plan for policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Strategy {
    /// /32 host routes only. Wins via specificity, leaves VPN routes untouched.
    /// Preferred: atomic Kapa (no race condition when we delete our routes,
    /// the VPN's /24 is immediately dominant again).
    Coexistence,
    /// /32 routes + lower Wi-Fi interface metric + delete rival /32 routes.
    /// Only when every target has a VPN /32 rival. Kapa has a race window
    /// (~30-60s) while the VPN re-adds its /32s — handled by Phase 7 retry.
    Aggressive,
    /// Per-target mix: Coexistence for weak rivals, Aggressive for strong ones.
    Hybrid,
}

/// Small IPv4 CIDR newtype. Avoids pulling in the `ipnet` crate for this one
/// use case. `prefix_len` is always 0..=32.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ipv4Net {
    pub network: Ipv4Addr,
    pub prefix_len: u8,
}

impl Ipv4Net {
    pub fn new(network: Ipv4Addr, prefix_len: u8) -> Self {
        Self { network, prefix_len }
    }

    /// Dotted-quad subnet mask for route commands ("255.255.255.0").
    pub fn netmask(&self) -> Ipv4Addr {
        let bits: u32 = if self.prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix_len as u32)
        };
        Ipv4Addr::from(bits)
    }
}

impl std::fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

// ===== Phase 3/6 Mechanism taxonomy =====

/// Identifies a concrete side-effect class a platform engine may perform.
///
/// State is keyed by these tags so reconcile knows what undo operation
/// to run for each applied mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MechanismTag {
    /// Kernel route table entries (`route add` / `route -n add` / `ip route add`).
    KernelRoute,
    /// macOS service-level additional routes (`networksetup -setadditionalroutes`).
    /// Persistent across reboots — high orphan risk.
    NetworksetupRoute,
    /// macOS PF anchor (`pfctl -a com.routeshift`) plus optional `/etc/pf.conf`
    /// reference line.
    PfAnchor,
    /// Windows interface metric change on the Wi-Fi adapter.
    InterfaceMetric,
    /// System proxy disable (registry / networksetup / gsettings).
    ProxyDisable,
    /// IPv6 policy adjustment (prefer IPv4 for targets).
    Ipv6Policy,
}

// ===== Phase 4 / 7 Verify output =====

/// Result of verifying that every target IP routes through the desired
/// interface (Wi-Fi during Phase 4, not-Wi-Fi during Phase 7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    pub per_target: Vec<TargetVerdict>,
    pub overall: VerifyOutcome,
}

impl VerifyReport {
    pub fn empty() -> Self {
        Self {
            per_target: Vec::new(),
            overall: VerifyOutcome::Unknown,
        }
    }

    /// Compute overall outcome from per-target verdicts.
    /// Majority rules: if most targets fail, overall fails.
    pub fn aggregate(per_target: Vec<TargetVerdict>) -> Self {
        if per_target.is_empty() {
            return Self::empty();
        }
        let total = per_target.len();
        let passing = per_target
            .iter()
            .filter(|v| v.outcome == VerifyOutcome::Pass)
            .count();
        let failing = per_target
            .iter()
            .filter(|v| v.outcome == VerifyOutcome::Fail)
            .count();

        let overall = if failing * 2 > total {
            VerifyOutcome::Fail
        } else if passing == total {
            VerifyOutcome::Pass
        } else if passing > 0 {
            VerifyOutcome::Degraded
        } else {
            VerifyOutcome::Unknown
        };

        Self { per_target, overall }
    }
}

/// Verdict for a single target IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetVerdict {
    pub target: IpAddr,
    /// Interface the kernel would currently use for this destination.
    /// On Windows this is the `InterfaceIndex` from `GetBestRoute2` /
    /// `Find-NetRoute`; on macOS it's the `interface:` field from
    /// `route -n get`.
    pub winning_interface: Option<String>,
    pub winning_gateway: Option<IpAddr>,
    /// First hop IP from a 1-hop traceroute. Cross-check against winning_gateway.
    pub traceroute_first_hop: Option<IpAddr>,
    /// Whether a TLS handshake reached the target successfully. `None` if we
    /// didn't run a TLS probe for this target.
    pub tls_ok: Option<bool>,
    pub outcome: VerifyOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyOutcome {
    /// Route goes through the expected interface and TLS (if probed) succeeded.
    Pass,
    /// Route goes through the WRONG interface (rival still wins in Phase 4,
    /// or Wi-Fi still wins in Phase 7).
    Fail,
    /// Route interface is correct but TLS probe failed. Not a hard fail —
    /// some targets have cert pinning or block handshakes entirely.
    Degraded,
    /// Could not probe (e.g. DNS resolution failed for this target).
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_net_netmask_derivation() {
        assert_eq!(
            Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 24).netmask(),
            Ipv4Addr::new(255, 255, 255, 0)
        );
        assert_eq!(
            Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 32).netmask(),
            Ipv4Addr::new(255, 255, 255, 255)
        );
        assert_eq!(
            Ipv4Net::new(Ipv4Addr::new(0, 0, 0, 0), 0).netmask(),
            Ipv4Addr::new(0, 0, 0, 0)
        );
        assert_eq!(
            Ipv4Net::new(Ipv4Addr::new(192, 168, 0, 0), 16).netmask(),
            Ipv4Addr::new(255, 255, 0, 0)
        );
    }

    #[test]
    fn ipv4_net_display() {
        let net = Ipv4Net::new(Ipv4Addr::new(160, 79, 104, 0), 24);
        assert_eq!(format!("{}", net), "160.79.104.0/24");
    }

    #[test]
    fn verify_report_aggregate_all_pass() {
        let verdicts = vec![
            TargetVerdict {
                target: "1.1.1.1".parse().unwrap(),
                winning_interface: Some("en0".into()),
                winning_gateway: None,
                traceroute_first_hop: None,
                tls_ok: Some(true),
                outcome: VerifyOutcome::Pass,
            },
            TargetVerdict {
                target: "8.8.8.8".parse().unwrap(),
                winning_interface: Some("en0".into()),
                winning_gateway: None,
                traceroute_first_hop: None,
                tls_ok: Some(true),
                outcome: VerifyOutcome::Pass,
            },
        ];
        let report = VerifyReport::aggregate(verdicts);
        assert_eq!(report.overall, VerifyOutcome::Pass);
    }

    #[test]
    fn verify_report_aggregate_majority_fail() {
        let verdicts = vec![
            TargetVerdict {
                target: "1.1.1.1".parse().unwrap(),
                winning_interface: Some("utun5".into()),
                winning_gateway: None,
                traceroute_first_hop: None,
                tls_ok: None,
                outcome: VerifyOutcome::Fail,
            },
            TargetVerdict {
                target: "8.8.8.8".parse().unwrap(),
                winning_interface: Some("utun5".into()),
                winning_gateway: None,
                traceroute_first_hop: None,
                tls_ok: None,
                outcome: VerifyOutcome::Fail,
            },
            TargetVerdict {
                target: "9.9.9.9".parse().unwrap(),
                winning_interface: Some("en0".into()),
                winning_gateway: None,
                traceroute_first_hop: None,
                tls_ok: Some(true),
                outcome: VerifyOutcome::Pass,
            },
        ];
        let report = VerifyReport::aggregate(verdicts);
        assert_eq!(report.overall, VerifyOutcome::Fail);
    }

    #[test]
    fn verify_report_aggregate_degraded() {
        let verdicts = vec![
            TargetVerdict {
                target: "1.1.1.1".parse().unwrap(),
                winning_interface: Some("en0".into()),
                winning_gateway: None,
                traceroute_first_hop: None,
                tls_ok: Some(true),
                outcome: VerifyOutcome::Pass,
            },
            TargetVerdict {
                target: "8.8.8.8".parse().unwrap(),
                winning_interface: Some("en0".into()),
                winning_gateway: None,
                traceroute_first_hop: None,
                tls_ok: Some(false),
                outcome: VerifyOutcome::Degraded,
            },
        ];
        let report = VerifyReport::aggregate(verdicts);
        assert_eq!(report.overall, VerifyOutcome::Degraded);
    }

    #[test]
    fn verify_report_empty_is_unknown() {
        let report = VerifyReport::aggregate(Vec::new());
        assert_eq!(report.overall, VerifyOutcome::Unknown);
    }

    #[test]
    fn serde_round_trip_apply_plan() {
        let plan = ApplyPlan {
            strategy: Strategy::Coexistence,
            snapshot: NetworkSnapshot {
                wifi: WifiInterface {
                    index: 50,
                    name: "Wi-Fi".into(),
                    mac: Some("aa:bb:cc:dd:ee:ff".into()),
                    ipv4: Some(Ipv4Addr::new(192, 168, 1, 10)),
                    is_virtual: false,
                    is_up: true,
                    default_metric: Some(35),
                },
                default_gateway: "192.168.1.1".parse().unwrap(),
                primary_service_name: "Wi-Fi".into(),
                proxy: ProxyState::Disabled,
                ipv6_enabled: true,
                detected_at: 1_700_000_000,
            },
            targets_host: vec!["8.8.8.8".parse().unwrap()],
            targets_subnet: vec![Ipv4Net::new(Ipv4Addr::new(160, 79, 104, 0), 24)],
            mechanisms: vec![MechanismTag::KernelRoute, MechanismTag::PfAnchor],
        };
        let json = serde_json::to_string(&plan).expect("serialize");
        let back: ApplyPlan = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.strategy, Strategy::Coexistence);
        assert_eq!(back.targets_host.len(), 1);
        assert_eq!(back.targets_subnet[0].prefix_len, 24);
    }
}
