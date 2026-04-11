//! Strategy selection — pure function over (NetworkSnapshot, RivalMap).
//!
//! Decides whether Phase 3 Apply should use:
//!   - **Coexistence**: install /32 host routes only, leave VPN routes alone.
//!     Wins via longest-prefix-match. Preferred: Kapa is atomic because
//!     VPN state is never mutated.
//!   - **Aggressive**: install /32 + lower Wi-Fi interface metric + delete
//!     rival /32 routes. Only when every target has a /32 rival (enterprise
//!     VPN with full split-tunnel enforcement). Kapa has a 30–60s race
//!     window while the VPN re-adds its /32s.
//!   - **Hybrid**: mix — Coexistence for weak rivals, Aggressive for strong.
//!
//! The picker is a pure function so it can be unit-tested with table-driven
//! cases covering every (rivals, prefix_len, vpn_probability) combination.

use crate::engine::types::{NetworkSnapshot, RivalMap, Strategy};

/// Pick the best strategy for the given discovery results.
pub fn select(_snapshot: &NetworkSnapshot, rivals: &RivalMap) -> Strategy {
    if rivals.entries.is_empty() {
        return Strategy::Coexistence;
    }

    let total = rivals.entries.len();
    let strong = rivals
        .entries
        .iter()
        .filter(|e| e.current_prefix_len == 32 && e.likely_vpn)
        .count();

    if strong == 0 {
        Strategy::Coexistence
    } else if strong == total {
        Strategy::Aggressive
    } else {
        Strategy::Hybrid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::types::{
        NetworkSnapshot, ProxyState, RivalEntry, RivalMap, WifiInterface,
    };

    fn snap() -> NetworkSnapshot {
        NetworkSnapshot {
            wifi: WifiInterface {
                index: 0,
                name: "Wi-Fi".into(),
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

    fn entry(target: &str, prefix_len: u8, vpn: bool) -> RivalEntry {
        RivalEntry {
            target: target.parse().unwrap(),
            current_gateway: None,
            current_interface: None,
            current_prefix_len: prefix_len,
            likely_vpn: vpn,
        }
    }

    #[test]
    fn no_rivals_selects_coexistence() {
        let s = select(&snap(), &RivalMap::default());
        assert_eq!(s, Strategy::Coexistence);
    }

    #[test]
    fn weak_rivals_only_selects_coexistence() {
        let rivals = RivalMap {
            entries: vec![
                entry("8.8.8.8", 24, true),
                entry("1.1.1.1", 0, true),
                entry("160.79.104.10", 24, true),
            ],
        };
        assert_eq!(select(&snap(), &rivals), Strategy::Coexistence);
    }

    #[test]
    fn all_strong_rivals_selects_aggressive() {
        let rivals = RivalMap {
            entries: vec![
                entry("8.8.8.8", 32, true),
                entry("1.1.1.1", 32, true),
                entry("160.79.104.10", 32, true),
            ],
        };
        assert_eq!(select(&snap(), &rivals), Strategy::Aggressive);
    }

    #[test]
    fn mixed_strong_and_weak_selects_hybrid() {
        let rivals = RivalMap {
            entries: vec![
                entry("8.8.8.8", 32, true),
                entry("1.1.1.1", 24, true),
                entry("160.79.104.10", 32, true),
            ],
        };
        assert_eq!(select(&snap(), &rivals), Strategy::Hybrid);
    }

    #[test]
    fn strong_rival_with_non_vpn_does_not_trigger_aggressive() {
        // A /32 that isn't VPN-owned isn't a real rival — it's just a cached
        // host route. Coexistence still wins because the /32 likely points
        // to our gateway already.
        let rivals = RivalMap {
            entries: vec![entry("8.8.8.8", 32, false)],
        };
        assert_eq!(select(&snap(), &rivals), Strategy::Coexistence);
    }
}
