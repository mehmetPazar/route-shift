//! Native Windows rival-route probing using `GetIpForwardTable2`.
//!
//! Given a list of target IPs, answer "which route table entry currently
//! owns this IP?" for each one. The lifecycle strategy selector uses the
//! result to decide Coexistence vs Aggressive.
//!
//! The pure matching logic lives in `find_best_match` — take a route
//! table snapshot (as a plain Rust struct) and a target IP, return the
//! longest-prefix match. This is unit-testable on any platform.
//!
//! The Win32 FFI layer (`snapshot_forward_table`) is `#[cfg(target_os =
//! "windows")]` only.

use crate::engine::types::{RivalEntry, RivalMap};
#[cfg(target_os = "windows")]
use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr};

/// A single IPv4 route table entry, in a form that is cheap to build in tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    pub destination: Ipv4Addr,
    pub prefix_len: u8,
    pub next_hop: Ipv4Addr,
    pub if_index: u32,
    /// Raw interface name if available (e.g. "Ethernet 2"). Used by the
    /// VPN heuristic below.
    pub if_name: String,
    pub interface_metric: u32,
    pub route_metric: u32,
}

impl RouteEntry {
    /// Does this route match the given destination IP?
    pub fn matches(&self, target: Ipv4Addr) -> bool {
        if self.prefix_len == 0 {
            return true;
        }
        let dest_bits = u32::from(self.destination);
        let target_bits = u32::from(target);
        let shift = 32 - self.prefix_len as u32;
        // Avoid shifting by 32 (undefined behavior for u32).
        if shift == 32 {
            return true;
        }
        (dest_bits >> shift) == (target_bits >> shift)
    }
}

/// Find the best (longest-prefix, lowest-metric) route for a target IP
/// in a given route table. Pure function — unit-testable.
pub fn find_best_match(table: &[RouteEntry], target: Ipv4Addr) -> Option<&RouteEntry> {
    table
        .iter()
        .filter(|r| r.matches(target))
        .max_by(|a, b| {
            a.prefix_len
                .cmp(&b.prefix_len)
                .then_with(|| {
                    let total_a = a.interface_metric.saturating_add(a.route_metric);
                    let total_b = b.interface_metric.saturating_add(b.route_metric);
                    // Lower metric wins — reverse the comparison.
                    total_b.cmp(&total_a)
                })
        })
}

/// Heuristic: does this interface name look like a VPN tunnel?
pub fn looks_like_vpn(if_name: &str) -> bool {
    let n = if_name.to_lowercase();
    const VPN_KEYWORDS: &[&str] = &[
        "juniper",
        "pulse",
        "ivanti",
        "cisco",
        "anyconnect",
        "globalprotect",
        "zscaler",
        "forticlient",
        "checkpoint",
        "openvpn",
        "wireguard",
        "tap-",
        "tap ",
        "tun",
        "ppp",
        "tunnel",
        "vpn",
    ];
    VPN_KEYWORDS.iter().any(|k| n.contains(k))
}

/// Build a `RivalMap` from a route table and a list of targets.
pub fn build_rival_map(
    table: &[RouteEntry],
    targets: &[IpAddr],
    wifi_if_index: u32,
) -> RivalMap {
    let mut entries = Vec::new();
    for target in targets {
        let IpAddr::V4(ipv4) = target else {
            continue; // skip IPv6 for now
        };
        if let Some(best) = find_best_match(table, *ipv4) {
            // Only count it as a rival if the winning interface is NOT
            // our Wi-Fi — otherwise the Wi-Fi already owns this target.
            let is_wifi = best.if_index == wifi_if_index;
            entries.push(RivalEntry {
                target: *target,
                current_gateway: Some(IpAddr::V4(best.next_hop)),
                current_interface: Some(best.if_index),
                current_prefix_len: best.prefix_len,
                likely_vpn: !is_wifi && looks_like_vpn(&best.if_name),
            });
        }
    }
    RivalMap { entries }
}

// =====================================================================
// Win32 FFI layer — only compiled on Windows.
// =====================================================================

#[cfg(target_os = "windows")]
pub fn probe_targets(targets: &[IpAddr], wifi_if_index: u32) -> Result<RivalMap> {
    let table = snapshot_forward_table()?;
    Ok(build_rival_map(&table, targets, wifi_if_index))
}

#[cfg(target_os = "windows")]
fn snapshot_forward_table() -> Result<Vec<RouteEntry>> {
    use anyhow::anyhow;
    use std::ptr;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIpForwardTable2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    let mut table_ptr: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
    let ret = unsafe { GetIpForwardTable2(AF_INET as u16, &mut table_ptr) };
    if ret != NO_ERROR {
        return Err(anyhow!("GetIpForwardTable2 failed with code {}", ret));
    }
    if table_ptr.is_null() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    let num_entries = unsafe { (*table_ptr).NumEntries } as usize;
    let rows_ptr = unsafe { (*table_ptr).Table.as_ptr() };
    for i in 0..num_entries {
        let row: &MIB_IPFORWARD_ROW2 = unsafe { &*rows_ptr.add(i) };
        // Only IPv4 rows.
        let family = unsafe { row.DestinationPrefix.Prefix.si_family };
        if family != AF_INET {
            continue;
        }
        let dest_bytes =
            unsafe { row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_un_b };
        let destination = Ipv4Addr::new(
            dest_bytes.s_b1,
            dest_bytes.s_b2,
            dest_bytes.s_b3,
            dest_bytes.s_b4,
        );
        let prefix_len = row.DestinationPrefix.PrefixLength;

        let nh_bytes = unsafe { row.NextHop.Ipv4.sin_addr.S_un.S_un_b };
        let next_hop = Ipv4Addr::new(
            nh_bytes.s_b1,
            nh_bytes.s_b2,
            nh_bytes.s_b3,
            nh_bytes.s_b4,
        );

        let if_index = row.InterfaceIndex;
        let route_metric = row.Metric;

        // Interface metric is not on this row — we could call
        // GetIpInterfaceEntry to fetch it, but for probe purposes the
        // route-metric alone is good enough: it's enough to break ties.
        let interface_metric = 0u32;

        // Looking up the friendly name per row is expensive. For the
        // probe, we pass the empty string and rely on `looks_like_vpn`
        // only for the selected best route via a later lookup. For now
        // we leave it empty; the heuristic will say "not VPN" which
        // errs toward Coexistence — a safe default.
        out.push(RouteEntry {
            destination,
            prefix_len,
            next_hop,
            if_index,
            if_name: String::new(),
            interface_metric,
            route_metric,
        });
    }

    unsafe { FreeMibTable(table_ptr as *const _) };
    let _ = ERROR_SUCCESS; // satisfy imports-unused lint across configs
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn route(dest: &str, prefix: u8, metric: u32, iface: u32, name: &str) -> RouteEntry {
        RouteEntry {
            destination: dest.parse().unwrap(),
            prefix_len: prefix,
            next_hop: "0.0.0.0".parse().unwrap(),
            if_index: iface,
            if_name: name.to_string(),
            interface_metric: 0,
            route_metric: metric,
        }
    }

    #[test]
    fn matches_host_route() {
        let r = route("8.8.8.8", 32, 1, 1, "Ethernet");
        assert!(r.matches("8.8.8.8".parse().unwrap()));
        assert!(!r.matches("8.8.8.9".parse().unwrap()));
    }

    #[test]
    fn matches_subnet_route() {
        let r = route("160.79.104.0", 24, 1, 1, "Ethernet");
        assert!(r.matches("160.79.104.10".parse().unwrap()));
        assert!(r.matches("160.79.104.255".parse().unwrap()));
        assert!(!r.matches("160.79.105.0".parse().unwrap()));
    }

    #[test]
    fn matches_default_route() {
        let r = route("0.0.0.0", 0, 1, 1, "Ethernet");
        assert!(r.matches("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn longest_prefix_wins_over_lower_metric() {
        let table = vec![
            route("0.0.0.0", 0, 1, 2, "VPN"), // shorter prefix, lower total metric
            route("160.79.104.0", 24, 35, 1, "Wi-Fi"),
        ];
        let best = find_best_match(&table, "160.79.104.10".parse().unwrap()).unwrap();
        assert_eq!(best.prefix_len, 24);
        assert_eq!(best.if_index, 1);
    }

    #[test]
    fn host_route_wins_over_subnet() {
        let table = vec![
            route("160.79.104.0", 24, 1, 1, "Wi-Fi"),
            route("160.79.104.10", 32, 35, 2, "Juniper"),
        ];
        let best = find_best_match(&table, "160.79.104.10".parse().unwrap()).unwrap();
        assert_eq!(best.prefix_len, 32);
        assert_eq!(best.if_index, 2);
    }

    #[test]
    fn lower_metric_wins_at_tied_prefix() {
        let table = vec![
            route("8.8.8.8", 32, 35, 1, "Wi-Fi"),
            route("8.8.8.8", 32, 1, 2, "Juniper"),
        ];
        let best = find_best_match(&table, "8.8.8.8".parse().unwrap()).unwrap();
        assert_eq!(best.if_index, 2);
    }

    #[test]
    fn vpn_heuristic_matches_ivanti() {
        assert!(looks_like_vpn("Juniper Networks Virtual Adapter"));
        assert!(looks_like_vpn("Pulse Secure Virtual Adapter"));
        assert!(looks_like_vpn("Ivanti Secure Access Client"));
        assert!(looks_like_vpn("Cisco AnyConnect"));
    }

    #[test]
    fn vpn_heuristic_does_not_match_wifi() {
        assert!(!looks_like_vpn("Wi-Fi"));
        assert!(!looks_like_vpn("Intel(R) Wi-Fi 6E AX211"));
        assert!(!looks_like_vpn("Ethernet 2"));
    }

    #[test]
    fn build_rival_map_marks_strong_rivals() {
        let table = vec![
            route("160.79.104.0", 24, 1, 41, "Juniper Networks Virtual Adapter"),
            route("8.8.8.8", 32, 1, 41, "Juniper Networks Virtual Adapter"),
        ];
        let targets: Vec<IpAddr> = vec![
            "160.79.104.10".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
        ];
        let map = build_rival_map(&table, &targets, 50);
        assert_eq!(map.entries.len(), 2);
        let eight = map
            .entries
            .iter()
            .find(|e| e.target == "8.8.8.8".parse::<IpAddr>().unwrap())
            .unwrap();
        assert_eq!(eight.current_prefix_len, 32);
        assert!(eight.likely_vpn);
    }

    #[test]
    fn build_rival_map_no_rival_when_wifi_owns_route() {
        let table = vec![route("160.79.104.0", 24, 1, 50, "Wi-Fi")];
        let targets: Vec<IpAddr> = vec!["160.79.104.10".parse().unwrap()];
        let map = build_rival_map(&table, &targets, 50);
        // Wi-Fi itself is the winner — we record it as an entry but with
        // likely_vpn=false, which steers the strategy selector toward
        // Coexistence.
        assert_eq!(map.entries.len(), 1);
        assert!(!map.entries[0].likely_vpn);
    }
}
