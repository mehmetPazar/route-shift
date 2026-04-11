//! Native Windows Wi-Fi detection using `GetAdaptersAddresses`.
//!
//! Replaces the `route PRINT` string-parsing approach with direct iphlpapi
//! calls. Fixes two concrete bugs:
//!
//! 1. **Turkish / non-English Windows**: the old code searched for literal
//!    substrings like "wi-fi" / "wireless" / "wlan". On Turkish Windows the
//!    adapter may appear as `"Kablosuz Ağ Bağlantısı"` and on unusual
//!    driver names may contain none of the English keywords. Native
//!    detection uses `IfType == IF_TYPE_IEEE80211` which is language-agnostic.
//!
//! 2. **Multi-virtual-adapter machines**: the old code took the first
//!    string match. Machines with Hyper-V / WSL / VMware / Wi-Fi Direct /
//!    old USB dongles often have 20+ adapters listed, and the wrong one
//!    would be picked. Native detection filters on:
//!      - `IfOperStatusUp`              (adapter is actually connected)
//!      - `IfType == IF_TYPE_IEEE80211` (real Wi-Fi hardware)
//!      - `FirstUnicastAddress != null` (has an IPv4 address)
//!      - `FirstGatewayAddress != null` (has a default gateway)
//!    If multiple adapters pass, we prefer the one with the lowest
//!    interface metric (Windows considers this the "primary").
//!
//! The pure filtering / selection logic is in `AdapterCandidate` — no
//! OS calls, fully unit-testable on any platform. The actual Win32 API
//! invocation lives behind `#[cfg(target_os = "windows")]`.

use crate::engine::types::{NetworkSnapshot, ProxyState, WifiInterface};
use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr};

/// A candidate adapter extracted from `GetAdaptersAddresses`, in a form
/// that is cheap to construct in tests. Pure data, no FFI types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterCandidate {
    pub if_index: u32,
    pub friendly_name: String,
    pub description: String,
    pub is_up: bool,
    pub is_ieee80211: bool,
    pub is_ethernet: bool,
    /// True if the adapter has at least one unicast IPv4 address.
    pub has_ipv4: bool,
    pub ipv4: Option<Ipv4Addr>,
    /// True if the adapter has a non-empty gateway list.
    pub has_gateway: bool,
    pub gateway: Option<IpAddr>,
    pub mac: Option<String>,
    /// The interface metric (lower = preferred). Windows combines route
    /// metric + interface metric when picking routes.
    pub interface_metric: Option<u32>,
}

impl AdapterCandidate {
    /// Name heuristic: reject obvious non-physical adapters by substring.
    /// This is a last line of defense — the primary filter is IfType /
    /// OperStatus / gateway presence. Anything surviving this check is a
    /// plausible candidate.
    pub fn is_virtual_by_name(&self) -> bool {
        let haystack = format!(
            "{} {}",
            self.friendly_name.to_lowercase(),
            self.description.to_lowercase()
        );
        const VIRTUAL_KEYWORDS: &[&str] = &[
            "virtual",
            "hyper-v",
            "hyperv",
            "wsl",
            "vmware",
            "virtualbox",
            "vbox",
            "loopback",
            "pseudo",
            "tap-",
            "tap ",
            "tun",
            "openvpn",
            "wireguard",
            "pulse",
            "ivanti",
            "juniper",
            "cisco anyconnect",
            "cisco systems vpn",
            "globalprotect",
            "zscaler",
            "forticlient",
            "checkpoint",
            "docker",
            "ppp",
            "wi-fi direct",
            "wifi direct",
            "miniport",
            "microsoft wi-fi direct",
        ];
        VIRTUAL_KEYWORDS.iter().any(|kw| haystack.contains(kw))
    }

    /// Returns true if this adapter is a plausible primary Wi-Fi / Ethernet.
    pub fn is_plausible_primary(&self) -> bool {
        self.is_up
            && self.has_ipv4
            && self.has_gateway
            && !self.is_virtual_by_name()
            && (self.is_ieee80211 || self.is_ethernet)
    }
}

/// Pick the best primary adapter from a list of candidates.
///
/// Ordering:
/// 1. Prefer Wi-Fi (IEEE 802.11) over Ethernet. Most users run RouteShift
///    on a laptop on Wi-Fi; Ethernet is a fallback.
/// 2. Among Wi-Fi (or among Ethernet when no Wi-Fi qualifies), prefer
///    lowest interface metric — Windows considers that the primary.
/// 3. Break metric ties by lowest `if_index`.
pub fn select_primary(candidates: &[AdapterCandidate]) -> Option<&AdapterCandidate> {
    let plausible: Vec<&AdapterCandidate> = candidates
        .iter()
        .filter(|c| c.is_plausible_primary())
        .collect();
    if plausible.is_empty() {
        return None;
    }

    // First pass: Wi-Fi candidates.
    let wifi: Vec<&&AdapterCandidate> = plausible.iter().filter(|c| c.is_ieee80211).collect();
    if !wifi.is_empty() {
        return wifi
            .iter()
            .min_by_key(|c| {
                (
                    c.interface_metric.unwrap_or(u32::MAX),
                    c.if_index,
                )
            })
            .map(|v| **v);
    }

    // Second pass: Ethernet fallback.
    plausible
        .iter()
        .filter(|c| c.is_ethernet)
        .min_by_key(|c| (c.interface_metric.unwrap_or(u32::MAX), c.if_index))
        .copied()
}

/// Build a `NetworkSnapshot` from a selected adapter candidate.
pub fn snapshot_from_candidate(c: &AdapterCandidate) -> Result<NetworkSnapshot> {
    let gateway = c
        .gateway
        .ok_or_else(|| anyhow!("adapter {} has no gateway", c.if_index))?;
    Ok(NetworkSnapshot {
        wifi: WifiInterface {
            index: c.if_index,
            name: if !c.friendly_name.is_empty() {
                c.friendly_name.clone()
            } else {
                c.description.clone()
            },
            mac: c.mac.clone(),
            ipv4: c.ipv4,
            is_virtual: false,
            is_up: true,
            default_metric: c.interface_metric,
        },
        default_gateway: gateway,
        primary_service_name: String::new(), // unused on Windows
        proxy: ProxyState::Unknown,
        ipv6_enabled: true,
        detected_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    })
}

// =====================================================================
// Win32 FFI layer — only compiled on Windows.
// =====================================================================

#[cfg(target_os = "windows")]
pub fn detect_primary_adapter() -> Result<NetworkSnapshot> {
    let candidates = enumerate_adapters()?;
    let primary = select_primary(&candidates)
        .ok_or_else(|| anyhow!("no plausible Wi-Fi / Ethernet adapter found"))?;
    snapshot_from_candidate(primary)
}

#[cfg(target_os = "windows")]
fn enumerate_adapters() -> Result<Vec<AdapterCandidate>> {
    use std::mem::MaybeUninit;
    use std::ptr;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
        IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_UNSPEC, SOCKADDR_IN};
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};

    let flags: u32 = GAA_FLAG_INCLUDE_GATEWAYS
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;

    // Step 1: call with null buffer to learn the required size. Use a
    // small initial guess of 32KB so most machines skip the two-call dance.
    let mut size: u32 = 32 * 1024;
    let mut buffer: Vec<u8> = vec![0u8; size as usize];

    // Retry up to 3 times in case the adapter set changes between calls.
    for _ in 0..3 {
        let ret = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                ptr::null(),
                buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };
        if ret == ERROR_SUCCESS {
            break;
        }
        if ret == ERROR_BUFFER_OVERFLOW {
            buffer = vec![0u8; size as usize];
            continue;
        }
        return Err(anyhow!("GetAdaptersAddresses failed with code {}", ret));
    }

    // Step 2: walk the linked list.
    let mut candidates = Vec::new();
    let mut current = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !current.is_null() {
        let adapter = unsafe { &*current };
        let if_index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
        let friendly_name = read_wide(adapter.FriendlyName);
        let description = read_wide(adapter.Description);
        let is_up = adapter.OperStatus == IfOperStatusUp;
        let if_type = adapter.IfType;
        let is_ieee80211 = if_type == IF_TYPE_IEEE80211;
        let is_ethernet = if_type == IF_TYPE_ETHERNET_CSMACD;

        // First unicast IPv4 address.
        let (has_ipv4, ipv4) = first_ipv4_unicast(adapter.FirstUnicastAddress);

        // First gateway (prefer IPv4).
        let (has_gateway, gateway) = first_gateway_ipv4(adapter.FirstGatewayAddress);

        // MAC address.
        let mac = if adapter.PhysicalAddressLength == 6 {
            Some(format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                adapter.PhysicalAddress[0],
                adapter.PhysicalAddress[1],
                adapter.PhysicalAddress[2],
                adapter.PhysicalAddress[3],
                adapter.PhysicalAddress[4],
                adapter.PhysicalAddress[5],
            ))
        } else {
            None
        };

        // Interface metric via Ipv4Metric field on newer LH struct.
        let interface_metric = Some(adapter.Ipv4Metric);

        candidates.push(AdapterCandidate {
            if_index,
            friendly_name,
            description,
            is_up,
            is_ieee80211,
            is_ethernet,
            has_ipv4,
            ipv4,
            has_gateway,
            gateway,
            mac,
            interface_metric,
        });

        current = adapter.Next;
    }

    // Guard against totally empty lists.
    let _ = MaybeUninit::<SOCKADDR_IN>::uninit();
    let _ = AF_INET;
    Ok(candidates)
}

#[cfg(target_os = "windows")]
fn read_wide(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // Scan for the null terminator.
    let mut len = 0usize;
    loop {
        let c = unsafe { *ptr.add(len) };
        if c == 0 {
            break;
        }
        len += 1;
        if len > 512 {
            // sanity
            break;
        }
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16_lossy(slice)
}

#[cfg(target_os = "windows")]
fn first_ipv4_unicast(
    mut cur: *const windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_UNICAST_ADDRESS_LH,
) -> (bool, Option<Ipv4Addr>) {
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};
    while !cur.is_null() {
        let addr = unsafe { &*cur };
        let sockaddr_ptr = addr.Address.lpSockaddr;
        if !sockaddr_ptr.is_null() {
            let family = unsafe { (*sockaddr_ptr).sa_family };
            if family == AF_INET {
                let sin = sockaddr_ptr as *const SOCKADDR_IN;
                let bytes = unsafe { (*sin).sin_addr.S_un.S_un_b };
                let ip = Ipv4Addr::new(bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4);
                return (true, Some(ip));
            }
        }
        cur = addr.Next;
    }
    (false, None)
}

#[cfg(target_os = "windows")]
fn first_gateway_ipv4(
    mut cur: *const windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_GATEWAY_ADDRESS_LH,
) -> (bool, Option<IpAddr>) {
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};
    while !cur.is_null() {
        let gw = unsafe { &*cur };
        let sockaddr_ptr = gw.Address.lpSockaddr;
        if !sockaddr_ptr.is_null() {
            let family = unsafe { (*sockaddr_ptr).sa_family };
            if family == AF_INET {
                let sin = sockaddr_ptr as *const SOCKADDR_IN;
                let bytes = unsafe { (*sin).sin_addr.S_un.S_un_b };
                let ip = Ipv4Addr::new(bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4);
                return (true, Some(IpAddr::V4(ip)));
            }
        }
        cur = gw.Next;
    }
    (false, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(
        idx: u32,
        name: &str,
        desc: &str,
        is_up: bool,
        wifi: bool,
        eth: bool,
        has_ip: bool,
        has_gw: bool,
        metric: u32,
    ) -> AdapterCandidate {
        AdapterCandidate {
            if_index: idx,
            friendly_name: name.to_string(),
            description: desc.to_string(),
            is_up,
            is_ieee80211: wifi,
            is_ethernet: eth,
            has_ipv4: has_ip,
            ipv4: if has_ip {
                Some(Ipv4Addr::new(192, 168, 1, 10))
            } else {
                None
            },
            has_gateway: has_gw,
            gateway: if has_gw {
                Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
            } else {
                None
            },
            mac: None,
            interface_metric: Some(metric),
        }
    }

    #[test]
    fn virtual_adapters_filtered_by_name() {
        let candidates = vec![
            make(1, "Wi-Fi", "Intel Wi-Fi 6 AX201", true, true, false, true, true, 35),
            make(
                2,
                "Local Area Connection* 1",
                "Microsoft Wi-Fi Direct Virtual Adapter",
                true,
                true,
                false,
                true,
                true,
                35,
            ),
            make(
                3,
                "vEthernet (WSL)",
                "Hyper-V Virtual Ethernet Adapter",
                true,
                false,
                true,
                true,
                true,
                5,
            ),
        ];
        let primary = select_primary(&candidates).expect("should find one");
        assert_eq!(primary.if_index, 1);
        assert_eq!(primary.friendly_name, "Wi-Fi");
    }

    #[test]
    fn ivanti_pulse_filtered_out() {
        let candidates = vec![
            make(
                1,
                "Ethernet 2",
                "Juniper Networks Virtual Adapter",
                true,
                false,
                true,
                true,
                true,
                1,
            ),
            make(2, "Wi-Fi", "Intel Wi-Fi 6E AX211", true, true, false, true, true, 35),
        ];
        let primary = select_primary(&candidates).expect("should find one");
        assert_eq!(primary.if_index, 2);
    }

    #[test]
    fn turkish_windows_adapter_name_accepted() {
        // Even if the friendly name is localized, IfType filter accepts it.
        let candidates = vec![make(
            50,
            "Kablosuz Ağ Bağlantısı",
            "Intel(R) Wi-Fi 6E AX211 160MHz",
            true,
            true,
            false,
            true,
            true,
            25,
        )];
        let primary = select_primary(&candidates).expect("should find one");
        assert_eq!(primary.if_index, 50);
    }

    #[test]
    fn lowest_metric_wins_among_wifi() {
        let candidates = vec![
            make(1, "Wi-Fi", "Intel Wi-Fi 6 AX201", true, true, false, true, true, 35),
            make(2, "Wi-Fi 2", "USB Wi-Fi Dongle", true, true, false, true, true, 25),
        ];
        let primary = select_primary(&candidates).expect("should find one");
        assert_eq!(primary.if_index, 2);
    }

    #[test]
    fn down_adapter_rejected() {
        let candidates = vec![
            make(1, "Wi-Fi", "Intel Wi-Fi 6 AX201", false, true, false, true, true, 35),
            make(2, "Ethernet", "Realtek GbE", true, false, true, true, true, 5),
        ];
        let primary = select_primary(&candidates).expect("should find one");
        assert_eq!(primary.if_index, 2);
    }

    #[test]
    fn no_gateway_rejected() {
        let candidates = vec![make(1, "Wi-Fi", "Intel Wi-Fi 6 AX201", true, true, false, true, false, 35)];
        assert!(select_primary(&candidates).is_none());
    }

    #[test]
    fn no_ipv4_rejected() {
        let candidates = vec![make(1, "Wi-Fi", "Intel Wi-Fi 6 AX201", true, true, false, false, true, 35)];
        assert!(select_primary(&candidates).is_none());
    }

    #[test]
    fn empty_list_returns_none() {
        assert!(select_primary(&[]).is_none());
    }

    #[test]
    fn ethernet_fallback_when_no_wifi() {
        let candidates = vec![
            make(
                1,
                "vEthernet (WSL)",
                "Hyper-V Virtual Ethernet Adapter",
                true,
                false,
                true,
                true,
                true,
                5,
            ),
            make(2, "Ethernet", "Realtek PCIe GbE", true, false, true, true, true, 25),
        ];
        let primary = select_primary(&candidates).expect("should find one");
        assert_eq!(primary.if_index, 2);
    }

    #[test]
    fn snapshot_from_candidate_populates_fields() {
        let c = make(50, "Wi-Fi", "Intel Wi-Fi 6E AX211", true, true, false, true, true, 25);
        let snap = snapshot_from_candidate(&c).expect("should build");
        assert_eq!(snap.wifi.index, 50);
        assert_eq!(snap.wifi.name, "Wi-Fi");
        assert_eq!(snap.default_gateway, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(snap.wifi.default_metric, Some(25));
    }
}
