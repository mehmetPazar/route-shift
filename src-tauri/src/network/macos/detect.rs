//! Native macOS primary-interface detection.
//!
//! This module intentionally does **not** trust `scutil --nwi`'s
//! `Primary IPv4 Interface` field when a NetworkExtension VPN is active.
//! When Zscaler / GlobalProtect / Ivanti style VPNs take over the default
//! route, scutil reports the `utunN` tunnel as primary. `utunN` has no
//! DHCP lease, so every downstream discovery step then fails.
//!
//! Instead we always look for the physical Wi-Fi (or Ethernet) hardware
//! port directly via `networksetup -listallhardwareports`, read its BSD
//! device name (e.g. `en0`), and ask `ipconfig getoption <device> router`
//! for the real DHCP-learned gateway. That gateway is unaffected by any
//! VPN because it comes from the interface's own DHCP lease.
//!
//! Fallbacks, in order:
//!   1. Physical hardware port from `networksetup -listallhardwareports`
//!   2. `scutil --nwi` Primary IPv4 Interface (only when no Wi-Fi found)
//!   3. `route -n get default -ifscope <dev>` for the gateway if ipconfig
//!      returns nothing
//!   4. `.1` of the interface's own /24 as a last-resort guess (logged)
//!
//! The pure parsing logic is cross-platform testable. The actual
//! `Command::new(...)` invocations live behind `#[cfg(target_os = "macos")]`.

use crate::engine::types::{NetworkSnapshot, ProxyState, WifiInterface};
use anyhow::{anyhow, Context, Result};
use std::net::{IpAddr, Ipv4Addr};

/// Extract the `Primary IPv4 Interface` line value from `scutil --nwi`
/// output. Returns `None` if the key is missing.
///
/// Sample relevant line (all macOS versions, all locales):
/// `   Primary IPv4 Interface : en0`
pub fn parse_primary_interface(scutil_output: &str) -> Option<String> {
    for line in scutil_output.lines() {
        let trimmed = line.trim();
        // Case-insensitive prefix match so minor wording drift still works.
        let lower = trimmed.to_lowercase();
        if lower.starts_with("primary ipv4 interface") {
            if let Some((_, value)) = trimmed.split_once(':') {
                let name = value.trim();
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

/// Extract a gateway IP from `ipconfig getoption <iface> router` output.
///
/// The command prints just one line like `192.168.1.1\n` on success and
/// nothing on failure. We accept both cases plus any extra whitespace.
pub fn parse_gateway(ipconfig_output: &str) -> Option<Ipv4Addr> {
    let trimmed = ipconfig_output.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<Ipv4Addr>().ok()
}

/// Parse `route -n get default -ifscope <dev>` output for the `gateway:`
/// line. Used as a fallback when `ipconfig getoption` returns nothing.
pub fn parse_route_gateway(route_output: &str) -> Option<Ipv4Addr> {
    for line in route_output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("gateway:") {
            if let Ok(ip) = rest.trim().parse::<Ipv4Addr>() {
                return Some(ip);
            }
        }
    }
    None
}

/// Parse `ifconfig <iface>` output for the first non-loopback IPv4 address.
pub fn parse_ifconfig_inet(ifconfig_output: &str) -> Option<Ipv4Addr> {
    for line in ifconfig_output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            let first = rest.split_whitespace().next().unwrap_or("");
            if let Ok(ip) = first.parse::<Ipv4Addr>() {
                if ip != Ipv4Addr::new(127, 0, 0, 1) {
                    return Some(ip);
                }
            }
        }
    }
    None
}

/// Classification of a hardware port entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortKind {
    Wifi,
    Ethernet,
    Other,
}

/// One entry parsed from `networksetup -listallhardwareports`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwarePort {
    pub service_name: String, // e.g. "Wi-Fi", "Ethernet"
    pub device: String,       // e.g. "en0"
    pub kind: PortKind,
}

/// Parse `networksetup -listallhardwareports` and return every hardware
/// port entry with a non-empty BSD device name. Order is preserved so
/// callers can apply their own preference (Wi-Fi > Ethernet > Other).
///
/// Input shape (three lines per entry, blank between entries):
/// ```text
/// Hardware Port: Wi-Fi
/// Device: en0
/// Ethernet Address: aa:bb:cc:dd:ee:ff
/// ```
pub fn parse_hardware_ports(input: &str) -> Vec<HardwarePort> {
    let mut out = Vec::new();
    let mut current_port: Option<String> = None;

    for line in input.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("Hardware Port:") {
            current_port = Some(name.trim().to_string());
            continue;
        }
        if let Some(dev) = trimmed.strip_prefix("Device:") {
            let device = dev.trim().to_string();
            if let Some(port_name) = current_port.as_ref() {
                if !device.is_empty() {
                    let kind = classify_port(port_name);
                    out.push(HardwarePort {
                        service_name: port_name.clone(),
                        device,
                        kind,
                    });
                }
            }
            continue;
        }
    }

    out
}

fn classify_port(name: &str) -> PortKind {
    let lower = name.to_lowercase();
    if lower.contains("wi-fi") || lower.contains("wifi") || lower.contains("airport") {
        PortKind::Wifi
    } else if lower.contains("ethernet") || lower.contains("thunderbolt") || lower.contains("usb") {
        PortKind::Ethernet
    } else {
        PortKind::Other
    }
}

/// Pick the best primary physical port from a parsed hardware-port list.
/// Preference order: Wi-Fi > Ethernet > Other. Virtual / VPN devices
/// (utun*, ipsec*, ppp*, tap*, tun*) are never returned.
pub fn select_primary_port(ports: &[HardwarePort]) -> Option<&HardwarePort> {
    let is_physical = |p: &&HardwarePort| {
        let dev = p.device.as_str();
        !(dev.starts_with("utun")
            || dev.starts_with("ipsec")
            || dev.starts_with("ppp")
            || dev.starts_with("tap")
            || dev.starts_with("tun"))
    };

    if let Some(p) = ports.iter().filter(is_physical).find(|p| p.kind == PortKind::Wifi) {
        return Some(p);
    }
    if let Some(p) = ports
        .iter()
        .filter(is_physical)
        .find(|p| p.kind == PortKind::Ethernet)
    {
        return Some(p);
    }
    ports.iter().filter(is_physical).next()
}

/// Build a `NetworkSnapshot` from the resolved inputs. Pure, testable.
pub fn build_snapshot(
    device: &str,
    service_name: &str,
    gateway: IpAddr,
    wifi_ipv4: Option<Ipv4Addr>,
) -> NetworkSnapshot {
    NetworkSnapshot {
        wifi: WifiInterface {
            index: 0, // kernel ifindex not used on macOS
            name: device.to_string(),
            mac: None,
            ipv4: wifi_ipv4,
            is_virtual: false,
            is_up: true,
            default_metric: None,
        },
        default_gateway: gateway,
        primary_service_name: service_name.to_string(),
        proxy: ProxyState::Unknown,
        ipv6_enabled: true,
        detected_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    }
}

/// Best-effort derive a `.1` gateway from a `192.168.42.17`-style interface
/// IPv4. This is the last-resort fallback when every other probe failed.
pub fn guess_gateway_from_ipv4(ip: Ipv4Addr) -> Ipv4Addr {
    let [a, b, c, _] = ip.octets();
    Ipv4Addr::new(a, b, c, 1)
}

// =====================================================================
// FFI layer — only compiled on macOS.
// =====================================================================

#[cfg(target_os = "macos")]
pub fn detect_primary_interface() -> Result<NetworkSnapshot> {
    use std::process::Command;

    // 1. networksetup -listallhardwareports → physical Wi-Fi / Ethernet device.
    //    We intentionally do NOT read scutil --nwi's Primary IPv4 Interface
    //    first because active VPNs (utun*) hijack that field and produce
    //    useless downstream answers.
    let hw_out = Command::new("networksetup")
        .args(["-listallhardwareports"])
        .output()
        .context("networksetup -listallhardwareports")?;
    if !hw_out.status.success() {
        return Err(anyhow!(
            "networksetup -listallhardwareports failed: {}",
            String::from_utf8_lossy(&hw_out.stderr).trim()
        ));
    }
    let hw_str = String::from_utf8_lossy(&hw_out.stdout);
    let ports = parse_hardware_ports(&hw_str);
    let primary = select_primary_port(&ports);

    // 2. Pick (service_name, device). If no physical port exists, fall back
    //    to scutil --nwi but reject VPN tunnel devices there too.
    let (service_name, device) = if let Some(p) = primary {
        (p.service_name.clone(), p.device.clone())
    } else {
        let scutil_out = Command::new("scutil")
            .args(["--nwi"])
            .output()
            .context("scutil --nwi")?;
        let scutil_str = String::from_utf8_lossy(&scutil_out.stdout);
        let dev = parse_primary_interface(&scutil_str).ok_or_else(|| {
            anyhow!(
                "no physical hardware port found and scutil --nwi reported no Primary IPv4 Interface"
            )
        })?;
        if dev.starts_with("utun")
            || dev.starts_with("ipsec")
            || dev.starts_with("ppp")
            || dev.starts_with("tap")
            || dev.starts_with("tun")
        {
            return Err(anyhow!(
                "only VPN-tunnel interfaces are available (scutil reported '{}'); Wi-Fi not connected?",
                dev
            ));
        }
        ("Wi-Fi".to_string(), dev)
    };

    // 3. Try ipconfig getoption <device> router first (DHCP lease, VPN-proof).
    let ipconfig_out = Command::new("ipconfig")
        .args(["getoption", &device, "router"])
        .output()
        .with_context(|| format!("ipconfig getoption {} router", device))?;
    let ipconfig_str = String::from_utf8_lossy(&ipconfig_out.stdout);
    let mut gateway = parse_gateway(&ipconfig_str);

    // 4. Fall back to `route -n get default -ifscope <device>`.
    if gateway.is_none() {
        if let Ok(out) = Command::new("route")
            .args(["-n", "get", "default", "-ifscope", &device])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            gateway = parse_route_gateway(&text);
        }
    }

    // 5. Read the interface's own IPv4 once; we need it for the last-resort
    //    gateway guess and for the snapshot.
    let ifaddr_out = Command::new("ipconfig")
        .args(["getifaddr", &device])
        .output()
        .ok();
    let wifi_ipv4 = ifaddr_out
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<Ipv4Addr>().ok());

    // If we still have no gateway, derive `.1` from the interface's own IP.
    // This is never a great answer but it matches how the legacy code
    // behaved on this machine for months, so preserving it keeps the app
    // usable while the user investigates their DHCP situation.
    let gateway = gateway.or_else(|| wifi_ipv4.map(guess_gateway_from_ipv4)).ok_or_else(|| {
        anyhow!(
            "could not determine gateway for {} via ipconfig or route; is {} connected?",
            device,
            device
        )
    })?;

    Ok(build_snapshot(
        &device,
        &service_name,
        IpAddr::V4(gateway),
        wifi_ipv4,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCUTIL_SAMPLE: &str = r#"
Network information

IPv4 network interface information
     en0 : flags      : 0x5 (IPv4,DNS)
       address    : 192.168.1.42
       reach      : 0x00020002 (Reachable,Directly Reachable Address)

IPv6 network interface information
     en0 : flags      : 0x5 (IPv6,DNS)

   REACH : flags 0x00020002 (Reachable,Directly Reachable Address)

Network interfaces: en0

   Primary IPv4 Interface : en0
   Primary IPv6 Interface : en0
   Primary DNS IPv4 Interface : en0
"#;

    const SCUTIL_UNUSUAL_FORMAT: &str = r#"
   Primary IPv4 Interface   :   utun4
"#;

    const HARDWARE_PORTS_SAMPLE: &str = r#"Hardware Port: Wi-Fi
Device: en0
Ethernet Address: aa:bb:cc:dd:ee:ff

Hardware Port: Thunderbolt Ethernet
Device: en5
Ethernet Address: 11:22:33:44:55:66

Hardware Port: Bluetooth PAN
Device: en6
Ethernet Address: 77:88:99:aa:bb:cc
"#;

    const HARDWARE_PORTS_ETH_ONLY: &str = r#"Hardware Port: Ethernet
Device: en1
Ethernet Address: de:ad:be:ef:00:01
"#;

    const HARDWARE_PORTS_NO_PHYSICAL: &str = r#"Hardware Port: Virtual Tunnel
Device: utun4

Hardware Port: Bluetooth PAN
Device: en9
"#;

    #[test]
    fn parses_standard_scutil_primary_interface() {
        assert_eq!(
            parse_primary_interface(SCUTIL_SAMPLE),
            Some("en0".to_string())
        );
    }

    #[test]
    fn parses_scutil_with_extra_whitespace() {
        assert_eq!(
            parse_primary_interface(SCUTIL_UNUSUAL_FORMAT),
            Some("utun4".to_string())
        );
    }

    #[test]
    fn returns_none_when_scutil_output_has_no_primary() {
        let out = "no primary line here\n";
        assert_eq!(parse_primary_interface(out), None);
    }

    #[test]
    fn parses_ipconfig_gateway_simple() {
        assert_eq!(
            parse_gateway("192.168.1.1\n"),
            Some("192.168.1.1".parse().unwrap())
        );
    }

    #[test]
    fn parses_ipconfig_gateway_with_whitespace() {
        assert_eq!(
            parse_gateway("   10.0.0.1  \n"),
            Some("10.0.0.1".parse().unwrap())
        );
    }

    #[test]
    fn ipconfig_empty_output_returns_none() {
        assert_eq!(parse_gateway(""), None);
        assert_eq!(parse_gateway("\n\n"), None);
    }

    #[test]
    fn ipconfig_nonsense_output_returns_none() {
        assert_eq!(parse_gateway("not-an-ip"), None);
    }

    #[test]
    fn parses_route_default_gateway() {
        let sample = r#"   route to: default
destination: default
       mask: default
    gateway: 10.0.0.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
"#;
        assert_eq!(parse_route_gateway(sample), Some("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn route_gateway_missing_returns_none() {
        assert_eq!(parse_route_gateway("no gateway field here\n"), None);
    }

    #[test]
    fn parses_ifconfig_inet_line() {
        let sample = r#"en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
    ether aa:bb:cc:dd:ee:ff
    inet 192.168.1.42 netmask 0xffffff00 broadcast 192.168.1.255
    inet6 fe80::1%en0 prefixlen 64 scopeid 0x4
"#;
        assert_eq!(
            parse_ifconfig_inet(sample),
            Some("192.168.1.42".parse().unwrap())
        );
    }

    #[test]
    fn parses_hardware_ports_in_order() {
        let ports = parse_hardware_ports(HARDWARE_PORTS_SAMPLE);
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0].service_name, "Wi-Fi");
        assert_eq!(ports[0].device, "en0");
        assert_eq!(ports[0].kind, PortKind::Wifi);
        assert_eq!(ports[1].kind, PortKind::Ethernet);
        assert_eq!(ports[2].kind, PortKind::Other);
    }

    #[test]
    fn selects_wifi_when_present() {
        let ports = parse_hardware_ports(HARDWARE_PORTS_SAMPLE);
        let primary = select_primary_port(&ports).expect("should find a primary");
        assert_eq!(primary.device, "en0");
        assert_eq!(primary.kind, PortKind::Wifi);
    }

    #[test]
    fn selects_ethernet_when_no_wifi() {
        let ports = parse_hardware_ports(HARDWARE_PORTS_ETH_ONLY);
        let primary = select_primary_port(&ports).expect("should find a primary");
        assert_eq!(primary.device, "en1");
        assert_eq!(primary.kind, PortKind::Ethernet);
    }

    #[test]
    fn rejects_vpn_tunnel_devices_in_selection() {
        let ports = parse_hardware_ports(HARDWARE_PORTS_NO_PHYSICAL);
        let primary = select_primary_port(&ports).expect("bluetooth pan is still physical");
        assert_eq!(primary.device, "en9");
        assert_ne!(primary.device, "utun4");
    }

    #[test]
    fn classify_port_handles_common_names() {
        assert_eq!(classify_port("Wi-Fi"), PortKind::Wifi);
        assert_eq!(classify_port("AirPort"), PortKind::Wifi);
        assert_eq!(classify_port("Thunderbolt Ethernet"), PortKind::Ethernet);
        assert_eq!(classify_port("USB 10/100/1000 LAN"), PortKind::Ethernet);
        assert_eq!(classify_port("Bluetooth PAN"), PortKind::Other);
    }

    #[test]
    fn guess_gateway_from_ipv4_uses_dot_one() {
        assert_eq!(
            guess_gateway_from_ipv4("192.168.42.17".parse().unwrap()),
            "192.168.42.1".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn build_snapshot_populates_expected_fields() {
        let snap = build_snapshot(
            "en0",
            "Wi-Fi",
            "192.168.1.1".parse().unwrap(),
            Some("192.168.1.42".parse().unwrap()),
        );
        assert_eq!(snap.wifi.name, "en0");
        assert_eq!(snap.primary_service_name, "Wi-Fi");
        assert_eq!(snap.default_gateway, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(snap.wifi.ipv4, Some("192.168.1.42".parse().unwrap()));
        assert!(!snap.wifi.is_virtual);
    }
}
