//! Windows route command builder.
//!
//! The Ivanti-fix story in one line: **never pass the `IF <idx>` parameter
//! to `route ADD`**. Windows adds the interface's InterfaceMetric to the
//! user-specified route metric only when `IF` is given, so our routes end
//! up with effective metric 36 (Wi-Fi InterfaceMetric 35 + 1) while
//! Ivanti's own routes sit at effective metric 1. Ivanti wins, bypass
//! silently fails.
//!
//! Without `IF`, Windows resolves the interface from the gateway and
//! stores the user-specified metric as-is. Combined with Strategy-driven
//! Wi-Fi interface metric override (Step 7's `metric.rs`), our routes
//! end up at effective metric 2 (1 + 1) versus Ivanti's 1. A host /32
//! adds one final tie-break via longest-prefix-match.
//!
//! This module is a pure string builder — no FFI, no shell. Testable on
//! any platform.

use std::net::{IpAddr, Ipv4Addr};

/// Build the batch of `route ADD` commands for a list of targets.
///
/// - `exact_ips`: each one becomes a `/32` host route
/// - `subnets`: each one becomes a `/24` subnet route
/// - `gateway`: next-hop for every line
///
/// Every command uses `route DELETE ... >nul 2>&1` first so stale routes
/// from a prior session don't cause `route ADD` to fail. Each command is
/// independent and failure-tolerant when concatenated with `&`.
pub fn build_add_commands(
    exact_ips: &[Ipv4Addr],
    subnets: &[Ipv4Addr],
    gateway: IpAddr,
    metric: u32,
) -> Vec<String> {
    let mut cmds = Vec::new();
    for ip in exact_ips {
        cmds.push(format!(
            "route DELETE {ip} >nul 2>&1 & route ADD {ip} MASK 255.255.255.255 {gw} METRIC {metric}",
            ip = ip,
            gw = gateway,
            metric = metric,
        ));
    }
    for net in subnets {
        cmds.push(format!(
            "route DELETE {net} >nul 2>&1 & route ADD {net} MASK 255.255.255.0 {gw} METRIC {metric}",
            net = net,
            gw = gateway,
            metric = metric,
        ));
    }
    cmds
}

/// Build the batch of `route DELETE` commands to reverse `build_add_commands`.
pub fn build_delete_commands(exact_ips: &[Ipv4Addr], subnets: &[Ipv4Addr]) -> Vec<String> {
    let mut cmds = Vec::new();
    for ip in exact_ips {
        cmds.push(format!("route DELETE {ip} >nul 2>&1", ip = ip));
    }
    for net in subnets {
        cmds.push(format!("route DELETE {net} >nul 2>&1", net = net));
    }
    cmds
}

/// Join a batch into a single `cmd /C` invocation string. Each inner
/// command is wrapped so one failure doesn't abort the rest: `(cmd || ver >nul)`
/// — the `ver` fallback is a no-op builtin that always succeeds.
pub fn join_batch(cmds: &[String]) -> String {
    cmds.iter()
        .map(|c| format!("({} || ver >nul)", c))
        .collect::<Vec<_>>()
        .join(" & ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn add_uses_no_if_parameter() {
        let cmds = build_add_commands(
            &[v4("8.8.8.8")],
            &[v4("160.79.104.0")],
            IpAddr::V4(v4("192.168.1.1")),
            1,
        );
        assert_eq!(cmds.len(), 2);
        for cmd in &cmds {
            assert!(!cmd.contains(" IF "), "should never include `IF` parameter");
            assert!(cmd.contains("METRIC 1"));
        }
    }

    #[test]
    fn add_includes_delete_before_add() {
        let cmds = build_add_commands(
            &[v4("8.8.8.8")],
            &[],
            IpAddr::V4(v4("192.168.1.1")),
            1,
        );
        assert_eq!(cmds.len(), 1);
        assert!(cmds[0].starts_with("route DELETE 8.8.8.8"));
        assert!(cmds[0].contains("route ADD 8.8.8.8"));
    }

    #[test]
    fn host_routes_use_32_mask() {
        let cmds = build_add_commands(
            &[v4("1.1.1.1")],
            &[],
            IpAddr::V4(v4("192.168.1.1")),
            1,
        );
        assert!(cmds[0].contains("MASK 255.255.255.255"));
    }

    #[test]
    fn subnet_routes_use_24_mask() {
        let cmds = build_add_commands(
            &[],
            &[v4("160.79.104.0")],
            IpAddr::V4(v4("192.168.1.1")),
            1,
        );
        assert!(cmds[0].contains("MASK 255.255.255.0"));
    }

    #[test]
    fn delete_strips_routes() {
        let cmds = build_delete_commands(
            &[v4("8.8.8.8"), v4("1.1.1.1")],
            &[v4("160.79.104.0")],
        );
        assert_eq!(cmds.len(), 3);
        assert!(cmds[0].starts_with("route DELETE 8.8.8.8"));
        assert!(cmds[2].starts_with("route DELETE 160.79.104.0"));
    }

    #[test]
    fn join_batch_uses_failure_tolerant_syntax() {
        let cmds = vec!["route ADD a".to_string(), "route ADD b".to_string()];
        let batch = join_batch(&cmds);
        assert_eq!(batch, "(route ADD a || ver >nul) & (route ADD b || ver >nul)");
    }

    #[test]
    fn empty_inputs_produce_empty_batch() {
        let cmds = build_add_commands(&[], &[], IpAddr::V4(v4("192.168.1.1")), 1);
        assert!(cmds.is_empty());
        assert_eq!(join_batch(&cmds), "");
    }

    #[test]
    fn multiple_ips_and_subnets_ordered_consistently() {
        let cmds = build_add_commands(
            &[v4("8.8.8.8"), v4("8.8.4.4"), v4("1.1.1.1")],
            &[v4("160.79.104.0"), v4("104.18.32.0")],
            IpAddr::V4(v4("10.0.0.1")),
            1,
        );
        assert_eq!(cmds.len(), 5);
        assert!(cmds[0].contains("8.8.8.8"));
        assert!(cmds[1].contains("8.8.4.4"));
        assert!(cmds[2].contains("1.1.1.1"));
        assert!(cmds[3].contains("160.79.104.0"));
        assert!(cmds[4].contains("104.18.32.0"));
    }
}
