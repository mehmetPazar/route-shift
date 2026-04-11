//! Windows interface metric management.
//!
//! Used only by the Aggressive strategy: when every target IP has a VPN
//! /32 rival, installing our own /32 only ties specificity with the VPN,
//! and Windows picks the lower effective metric. Windows computes the
//! effective metric as `route_metric + interface_metric`, so lowering the
//! Wi-Fi InterfaceMetric to 1 brings our total to 2 while Ivanti's tunnel
//! adapter sits at 1 — and adding `/32` finishes the tie-break.
//!
//! This module uses `netsh interface ipv4 set/show interface` because it
//! is stable across Windows 10+ and much simpler than iphlpapi FFI.
//! The native FFI path via `GetIpInterfaceEntry` / `SetIpInterfaceEntry`
//! can replace this in a future step if netsh proves unreliable.
//!
//! Pure parsing / command-building is cross-platform testable; the actual
//! `Command::new("netsh")` invocation lives behind `#[cfg(target_os = "windows")]`.

#[cfg(target_os = "windows")]
use anyhow::{anyhow, Result};

/// Parse the `InterfaceMetric` value out of `netsh interface ipv4 show
/// interface "Wi-Fi"` output. Returns None if the metric line is missing
/// or malformed.
///
/// Example relevant line (English): `Metric                                : 25`
/// Example relevant line (Turkish): `Ölçüm                                 : 25`
///
/// We match by the ": N" suffix because the label is localized.
pub fn parse_interface_metric(output: &str) -> Option<u32> {
    for line in output.lines() {
        // Candidate lines look like `Label: 25` — look for a colon
        // followed by whitespace and digits at the end of the line.
        let Some((_, value)) = line.rsplit_once(':') else {
            continue;
        };
        let trimmed = value.trim();
        if let Ok(n) = trimmed.parse::<u32>() {
            // Sanity: typical metrics are 1..=10000. Reject absurd values
            // that come from unrelated lines (like MTU).
            if n > 0 && n <= 10_000 {
                return Some(n);
            }
        }
    }
    None
}

/// Produce the command arguments for `netsh interface ipv4 set interface`
/// with a metric override. Returns the arg vector so tests can verify it
/// doesn't change shape unexpectedly.
pub fn build_set_metric_args(if_index: u32, metric: u32) -> Vec<String> {
    vec![
        "interface".to_string(),
        "ipv4".to_string(),
        "set".to_string(),
        "interface".to_string(),
        format!("interface={}", if_index),
        format!("metric={}", metric),
    ]
}

/// Produce the args to read the current interface metric.
pub fn build_show_metric_args(if_index: u32) -> Vec<String> {
    vec![
        "interface".to_string(),
        "ipv4".to_string(),
        "show".to_string(),
        "interface".to_string(),
        format!("interface={}", if_index),
    ]
}

/// Produce the args to restore the metric to automatic selection.
/// Used on Kapa when we didn't record the original (rare fallback).
pub fn build_automatic_metric_args(if_index: u32) -> Vec<String> {
    vec![
        "interface".to_string(),
        "ipv4".to_string(),
        "set".to_string(),
        "interface".to_string(),
        format!("interface={}", if_index),
        "metric=automatic".to_string(),
    ]
}

// =====================================================================
// FFI layer — only compiled on Windows.
// =====================================================================

#[cfg(target_os = "windows")]
pub fn read_current_metric(if_index: u32) -> Result<u32> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let args = build_show_metric_args(if_index);
    let output = Command::new("netsh")
        .args(args.iter().map(|s| s.as_str()))
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| anyhow!("netsh read metric: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_interface_metric(&stdout).ok_or_else(|| {
        anyhow!(
            "could not parse metric from netsh output: {}",
            stdout.trim()
        )
    })
}

#[cfg(target_os = "windows")]
pub fn set_metric(if_index: u32, metric: u32) -> Result<()> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let args = build_set_metric_args(if_index, metric);
    let output = Command::new("netsh")
        .args(args.iter().map(|s| s.as_str()))
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| anyhow!("netsh set metric: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("netsh set metric failed: {}", stderr.trim()));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn restore_automatic(if_index: u32) -> Result<()> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let args = build_automatic_metric_args(if_index);
    let output = Command::new("netsh")
        .args(args.iter().map(|s| s.as_str()))
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| anyhow!("netsh automatic metric: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("netsh automatic metric failed: {}", stderr.trim()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENGLISH_OUTPUT: &str = r#"
Configuration for interface "Wi-Fi"
    DHCP enabled:                         Yes
    InterfaceMetric:                      25
    Dad Transmits:                        1
"#;

    const TURKISH_OUTPUT: &str = r#"
"Kablosuz Ağ Bağlantısı" arabirimi için yapılandırma
    DHCP etkin:                           Evet
    Arabirim Ölçümü:                      35
    Dad iletimleri:                       1
"#;

    #[test]
    fn parse_english_output() {
        assert_eq!(parse_interface_metric(ENGLISH_OUTPUT), Some(25));
    }

    #[test]
    fn parse_turkish_output() {
        assert_eq!(parse_interface_metric(TURKISH_OUTPUT), Some(35));
    }

    #[test]
    fn parse_rejects_missing_metric_line() {
        let output = "no relevant line here\nnothing\n";
        assert_eq!(parse_interface_metric(output), None);
    }

    #[test]
    fn parse_skips_absurd_values() {
        let output = "Some label: 99999999\n";
        assert_eq!(parse_interface_metric(output), None);
    }

    #[test]
    fn parse_picks_first_valid_value() {
        // First metric-like value wins.
        let output = "Label A: 5\nLabel B: 25\n";
        assert_eq!(parse_interface_metric(output), Some(5));
    }

    #[test]
    fn build_set_metric_args_shape() {
        let args = build_set_metric_args(50, 1);
        assert_eq!(args.len(), 6);
        assert_eq!(args[0], "interface");
        assert_eq!(args[4], "interface=50");
        assert_eq!(args[5], "metric=1");
    }

    #[test]
    fn build_show_metric_args_shape() {
        let args = build_show_metric_args(42);
        assert_eq!(args[2], "show");
        assert_eq!(args[4], "interface=42");
    }

    #[test]
    fn build_automatic_metric_args_shape() {
        let args = build_automatic_metric_args(50);
        assert_eq!(args[5], "metric=automatic");
    }
}
