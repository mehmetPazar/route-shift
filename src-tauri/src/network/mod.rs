use serde::{Deserialize, Serialize};

// Both macos and windows submodules are always compiled so their pure-logic
// helpers (parsers, filters, command builders) can be cross-platform
// unit-tested. The actual `PlatformNetwork` impls and OS FFI calls are
// individually gated by `#[cfg(target_os = "...")]` inside each module.
pub mod macos;
pub mod windows;
#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
pub use macos::PlatformNetwork;
#[cfg(target_os = "windows")]
pub use windows::PlatformNetwork;
#[cfg(target_os = "linux")]
pub use linux::PlatformNetwork;

/// Ağ yapılandırma bilgileri
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub gateway: String,
    pub interface_name: String,
    pub service_name: String,
}

/// DNS sunucuları (Wi-Fi üzerinden yönlendirilecek)
pub const DNS_SERVERS: &[&str] = &["8.8.8.8", "8.8.4.4", "1.1.1.1"];

/// Platform-bagimsiz ag islemleri trait'i.
///
/// This is the **legacy** trait. The new architecture uses `engine::BypassEngine`
/// instead (see `docs: plans/zany-wandering-parrot.md`). `NetworkOps` is kept
/// around because a handful of helpers — `show_status`, `traceroute`,
/// `ensure_proxy_disabled`, and `toggle_domain_route`'s inline path — still
/// call into it. Step 10 removed the main Aç/Kapa path from this trait.
pub trait NetworkOps {
    fn detect_network_config(on_log: &dyn Fn(&str)) -> Result<NetworkConfig, String>;
    fn show_status(on_log: &dyn Fn(&str));
    fn traceroute(target: &str, gateway: &str, on_log: &dyn Fn(&str));
    #[allow(dead_code)]
    fn ensure_proxy_disabled(_on_log: &dyn Fn(&str)) {}
}
