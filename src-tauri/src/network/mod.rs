use serde::{Deserialize, Serialize};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;
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
    pub wifi_ip: String,
    pub vpn_ip: Option<String>,
    pub gateway: String,
    pub interface_name: String,
}

/// DNS sunucuları (Wi-Fi üzerinden yönlendirilecek)
pub const DNS_SERVERS: &[&str] = &["8.8.8.8", "8.8.4.4", "1.1.1.1"];

/// Platform-bagimsiz ag islemleri trait'i
pub trait NetworkOps {
    fn detect_network_config(on_log: &dyn Fn(&str)) -> Result<NetworkConfig, String>;
    fn show_status(on_log: &dyn Fn(&str));
    fn traceroute(target: &str, gateway: &str, on_log: &dyn Fn(&str));
    fn ensure_proxy_disabled(_on_log: &dyn Fn(&str)) {}
}
