//! Windows platform backend for RouteShift.
//!
//! The existing `PlatformNetwork` type (below) still contains the legacy
//! `route PRINT` parsing + `route ADD` command shell-out path. Step 6/7
//! layers new native-API modules alongside it:
//!
//!   - `detect` — native Wi-Fi adapter discovery via `GetAdaptersAddresses`
//!   - `probe`  — native rival-route detection via `GetIpForwardTable2`
//!
//! Step 10 retires the `PlatformNetwork` flat impl once the native path
//! is the default for both detect and apply.

// Pure-logic modules — compiled on all platforms so their unit tests
// run in normal `cargo test` from macOS / Linux. The Win32 FFI inside
// them is individually gated by `#[cfg(target_os = "windows")]`.
#[allow(dead_code)]
pub mod detect;
#[allow(dead_code)]
pub mod metric;
#[allow(dead_code)]
pub mod probe;
#[allow(dead_code)]
pub mod routes;

#[cfg(target_os = "windows")]
use super::{NetworkConfig, NetworkOps};
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
#[cfg(target_os = "windows")]
use std::process::Command;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[cfg(target_os = "windows")]
pub struct PlatformNetwork;

#[cfg(target_os = "windows")]
impl PlatformNetwork {
    fn exec(cmd: &str, args: &[&str]) -> Result<String, String> {
        let output = Command::new(cmd)
            .args(args)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("{} çalıştırılamadı: {}", cmd, e))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("{} hatası: {}", cmd, stderr.trim()))
        }
    }

    /// Wi-Fi interface ID'sini route PRINT çıktısından bul
    fn find_wifi_interface_id(route_output: &str) -> Option<(u32, String)> {
        let iface_lines: Vec<&str> = route_output
            .lines()
            .filter(|l| {
                let trimmed = l.trim();
                !trimmed.is_empty()
                    && trimmed.chars().next().map_or(false, |c| c.is_ascii_digit())
                    && trimmed.contains("...")
            })
            .collect();

        for line in &iface_lines {
            // ID...MAC...Name formatı
            let parts: Vec<&str> = line.split("...").collect();
            if parts.len() < 2 {
                continue;
            }

            let id_str = parts[0].trim();
            let id: u32 = match id_str.parse() {
                Ok(v) => v,
                Err(_) => continue,
            };

            let name = parts.last().unwrap_or(&"").trim().to_string();

            // Sanal/VPN interface'leri atla
            if name.to_lowercase().contains("direct")
                || name.to_lowercase().contains("virtual")
                || name.to_lowercase().contains("hyper")
                || name.to_lowercase().contains("bluetooth")
                || name.to_lowercase().contains("loopback")
                || name.to_lowercase().contains("juniper")
                || name.to_lowercase().contains("cisco")
                || name.to_lowercase().contains("vpn")
                || name.to_lowercase().contains("tap")
                || name.to_lowercase().contains("tun")
            {
                continue;
            }

            // Wi-Fi adaptörü mü?
            let lower = name.to_lowercase();
            if lower.contains("wi-fi")
                || lower.contains("wifi")
                || lower.contains("wireless")
                || lower.contains("wlan")
            {
                return Some((id, name));
            }
        }

        // Wi-Fi bulunamadıysa Ethernet dene
        for line in &iface_lines {
            let parts: Vec<&str> = line.split("...").collect();
            if parts.len() < 2 {
                continue;
            }
            let id_str = parts[0].trim();
            let id: u32 = match id_str.parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let name = parts.last().unwrap_or(&"").trim().to_string();
            let lower = name.to_lowercase();
            if lower.contains("virtual") || lower.contains("hyper") || lower.contains("vpn") {
                continue;
            }
            if lower.contains("ethernet") || lower.contains("realtek") {
                return Some((id, name));
            }
        }

        None
    }
}

#[cfg(target_os = "windows")]
impl PlatformNetwork {
    /// Birden fazla route komutunu toplu çalıştır (Windows'ta manifest ile admin yetkisi sağlanır)
    pub fn exec_routes_elevated(commands: &[String], on_log: &dyn Fn(&str)) -> Result<(), String> {
        if commands.is_empty() {
            return Ok(());
        }

        on_log("    Route komutları çalıştırılıyor...");

        // Her komutu error-tolerant yap — tek komut hatası batch'i durdurmasın
        let safe_commands: Vec<String> = commands
            .iter()
            .map(|cmd| format!("({} || ver >nul)", cmd))
            .collect();
        let batch = safe_commands.join(" & ");
        let output = Command::new("cmd")
            .args(["/C", &batch])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("cmd çalıştırılamadı: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        let mut has_error = false;

        for line in stdout.lines().chain(stderr.lines()) {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.contains("not found") || trimmed.contains("not in table") {
                continue;
            }
            if trimmed.contains("requires elevation") || trimmed.contains("Access is denied") {
                has_error = true;
                on_log(&format!("    [!] {}", trimmed));
            } else if trimmed.contains("OK!") || trimmed.contains("Ok.") {
                // Windows route ADD başarı mesajı
            } else {
                on_log(&format!("    {}", trimmed));
            }
        }

        if has_error {
            Err("Route komutları için yönetici (admin) yetkisi gerekli! Uygulamayı yönetici olarak çalıştırın.".to_string())
        } else {
            Ok(())
        }
    }
}

#[cfg(target_os = "windows")]
impl NetworkOps for PlatformNetwork {
    fn detect_network_config(on_log: &dyn Fn(&str)) -> Result<NetworkConfig, String> {
        // Faz 1 (paralel): route PRINT + netsh show config aynı anda
        let (route_result, netsh_result) = std::thread::scope(|s| {
            let h1 = s.spawn(|| Self::exec("route", &["PRINT"]));
            let h2 = s.spawn(|| Self::exec("netsh", &["interface", "ip", "show", "config"]));
            (h1.join().unwrap(), h2.join().unwrap())
        });

        let route_output = route_result
            .map_err(|e| format!("route PRINT çalıştırılamadı: {}", e))?;
        let netsh_output = netsh_result.unwrap_or_else(|_| String::new());

        let (iface_id, iface_name) = Self::find_wifi_interface_id(&route_output)
            .ok_or("Wi-Fi arayüzü bulunamadı!")?;

        on_log(&format!("    Wi-Fi   : {} (IF {})", iface_name, iface_id));

        let mut gateway = None;
        let mut in_wifi_section = false;

        for line in netsh_output.lines() {
            let trimmed = line.trim();

            if trimmed.contains("Wi-Fi") || trimmed.contains(&iface_name) {
                in_wifi_section = true;
                continue;
            }

            if in_wifi_section {
                if trimmed.starts_with("Default Gateway:") || trimmed.contains("Gateway") {
                    if let Some(gw) = trimmed.split_whitespace().last() {
                        if gw.contains('.') {
                            gateway = Some(gw.to_string());
                        }
                    }
                }
                if trimmed.is_empty() && gateway.is_some() {
                    break;
                }
            }
        }

        let gateway = gateway.unwrap_or_else(|| "192.168.1.1".to_string());
        on_log(&format!("    Gateway : {}", gateway));

        Ok(NetworkConfig {
            gateway,
            interface_name: iface_id.to_string(),
            service_name: "Wi-Fi".to_string(),
        })
    }

    fn show_status(on_log: &dyn Fn(&str)) {
        on_log("  Mevcut Route Tablosu (bypass):");
        on_log(&format!("  {}", "-".repeat(55)));

        match Self::exec("route", &["PRINT", "-4"]) {
            Ok(output) => {
                let mut found = false;
                for line in output.lines() {
                    let trimmed = line.trim();
                    if trimmed.contains("160.79.")
                        || trimmed.contains("8.8.8.8")
                        || trimmed.contains("8.8.4.4")
                        || trimmed.contains("1.1.1.1")
                        || trimmed.contains("104.18.")
                    {
                        on_log(&format!("  {}", trimmed));
                        found = true;
                    }
                }
                if !found {
                    on_log("  Bypass route bulunamadı.");
                }
            }
            Err(e) => {
                on_log(&format!("  HATA: route PRINT çalıştırılamadı: {}", e));
            }
        }
    }

    fn traceroute(target: &str, gateway: &str, on_log: &dyn Fn(&str)) {
        // Windows: tracert
        let output = Command::new("tracert")
            .args(["-d", "-h", "1", "-w", "500", target])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        match output {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout);
                for line in text.lines() {
                    // İlk hop satırını bul
                    let trimmed = line.trim();
                    if trimmed.starts_with('1') || trimmed.contains("ms") {
                        // IP adresini çıkar
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if let Some(ip) = parts.iter().find(|p| p.contains('.') && !p.contains("ms")) {
                            let is_wifi = *ip == gateway;
                            let label = if is_wifi {
                                "Wi-Fi ✓".to_string()
                            } else {
                                format!("{} (VPN?)", ip)
                            };
                            on_log(&format!("    {:<25} ilk hop: {} -> {}", target, ip, label));
                            break;
                        }
                    }
                }
            }
            Err(_) => {
                on_log(&format!("    {:<25} -> zaman aşımı", target));
            }
        }
    }

    fn ensure_proxy_disabled(on_log: &dyn Fn(&str)) {
        // Windows registry'den proxy kontrol
        let output = Command::new("reg")
            .args([
                "query",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                "/v",
                "ProxyEnable",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        if let Ok(out) = output {
            let text = String::from_utf8_lossy(&out.stdout);
            if text.contains("0x1") {
                // reg add ve reg delete paralel (bağımsız registry key'ler)
                std::thread::scope(|s| {
                    s.spawn(|| {
                        let _ = Command::new("reg")
                            .args([
                                "add",
                                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                                "/v", "ProxyEnable",
                                "/t", "REG_DWORD",
                                "/d", "0",
                                "/f",
                            ])
                            .creation_flags(CREATE_NO_WINDOW)
                            .output();
                    });
                    s.spawn(|| {
                        let _ = Command::new("reg")
                            .args([
                                "delete",
                                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                                "/v", "ProxyServer",
                                "/f",
                            ])
                            .creation_flags(CREATE_NO_WINDOW)
                            .output();
                    });
                });
                on_log("    [!] Sistem proxy ayarı aktifti, kapatıldı.");
            }
        }
    }
}
