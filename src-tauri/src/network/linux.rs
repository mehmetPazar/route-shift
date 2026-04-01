use super::{NetworkConfig, NetworkOps};
use std::process::Command;

pub struct PlatformNetwork;

impl PlatformNetwork {
    fn exec(cmd: &str, args: &[&str]) -> Result<String, String> {
        let output = Command::new(cmd)
            .args(args)
            .output()
            .map_err(|e| format!("{} çalıştırılamadı: {}", cmd, e))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("{} hatası: {}", cmd, stderr.trim()))
        }
    }

    /// Wi-Fi interface adını bul (wlan0, wlp2s0 vs.)
    fn find_wifi_interface() -> Option<String> {
        // iw dev ile Wi-Fi interface'leri listele
        if let Ok(output) = Self::exec("iw", &["dev"]) {
            for line in output.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("Interface") {
                    let name = trimmed.trim_start_matches("Interface").trim().to_string();
                    return Some(name);
                }
            }
        }

        // Fallback: /sys/class/net/ altında wireless/ dizini olan interface
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let wireless_path = format!("/sys/class/net/{}/wireless", name);
                if std::path::Path::new(&wireless_path).exists() {
                    return Some(name);
                }
            }
        }

        // Son çare: wlan* veya wlp* ile başlayan interface
        if let Ok(output) = Self::exec("ip", &["link", "show"]) {
            for line in output.lines() {
                if line.contains("wlan") || line.contains("wlp") {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() > 1 {
                        return Some(parts[1].trim().to_string());
                    }
                }
            }
        }

        // Fallback: Ethernet interface (lo hariç, type=1)
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name == "lo" { continue; }
                let type_path = format!("/sys/class/net/{}/type", name);
                if let Ok(t) = std::fs::read_to_string(&type_path) {
                    if t.trim() == "1" {
                        // wireless/ dizini yoksa Ethernet
                        let wireless_path = format!("/sys/class/net/{}/wireless", name);
                        if !std::path::Path::new(&wireless_path).exists() {
                            return Some(name);
                        }
                    }
                }
            }
        }

        None
    }

    /// Wi-Fi IP adresini bul
    fn find_wifi_ip(interface: &str) -> Option<String> {
        let output = Self::exec("ip", &["-4", "addr", "show", interface]).ok()?;

        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("inet ") {
                // "inet 192.168.1.100/24 brd ..." formatında
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() > 1 {
                    let ip_cidr = parts[1];
                    let ip = ip_cidr.split('/').next()?;
                    return Some(ip.to_string());
                }
            }
        }

        None
    }

    /// Default gateway'i bul
    fn find_gateway() -> Option<String> {
        let output = Self::exec("ip", &["route", "show", "default"]).ok()?;

        // "default via 192.168.1.1 dev wlan0 ..." formatında
        for line in output.lines() {
            if line.starts_with("default") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 2 && parts[1] == "via" {
                    return Some(parts[2].to_string());
                }
            }
        }

        None
    }

    /// VPN interface tespiti (tun*, tap*, wg*)
    fn find_vpn_ip() -> Option<String> {
        let output = Self::exec("ip", &["-4", "addr", "show"]).ok()?;

        let mut current_iface = String::new();
        for line in output.lines() {
            // Interface başlığı: "3: tun0: <...>"
            if !line.starts_with(' ') {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() > 1 {
                    current_iface = parts[1].trim().to_string();
                }
            }

            if current_iface.starts_with("tun")
                || current_iface.starts_with("tap")
                || current_iface.starts_with("wg")
                || current_iface.starts_with("ppp")
                || current_iface.starts_with("ipsec")
            {
                let trimmed = line.trim();
                if trimmed.starts_with("inet ") {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() > 1 {
                        let ip = parts[1].split('/').next()?;
                        return Some(ip.to_string());
                    }
                }
            }
        }

        None
    }
}

impl PlatformNetwork {
    /// Birden fazla route komutunu toplu çalıştır (Linux'ta pkexec ile admin)
    pub fn exec_routes_elevated(commands: &[String], on_log: &dyn Fn(&str)) -> Result<(), String> {
        if commands.is_empty() {
            return Ok(());
        }

        on_log("    Yönetici izni isteniyor...");

        let batch = commands.join(" ; ");
        let output = Command::new("pkexec")
            .args(["sh", "-c", &batch])
            .output()
            .map_err(|e| format!("pkexec çalıştırılamadı: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        for text in [&stdout, &stderr] {
            for line in text.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.contains("No such process") && !trimmed.contains("not found") {
                    on_log(&format!("    {}", trimmed));
                }
            }
        }

        if output.status.success() {
            Ok(())
        } else {
            Err(format!("Yetki hatası: {}", stderr.trim()))
        }
    }
}

impl NetworkOps for PlatformNetwork {
    fn detect_network_config(on_log: &dyn Fn(&str)) -> Result<NetworkConfig, String> {
        // Faz 1 (paralel): Wi-Fi interface + VPN IP + Gateway (hepsi bağımsız)
        let (wifi_result, vpn_ip, gateway_result) = std::thread::scope(|s| {
            let h1 = s.spawn(|| Self::find_wifi_interface());
            let h2 = s.spawn(|| Self::find_vpn_ip());
            let h3 = s.spawn(|| Self::find_gateway());
            (h1.join().unwrap(), h2.join().unwrap(), h3.join().unwrap())
        });

        let interface = wifi_result
            .ok_or("Wi-Fi arayüzü bulunamadı! Wi-Fi bağlı mı?")?;
        on_log(&format!("    Wi-Fi   : {}", interface));

        // Faz 2: Wi-Fi IP (interface'e bağlı)
        let wifi_ip = Self::find_wifi_ip(&interface)
            .ok_or("Wi-Fi IP adresi alınamadı")?;
        on_log(&format!("    IP      : {}", wifi_ip));

        let gateway = gateway_result.unwrap_or_else(|| {
            // Fallback: IP'den tahmin
            let parts: Vec<&str> = wifi_ip.split('.').collect();
            if parts.len() == 4 {
                format!("{}.{}.{}.1", parts[0], parts[1], parts[2])
            } else {
                "192.168.1.1".to_string()
            }
        });
        on_log(&format!("    Gateway : {}", gateway));

        if let Some(ref vip) = vpn_ip {
            on_log(&format!("    VPN     : {}", vip));
        }

        Ok(NetworkConfig {
            wifi_ip,
            vpn_ip,
            gateway,
            interface_name: interface,
        })
    }

    fn show_status(on_log: &dyn Fn(&str)) {
        on_log("  Mevcut Route Tablosu (bypass):");
        on_log(&format!("  {}", "-".repeat(55)));

        match Self::exec("ip", &["route", "show"]) {
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
                on_log(&format!("  HATA: ip route show çalıştırılamadı: {}", e));
            }
        }
    }

    fn traceroute(target: &str, gateway: &str, on_log: &dyn Fn(&str)) {
        let output = Command::new("traceroute")
            .args(["-n", "-m", "1", "-q", "1", "-w", "1", target])
            .output();

        match output {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout);
                for line in text.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with('1') {
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if parts.len() > 1 {
                            let hop_ip = parts[1];
                            let is_wifi = hop_ip == gateway;
                            let label = if is_wifi {
                                "Wi-Fi ✓".to_string()
                            } else {
                                format!("{} (VPN?)", hop_ip)
                            };
                            on_log(&format!("    {:<25} ilk hop: {} -> {}", target, hop_ip, label));
                        }
                        break;
                    }
                }
            }
            Err(_) => {
                on_log(&format!("    {:<25} -> zaman aşımı", target));
            }
        }
    }

    fn ensure_proxy_disabled(on_log: &dyn Fn(&str)) {
        // GNOME proxy kontrolü
        let output = Command::new("gsettings")
            .args(["get", "org.gnome.system.proxy", "mode"])
            .output();

        if let Ok(out) = output {
            let text = String::from_utf8_lossy(&out.stdout);
            if text.trim().contains("manual") {
                let _ = Command::new("gsettings")
                    .args(["set", "org.gnome.system.proxy", "mode", "'none'"])
                    .output();
                on_log("    [!] Sistem proxy ayarı aktifti, kapatıldı.");
            }
        }
    }
}
