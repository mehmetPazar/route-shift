use super::{NetworkConfig, NetworkOps};
use std::process::Command;

pub struct PlatformNetwork;

impl PlatformNetwork {
    /// Komut çalıştır, stdout döndür
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

    /// Admin yetkisiyle shell komutu çalıştır (osascript ile tek şifre sorusu)
    fn exec_elevated(shell_cmd: &str) -> Result<String, String> {
        let script = format!(
            "do shell script \"{}\" with administrator privileges",
            shell_cmd.replace('\\', "\\\\").replace('"', "\\\"")
        );

        let output = Command::new("osascript")
            .args(["-e", &script])
            .output()
            .map_err(|e| format!("osascript çalıştırılamadı: {}", e))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("Yetki hatası: {}", stderr.trim()))
        }
    }

    /// Birden fazla route komutunu tek admin yetkisi ile toplu çalıştır
    pub fn exec_routes_elevated(commands: &[String], on_log: &dyn Fn(&str)) -> Result<(), String> {
        if commands.is_empty() {
            return Ok(());
        }

        on_log("    Yönetici izni isteniyor...");

        // Tüm komutları ; ile birleştir
        let batch = commands.join(" ; ");
        match Self::exec_elevated(&batch) {
            Ok(output) => {
                for line in output.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty()
                        && !trimmed.contains("not in table")
                        && !trimmed.contains("not found")
                    {
                        on_log(&format!("    {}", trimmed));
                    }
                }
                Ok(())
            }
            Err(e) => {
                on_log(&format!("    HATA: {}", e));
                Err(e)
            }
        }
    }

    /// Wi-Fi interface adını bul (en0, en1 vs.)
    fn find_wifi_interface() -> Option<(String, String)> {
        // networksetup ile Wi-Fi servisini ve donanım portunu bul
        let output = Command::new("networksetup")
            .args(["-listallhardwareports"])
            .output()
            .ok()?;

        let text = String::from_utf8_lossy(&output.stdout);
        let mut lines = text.lines().peekable();
        let mut found_wifi = false;

        while let Some(line) = lines.next() {
            if line.contains("Wi-Fi") || line.contains("AirPort") {
                found_wifi = true;
                continue;
            }
            if found_wifi && line.starts_with("Device:") {
                let device = line.trim_start_matches("Device:").trim().to_string();
                return Some(("Wi-Fi".to_string(), device));
            }
            if line.starts_with("Hardware Port:") {
                found_wifi = false;
            }
        }

        // Fallback: Ethernet veya Thunderbolt
        let mut found_eth = false;
        let mut eth_lines = text.lines().peekable();
        while let Some(line) = eth_lines.next() {
            if line.contains("Ethernet") || line.contains("Thunderbolt") {
                found_eth = true;
                continue;
            }
            if found_eth && line.starts_with("Device:") {
                let device = line.trim_start_matches("Device:").trim().to_string();
                return Some(("Ethernet".to_string(), device));
            }
            if line.starts_with("Hardware Port:") {
                found_eth = false;
            }
        }

        None
    }

    /// Default gateway'i bul
    fn find_gateway(interface: &str) -> Option<String> {
        // route -n get default ile gateway bul
        let output = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .ok()?;

        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("gateway:") {
                return Some(trimmed.trim_start_matches("gateway:").trim().to_string());
            }
        }

        // Alternatif: ifconfig'ten tahmin
        let output = Command::new("ifconfig")
            .args([interface])
            .output()
            .ok()?;

        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if line.contains("inet ") && !line.contains("127.0.0.1") {
                // IP adresinden gateway tahmin: x.x.x.1
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(pos) = parts.iter().position(|&p| p == "inet") {
                    if let Some(ip) = parts.get(pos + 1) {
                        let octets: Vec<&str> = ip.split('.').collect();
                        if octets.len() == 4 {
                            return Some(format!("{}.{}.{}.1", octets[0], octets[1], octets[2]));
                        }
                    }
                }
            }
        }

        None
    }

    /// Wi-Fi IP adresini bul
    fn find_wifi_ip(interface: &str) -> Option<String> {
        let output = Command::new("ifconfig")
            .args([interface])
            .output()
            .ok()?;

        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("inet ") && !trimmed.contains("127.0.0.1") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() > 1 {
                    return Some(parts[1].to_string());
                }
            }
        }

        None
    }

    /// VPN interface tespiti (utun*, tun*, tap*, ppp*)
    fn find_vpn_ip() -> Option<String> {
        let output = Command::new("ifconfig")
            .output()
            .ok()?;

        let text = String::from_utf8_lossy(&output.stdout);
        let mut current_iface = String::new();

        for line in text.lines() {
            // Interface başlığı
            if !line.starts_with('\t') && !line.starts_with(' ') && line.contains(':') {
                current_iface = line.split(':').next().unwrap_or("").to_string();
            }

            // VPN interface'i mi?
            if current_iface.starts_with("utun")
                || current_iface.starts_with("tun")
                || current_iface.starts_with("tap")
                || current_iface.starts_with("ppp")
                || current_iface.starts_with("ipsec")
                || current_iface.starts_with("wg")
            {
                let trimmed = line.trim();
                if trimmed.starts_with("inet ") {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() > 1 {
                        return Some(parts[1].to_string());
                    }
                }
            }
        }

        None
    }
}

impl NetworkOps for PlatformNetwork {
    fn detect_network_config(on_log: &dyn Fn(&str)) -> Result<NetworkConfig, String> {
        // Faz 1 (paralel): Wi-Fi interface + VPN tespiti
        let (wifi_result, vpn_ip) = std::thread::scope(|s| {
            let h1 = s.spawn(|| Self::find_wifi_interface());
            let h2 = s.spawn(|| Self::find_vpn_ip());
            (h1.join().unwrap(), h2.join().unwrap())
        });

        let (service_name, interface) = wifi_result
            .ok_or("Wi-Fi arayüzü bulunamadı! Wi-Fi bağlı mı?")?;
        on_log(&format!("    Wi-Fi   : {} ({})", service_name, interface));

        // Faz 2 (paralel): Wi-Fi IP + Gateway (ikisi de sadece interface adına bağlı)
        let (wifi_ip_result, gateway_result) = std::thread::scope(|s| {
            let iface = &interface;
            let h1 = s.spawn(move || Self::find_wifi_ip(iface));
            let h2 = s.spawn(move || Self::find_gateway(iface));
            (h1.join().unwrap(), h2.join().unwrap())
        });

        let wifi_ip = wifi_ip_result.ok_or("Wi-Fi IP adresi alınamadı")?;
        on_log(&format!("    IP      : {}", wifi_ip));

        let gateway = gateway_result.ok_or("Gateway tespit edilemedi")?;
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

        let output = Command::new("netstat")
            .args(["-rn", "-f", "inet"])
            .output();

        match output {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout);
                let mut found = false;
                for line in text.lines() {
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
                on_log(&format!("  HATA: netstat çalıştırılamadı: {}", e));
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
                // İlk hop'u bul
                for line in text.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with('1') {
                        // "1  192.168.1.1  1.234 ms ..." formatında
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
        // macOS'ta HTTP + HTTPS proxy kontrolü
        for (check_arg, disable_arg, label) in [
            ("-getwebproxy", "-setwebproxystate", "HTTP"),
            ("-getsecurewebproxy", "-setsecurewebproxystate", "HTTPS"),
        ] {
            let output = Command::new("networksetup")
                .args([check_arg, "Wi-Fi"])
                .output();

            if let Ok(out) = output {
                let text = String::from_utf8_lossy(&out.stdout);
                if text.contains("Enabled: Yes") {
                    let _ = Command::new("networksetup")
                        .args([disable_arg, "Wi-Fi", "off"])
                        .output();
                    on_log(&format!("    [!] {} proxy aktifti, kapatıldı.", label));
                }
            }
        }
    }
}
