use super::{NetworkConfig, NetworkOps};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct PlatformNetwork;

// ==================== ELEVATION (tek seferlik sudoers kurulumu) ====================

/// Sudoers kurulumu yapıldı mı? (sudo -n /sbin/route şifresiz çalışıyor mu)
static AUTHED: AtomicBool = AtomicBool::new(false);

impl PlatformNetwork {
    /// Uygulama açılışında bir kez çağrılır.
    /// /etc/sudoers.d/routeshift dosyasını kontrol eder / oluşturur.
    /// Kullanıcı yalnızca ilk kurulumda şifre penceresi görür.
    /// Returns Ok(true) = zaten yetkili, Ok(false) = yeni kuruldu.
    pub fn ensure_admin() -> Result<bool, String> {
        // Test: sudo -n /sbin/route VE /sbin/pfctl çalışıyor mu?
        let route_ok = Command::new("sudo")
            .args(["-n", "/sbin/route", "-n", "get", "default"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        let pfctl_ok = Command::new("sudo")
            .args(["-n", "/sbin/pfctl", "-a", "com.routeshift", "-sr"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        let netsetup_ok = Command::new("sudo")
            .args(["-n", "/usr/sbin/networksetup", "-getadditionalroutes", "Wi-Fi"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        // Sudoers dosyası MUTLAKA var olmalı (geçici sudo ticket'a güvenme)
        let sudoers_exists = std::path::Path::new("/etc/sudoers.d/routeshift").exists();
        if route_ok && pfctl_ok && netsetup_ok && sudoers_exists {
            AUTHED.store(true, Ordering::Relaxed);
            return Ok(true);
        }

        // Sudoers kurulumu gerekli — osascript ile tek seferlik şifre penceresi
        let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
        let sudoers_file = "/etc/sudoers.d/routeshift";
        let sudoers_line = format!("{} ALL=(root) NOPASSWD: /sbin/route, /sbin/pfctl, /usr/sbin/networksetup", user);

        let shell_cmd = format!(
            "echo '{}' > {} && chown root:wheel {} && chmod 0440 {} && visudo -c -f {} 2>&1 || (rm -f {} && exit 1)",
            sudoers_line, sudoers_file,
            sudoers_file, sudoers_file, sudoers_file, sudoers_file
        );

        let escaped = shell_cmd.replace('\\', "\\\\").replace('"', "\\\"");
        let script = format!(
            "do shell script \"{}\" with administrator privileges",
            escaped
        );

        let output = Command::new("osascript")
            .args(["-e", &script])
            .output()
            .map_err(|e| format!("osascript çalıştırılamadı: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Sudoers kurulumu başarısız: {}", stderr.trim()));
        }

        // Doğrula
        let route_verify = Command::new("sudo")
            .args(["-n", "/sbin/route", "-n", "get", "default"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        let pfctl_verify = Command::new("sudo")
            .args(["-n", "/sbin/pfctl", "-a", "com.routeshift", "-sr"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        let netsetup_verify = Command::new("sudo")
            .args(["-n", "/usr/sbin/networksetup", "-getadditionalroutes", "Wi-Fi"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if route_verify && pfctl_verify && netsetup_verify {
            AUTHED.store(true, Ordering::Relaxed);
            Ok(false)
        } else {
            Err("Sudoers kuruldu ama doğrulama başarısız".to_string())
        }
    }

    /// Route komutlarını yükseltilmiş yetkiyle çalıştır.
    /// ensure_admin() başarılıysa sudo -n ile şifresiz çalışır.
    /// Değilse osascript fallback kullanır (her seferinde şifre sorar).
    pub fn exec_routes_elevated(commands: &[String], on_log: &dyn Fn(&str)) -> Result<(), String> {
        if commands.is_empty() {
            return Ok(());
        }

        // Her komutu (cmd ; true) ile sar — delete hatası batch'i durdurmasın
        let safe_commands: Vec<String> = commands
            .iter()
            .map(|cmd| format!("( {} ; true )", cmd))
            .collect();
        let batch = safe_commands.join(" ; ");

        // Birincil yol: sudo -n (sudoers kuruluysa şifre sormaz)
        if AUTHED.load(Ordering::Relaxed) {
            let output = Command::new("sudo")
                .args(["-n", "sh", "-c", &batch])
                .output()
                .map_err(|e| format!("sudo çalıştırılamadı: {}", e))?;

            Self::log_output(&String::from_utf8_lossy(&output.stdout), on_log);
            return Ok(());
        }

        // Fallback: osascript (ensure_admin çağrılmadıysa veya başarısız olduysa)
        on_log("    Yönetici izni isteniyor...");
        let full_cmd = format!("{} ; exit 0", batch);
        let escaped = full_cmd.replace('\\', "\\\\").replace('"', "\\\"");
        let script = format!(
            "do shell script \"{}\" with administrator privileges",
            escaped
        );

        let output = Command::new("osascript")
            .args(["-e", &script])
            .output()
            .map_err(|e| format!("osascript çalıştırılamadı: {}", e))?;

        if output.status.success() {
            Self::log_output(&String::from_utf8_lossy(&output.stdout), on_log);
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("Yetki hatası: {}", stderr.trim()))
        }
    }

    fn log_output(output: &str, on_log: &dyn Fn(&str)) {
        for line in output.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty()
                && !trimmed.contains("not in table")
                && !trimmed.contains("not found")
            {
                on_log(&format!("    {}", trimmed));
            }
        }
    }

    // ── PF (Packet Filter) bypass ─────────────────────────────

    /// PF route-to kuralları ekle — NetworkExtension tabanlı VPN'leri bypass eder.
    /// Trafiği doğrudan Wi-Fi interface'inden çıkarır.
    pub fn add_pf_bypass(
        dns_ips: &[&str],
        subnets: &[String],
        gateway: &str,
        iface: &str,
        on_log: &dyn Fn(&str),
    ) -> Result<(), String> {
        if dns_ips.is_empty() && subnets.is_empty() {
            return Ok(());
        }

        // Hedef IP/subnet listesi oluştur
        let mut targets: Vec<String> = Vec::new();
        for ip in dns_ips {
            targets.push(ip.to_string());
        }
        for subnet in subnets {
            targets.push(format!("{}/24", subnet));
        }
        let target_list = targets.join(", ");

        // PF kuralını oluştur
        let rule = format!(
            "pass out route-to ({} {}) from any to {{ {} }} no state\n",
            iface, gateway, target_list
        );

        // Kuralları stdin üzerinden pipe et (temp dosya yok)
        use std::io::Write;
        let mut child = Command::new("sudo")
            .args(["-n", "pfctl", "-a", "com.routeshift", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("pfctl çalıştırılamadı: {}", e))?;

        if let Some(ref mut stdin) = child.stdin {
            let _ = stdin.write_all(rule.as_bytes());
        }
        drop(child.stdin.take()); // stdin'i kapat → pfctl okumayı bitirir

        let output = child.wait_with_output()
            .map_err(|e| format!("pfctl beklenirken hata: {}", e))?;

        if output.status.success() {
            on_log("    [PF] route-to kuralları yüklendi ✓");
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("syntax error") {
                Err(format!("PF kural hatası: {}", stderr.trim()))
            } else {
                // pfctl uyarı mesajları yazdı ama kural yüklendi
                on_log("    [PF] route-to kuralları yüklendi ✓");
                Ok(())
            }
        }
    }

    /// PF bypass kurallarını kaldır
    pub fn remove_pf_bypass(on_log: &dyn Fn(&str)) {
        let output = Command::new("sudo")
            .args(["-n", "pfctl", "-a", "com.routeshift", "-F", "all"])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                on_log("    [PF] route-to kuralları kaldırıldı ✓");
            }
            _ => {} // Sessizce devam — anchor zaten boş olabilir
        }
    }

    // ── networksetup route'ları (VPN bypass — unscoped) ──────

    /// networksetup ile route ekle — VPN aktifken bile unscoped (global) route oluşturur.
    /// `route add` ile eklenen route'lar macOS tarafından auto-scope'lanır ve VPN'i bypass edemez.
    /// `networksetup -setadditionalroutes` ise service-level route oluşturur → unscoped kalır.
    pub fn exec_routes_networksetup(
        dns_ips: &[&str],
        subnets: &[String],
        gateway: &str,
        service_name: &str,
        on_log: &dyn Fn(&str),
    ) -> Result<(), String> {
        // networksetup format: IP1 MASK1 GW1 IP2 MASK2 GW2 ...
        let mut args: Vec<String> = vec![
            "-setadditionalroutes".to_string(),
            service_name.to_string(),
        ];

        for ip in dns_ips {
            args.push(ip.to_string());
            args.push("255.255.255.255".to_string()); // /32 host route
            args.push(gateway.to_string());
        }
        for subnet in subnets {
            args.push(subnet.to_string());
            args.push("255.255.255.0".to_string()); // /24 subnet
            args.push(gateway.to_string());
        }

        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let mut cmd_args = vec!["-n", "networksetup"];
        cmd_args.extend(arg_refs.iter());

        let output = Command::new("sudo")
            .args(&cmd_args)
            .output()
            .map_err(|e| format!("networksetup çalıştırılamadı: {}", e))?;

        if output.status.success() {
            on_log(&format!("    [networksetup] {} host + {} subnet route eklendi ✓",
                dns_ips.len(), subnets.len()));
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("networksetup hatası: {}", stderr.trim()))
        }
    }

    /// networksetup route'larını temizle
    pub fn clear_routes_networksetup(service_name: &str, on_log: &dyn Fn(&str)) {
        let output = Command::new("sudo")
            .args(["-n", "networksetup", "-setadditionalroutes", service_name])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                on_log("    [networksetup] route'lar temizlendi ✓");
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                on_log(&format!("    HATA: networksetup temizleme: {}", stderr.trim()));
            }
            Err(e) => {
                on_log(&format!("    HATA: networksetup çalıştırılamadı: {}", e));
            }
        }
    }

    /// Temizlik — networksetup route'ları + PF kurallarını kaldır
    pub fn stop_elevated_session() {
        // networksetup route'larını temizle
        let _ = Command::new("sudo")
            .args(["-n", "networksetup", "-setadditionalroutes", "Wi-Fi"])
            .output();
        // PF kurallarını temizle
        let _ = Command::new("sudo")
            .args(["-n", "pfctl", "-a", "com.routeshift", "-F", "all"])
            .output();
    }

    // ── Ağ tespiti ──────────────────────────────────────────────

    fn find_wifi_interface() -> Option<(String, String)> {
        let output = Command::new("networksetup")
            .args(["-listallhardwareports"])
            .output()
            .ok()?;

        let text = String::from_utf8_lossy(&output.stdout);
        let mut found_wifi = false;

        for line in text.lines() {
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

        let mut found_eth = false;
        for line in text.lines() {
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

    fn find_gateway(interface: &str) -> Option<String> {
        let output = Command::new("route")
            .args(["-n", "get", "default", "-ifscope", interface])
            .output()
            .ok()?;

        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("gateway:") {
                return Some(trimmed.trim_start_matches("gateway:").trim().to_string());
            }
        }

        let output = Command::new("ifconfig")
            .args([interface])
            .output()
            .ok()?;

        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if line.contains("inet ") && !line.contains("127.0.0.1") {
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

}

impl NetworkOps for PlatformNetwork {
    fn detect_network_config(on_log: &dyn Fn(&str)) -> Result<NetworkConfig, String> {
        let (service_name, interface) = Self::find_wifi_interface()
            .ok_or("Wi-Fi arayüzü bulunamadı! Wi-Fi bağlı mı?")?;
        on_log(&format!("    Wi-Fi   : {} ({})", service_name, interface));

        let gateway = Self::find_gateway(&interface).unwrap_or_else(|| "192.168.1.1".to_string());
        on_log(&format!("    Gateway : {}", gateway));

        Ok(NetworkConfig {
            gateway,
            interface_name: interface,
            service_name,
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
            .args(["-n", "-m", "1", "-q", "1", "-w", "2", target])
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
