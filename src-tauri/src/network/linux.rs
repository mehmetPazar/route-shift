use super::{NetworkConfig, NetworkOps};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct PlatformNetwork;

// ==================== ELEVATION (tek seferlik sudoers kurulumu) ====================

/// Sudoers kurulumu yapıldı mı? (sudo -n ip route şifresiz çalışıyor mu)
static AUTHED: AtomicBool = AtomicBool::new(false);

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

}

impl PlatformNetwork {
    /// Uygulama açılışında bir kez çağrılır.
    /// /etc/sudoers.d/routeshift dosyasını kontrol eder / oluşturur.
    /// Kullanıcı yalnızca ilk kurulumda şifre penceresi görür (pkexec).
    /// Returns Ok(true) = zaten yetkili, Ok(false) = yeni kuruldu.
    pub fn ensure_admin() -> Result<bool, String> {
        // Test: sudo -n ip route show çalışıyor mu?
        let test_ok = Command::new("sudo")
            .args(["-n", "ip", "route", "show"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        // Sudoers dosyası MUTLAKA var olmalı (geçici sudo ticket'a güvenme)
        let sudoers_exists = std::path::Path::new("/etc/sudoers.d/routeshift").exists();
        if test_ok && sudoers_exists {
            AUTHED.store(true, Ordering::Relaxed);
            return Ok(true);
        }

        // pkexec ile sudoers dosyası oluştur (tek seferlik)
        let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
        let sudoers_line = format!(
            "{} ALL=(root) NOPASSWD: /usr/sbin/ip, /sbin/ip",
            user
        );
        let shell_cmd = format!(
            "echo '{}' > /etc/sudoers.d/routeshift && chown root:root /etc/sudoers.d/routeshift && chmod 0440 /etc/sudoers.d/routeshift && visudo -c -f /etc/sudoers.d/routeshift 2>&1 || (rm -f /etc/sudoers.d/routeshift && exit 1)",
            sudoers_line
        );

        let output = Command::new("pkexec")
            .args(["sh", "-c", &shell_cmd])
            .output()
            .map_err(|e| format!("pkexec çalıştırılamadı: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Sudoers kurulumu başarısız: {}", stderr.trim()));
        }

        // Doğrula
        let verify = Command::new("sudo")
            .args(["-n", "ip", "route", "show"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if verify {
            AUTHED.store(true, Ordering::Relaxed);
            Ok(false)
        } else {
            Err("Sudoers kuruldu ama doğrulama başarısız".to_string())
        }
    }

    /// Route komutlarını yükseltilmiş yetkiyle çalıştır.
    /// ensure_admin() başarılıysa sudo -n ile şifresiz çalışır.
    /// Değilse pkexec fallback kullanır (her seferinde şifre sorar).
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
            Self::log_output(&String::from_utf8_lossy(&output.stderr), on_log);
            return Ok(());
        }

        // Fallback: pkexec (ensure_admin çağrılmadıysa veya başarısız olduysa)
        on_log("    Yönetici izni isteniyor...");
        let output = Command::new("pkexec")
            .args(["sh", "-c", &batch])
            .output()
            .map_err(|e| format!("pkexec çalıştırılamadı: {}", e))?;

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
                && !trimmed.contains("No such process")
                && !trimmed.contains("not found")
            {
                on_log(&format!("    {}", trimmed));
            }
        }
    }

}

impl NetworkOps for PlatformNetwork {
    fn detect_network_config(on_log: &dyn Fn(&str)) -> Result<NetworkConfig, String> {
        let (wifi_result, gateway_result) = std::thread::scope(|s| {
            let h1 = s.spawn(|| Self::find_wifi_interface());
            let h2 = s.spawn(|| Self::find_gateway());
            (h1.join().unwrap(), h2.join().unwrap())
        });

        let interface = wifi_result
            .ok_or("Wi-Fi arayüzü bulunamadı! Wi-Fi bağlı mı?")?;
        on_log(&format!("    Wi-Fi   : {}", interface));

        let gateway = gateway_result.unwrap_or_else(|| "192.168.1.1".to_string());
        on_log(&format!("    Gateway : {}", gateway));

        Ok(NetworkConfig {
            gateway,
            interface_name: interface.clone(),
            service_name: interface,
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
