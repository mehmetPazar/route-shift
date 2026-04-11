// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod dns;
mod domains;
mod network;
mod tls_verify;

// New three-layer architecture scaffolding (see docs: plans/zany-wandering-parrot.md).
// These modules are empty stubs at Step 1 and do not affect runtime behavior yet.
// Subsequent steps fill them in while keeping the app working throughout.
#[allow(dead_code)]
mod engine;
#[allow(dead_code)]
mod state;
#[allow(dead_code)]
mod lifecycle;

use domains::{DomainsConfig, DomainInfo};
use network::{NetworkOps, PlatformNetwork};
use std::sync::Mutex;
use tauri::{
    menu::{MenuBuilder, MenuItemBuilder},
    tray::TrayIconBuilder,
    AppHandle, Emitter, Manager, State,
};
use tokio::task::spawn_blocking;

/// Platform-spesifik route komut stringleri oluştur
#[allow(unused_variables)]
fn build_add_route_commands(subnets: &[String], dns_servers: &[&str], gateway: &str, iface: &str) -> Vec<String> {
    let mut commands = Vec::new();

    #[cfg(target_os = "macos")]
    {
        // Gateway Wi-Fi subnet'inde → kernel connected route üzerinden en0'a yönlendirir.
        // /32 ve /24 route'lar VPN'in /1 route'larından daha spesifik → global table'da öncelik alır.
        // NOT: -interface veya -ifscope KULLANMA — route'u IFSCOPE yapar, VPN aktifken global trafiğe uygulanmaz.
        for dns_ip in dns_servers {
            commands.push(format!(
                "route -n delete -host {} 2>/dev/null ; route -n add -host {} {}",
                dns_ip, dns_ip, gateway
            ));
        }
        for subnet in subnets {
            commands.push(format!(
                "route -n delete -net {}/24 2>/dev/null ; route -n add -net {}/24 {}",
                subnet, subnet, gateway
            ));
        }
    }

    #[cfg(target_os = "windows")]
    {
        for dns_ip in dns_servers {
            commands.push(format!("route DELETE {} >nul 2>&1 & route ADD {} MASK 255.255.255.255 {} IF {} METRIC 1", dns_ip, dns_ip, gateway, iface));
        }
        for subnet in subnets {
            commands.push(format!("route DELETE {} >nul 2>&1 & route ADD {} MASK 255.255.255.0 {} IF {} METRIC 1", subnet, subnet, gateway, iface));
        }
    }

    #[cfg(target_os = "linux")]
    {
        for dns_ip in dns_servers {
            commands.push(format!("ip route del {}/32 2>/dev/null ; ip route add {}/32 via {} dev {}", dns_ip, dns_ip, gateway, iface));
        }
        for subnet in subnets {
            commands.push(format!("ip route del {}/24 2>/dev/null ; ip route add {}/24 via {} dev {}", subnet, subnet, gateway, iface));
        }
    }

    commands
}

#[allow(unused_variables)]
fn build_remove_route_commands(subnets: &[String], dns_servers: &[&str], iface: &str) -> Vec<String> {
    let mut commands = Vec::new();

    #[cfg(target_os = "macos")]
    {
        // Hem unscoped hem scoped (-ifscope) route'ları sil
        for dns_ip in dns_servers {
            commands.push(format!(
                "route -n delete -host {} 2>/dev/null ; route -n delete -ifscope {} -host {} 2>/dev/null",
                dns_ip, iface, dns_ip
            ));
        }
        for subnet in subnets {
            commands.push(format!(
                "route -n delete -net {}/24 2>/dev/null ; route -n delete -ifscope {} -net {}/24 2>/dev/null",
                subnet, iface, subnet
            ));
        }
    }

    #[cfg(target_os = "windows")]
    {
        for dns_ip in dns_servers {
            commands.push(format!("route DELETE {} >nul 2>&1", dns_ip));
        }
        for subnet in subnets {
            commands.push(format!("route DELETE {} >nul 2>&1", subnet));
        }
    }

    #[cfg(target_os = "linux")]
    {
        for dns_ip in dns_servers {
            commands.push(format!("ip route del {}/32 2>/dev/null", dns_ip));
        }
        for subnet in subnets {
            commands.push(format!("ip route del {}/24 2>/dev/null", subnet));
        }
    }

    commands
}

struct AppState {
    active: Mutex<bool>,
}

fn emit_log(app: &AppHandle, msg: &str) {
    let _ = app.emit("log-line", msg.to_string());
}

fn flush_logs(app: &AppHandle, logs: &[String]) {
    for line in logs {
        let _ = app.emit("log-line", line.clone());
    }
}

fn make_logger() -> std::sync::Arc<Mutex<Vec<String>>> {
    std::sync::Arc::new(Mutex::new(Vec::new()))
}

fn take_logs(logger: &std::sync::Arc<Mutex<Vec<String>>>) -> Vec<String> {
    std::mem::take(&mut *logger.lock().unwrap())
}

macro_rules! log_cb {
    ($logger:expr) => {{
        let l = $logger.clone();
        move |msg: &str| { l.lock().unwrap().push(msg.to_string()); }
    }};
}

/// Doğrulama adımını paralel çalıştır (traceroute + TLS — 4 thread aynı anda)
fn run_verify_parallel(gateway: &str) -> Vec<String> {
    let loggers: Vec<_> = (0..4).map(|_| make_logger()).collect();

    std::thread::scope(|s| {
        let l0 = loggers[0].clone();
        let l1 = loggers[1].clone();
        let l2 = loggers[2].clone();
        let l3 = loggers[3].clone();

        s.spawn(move || PlatformNetwork::traceroute("claude.ai", gateway, &log_cb!(l0)));
        s.spawn(move || PlatformNetwork::traceroute("8.8.8.8", gateway, &log_cb!(l1)));
        s.spawn(move || tls_verify::verify_tls("claude.ai", &log_cb!(l2)));
        s.spawn(move || tls_verify::verify_tls("api.anthropic.com", &log_cb!(l3)));
    });

    // Logları sıralı birleştir: traceroute'lar önce, sonra TLS
    let mut result = Vec::new();
    result.extend(take_logs(&loggers[0]));
    result.extend(take_logs(&loggers[1]));
    result.push(String::new());
    result.extend(take_logs(&loggers[2]));
    result.extend(take_logs(&loggers[3]));
    result
}

// ==================== TAURI KOMUTLARI ====================

#[tauri::command]
fn get_domains() -> Vec<DomainInfo> {
    domains::get_domains()
}

#[tauri::command]
fn save_domains(data: DomainsConfig) -> Result<(), String> {
    domains::save_domains_config(&data)
}

#[tauri::command]
async fn ensure_admin() -> Result<bool, String> {
    #[cfg(target_os = "macos")]
    {
        spawn_blocking(|| PlatformNetwork::ensure_admin())
            .await
            .map_err(|e| format!("Thread hatası: {}", e))?
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(true)
    }
}

#[tauri::command]
async fn bypass_run(mode: String, app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    let mode_label = match mode.as_str() {
        "" | "add" => "ADD",
        "remove" => "REMOVE",
        "test" => "TEST",
        "status" => "STATUS",
        other => other,
    };
    emit_log(&app, &format!("{} başlatılıyor...", mode_label));

    // ======================================================================
    // ADD and REMOVE modes now go exclusively through the new three-layer
    // orchestrator (lifecycle::*). The legacy inline Aç/Kapa implementation
    // was removed in Step 10. TEST and STATUS still use the legacy helpers
    // below — they don't mutate state and are simple enough that porting
    // them would add complexity without payoff.
    // ======================================================================
    if mode == "add" || mode.is_empty() {
        let active_domains = domains::get_active_domains();
        let result = lifecycle::run_add(app.clone(), active_domains).await;
        if result.is_ok() {
            *state.active.lock().unwrap() = true;
        }
        return result;
    }
    if mode == "remove" {
        let result = lifecycle::run_remove(app.clone()).await;
        if result.is_ok() {
            *state.active.lock().unwrap() = false;
        }
        return result;
    }

    // STATUS modu — basit, paralel gerektirmez
    if mode == "status" {
        let logger = make_logger();
        let l = logger.clone();
        spawn_blocking(move || {
            PlatformNetwork::show_status(&log_cb!(l));
        }).await.unwrap_or(());
        flush_logs(&app, &take_logs(&logger));
        let _ = app.emit("run-done", serde_json::json!({ "success": true, "mode": "status" }));
        return Ok(());
    }

    // TEST modu — sadece network detect + paralel verify
    if mode == "test" {
        // Network detect
        emit_log(&app, "\n  [1/2] Ağ arayüzleri tespit ediliyor...\n");
        let logger = make_logger();
        let l = logger.clone();
        let detect_result = spawn_blocking(move || {
            PlatformNetwork::detect_network_config(&log_cb!(l))
        }).await.unwrap_or_else(|e| Err(format!("Thread hatası: {}", e)));
        flush_logs(&app, &take_logs(&logger));

        let config = match detect_result {
            Ok(c) => c,
            Err(e) => {
                emit_log(&app, &format!("HATA: {}", e));
                let _ = app.emit("run-done", serde_json::json!({ "success": false, "mode": "test", "error": e }));
                return Err(e);
            }
        };

        // Paralel verify (4 thread aynı anda)
        emit_log(&app, "\n  [2/2] Bağlantı doğrulanıyor (paralel)...\n");
        let gw = config.gateway.clone();
        let verify_logs = spawn_blocking(move || run_verify_parallel(&gw))
            .await.unwrap_or_default();
        flush_logs(&app, &verify_logs);

        let _ = app.emit("run-done", serde_json::json!({ "success": true, "mode": "test" }));
        return Ok(());
    }

    // Any other unknown mode — no-op to stay future-compatible.
    let _ = state;
    emit_log(&app, &format!("  Bilinmeyen mod: {}", mode));
    let _ = app.emit(
        "run-done",
        serde_json::json!({ "success": false, "mode": mode, "error": "unknown mode" }),
    );
    Ok(())
}

/// Tekil domain route toggle (hızlı, sadece ilgili domain)
#[tauri::command]
async fn toggle_domain_route(domain: String, enable: bool, app: AppHandle) -> Result<(), String> {
    let action = if enable { "ekleniyor" } else { "kaldırılıyor" };
    emit_log(&app, &format!("{} route {} ...", domain, action));

    // Ağ tespiti
    let logger = make_logger();
    let l = logger.clone();
    let detect_result = spawn_blocking(move || {
        PlatformNetwork::detect_network_config(&log_cb!(l))
    }).await.unwrap_or_else(|e| Err(format!("Thread hatası: {}", e)));
    // detect loglarını göstermeye gerek yok (hız için)

    let config = match detect_result {
        Ok(c) => c,
        Err(e) => {
            emit_log(&app, &format!("HATA: {}", e));
            return Err(e);
        }
    };

    // Sadece bu domain'i çöz
    let dns_result = dns::resolve_domains(&[domain.clone()]).await;
    for log_line in &dns_result.logs {
        emit_log(&app, log_line);
    }

    if dns_result.subnets.is_empty() {
        emit_log(&app, &format!("HATA: {} için IP çözümlenemedi", domain));
        return Err("DNS çözümleme başarısız".to_string());
    }

    // Route ekle veya sil (DNS server'lara dokunma)
    let subnets = dns_result.subnets;
    let gw = config.gateway.clone();
    let iface = config.interface_name.clone();
    let log2 = make_logger();
    let l2 = log2.clone();
    spawn_blocking(move || {
        let cb = log_cb!(l2);
        let commands = if enable {
            build_add_route_commands(&subnets, &[], &gw, &iface)
        } else {
            build_remove_route_commands(&subnets, &[], &iface)
        };
        match PlatformNetwork::exec_routes_elevated(&commands, &cb) {
            Ok(()) => {
                let symbol = if enable { "+" } else { "-" };
                for subnet in &subnets {
                    cb(&format!("    [{}] {}/24 ✓", symbol, subnet));
                }
            }
            Err(e) => cb(&format!("    HATA: {}", e)),
        }
        // PF kurallarını güncelle (tüm aktif domain'ler için yeniden oluştur)
        #[cfg(target_os = "macos")]
        {
            if enable {
                let _ = PlatformNetwork::add_pf_bypass(&[], &subnets, &gw, &iface, &cb);
            } else {
                // Domain kaldırıldığında PF'i tam olarak yeniden oluşturmak gerekir
                // Basitlik için: tekil toggle'da PF güncellenmez, ana ON/OFF ile güncellenir
            }
        }
    }).await.unwrap_or(());
    flush_logs(&app, &take_logs(&log2));

    let status = if enable { "eklendi" } else { "kaldırıldı" };
    emit_log(&app, &format!("{} route {} ✓", domain, status));

    Ok(())
}

// ==================== ANA UYGULAMA ====================

fn main() {
    tauri::Builder::default()
        .manage(AppState {
            active: Mutex::new(false),
        })
        .invoke_handler(tauri::generate_handler![bypass_run, get_domains, save_domains, toggle_domain_route, ensure_admin])
        .setup(|app| {
            let quit = MenuItemBuilder::with_id("quit", "Çıkış").build(app)?;
            let show = MenuItemBuilder::with_id("show", "Göster").build(app)?;
            let bypass_on = MenuItemBuilder::with_id("bypass_on", "Aç").build(app)?;
            let bypass_off = MenuItemBuilder::with_id("bypass_off", "Kapat").build(app)?;

            let menu = MenuBuilder::new(app)
                .item(&show)
                .separator()
                .item(&bypass_on)
                .item(&bypass_off)
                .separator()
                .item(&quit)
                .build()?;

            // ---------- Startup reconcile + signal handler ----------
            // Runs the Layer 3 reconcile pass: cleans up orphaned state
            // from a crashed previous session (notably the macOS
            // networksetup additional-routes bug). Fail-soft: any error
            // is logged and the app continues in Idle.
            {
                let app_handle = app.handle().clone();
                let engine = engine::current_engine();
                // Spawn async so setup() returns quickly. Reconcile events
                // land in the log panel as the UI becomes interactive.
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = lifecycle::hooks::on_startup(&app_handle, engine) {
                        tracing::warn!("startup reconcile failed: {}", e);
                    }
                });
            }

            // Emergency Ctrl+C / SIGTERM cleanup. Synchronous so it can run
            // from a signal context.
            if let Ok(state_dir) = app.path().app_data_dir() {
                lifecycle::hooks::install_signal_handler(state_dir);
            }

            let _tray = TrayIconBuilder::new()
                .icon(app.default_window_icon().cloned().unwrap())
                .menu(&menu)
                .show_menu_on_left_click(false)
                .tooltip("RouteShift")
                .on_menu_event(move |app, event| {
                    match event.id().as_ref() {
                        "quit" => {
                            // Graceful shutdown: run the full Phase 6→8
                            // rollback via the orchestrator, then exit.
                            // Falls back to the legacy best-effort cleanup
                            // on macOS if the new path is not active.
                            let app_handle = app.clone();
                            tauri::async_runtime::spawn(async move {
                                let _ = lifecycle::hooks::on_tray_quit(app_handle.clone()).await;
                                #[cfg(target_os = "macos")]
                                PlatformNetwork::stop_elevated_session();
                                app_handle.exit(0);
                            });
                        }
                        "show" => {
                            if let Some(w) = app.get_webview_window("main") {
                                let _ = w.show();
                                let _ = w.set_focus();
                            }
                        }
                        "bypass_on" => { let _ = app.emit("tray-action", "add"); }
                        "bypass_off" => { let _ = app.emit("tray-action", "remove"); }
                        _ => {}
                    }
                })
                .build(app)?;

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .expect("RouteShift başlatılamadı");
}
