fn main() {
    // Windows'ta admin yetkisi (UAC) gerektiren manifest ekle
    #[cfg(target_os = "windows")]
    {
        let mut windows = tauri_build::WindowsAttributes::new();
        windows = windows.app_manifest(include_str!("routeshift.exe.manifest"));
        let attrs = tauri_build::Attributes::new().windows_attributes(windows);
        tauri_build::try_build(attrs).expect("tauri build failed");
    }

    #[cfg(not(target_os = "windows"))]
    {
        tauri_build::build();
    }
}
