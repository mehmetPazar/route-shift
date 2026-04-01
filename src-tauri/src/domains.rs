use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

/// Builtin bypass domainleri
pub const BUILTIN_DOMAINS: &[&str] = &[
    // Anthropic / Claude
    "claude.ai",
    "anthropic.com",
    "api.anthropic.com",
    "console.anthropic.com",
    // OpenAI / ChatGPT
    "chat.openai.com",
    "openai.com",
    "api.openai.com",
    "cdn.openai.com",
    "chatgpt.com",
    // Spotify
    "open.spotify.com",
    "spotify.com",
    "open.spotifycdn.com",
    "audio-ak-spotify-com.akamaized.net",
    "i.scdn.co",
    "seed-mix-image.spotifycdn.com",
    "daily-mix.scdn.co",
    "newjams-images.scdn.co",
    "audio4-ak-spotify-com.akamaized.net",
];

/// domains.json dosya yapısı
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct DomainsConfig {
    #[serde(default)]
    pub extra: Vec<String>,
    #[serde(default)]
    pub disabled: Vec<String>,
}

/// UI'ya gönderilen domain bilgisi
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DomainInfo {
    pub domain: String,
    pub source: String, // "builtin" | "custom"
    pub enabled: bool,
}

/// domains.json dosya yolunu döndür (platforma göre AppData/config dizini)
pub fn get_domains_json_path() -> PathBuf {
    let config_dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."));
    let app_dir = config_dir.join("com.routeshift.app");
    if !app_dir.exists() {
        let _ = fs::create_dir_all(&app_dir);
    }
    app_dir.join("domains.json")
}

/// domains.json'u oku
pub fn read_domains_config() -> DomainsConfig {
    let path = get_domains_json_path();
    match fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => DomainsConfig::default(),
    }
}

/// domains.json'a yaz
pub fn save_domains_config(config: &DomainsConfig) -> Result<(), String> {
    let path = get_domains_json_path();
    let content = serde_json::to_string_pretty(config)
        .map_err(|e| format!("JSON serialize hatasi: {}", e))?;
    fs::write(&path, content)
        .map_err(|e| format!("Dosya yazma hatasi: {}", e))?;
    Ok(())
}

/// Merge edilmiş domain listesini döndür (UI için)
pub fn get_domains() -> Vec<DomainInfo> {
    let config = read_domains_config();
    let disabled_set: HashSet<&str> = config.disabled.iter().map(|s| s.as_str()).collect();
    let builtin_set: HashSet<&str> = BUILTIN_DOMAINS.iter().copied().collect();

    let mut result = Vec::new();

    // Builtin domainler
    for &d in BUILTIN_DOMAINS {
        result.push(DomainInfo {
            domain: d.to_string(),
            source: "builtin".to_string(),
            enabled: !disabled_set.contains(d),
        });
    }

    // Custom (ekstra) domainler
    for d in &config.extra {
        if !builtin_set.contains(d.as_str()) {
            result.push(DomainInfo {
                domain: d.clone(),
                source: "custom".to_string(),
                enabled: !disabled_set.contains(d.as_str()),
            });
        }
    }

    result
}

/// Aktif (enabled) domain listesini döndür
pub fn get_active_domains() -> Vec<String> {
    get_domains()
        .into_iter()
        .filter(|d| d.enabled)
        .map(|d| d.domain)
        .collect()
}
