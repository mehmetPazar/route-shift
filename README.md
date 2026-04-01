# RouteShift

Belirli domainleri VPN yerine Wi-Fi (veya Ethernet) uzerinden yonlendiren masaustu uygulamasi. Proxy kullanmaz, dogrudan isletim sistemi route tablosunu manipule eder.

## Ne Yapar?

VPN kullanirken belirli servislerin (Claude, ChatGPT, Spotify vb.) VPN yerine dogrudan internet uzerinden gitmesini saglar. Route tablosuna `/24` subnet kurallari ekleyerek ilgili trafigi Wi-Fi gateway'ine yonlendirir.

**Desteklenen platformlar:** Windows, macOS, Linux

## Yerlesik Domainler

- **Anthropic/Claude:** claude.ai, anthropic.com, api.anthropic.com, console.anthropic.com
- **OpenAI/ChatGPT:** chatgpt.com, openai.com, api.openai.com, cdn.openai.com
- **Spotify:** spotify.com, open.spotify.com ve CDN domainleri

Uygulama icinden ozel domain eklenebilir/kaldirilabilir.

## Build

### Gereksinimler

- [Rust](https://rustup.rs/) (stable)
- [Tauri CLI](https://tauri.app/start/): `cargo install tauri-cli`
- Windows: WebView2 (Windows 10+ ile gelir)

### Gelistirme

```bash
cargo tauri dev
```

### Release Build

```bash
cargo tauri build
```

Ciktilar `src-tauri/target/release/bundle/` altinda olusur:
- `.exe` — Standalone calistirilabilir
- `.msi` — Windows Installer
- `*-setup.exe` — NSIS Installer

## Kullanim

1. Uygulamayi yonetici olarak calistirin (route tablosu icin gerekli)
2. **Ac** — Bypass'i aktif eder (DNS cozumleme + route ekleme + dogrulama)
3. **Kapa** — Tum route'lari kaldirir
4. **Test** — Mevcut baglantinin bypass'tan gecip gecmedigini kontrol eder
5. **Domains** sekmesinden domain ekleyip cikarabilir, mevcut domainleri acip kapatabilirsiniz
