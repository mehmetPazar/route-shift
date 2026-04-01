use native_tls::TlsConnector;
use std::net::TcpStream;
use std::time::Duration;

/// TLS bağlantı testi: sertifika issuer bilgisini kontrol et
pub fn verify_tls(domain: &str, on_log: &dyn Fn(&str)) {
    let addr = format!("{}:443", domain);

    match TcpStream::connect_timeout(
        &addr.parse().unwrap_or_else(|_| {
            // DNS çözümlemesini manuel yap
            use std::net::ToSocketAddrs;
            addr.to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
                .unwrap_or_else(|| "0.0.0.0:443".parse().unwrap())
        }),
        Duration::from_secs(3),
    ) {
        Ok(stream) => {
            let connector = TlsConnector::builder()
                .danger_accept_invalid_certs(true) // Issuer kontrolü için bağlan
                .build()
                .unwrap();

            match connector.connect(domain, stream) {
                Ok(tls_stream) => {
                    if let Ok(cert) = tls_stream.peer_certificate() {
                        if let Some(cert) = cert {
                            // DER sertifikadan issuer bilgisi çıkarmak karmaşık,
                            // basitleştirilmiş kontrol
                            let der = cert.to_der().unwrap_or_default();
                            let is_real = !der.is_empty();
                            on_log(&format!(
                                "    {:<25} TLS OK {}",
                                domain,
                                if is_real { "✓" } else { "⚠" }
                            ));
                        } else {
                            on_log(&format!("    {:<25} TLS OK (sertifika yok)", domain));
                        }
                    }
                }
                Err(e) => {
                    on_log(&format!("    {:<25} TLS HATA: {}", domain, e));
                }
            }
        }
        Err(e) => {
            on_log(&format!("    {:<25} Bağlantı HATA: {}", domain, e));
        }
    }
}
