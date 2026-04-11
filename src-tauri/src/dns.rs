use futures::future::join_all;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use tokio::net::lookup_host;

/// DNS çözümleme sonucu
pub struct DnsResult {
    /// /24 subnet stringleri, dotted-quad network adresi (eski API, uyumluluk için).
    pub subnets: Vec<String>,
    /// Tam çözümlenen IPv4 adresleri — Phase 1 Discovery, host-specific /32
    /// route'ları için kullanır. Coexistence stratejisinin spesifiklik kozu.
    pub exact_ips: Vec<Ipv4Addr>,
    pub logs: Vec<String>,
}

/// Domainleri DNS ile paralel çöz ve /24 subnet listesi döndür
pub async fn resolve_domains(domains: &[String]) -> DnsResult {
    let mut logs = Vec::new();
    logs.push(format!("    Toplam {} domain çözümlenecek (paralel)", domains.len()));

    // Tüm DNS lookup'ları paralel başlat
    let futures: Vec<_> = domains
        .iter()
        .map(|domain| {
            let domain = domain.clone();
            async move {
                let lookup_addr = format!("{}:443", domain);
                let result: Result<Vec<std::net::SocketAddr>, _> =
                    match lookup_host(lookup_addr.as_str()).await {
                        Ok(addrs) => Ok(addrs.collect()),
                        Err(e) => Err(e),
                    };
                (domain, result)
            }
        })
        .collect();

    let results = join_all(futures).await;

    // Sonuçları topla
    let mut subnet_set: HashSet<String> = HashSet::new();
    let mut exact_ip_set: HashSet<Ipv4Addr> = HashSet::new();

    for (domain, result) in results {
        match result {
            Ok(addrs) => {
                let mut found = false;
                for addr in addrs {
                    if let std::net::IpAddr::V4(ipv4) = addr.ip() {
                        let octets = ipv4.octets();
                        let subnet = format!("{}.{}.{}.0", octets[0], octets[1], octets[2]);
                        subnet_set.insert(subnet);
                        exact_ip_set.insert(ipv4);
                        logs.push(format!("    {:<30} -> {}", domain, ipv4));
                        found = true;
                    }
                }
                if !found {
                    logs.push(format!("    {:<30} -> IPv4 bulunamadı", domain));
                }
            }
            Err(err) => {
                logs.push(format!("    {:<30} -> HATA: {}", domain, err));
            }
        }
    }

    // Bilinen Anthropic IP bloklari
    let known_subnets = ["160.79.104.0"];
    for subnet in &known_subnets {
        if !subnet_set.contains(*subnet) {
            subnet_set.insert(subnet.to_string());
            logs.push(format!("    {:<30} -> {}/24", "(sabit liste)", subnet));
        }
    }

    DnsResult {
        subnets: subnet_set.into_iter().collect(),
        exact_ips: exact_ip_set.into_iter().collect(),
        logs,
    }
}
