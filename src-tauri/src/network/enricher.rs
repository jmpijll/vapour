use std::net::{IpAddr, Ipv4Addr};

pub struct EnrichedEndpoint {
    pub host: Option<String>,
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub cloud_provider: Option<String>,
    pub service_tag: Option<String>,
    pub is_tls: bool,
    pub is_local: bool,
}

pub struct TrafficEnricher {
    destinations: super::destinations::DestinationResolver,
}

impl TrafficEnricher {
    pub fn new() -> Self {
        Self {
            destinations: super::destinations::DestinationResolver::new(),
        }
    }

    pub fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                ipv4.is_loopback()
                    || ipv4.is_private()
                    || ipv4.is_link_local()
                    || ipv4.is_unspecified()
                    || ipv4.is_multicast()
                    || ipv4.is_broadcast()
            }
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback()
                    || ipv6.is_unspecified()
                    || ipv6.is_multicast()
                    // Unique local addresses (fc00::/7)
                    || (ipv6.segments()[0] & 0xfe00) == 0xfc00
                    // Link-local addresses (fe80::/10)
                    || (ipv6.segments()[0] & 0xffc0) == 0xfe80
            }
        }
    }

    pub fn classify_port(port: u16) -> (&'static str, bool) {
        match port {
            443 => ("HTTPS", true),
            8443 => ("HTTPS Alt", true),
            853 => ("DNS-over-TLS", true),
            993 => ("IMAPS", true),
            995 => ("POP3S", true),
            465 => ("SMTPS", true),
            22 => ("SSH", true),
            80 => ("HTTP", false),
            8080 => ("HTTP Alt", false),
            53 => ("DNS", false),
            21 => ("FTP", false),
            23 => ("Telnet", false),
            25 => ("SMTP", false),
            123 => ("NTP", false),
            137 | 138 | 139 => ("NetBIOS", false),
            445 => ("SMB", false),
            3389 => ("RDP", true),
            5353 => ("mDNS", false),
            1900 => ("SSDP", false),
            27015..=27050 => ("Steam P2P / Game", false),
            50000..=65535 => ("Dynamic / Ephemeral", false),
            _ => ("TCP/UDP", false),
        }
    }

    pub fn identify_cloud_and_geo(
        &self,
        ip: &IpAddr,
    ) -> (
        Option<&'static str>,
        Option<&'static str>,
        Option<&'static str>,
    ) {
        if Self::is_private_ip(ip) {
            return (Some("Local Network"), Some("LAN"), Some("Private LAN"));
        }

        if let IpAddr::V4(v4) = ip {
            let octets = v4.octets();
            let b0 = octets[0];
            let b1 = octets[1];

            // 1. Cloudflare
            if (b0 == 1 && (b1 == 1 || b1 == 0))
                || (b0 == 104 && (16..=31).contains(&b1))
                || (b0 == 172 && (64..=71).contains(&b1))
                || (b0 == 162 && b1 == 158)
                || (b0 == 198 && b1 == 41)
            {
                return (Some("Cloudflare"), Some("US"), Some("Cloudflare Edge"));
            }

            // 2. Google / GCP
            if (b0 == 8 && (b1 == 8 || b1 == 4))
                || (b0 == 142 && b1 == 250)
                || (b0 == 172 && b1 == 217)
                || (b0 == 216 && b1 == 58)
                || (b0 == 34)
                || (b0 == 35)
                || (b0 == 74 && b1 == 125)
                || (b0 == 173 && b1 == 194)
            {
                return (Some("Google Cloud"), Some("US"), Some("Google Network"));
            }

            // 3. Microsoft / Azure
            if (b0 == 20)
                || (b0 == 40)
                || (b0 == 52 && (96..=127).contains(&b1))
                || (b0 == 13 && (64..=107).contains(&b1))
                || (b0 == 23 && (96..=103).contains(&b1))
                || (b0 == 104 && (40..=47).contains(&b1))
            {
                return (
                    Some("Microsoft / Azure"),
                    Some("US"),
                    Some("Microsoft Cloud"),
                );
            }

            // 4. Amazon / AWS
            if (b0 == 3 && (120..=127).contains(&b1))
                || (b0 == 18 && (184..=245).contains(&b1))
                || (b0 == 52 && (0..=95).contains(&b1))
                || (b0 == 54)
                || (b0 == 44 && (192..=223).contains(&b1))
                || (b0 == 99 && (80..=87).contains(&b1))
                || (b0 == 15)
                || (b0 == 13 && (32..=35).contains(&b1))
            {
                return (Some("Amazon AWS"), Some("US"), Some("Amazon Cloud"));
            }

            // 5. Akamai
            if (b0 == 23 && (32..=63).contains(&b1)) || (b0 == 104 && (64..=127).contains(&b1)) {
                return (Some("Akamai"), Some("US"), Some("Akamai CDN"));
            }

            // 6. Fastly
            if (b0 == 151 && b1 == 101) || (b0 == 199 && b1 == 232) {
                return (Some("Fastly"), Some("US"), Some("Fastly CDN"));
            }

            // 7. Valve / Steam
            if (b0 == 162 && b1 == 254) || (b0 == 208 && b1 == 78) || (b0 == 205 && b1 == 185) {
                return (Some("Steam / Valve"), Some("US"), Some("Steam Network"));
            }

            // 8. Apple
            if b0 == 17 {
                return (Some("Apple"), Some("US"), Some("Apple Network"));
            }

            // 9. GitHub
            if (b0 == 140 && b1 == 82) || (b0 == 185 && b1 == 199) {
                return (Some("GitHub"), Some("US"), Some("GitHub Infrastructure"));
            }

            // General GeoIP approximate allocation by first octet block
            let (country_code, country_name) = match b0 {
                2 | 31 | 46 | 62 | 80..=95 | 178 | 185 | 188 | 193..=195 | 212 | 213 | 217 => {
                    ("EU", "European Union")
                }
                14
                | 27
                | 36
                | 39
                | 42
                | 49
                | 101
                | 103
                | 110..=126
                | 133
                | 175
                | 180
                | 182
                | 183
                | 202
                | 203
                | 210
                | 211
                | 218..=223 => ("AP", "Asia / Pacific"),
                41 | 102 | 105 | 154 | 196 | 197 => ("AF", "Africa"),
                177 | 179 | 181 | 186 | 187 | 189 | 190 | 191 | 200 | 201 => {
                    ("SA", "South America")
                }
                _ => ("US", "United States"),
            };

            return (
                Some("Internet Host"),
                Some(country_code),
                Some(country_name),
            );
        }

        (Some("IPv6 Host"), Some("WW"), Some("Global IPv6"))
    }

    pub fn enrich(&self, remote_ip_str: &str, remote_port: u16) -> EnrichedEndpoint {
        let ip_parsed = remote_ip_str
            .parse::<IpAddr>()
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let is_local = Self::is_private_ip(&ip_parsed);
        let (service_tag, is_tls_port) = Self::classify_port(remote_port);
        let (cloud_provider, country_code, country_name) = self.identify_cloud_and_geo(&ip_parsed);

        let cached_host = self.destinations.lookup(ip_parsed);

        EnrichedEndpoint {
            host: cached_host,
            country_code: country_code.map(String::from),
            country_name: country_name.map(String::from),
            cloud_provider: cloud_provider.map(String::from),
            service_tag: Some(service_tag.to_string()),
            is_tls: is_tls_port,
            is_local,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_ips() {
        assert!(TrafficEnricher::is_private_ip(
            &"127.0.0.1".parse().unwrap()
        ));
        assert!(TrafficEnricher::is_private_ip(
            &"192.168.1.1".parse().unwrap()
        ));
        assert!(TrafficEnricher::is_private_ip(&"10.0.0.1".parse().unwrap()));
        assert!(!TrafficEnricher::is_private_ip(&"1.1.1.1".parse().unwrap()));
        assert!(!TrafficEnricher::is_private_ip(&"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_port_classification() {
        let (name, is_tls) = TrafficEnricher::classify_port(443);
        assert_eq!(name, "HTTPS");
        assert!(is_tls);

        let (name, is_tls) = TrafficEnricher::classify_port(80);
        assert_eq!(name, "HTTP");
        assert!(!is_tls);
    }

    #[test]
    fn test_cloud_identification() {
        let enricher = TrafficEnricher::new();
        let (cloud, country, _) = enricher.identify_cloud_and_geo(&"1.1.1.1".parse().unwrap());
        assert_eq!(cloud, Some("Cloudflare"));
        assert_eq!(country, Some("US"));

        let (cloud, _, _) = enricher.identify_cloud_and_geo(&"8.8.8.8".parse().unwrap());
        assert_eq!(cloud, Some("Google Cloud"));
    }
}
