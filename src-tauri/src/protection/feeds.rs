use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Official Feodo Tracker recommended feed. The endpoint and terms are published at
/// <https://feodotracker.abuse.ch/blocklist/>.
pub const FEODO_RECOMMENDED_JSON_URL: &str =
    "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json";
pub const FEODO_RECOMMENDED_NAME: &str = "Feodo Tracker recommended Botnet C2 IP Blocklist";
pub const FEODO_RECOMMENDED_LICENSE: &str = "CC0 1.0 (Feodo Tracker Terms of Services)";
pub const FEODO_RECOMMENDED_GENERATION_INTERVAL_SECS: u64 = 5 * 60;
pub const FEODO_RECOMMENDED_REFRESH_INTERVAL_SECS: u64 = 15 * 60;

/// Conservative parser bounds. The recommended feed is normally far below these limits.
pub const MAX_FEODO_INPUT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_FEODO_ENTRIES: usize = 100_000;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ThreatEndpoint {
    /// The JSON field is named `ip_address` in the official feed.
    pub ip_address: IpAddr,
    pub port: u16,
}

/// Metadata that can accompany an accepted snapshot in a future on-disk cache.
/// HTTP retrieval and persistence are intentionally outside this parser module.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FeedCacheMetadata {
    pub source: String,
    pub license: String,
    pub content_sha256: String,
    pub retrieved_at_unix_secs: u64,
    /// Number of unique IP/port pairs in the accepted snapshot.
    pub entry_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ValidatedThreatFeed {
    pub endpoints: Vec<ThreatEndpoint>,
    pub metadata: FeedCacheMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FeedParseError {
    EmptyInput,
    InputTooLarge { actual: usize, maximum: usize },
    InvalidJson(String),
    TopLevelNotArray,
    TooManyEntries { actual: usize, maximum: usize },
    EntryNotObject { index: usize },
    InvalidIp { index: usize, value: String },
    NonPublicIp { index: usize, value: String },
    InvalidPort { index: usize },
}

impl fmt::Display for FeedParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "feed is empty"),
            Self::InputTooLarge { actual, maximum } => {
                write!(f, "feed is {actual} bytes; maximum is {maximum}")
            }
            Self::InvalidJson(error) => write!(f, "feed JSON is invalid: {error}"),
            Self::TopLevelNotArray => write!(f, "feed JSON must be an array"),
            Self::TooManyEntries { actual, maximum } => {
                write!(f, "feed has {actual} entries; maximum is {maximum}")
            }
            Self::EntryNotObject { index } => write!(f, "feed entry {index} is not an object"),
            Self::InvalidIp { index, value } => {
                write!(f, "feed entry {index} has invalid IP address {value:?}")
            }
            Self::NonPublicIp { index, value } => {
                write!(f, "feed entry {index} has non-public IP address {value:?}")
            }
            Self::InvalidPort { index } => write!(f, "feed entry {index} has invalid port"),
        }
    }
}

impl std::error::Error for FeedParseError {}

/// Parse the official Feodo recommended JSON schema without making a network request.
/// Unknown fields are ignored so additions to the publisher's metadata do not break parsing.
pub fn parse_feodo_recommended_json(
    input: &[u8],
    retrieved_at_unix_secs: u64,
) -> Result<ValidatedThreatFeed, FeedParseError> {
    parse_feodo_recommended_json_with_limits(
        input,
        retrieved_at_unix_secs,
        MAX_FEODO_INPUT_BYTES,
        MAX_FEODO_ENTRIES,
    )
}

/// Variant with explicit bounds for tests and callers that need a smaller resource budget.
pub fn parse_feodo_recommended_json_with_limits(
    input: &[u8],
    retrieved_at_unix_secs: u64,
    maximum_bytes: usize,
    maximum_entries: usize,
) -> Result<ValidatedThreatFeed, FeedParseError> {
    if input.is_empty() {
        return Err(FeedParseError::EmptyInput);
    }
    if input.len() > maximum_bytes {
        return Err(FeedParseError::InputTooLarge {
            actual: input.len(),
            maximum: maximum_bytes,
        });
    }

    let document: serde_json::Value = serde_json::from_slice(input)
        .map_err(|error| FeedParseError::InvalidJson(error.to_string()))?;
    let entries = document
        .as_array()
        .ok_or(FeedParseError::TopLevelNotArray)?;
    if entries.len() > maximum_entries {
        return Err(FeedParseError::TooManyEntries {
            actual: entries.len(),
            maximum: maximum_entries,
        });
    }

    let mut endpoints = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let object = entry
            .as_object()
            .ok_or(FeedParseError::EntryNotObject { index })?;

        let ip_value = object
            .get("ip_address")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FeedParseError::InvalidIp {
                index,
                value: "<missing or non-string>".to_owned(),
            })?;
        let ip_address = ip_value
            .parse::<IpAddr>()
            .map_err(|_| FeedParseError::InvalidIp {
                index,
                value: ip_value.to_owned(),
            })?;
        if !is_public_ip(ip_address) {
            return Err(FeedParseError::NonPublicIp {
                index,
                value: ip_value.to_owned(),
            });
        }

        let port = object
            .get("port")
            .and_then(serde_json::Value::as_u64)
            .filter(|port| (1..=u16::MAX as u64).contains(port))
            .ok_or(FeedParseError::InvalidPort { index })? as u16;

        endpoints.push(ThreatEndpoint { ip_address, port });
    }

    endpoints.sort_unstable();
    endpoints.dedup();

    let metadata = FeedCacheMetadata {
        source: FEODO_RECOMMENDED_JSON_URL.to_owned(),
        license: FEODO_RECOMMENDED_LICENSE.to_owned(),
        content_sha256: format!("{:x}", Sha256::digest(input)),
        retrieved_at_unix_secs,
        entry_count: endpoints.len(),
    };

    Ok(ValidatedThreatFeed {
        endpoints,
        metadata,
    })
}

fn is_public_ip(ip_address: IpAddr) -> bool {
    match ip_address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, d] = address.octets();
    let private = a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168);
    let shared = a == 100 && (64..=127).contains(&b);
    let link_local = a == 169 && b == 254;
    let documentation = (a == 192 && b == 0 && c == 2)
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113);
    let benchmarking = a == 198 && (18..=19).contains(&b);
    let reserved_192 = a == 192 && b == 0 && c == 0;
    let reserved_0 = a == 0;
    let multicast_or_reserved = a >= 224;
    let broadcast = a == 255 && b == 255 && c == 255 && d == 255;

    !address.is_unspecified()
        && !address.is_loopback()
        && !private
        && !shared
        && !link_local
        && !documentation
        && !benchmarking
        && !reserved_192
        && !reserved_0
        && !multicast_or_reserved
        && !broadcast
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    let octets = address.octets();
    let in_global_unicast_range = (octets[0] & 0xe0) == 0x20; // 2000::/3
    let documentation = octets[0..4] == [0x20, 0x01, 0x0d, 0xb8];
    let unique_local = (octets[0] & 0xfe) == 0xfc; // fc00::/7
    let link_local = octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80; // fe80::/10
    let site_local = octets[0] == 0xfe && (octets[1] & 0xc0) == 0xc0; // fec0::/10
    let ipv4_compatible_or_mapped = octets[0..12].iter().all(|byte| *byte == 0)
        || (octets[0..10].iter().all(|byte| *byte == 0)
            && octets[10] == 0xff
            && octets[11] == 0xff);

    in_global_unicast_range
        && !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && !documentation
        && !unique_local
        && !link_local
        && !site_local
        && !ipv4_compatible_or_mapped
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn record(ip: &str, port: &str) -> String {
        format!(r#"{{"ip_address":"{ip}","port":{port},"status":"online"}}"#)
    }

    #[test]
    fn official_feed_identity_is_explicit() {
        assert_eq!(
            FEODO_RECOMMENDED_JSON_URL,
            "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
        );
        assert!(FEODO_RECOMMENDED_LICENSE.contains("CC0"));
    }

    #[test]
    fn accepts_public_ipv4_and_ipv6_preserves_ports_and_dedupes() {
        let input = format!(
            "[{}, {}, {}, {}]",
            record("2001:4860:4860::8888", "853"),
            record("8.8.8.8", "443"),
            record("8.8.8.8", "443"),
            record("8.8.8.8", "8443"),
        );

        let parsed = parse_feodo_recommended_json(input.as_bytes(), 1_757_000_000).unwrap();
        assert_eq!(parsed.endpoints.len(), 3);
        assert!(parsed.endpoints.contains(&ThreatEndpoint {
            ip_address: "8.8.8.8".parse().unwrap(),
            port: 443,
        }));
        assert!(parsed.endpoints.contains(&ThreatEndpoint {
            ip_address: "2001:4860:4860::8888".parse().unwrap(),
            port: 853,
        }));
        assert_eq!(parsed.metadata.entry_count, 3);
        assert_eq!(parsed.metadata.retrieved_at_unix_secs, 1_757_000_000);
        assert_eq!(parsed.metadata.content_sha256.len(), 64);
    }

    #[test]
    fn endpoint_order_is_deterministic_independent_of_input_order() {
        let first = format!(
            "[{}, {}]",
            record("8.8.8.8", "443"),
            record("1.1.1.1", "443")
        );
        let second = format!(
            "[{}, {}]",
            record("1.1.1.1", "443"),
            record("8.8.8.8", "443")
        );

        let a = parse_feodo_recommended_json(first.as_bytes(), 1).unwrap();
        let b = parse_feodo_recommended_json(second.as_bytes(), 2).unwrap();
        assert_eq!(a.endpoints, b.endpoints);
        assert_ne!(a.metadata.content_sha256, b.metadata.content_sha256);
    }

    #[test]
    fn accepts_unknown_official_schema_fields() {
        let input = br#"[{"ip_address":"8.8.8.8","port":443,"status":"online","hostname":"dns.google","as_number":15169,"as_name":"GOOGLE","country":"US","first_seen":"2025-12-30 13:56:31","last_online":"2026-03-12","malware":"fixture","future_field":{"a":1}}]"#;
        assert_eq!(
            parse_feodo_recommended_json(input, 1)
                .unwrap()
                .endpoints
                .len(),
            1
        );
    }

    #[test]
    fn rejects_empty_invalid_json_and_wrong_top_level() {
        assert!(matches!(
            parse_feodo_recommended_json(b"", 1),
            Err(FeedParseError::EmptyInput)
        ));
        assert!(matches!(
            parse_feodo_recommended_json(b"{}", 1),
            Err(FeedParseError::TopLevelNotArray)
        ));
        assert!(matches!(
            parse_feodo_recommended_json(b"[", 1),
            Err(FeedParseError::InvalidJson(_))
        ));
    }

    #[test]
    fn rejects_oversize_input_before_json_parse() {
        let input = br#"[]"#;
        assert!(matches!(
            parse_feodo_recommended_json_with_limits(input, 1, 1, 10),
            Err(FeedParseError::InputTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_more_than_the_entry_limit() {
        let input = format!(
            "[{}, {}]",
            record("8.8.8.8", "443"),
            record("1.1.1.1", "443")
        );
        assert!(matches!(
            parse_feodo_recommended_json_with_limits(input.as_bytes(), 1, 10_000, 1),
            Err(FeedParseError::TooManyEntries { .. })
        ));
    }

    #[test]
    fn rejects_missing_malformed_and_out_of_range_ports() {
        let cases = [
            r#"[{"ip_address":"8.8.8.8"}]"#,
            r#"[{"ip_address":"8.8.8.8","port":"443"}]"#,
            r#"[{"ip_address":"8.8.8.8","port":0}]"#,
            r#"[{"ip_address":"8.8.8.8","port":65536}]"#,
            r#"[{"ip_address":"8.8.8.8","port":-1}]"#,
        ];
        for input in cases {
            assert!(matches!(
                parse_feodo_recommended_json(input.as_bytes(), 1),
                Err(FeedParseError::InvalidPort { .. })
            ));
        }
    }

    #[test]
    fn rejects_missing_non_string_and_invalid_ip() {
        let cases = [
            r#"[{"port":443}]"#,
            r#"[{"ip_address":8,"port":443}]"#,
            r#"[{"ip_address":"not-an-ip","port":443}]"#,
        ];
        for input in cases {
            assert!(matches!(
                parse_feodo_recommended_json(input.as_bytes(), 1),
                Err(FeedParseError::InvalidIp { .. })
            ));
        }
    }

    #[test]
    fn rejects_nonpublic_ipv4_addresses_including_documentation_ranges() {
        for ip in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            let input = format!("[{}]", record(ip, "443"));
            assert!(
                matches!(
                    parse_feodo_recommended_json(input.as_bytes(), 1),
                    Err(FeedParseError::NonPublicIp { .. })
                ),
                "{ip}"
            );
        }
    }

    #[test]
    fn rejects_nonpublic_ipv6_addresses_including_documentation_and_mapped_forms() {
        for ip in [
            "::",
            "::1",
            "::ffff:8.8.8.8",
            "2001:db8::1",
            "fc00::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
        ] {
            let input = format!("[{}]", record(ip, "443"));
            assert!(
                matches!(
                    parse_feodo_recommended_json(input.as_bytes(), 1),
                    Err(FeedParseError::NonPublicIp { .. })
                ),
                "{ip}"
            );
        }
    }

    #[test]
    fn parsed_public_addresses_are_global_test_fixtures_without_network_calls() {
        for ip in ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"] {
            let parsed =
                parse_feodo_recommended_json(format!("[{}]", record(ip, "443")).as_bytes(), 1)
                    .unwrap();
            assert_eq!(
                parsed.endpoints[0].ip_address,
                ip.parse::<IpAddr>().unwrap()
            );
        }
    }
}
