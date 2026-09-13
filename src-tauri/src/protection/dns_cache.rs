//! Last-known-good DNS filter. Parsing is supplied by the real companion;
//! downloaded or cached text is never trusted merely because it has a hash.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};

const MAX_TEXT: usize = 8 * 1024 * 1024;
const MAX_ENVELOPE: u64 = (MAX_TEXT * 6 + 4096) as u64;
pub const REFRESH_INTERVAL_SECS: u64 = 24 * 60 * 60;
pub const MAX_CACHE_AGE_SECS: u64 = 7 * REFRESH_INTERVAL_SECS;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsFilter {
    version: u8,
    source: String,
    pub retrieved_at: u64,
    hash: String,
    pub rules_count: u64,
    pub rules: String,
}

impl DnsFilter {
    pub fn stale(&self, now: u64) -> bool {
        now.saturating_sub(self.retrieved_at) >= REFRESH_INTERVAL_SECS
    }
}

fn validate(rules: &str, parser: &impl Fn(&str) -> Result<u64, String>) -> Result<u64, String> {
    if rules.is_empty() || rules.len() > MAX_TEXT {
        return Err("DNS filter is empty or exceeds its size limit".into());
    }
    let count = parser(rules)?;
    if count == 0 {
        return Err("DNS filter contains no usable rules".into());
    }
    Ok(count)
}

pub fn replace(
    path: &Path,
    rules: String,
    now: u64,
    parser: impl Fn(&str) -> Result<u64, String>,
) -> Result<DnsFilter, String> {
    let rules_count = validate(&rules, &parser)?;
    let filter = DnsFilter {
        version: 1,
        source: super::download::ADGUARD_DNS_URL.into(),
        retrieved_at: now,
        hash: format!("{:x}", Sha256::digest(rules.as_bytes())),
        rules_count,
        rules,
    };
    let bytes = serde_json::to_vec(&filter).map_err(|e| e.to_string())?;
    super::cache::atomic_write(path, &bytes).map_err(|e| e.to_string())?;
    Ok(filter)
}

pub fn load(
    path: &Path,
    now: u64,
    parser: impl Fn(&str) -> Result<u64, String>,
) -> Result<Option<DnsFilter>, String> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let mut bytes = Vec::new();
    file.take(MAX_ENVELOPE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_ENVELOPE {
        return Err("DNS filter cache exceeds its size limit".into());
    }
    let filter: DnsFilter = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if now.saturating_sub(filter.retrieved_at) > MAX_CACHE_AGE_SECS {
        return Err("DNS filter is too old; refresh it before enabling protection".into());
    }
    if filter.version != 1
        || filter.source != super::download::ADGUARD_DNS_URL
        || filter.retrieved_at > now.saturating_add(300)
        || filter.hash != format!("{:x}", Sha256::digest(filter.rules.as_bytes()))
    {
        return Err("DNS filter cache metadata is invalid".into());
    }
    if validate(&filter.rules, &parser)? != filter.rules_count {
        return Err("DNS filter cache rule count changed".into());
    }
    Ok(Some(filter))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "Starts real loopback companion and validates explicit VAPOUR_ADGUARD_FILTER; no system DNS changes"]
    fn live_official_filter_round_trip() {
        use super::super::dns_process::{DnsProcessConfig, DnsProcessManager};
        let fixture =
            std::env::var_os("VAPOUR_ADGUARD_FILTER").expect("explicit official filter required");
        let rules = std::fs::read_to_string(fixture).unwrap();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "vapour-dns-cache-live-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("filter.json");
        let manager = DnsProcessManager::new(directory.join("engine"));
        let parser = |text: &str| {
            let status = manager.start(DnsProcessConfig {
                upstream: "127.0.0.1:9".into(),
                listen_address: "127.0.0.1".into(),
                listen_port: 0,
                rules: text.into(),
            })?;
            manager.stop()?;
            Ok(status.rules_count)
        };
        let stored =
            replace(&path, rules, 100, &parser).expect("real parser validates official list");
        assert!(stored.rules_count > 0);
        let loaded = load(&path, 100, &parser).unwrap().unwrap();
        assert_eq!(loaded.rules_count, stored.rules_count);
        assert_eq!(loaded.rules, stored.rules);
        println!(
            "Official DNS cache round trip: {} rules",
            loaded.rules_count
        );
        drop(manager);
        std::fs::remove_file(path).unwrap();
        let engine_dir = directory.join("engine");
        for entry in std::fs::read_dir(&engine_dir).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        std::fs::remove_dir(engine_dir).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    fn parser(text: &str) -> Result<u64, String> {
        if text == "||ads.example^" {
            Ok(1)
        } else {
            Err("invalid fixture".into())
        }
    }
    #[test]
    fn expired_cache_cannot_reenable_protection() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("vapour-dns-expiry-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("filter.json");
        replace(&path, "||ads.example^".into(), 100, parser).unwrap();
        let expired = load(&path, 100 + 8 * 86400, parser);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
        assert!(
            expired.is_err(),
            "an old list must be refreshed before enabling"
        );
    }
    #[test]
    fn invalid_replacement_preserves_the_previous_filter() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("vapour-dns-cache-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("filter.json");
        assert!(load(&path, 100, parser).unwrap().is_none());
        replace(&path, "||ads.example^".into(), 100, parser).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(replace(&path, "invalid".into(), 101, parser).is_err());
        assert!(replace(&path, "! comments only".into(), 101, |_| Ok(0)).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(load(&path, 102, parser).unwrap().unwrap().rules_count, 1);
        assert!(load(&path, 102, |_| Err("parser rejects cached text".into())).is_err());
        let mut tampered: serde_json::Value = serde_json::from_slice(&before).unwrap();
        tampered["rules"] = "||other.example^".into();
        std::fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert!(load(&path, 102, parser).is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }
}
