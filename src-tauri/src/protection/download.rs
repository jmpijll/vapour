//! Fixed-source HTTPS retrieval. Call from a background worker, never the UI thread.
use super::{
    cache,
    feeds::{ValidatedThreatFeed, FEODO_RECOMMENDED_JSON_URL, MAX_FEODO_INPUT_BYTES},
};
use std::{
    io::Read,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub fn fetch_feodo() -> Result<Vec<u8>, String> {
    let client = reqwest::blocking::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .user_agent("Vapour/0.1 threat-feed updater")
        .build()
        .map_err(|_| "HTTPS client unavailable".to_string())?;
    let response = client
        .get(FEODO_RECOMMENDED_JSON_URL)
        .send()
        .map_err(|_| "Threat feed download failed".to_string())?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(format!("Threat feed HTTP {}", response.status().as_u16()));
    }
    if response
        .content_length()
        .is_some_and(|n| n > MAX_FEODO_INPUT_BYTES as u64)
    {
        return Err("Threat feed exceeds size limit".into());
    }
    read_bounded(response)
}
fn read_bounded(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_FEODO_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Threat feed body could not be read".to_string())?;
    if bytes.len() > MAX_FEODO_INPUT_BYTES {
        return Err("Threat feed exceeds size limit".into());
    }
    Ok(bytes)
}
pub fn refresh_feodo(path: &Path) -> Result<ValidatedThreatFeed, String> {
    let bytes = fetch_feodo()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "System clock unavailable")?
        .as_secs();
    cache::replace_feodo_cache(path, &bytes, now)
        .map_err(|_| "Threat feed validation or cache update failed".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_oversize_body_without_content_length() {
        assert!(read_bounded(std::io::repeat(b' ')).is_err());
        assert_eq!(read_bounded(&b"[]"[..]).unwrap(), b"[]");
    }
    #[test]
    #[ignore = "Downloads official public Feodo feed; does not enable blocking or write a cache"]
    fn live_feed_download_and_validation() {
        let bytes = fetch_feodo().expect("HTTPS feed download");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let parsed = super::super::feeds::parse_feodo_recommended_json(&bytes, now)
            .expect("official feed schema");
        println!(
            "Feodo bytes={}, endpoints={}",
            bytes.len(),
            parsed.endpoints.len()
        );
    }
}
