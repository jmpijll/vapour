use super::feeds::{
    parse_feodo_recommended_json, FeedParseError, ValidatedThreatFeed, FEODO_RECOMMENDED_JSON_URL,
    FEODO_RECOMMENDED_LICENSE, MAX_FEODO_INPUT_BYTES,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Version of the small JSON envelope written by this module.
pub const FEODO_CACHE_FORMAT_VERSION: u32 = 1;

/// The raw feed is bounded by the parser. JSON string escaping can expand the
/// envelope, so loading allows a conservative two-times expansion plus a small
/// fixed header allowance while still placing a hard cap before deserialization.
pub const MAX_FEODO_CACHE_FILE_BYTES: usize = MAX_FEODO_INPUT_BYTES
    .saturating_mul(2)
    .saturating_add(16 * 1024);

/// Feed timestamps may be a few minutes ahead when the publisher and client
/// clocks differ. Older snapshots remain usable; freshness policy belongs to
/// the caller that schedules HTTP refreshes.
pub const MAX_CACHE_TIMESTAMP_SKEW_SECS: u64 = 5 * 60;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CacheError {
    Io(String),
    CacheTooLarge { actual: u64, maximum: usize },
    InvalidEnvelope(String),
    UnsupportedVersion { actual: u32, expected: u32 },
    SourceMismatch { actual: String },
    LicenseMismatch { actual: String },
    TimestampInFuture { retrieved_at: u64, now: u64 },
    HashMismatch { expected: String, actual: String },
    EntryCountMismatch { expected: u64, actual: usize },
    Feed(FeedParseError),
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "cache I/O failed: {error}"),
            Self::CacheTooLarge { actual, maximum } => {
                write!(f, "cache is {actual} bytes; maximum is {maximum}")
            }
            Self::InvalidEnvelope(error) => write!(f, "cache envelope is invalid: {error}"),
            Self::UnsupportedVersion { actual, expected } => {
                write!(f, "cache format version {actual} is unsupported; expected {expected}")
            }
            Self::SourceMismatch { actual } => {
                write!(f, "cache source is not the Feodo recommended feed: {actual:?}")
            }
            Self::LicenseMismatch { actual } => {
                write!(f, "cache license is not the Feodo feed license: {actual:?}")
            }
            Self::TimestampInFuture { retrieved_at, now } => write!(
                f,
                "cache timestamp {retrieved_at} is more than {MAX_CACHE_TIMESTAMP_SKEW_SECS}s ahead of {now}"
            ),
            Self::HashMismatch { expected, actual } => write!(
                f,
                "cache content hash {expected:?} does not match raw feed hash {actual:?}"
            ),
            Self::EntryCountMismatch { expected, actual } => write!(
                f,
                "cache entry count {expected} does not match reparsed feed count {actual}"
            ),
            Self::Feed(error) => write!(f, "cached feed is invalid: {error}"),
        }
    }
}

impl std::error::Error for CacheError {}

/// The only feed content persisted on disk is the original JSON bytes. Endpoint
/// vectors are deliberately absent: every load reparses and validates these bytes.
#[derive(Debug, Deserialize, Serialize)]
struct CacheEnvelope {
    format_version: u32,
    source: String,
    license: String,
    retrieved_at_unix_secs: u64,
    content_sha256: String,
    entry_count: u64,
    raw_feed_json: String,
}

/// Load a Feodo cache, returning `None` when the cache file does not exist.
/// The raw feed in the envelope is reparsed before any endpoints are returned.
pub fn load_feodo_cache(path: &Path) -> Result<Option<ValidatedThreatFeed>, CacheError> {
    let now = unix_now_secs()?;
    load_feodo_cache_at(path, now)
}

/// Deterministic/testable form of [`load_feodo_cache`] with an injected clock.
pub fn load_feodo_cache_at(
    path: &Path,
    now_unix_secs: u64,
) -> Result<Option<ValidatedThreatFeed>, CacheError> {
    let Some(bytes) = read_bounded(path)? else {
        return Ok(None);
    };

    let envelope: CacheEnvelope = serde_json::from_slice(&bytes)
        .map_err(|error| CacheError::InvalidEnvelope(error.to_string()))?;
    validate_envelope(envelope, now_unix_secs).map(Some)
}

/// Validate and atomically replace a cache with a newly retrieved raw feed.
/// Invalid feeds and failed writes leave an existing last-known-good file intact.
pub fn replace_feodo_cache(
    path: &Path,
    raw_feed_json: &[u8],
    retrieved_at_unix_secs: u64,
) -> Result<ValidatedThreatFeed, CacheError> {
    let now = unix_now_secs()?;
    replace_feodo_cache_at(path, raw_feed_json, retrieved_at_unix_secs, now)
}

/// Deterministic/testable form of [`replace_feodo_cache`] with an injected clock.
pub fn replace_feodo_cache_at(
    path: &Path,
    raw_feed_json: &[u8],
    retrieved_at_unix_secs: u64,
    now_unix_secs: u64,
) -> Result<ValidatedThreatFeed, CacheError> {
    let validated = parse_feodo_recommended_json(raw_feed_json, retrieved_at_unix_secs)
        .map_err(CacheError::Feed)?;
    validate_timestamp(retrieved_at_unix_secs, now_unix_secs)?;

    let raw_feed_json = String::from_utf8(raw_feed_json.to_vec())
        .map_err(|_| CacheError::InvalidEnvelope("raw feed is not valid UTF-8 JSON".to_owned()))?;
    let entry_count = u64::try_from(validated.endpoints.len()).map_err(|_| {
        CacheError::InvalidEnvelope("validated endpoint count exceeds u64".to_owned())
    })?;
    let envelope = CacheEnvelope {
        format_version: FEODO_CACHE_FORMAT_VERSION,
        source: FEODO_RECOMMENDED_JSON_URL.to_owned(),
        license: FEODO_RECOMMENDED_LICENSE.to_owned(),
        retrieved_at_unix_secs,
        content_sha256: validated.metadata.content_sha256.clone(),
        entry_count,
        raw_feed_json,
    };
    let bytes = serde_json::to_vec(&envelope)
        .map_err(|error| CacheError::InvalidEnvelope(error.to_string()))?;
    let serialized_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if bytes.len() > MAX_FEODO_CACHE_FILE_BYTES {
        return Err(CacheError::CacheTooLarge {
            actual: serialized_len,
            maximum: MAX_FEODO_CACHE_FILE_BYTES,
        });
    }

    atomic_write(path, &bytes)?;
    Ok(validated)
}

fn validate_envelope(
    envelope: CacheEnvelope,
    now_unix_secs: u64,
) -> Result<ValidatedThreatFeed, CacheError> {
    if envelope.format_version != FEODO_CACHE_FORMAT_VERSION {
        return Err(CacheError::UnsupportedVersion {
            actual: envelope.format_version,
            expected: FEODO_CACHE_FORMAT_VERSION,
        });
    }
    if envelope.source != FEODO_RECOMMENDED_JSON_URL {
        return Err(CacheError::SourceMismatch {
            actual: envelope.source,
        });
    }
    if envelope.license != FEODO_RECOMMENDED_LICENSE {
        return Err(CacheError::LicenseMismatch {
            actual: envelope.license,
        });
    }
    validate_timestamp(envelope.retrieved_at_unix_secs, now_unix_secs)?;

    let validated = parse_feodo_recommended_json(
        envelope.raw_feed_json.as_bytes(),
        envelope.retrieved_at_unix_secs,
    )
    .map_err(CacheError::Feed)?;
    let actual_hash = validated.metadata.content_sha256.clone();
    if envelope.content_sha256 != actual_hash {
        return Err(CacheError::HashMismatch {
            expected: envelope.content_sha256,
            actual: actual_hash,
        });
    }
    if envelope.entry_count != validated.endpoints.len() as u64 {
        return Err(CacheError::EntryCountMismatch {
            expected: envelope.entry_count,
            actual: validated.endpoints.len(),
        });
    }
    Ok(validated)
}

fn validate_timestamp(retrieved_at_unix_secs: u64, now_unix_secs: u64) -> Result<(), CacheError> {
    if retrieved_at_unix_secs > now_unix_secs.saturating_add(MAX_CACHE_TIMESTAMP_SKEW_SECS) {
        return Err(CacheError::TimestampInFuture {
            retrieved_at: retrieved_at_unix_secs,
            now: now_unix_secs,
        });
    }
    Ok(())
}

fn unix_now_secs() -> Result<u64, CacheError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| CacheError::Io(format!("system clock is before Unix epoch: {error}")))
}

fn read_bounded(path: &Path) -> Result<Option<Vec<u8>>, CacheError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(error)),
    };
    if let Ok(metadata) = file.metadata() {
        let length = metadata.len();
        if length > MAX_FEODO_CACHE_FILE_BYTES as u64 {
            return Err(CacheError::CacheTooLarge {
                actual: length,
                maximum: MAX_FEODO_CACHE_FILE_BYTES,
            });
        }
    }

    let read_limit = MAX_FEODO_CACHE_FILE_BYTES.saturating_add(1) as u64;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > MAX_FEODO_CACHE_FILE_BYTES {
        return Err(CacheError::CacheTooLarge {
            actual: bytes.len() as u64,
            maximum: MAX_FEODO_CACHE_FILE_BYTES,
        });
    }
    Ok(Some(bytes))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), CacheError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(io_error)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| CacheError::Io("cache path must contain a file name".to_owned()))?;

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
    let mut temporary_path = None;
    let mut temporary_file = None;
    for _ in 0..32 {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{}.tmp-{}-{id}",
            file_name.to_string_lossy(),
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temporary_path = Some(candidate);
                temporary_file = Some(file);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(io_error(error)),
        }
    }
    let temporary_path = temporary_path.ok_or_else(|| {
        CacheError::Io("could not allocate a unique cache temporary file".to_owned())
    })?;
    let mut temporary_file = temporary_file.expect("temporary path and file are paired");

    if let Err(error) = temporary_file.write_all(bytes) {
        drop(temporary_file);
        let _ = fs::remove_file(&temporary_path);
        return Err(io_error(error));
    }
    if let Err(error) = temporary_file.sync_all() {
        drop(temporary_file);
        let _ = fs::remove_file(&temporary_path);
        return Err(io_error(error));
    }
    drop(temporary_file);

    let result = atomic_replace(&temporary_path, path).map_err(io_error);
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn io_error(error: io::Error) -> CacheError {
    CacheError::Io(error.to_string())
}

#[cfg(not(windows))]
fn atomic_replace(temporary_path: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(temporary_path, destination)
}

#[cfg(windows)]
fn atomic_replace(temporary_path: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        MoveFileExW, ReplaceFileW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        REPLACEFILE_WRITE_THROUGH,
    };

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let temporary_wide = wide(temporary_path);
    let destination_wide = wide(destination);
    let destination_exists = destination.exists();
    if destination_exists {
        unsafe {
            ReplaceFileW(
                PCWSTR(destination_wide.as_ptr()),
                PCWSTR(temporary_wide.as_ptr()),
                PCWSTR::null(),
                REPLACEFILE_WRITE_THROUGH,
                None,
                None,
            )
        }
        .map_err(|_| io::Error::last_os_error())
    } else {
        unsafe {
            MoveFileExW(
                PCWSTR(temporary_wide.as_ptr()),
                PCWSTR(destination_wide.as_ptr()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
        .map_err(|_| io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    const TEST_NOW: u64 = 1_757_000_000;

    struct TempDirectory {
        path: PathBuf,
    }

    impl TempDirectory {
        fn new() -> Self {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            let base = std::env::temp_dir();
            for _ in 0..128 {
                let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
                let path = base.join(format!("vapour-feed-cache-{}-{id}", std::process::id()));
                match fs::create_dir(&path) {
                    Ok(()) => return Self { path },
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("cannot create test directory: {error}"),
                }
            }
            panic!("could not allocate a unique test directory");
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn feed(ip: &str, port: u16) -> Vec<u8> {
        format!(r#"[{{"ip_address":"{ip}","port":{port},"status":"online"}}]"#).into_bytes()
    }

    #[test]
    fn writes_and_loads_a_validated_feed() {
        let directory = TempDirectory::new();
        let path = directory.path.join("feodo-cache.json");
        let original = feed("8.8.8.8", 443);

        let written = replace_feodo_cache_at(&path, &original, TEST_NOW, TEST_NOW + 1).unwrap();
        let loaded = load_feodo_cache_at(&path, TEST_NOW + 1).unwrap().unwrap();

        assert_eq!(loaded, written);
        assert_eq!(loaded.metadata.retrieved_at_unix_secs, TEST_NOW);
        assert_eq!(
            loaded.metadata.source,
            super::super::feeds::FEODO_RECOMMENDED_JSON_URL
        );
    }

    #[test]
    fn corrupt_cache_is_rejected_without_returning_endpoints() {
        let directory = TempDirectory::new();
        let path = directory.path.join("feodo-cache.json");
        fs::write(&path, b"not-json").unwrap();

        assert!(matches!(
            load_feodo_cache_at(&path, TEST_NOW),
            Err(CacheError::InvalidEnvelope(_))
        ));
    }

    #[test]
    fn oversize_cache_is_rejected_before_deserialization() {
        let directory = TempDirectory::new();
        let path = directory.path.join("feodo-cache.json");
        fs::write(&path, vec![b'x'; MAX_FEODO_CACHE_FILE_BYTES + 1]).unwrap();

        assert!(matches!(
            load_feodo_cache_at(&path, TEST_NOW),
            Err(CacheError::CacheTooLarge { .. })
        ));
    }

    #[test]
    fn invalid_update_preserves_the_last_known_good_file() {
        let directory = TempDirectory::new();
        let path = directory.path.join("feodo-cache.json");
        let original = feed("8.8.8.8", 443);
        replace_feodo_cache_at(&path, &original, TEST_NOW, TEST_NOW + 1).unwrap();
        let previous_bytes = fs::read(&path).unwrap();

        let invalid = br#"[{"ip_address":"192.168.1.1","port":443}]"#;
        assert!(matches!(
            replace_feodo_cache_at(&path, invalid, TEST_NOW + 2, TEST_NOW + 2),
            Err(CacheError::Feed(FeedParseError::NonPublicIp { .. }))
        ));
        assert_eq!(fs::read(&path).unwrap(), previous_bytes);
        assert_eq!(
            load_feodo_cache_at(&path, TEST_NOW + 2)
                .unwrap()
                .unwrap()
                .endpoints[0]
                .ip_address,
            "8.8.8.8".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[cfg(windows)]
    #[test]
    fn failed_windows_replacement_preserves_the_last_known_good_file() {
        use std::os::windows::fs::OpenOptionsExt;

        let directory = TempDirectory::new();
        let path = directory.path.join("feodo-cache.json");
        let original = feed("8.8.8.8", 443);
        replace_feodo_cache_at(&path, &original, TEST_NOW, TEST_NOW + 1).unwrap();
        let previous_bytes = fs::read(&path).unwrap();

        let lock = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&path)
            .unwrap();
        let result =
            replace_feodo_cache_at(&path, &feed("1.1.1.1", 443), TEST_NOW + 2, TEST_NOW + 2);
        drop(lock);

        assert!(matches!(result, Err(CacheError::Io(_))));
        assert_eq!(fs::read(&path).unwrap(), previous_bytes);
    }

    #[test]
    fn tampered_hash_is_rejected_after_reparsing_raw_feed() {
        let directory = TempDirectory::new();
        let path = directory.path.join("feodo-cache.json");
        replace_feodo_cache_at(&path, &feed("8.8.8.8", 443), TEST_NOW, TEST_NOW + 1).unwrap();

        let mut envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        envelope["raw_feed_json"] =
            serde_json::Value::String(String::from_utf8(feed("1.1.1.1", 443)).unwrap());
        envelope["content_sha256"] = serde_json::Value::String("00".repeat(32));
        fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();

        assert!(matches!(
            load_feodo_cache_at(&path, TEST_NOW + 1),
            Err(CacheError::HashMismatch { .. })
        ));
    }

    #[test]
    fn serialized_endpoints_are_ignored_in_favor_of_reparsed_raw_feed() {
        let directory = TempDirectory::new();
        let path = directory.path.join("feodo-cache.json");
        replace_feodo_cache_at(&path, &feed("8.8.8.8", 443), TEST_NOW, TEST_NOW + 1).unwrap();

        let mut envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        envelope["endpoints"] = serde_json::json!([{
            "ip_address": "1.1.1.1",
            "port": 53,
        }]);
        fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();

        let loaded = load_feodo_cache_at(&path, TEST_NOW + 1).unwrap().unwrap();
        assert_eq!(loaded.endpoints.len(), 1);
        assert_eq!(
            loaded.endpoints[0].ip_address,
            "8.8.8.8".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(loaded.endpoints[0].port, 443);
    }

    #[test]
    fn tampered_source_and_future_timestamp_are_rejected() {
        let directory = TempDirectory::new();
        let path = directory.path.join("feodo-cache.json");
        replace_feodo_cache_at(&path, &feed("8.8.8.8", 443), TEST_NOW, TEST_NOW + 1).unwrap();

        let mut envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        envelope["source"] = serde_json::Value::String("https://example.invalid/feed".into());
        fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert!(matches!(
            load_feodo_cache_at(&path, TEST_NOW + 1),
            Err(CacheError::SourceMismatch { .. })
        ));

        replace_feodo_cache_at(&path, &feed("8.8.8.8", 443), TEST_NOW, TEST_NOW + 1).unwrap();
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        envelope["retrieved_at_unix_secs"] = serde_json::Value::from(TEST_NOW + 10_000);
        fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert!(matches!(
            load_feodo_cache_at(&path, TEST_NOW + 1),
            Err(CacheError::TimestampInFuture { .. })
        ));
    }

    #[test]
    fn missing_cache_returns_none() {
        let directory = TempDirectory::new();
        let path = directory.path.join("missing-cache.json");
        assert_eq!(load_feodo_cache_at(&path, TEST_NOW).unwrap(), None);
    }
}
