//! Bounded acquisition and persistence for the optional DB-IP Lite dataset.
//!
//! Dataset refreshes use only DB-IP's fixed HTTPS download host.  Destination
//! addresses are never sent to this module or to DB-IP: callers load the
//! resulting local [`DestinationTagSource`](crate::network::destination_tags::DestinationTagSource)
//! and perform all lookups in memory.  Refresh this module from a background
//! worker because the reqwest client is blocking.

use crate::network::destination_tags::{
    CacheConfig, CacheConfigError, DataLoadError, DbIpLiteSource, DestinationTagCache,
    DestinationTagSource, NoLocalDataSource, DB_IP_LITE_ATTRIBUTION, DB_IP_LITE_ATTRIBUTION_URL,
    DB_IP_LITE_SOURCE, MAX_DB_IP_CSV_BYTES,
};
use flate2::read::GzDecoder;
use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Cursor, Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// DB-IP's free Lite files are published below this fixed HTTPS host.
pub const DB_IP_DOWNLOAD_BASE_URL: &str = "https://download.db-ip.com/free";
pub const DB_IP_DOWNLOAD_HOST: &str = "download.db-ip.com";
pub const DB_IP_COUNTRY_URL_TEMPLATE: &str =
    "https://download.db-ip.com/free/dbip-country-lite-{YYYY-MM}.csv.gz";
pub const DB_IP_ASN_URL_TEMPLATE: &str =
    "https://download.db-ip.com/free/dbip-asn-lite-{YYYY-MM}.csv.gz";

/// The license and attribution are persisted with each installed pair so a
/// UI or diagnostics surface can show the data provenance.
pub const DB_IP_LITE_LICENSE: &str = "Creative Commons Attribution 4.0 International";
pub const DB_IP_LITE_LICENSE_URL: &str = "https://creativecommons.org/licenses/by/4.0/";

/// The current public archives are roughly 30 MiB compressed.  This leaves
/// room for a monthly release while keeping an untrusted HTTP response
/// bounded before decompression.
pub const MAX_COMPRESSED_DOWNLOAD_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(90);
pub const MAX_CACHED_PAIR_DIRS: usize = 2;
pub const CACHE_FORMAT_VERSION: u32 = 1;

const MANIFEST_FILE_NAME: &str = "manifest.json";
const PAIRS_DIRECTORY_NAME: &str = "pairs";
const COUNTRY_FILE_NAME: &str = "country.csv";
const ASN_FILE_NAME: &str = "asn.csv";
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_REDIRECTS: usize = 2;
const USER_AGENT: &str = "Vapour/0.1 destination-tags updater";

/// A validated DB-IP monthly release identifier.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct DbIpRelease {
    year: u16,
    month: u8,
}

impl DbIpRelease {
    pub fn new(year: u16, month: u8) -> Result<Self, TagDatabaseError> {
        let release = Self { year, month };
        release.validate()?;
        Ok(release)
    }

    /// Return the DB-IP release corresponding to the current UTC calendar
    /// month.  This uses the system clock only; no network request is made.
    pub fn current_utc() -> Result<Self, TagDatabaseError> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TagDatabaseError::SystemClockUnavailable)?;
        let days = i64::try_from(elapsed.as_secs() / 86_400)
            .map_err(|_| TagDatabaseError::SystemClockUnavailable)?;
        let (year, month, _) = civil_from_days(days);
        let year = u16::try_from(year).map_err(|_| TagDatabaseError::SystemClockUnavailable)?;
        let month = u8::try_from(month).map_err(|_| TagDatabaseError::SystemClockUnavailable)?;
        Self::new(year, month)
    }

    pub fn year(self) -> u16 {
        self.year
    }

    pub fn month(self) -> u8 {
        self.month
    }

    pub fn country_url(self) -> Result<String, TagDatabaseError> {
        self.validate()?;
        Ok(format!(
            "{DB_IP_DOWNLOAD_BASE_URL}/dbip-country-lite-{:04}-{:02}.csv.gz",
            self.year, self.month
        ))
    }

    pub fn asn_url(self) -> Result<String, TagDatabaseError> {
        self.validate()?;
        Ok(format!(
            "{DB_IP_DOWNLOAD_BASE_URL}/dbip-asn-lite-{:04}-{:02}.csv.gz",
            self.year, self.month
        ))
    }

    fn validate(self) -> Result<(), TagDatabaseError> {
        if !(2000..=2100).contains(&self.year) || !(1..=12).contains(&self.month) {
            return Err(TagDatabaseError::InvalidRelease {
                year: self.year,
                month: self.month,
            });
        }
        Ok(())
    }
}

impl fmt::Display for DbIpRelease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}", self.year, self.month)
    }
}

impl std::str::FromStr for DbIpRelease {
    type Err = TagDatabaseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (year, month) = value
            .split_once('-')
            .ok_or(TagDatabaseError::InvalidReleaseFormat)?;
        if year.len() != 4 || month.len() != 2 || month.contains('-') {
            return Err(TagDatabaseError::InvalidReleaseFormat);
        }
        let year = year
            .parse::<u16>()
            .map_err(|_| TagDatabaseError::InvalidReleaseFormat)?;
        let month = month
            .parse::<u8>()
            .map_err(|_| TagDatabaseError::InvalidReleaseFormat)?;
        Self::new(year, month)
    }
}

// Convert a signed count of days since 1970-01-01 to a proleptic Gregorian
// calendar date.  Keeping this conversion local avoids adding a clock/date
// dependency to the updater and makes the UTC boundary behavior testable.
fn civil_from_days(days_since_unix_epoch: i64) -> (i64, u8, u8) {
    let z = days_since_unix_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month_part = (5 * doy + 2) / 153;
    let day = doy - (153 * month_part + 2) / 5 + 1;
    let month = month_part + if month_part < 10 { 3 } else { -9 };
    let year = year + i64::from(month <= 2);
    (year, month as u8, day as u8)
}

/// Limits for HTTP retrieval and local gzip processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagDatabaseConfig {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_compressed_bytes: usize,
    pub max_decompressed_bytes: usize,
}

impl Default for TagDatabaseConfig {
    fn default() -> Self {
        Self {
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_compressed_bytes: MAX_COMPRESSED_DOWNLOAD_BYTES,
            max_decompressed_bytes: MAX_DB_IP_CSV_BYTES,
        }
    }
}

impl TagDatabaseConfig {
    fn validate(self) -> Result<(), TagDatabaseError> {
        if self.connect_timeout.is_zero() {
            return Err(TagDatabaseError::InvalidConfig {
                field: "connect_timeout",
            });
        }
        if self.request_timeout.is_zero() {
            return Err(TagDatabaseError::InvalidConfig {
                field: "request_timeout",
            });
        }
        if self.max_compressed_bytes == 0
            || self.max_compressed_bytes > MAX_COMPRESSED_DOWNLOAD_BYTES
        {
            return Err(TagDatabaseError::InvalidConfig {
                field: "max_compressed_bytes",
            });
        }
        if self.max_decompressed_bytes == 0 || self.max_decompressed_bytes > MAX_DB_IP_CSV_BYTES {
            return Err(TagDatabaseError::InvalidConfig {
                field: "max_decompressed_bytes",
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DatasetMetadata {
    pub release: DbIpRelease,
    pub source: String,
    pub source_url: String,
    pub license: String,
    pub license_url: String,
    pub attribution: String,
    pub country_ranges: usize,
    pub asn_ranges: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DatasetUnavailableReason {
    NotInstalled,
    CacheInvalid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DatasetStatus {
    Ready(DatasetMetadata),
    Unavailable { reason: DatasetUnavailableReason },
}

/// A source snapshot is immutable and can be handed to a cache or monitor.
/// The unavailable snapshot uses `NoLocalDataSource`, which never performs a
/// network lookup and returns explicit `unavailable` results for public IPs.
#[derive(Clone)]
pub struct DatasetSnapshot {
    pub status: DatasetStatus,
    source: Arc<dyn DestinationTagSource>,
}

impl fmt::Debug for DatasetSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatasetSnapshot")
            .field("status", &self.status)
            .field("source", &self.source.source_name())
            .finish()
    }
}

impl DatasetSnapshot {
    pub fn source(&self) -> Arc<dyn DestinationTagSource> {
        Arc::clone(&self.source)
    }

    pub fn cache(&self) -> DestinationTagCache {
        DestinationTagCache::new(self.source())
    }

    pub fn cache_with_config(
        &self,
        config: CacheConfig,
    ) -> Result<DestinationTagCache, CacheConfigError> {
        DestinationTagCache::with_config(self.source(), config)
    }

    fn ready(source: DbIpLiteSource, metadata: DatasetMetadata) -> Self {
        Self {
            status: DatasetStatus::Ready(metadata),
            source: Arc::new(source),
        }
    }

    fn unavailable(reason: DatasetUnavailableReason) -> Self {
        Self {
            status: DatasetStatus::Unavailable { reason },
            source: Arc::new(NoLocalDataSource),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagDatabaseError {
    InvalidRelease {
        year: u16,
        month: u8,
    },
    InvalidReleaseFormat,
    InvalidConfig {
        field: &'static str,
    },
    SystemClockUnavailable,
    HttpClient,
    HttpRequest,
    HttpStatus {
        status: u16,
    },
    RedirectRejected,
    ResponseTooLarge {
        actual: u64,
        maximum: usize,
    },
    ResponseRead,
    LocalFileTooLarge {
        actual: u64,
        maximum: usize,
    },
    Decompression,
    DecompressedTooLarge {
        actual: usize,
        maximum: usize,
    },
    Dataset(DataLoadError),
    Io {
        operation: &'static str,
        kind: io::ErrorKind,
    },
    ManifestTooLarge {
        actual: u64,
        maximum: usize,
    },
    ManifestInvalid(String),
    CachePairInvalid {
        field: &'static str,
    },
    Serialization,
}

impl fmt::Display for TagDatabaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRelease { year, month } => {
                write!(f, "DB-IP release {year:04}-{month:02} is invalid")
            }
            Self::InvalidReleaseFormat => f.write_str("DB-IP release must use YYYY-MM format"),
            Self::InvalidConfig { field } => write!(f, "invalid tag database setting: {field}"),
            Self::SystemClockUnavailable => {
                f.write_str("the system clock could not provide the current UTC release")
            }
            Self::HttpClient => f.write_str("could not create the DB-IP HTTPS client"),
            Self::HttpRequest => f.write_str("DB-IP download request failed"),
            Self::HttpStatus { status } => write!(f, "DB-IP download returned HTTP {status}"),
            Self::RedirectRejected => {
                f.write_str("DB-IP download redirected away from its fixed HTTPS host")
            }
            Self::ResponseTooLarge { actual, maximum } => {
                write!(f, "DB-IP response is {actual} bytes; maximum is {maximum}")
            }
            Self::ResponseRead => f.write_str("DB-IP response body could not be read"),
            Self::LocalFileTooLarge { actual, maximum } => {
                write!(
                    f,
                    "DB-IP local file is {actual} bytes; maximum is {maximum}"
                )
            }
            Self::Decompression => f.write_str("DB-IP gzip archive could not be decompressed"),
            Self::DecompressedTooLarge { actual, maximum } => write!(
                f,
                "DB-IP decompressed CSV reached {actual} bytes; maximum is {maximum}"
            ),
            Self::Dataset(error) => write!(f, "DB-IP CSV validation failed: {error}"),
            Self::Io { operation, kind } => write!(f, "DB-IP cache {operation} failed: {kind:?}"),
            Self::ManifestTooLarge { actual, maximum } => {
                write!(f, "DB-IP manifest is {actual} bytes; maximum is {maximum}")
            }
            Self::ManifestInvalid(error) => write!(f, "DB-IP manifest is invalid: {error}"),
            Self::CachePairInvalid { field } => {
                write!(f, "DB-IP cache pair has invalid {field}")
            }
            Self::Serialization => f.write_str("DB-IP cache manifest could not be serialized"),
        }
    }
}

impl std::error::Error for TagDatabaseError {}

impl From<DataLoadError> for TagDatabaseError {
    fn from(error: DataLoadError) -> Self {
        Self::Dataset(error)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DatasetManifest {
    format_version: u32,
    metadata: DatasetMetadata,
    pair_dir: String,
    country_bytes: usize,
    asn_bytes: usize,
    country_sha256: String,
    asn_sha256: String,
}

/// A filesystem-backed DB-IP Lite manager.
///
/// `refresh` performs two fixed-host HTTPS downloads, validates both CSV
/// files in memory, and publishes a complete pair through an atomic manifest.
/// A failed download, decompression, parse, or write leaves the previous
/// manifest and pair untouched.  `install_local_*` is the offline path for
/// already downloaded or separately packaged artifacts.
#[derive(Debug, Clone)]
pub struct TagDatabase {
    root: PathBuf,
    config: TagDatabaseConfig,
}

impl TagDatabase {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            config: TagDatabaseConfig::default(),
        }
    }

    pub fn with_config(
        root: impl Into<PathBuf>,
        config: TagDatabaseConfig,
    ) -> Result<Self, TagDatabaseError> {
        config.validate()?;
        Ok(Self {
            root: root.into(),
            config,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn manifest_path(&self) -> PathBuf {
        self.root.join(MANIFEST_FILE_NAME)
    }

    /// Refresh one known DB-IP monthly release using fixed official URLs.
    /// Call this from a background worker; no destination IP is included in
    /// the request.
    pub fn refresh(&self, release: DbIpRelease) -> Result<DatasetSnapshot, TagDatabaseError> {
        release.validate()?;
        let client = self.client()?;
        let country_url = release.country_url()?;
        let asn_url = release.asn_url()?;
        let country = self.fetch_gzip_csv(&client, &country_url)?;
        let asn = self.fetch_gzip_csv(&client, &asn_url)?;
        self.install_csv_bytes(release, &country, &asn)
    }

    /// Refresh the current UTC DB-IP monthly release.  Call this from a
    /// background worker because the underlying HTTP client is blocking.
    pub fn refresh_current(&self) -> Result<DatasetSnapshot, TagDatabaseError> {
        self.refresh(DbIpRelease::current_utc()?)
    }

    /// Install two already decompressed local CSV artifacts and publish them
    /// as one validated pair.  The files are never uploaded by this method.
    pub fn install_local_files(
        &self,
        release: DbIpRelease,
        country_path: &Path,
        asn_path: &Path,
    ) -> Result<DatasetSnapshot, TagDatabaseError> {
        let country = read_bounded_file(country_path, self.config.max_decompressed_bytes)?;
        let asn = read_bounded_file(asn_path, self.config.max_decompressed_bytes)?;
        self.install_csv_bytes(release, &country, &asn)
    }

    /// Install two local DB-IP `.csv.gz` artifacts without contacting the
    /// network.  This is useful for a separately managed monthly update job.
    pub fn install_local_gzip_files(
        &self,
        release: DbIpRelease,
        country_path: &Path,
        asn_path: &Path,
    ) -> Result<DatasetSnapshot, TagDatabaseError> {
        let country_gzip = read_bounded_file(country_path, self.config.max_compressed_bytes)?;
        let asn_gzip = read_bounded_file(asn_path, self.config.max_compressed_bytes)?;
        let country = decompress_gzip(&country_gzip, self.config.max_decompressed_bytes)?;
        let asn = decompress_gzip(&asn_gzip, self.config.max_decompressed_bytes)?;
        self.install_csv_bytes(release, &country, &asn)
    }

    /// Install CSV bytes after a caller has obtained them from a reviewed
    /// local source.  Parsing and bounds checks happen before persistence.
    pub fn install_local_csv(
        &self,
        release: DbIpRelease,
        country_csv: &[u8],
        asn_csv: &[u8],
    ) -> Result<DatasetSnapshot, TagDatabaseError> {
        self.install_csv_bytes(release, country_csv, asn_csv)
    }

    /// Load the last atomically published pair.  A missing or invalid cache
    /// becomes an explicit unavailable snapshot.  Call
    /// [`try_load_last_good`](Self::try_load_last_good) when the detailed
    /// validation error is needed for diagnostics.
    pub fn load_last_good(&self) -> DatasetSnapshot {
        match self.try_load_last_good() {
            Ok(Some(snapshot)) => snapshot,
            Ok(None) => DatasetSnapshot::unavailable(DatasetUnavailableReason::NotInstalled),
            Err(_) => DatasetSnapshot::unavailable(DatasetUnavailableReason::CacheInvalid),
        }
    }

    /// Detailed form of [`load_last_good`](Self::load_last_good), preserving
    /// the distinction between a missing cache and a corrupt one.
    pub fn try_load_last_good(&self) -> Result<Option<DatasetSnapshot>, TagDatabaseError> {
        let Some(bytes) = read_optional_bounded_file(&self.manifest_path(), MAX_MANIFEST_BYTES)?
        else {
            return Ok(None);
        };
        let manifest: DatasetManifest = serde_json::from_slice(&bytes)
            .map_err(|error| TagDatabaseError::ManifestInvalid(error.to_string()))?;
        validate_manifest(&manifest)?;

        let pair_root = self
            .root
            .join(PAIRS_DIRECTORY_NAME)
            .join(&manifest.pair_dir);
        let country_path = pair_root.join(COUNTRY_FILE_NAME);
        let asn_path = pair_root.join(ASN_FILE_NAME);
        let country = read_bounded_file(&country_path, self.config.max_decompressed_bytes)?;
        let asn = read_bounded_file(&asn_path, self.config.max_decompressed_bytes)?;
        if country.len() != manifest.country_bytes {
            return Err(TagDatabaseError::CachePairInvalid {
                field: "country_bytes",
            });
        }
        if asn.len() != manifest.asn_bytes {
            return Err(TagDatabaseError::CachePairInvalid { field: "asn_bytes" });
        }
        if sha256_hex(&country) != manifest.country_sha256 {
            return Err(TagDatabaseError::CachePairInvalid {
                field: "country_sha256",
            });
        }
        if sha256_hex(&asn) != manifest.asn_sha256 {
            return Err(TagDatabaseError::CachePairInvalid {
                field: "asn_sha256",
            });
        }
        let source = DbIpLiteSource::from_csv(Some(&country), Some(&asn))?;
        if source.country_range_count() != manifest.metadata.country_ranges {
            return Err(TagDatabaseError::CachePairInvalid {
                field: "country_ranges",
            });
        }
        if source.asn_range_count() != manifest.metadata.asn_ranges {
            return Err(TagDatabaseError::CachePairInvalid {
                field: "asn_ranges",
            });
        }
        cleanup_old_pairs(
            &self.root.join(PAIRS_DIRECTORY_NAME),
            Some(&manifest.pair_dir),
        );
        Ok(Some(DatasetSnapshot::ready(source, manifest.metadata)))
    }

    fn install_csv_bytes(
        &self,
        release: DbIpRelease,
        country: &[u8],
        asn: &[u8],
    ) -> Result<DatasetSnapshot, TagDatabaseError> {
        release.validate()?;
        ensure_size(country.len(), self.config.max_decompressed_bytes)?;
        ensure_size(asn.len(), self.config.max_decompressed_bytes)?;
        let source = DbIpLiteSource::from_csv(Some(country), Some(asn))?;
        let metadata = metadata_for(release, &source);
        self.persist_pair(&metadata, country, asn)?;
        Ok(DatasetSnapshot::ready(source, metadata))
    }

    fn client(&self) -> Result<Client, TagDatabaseError> {
        Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS))
            .connect_timeout(self.config.connect_timeout)
            .timeout(self.config.request_timeout)
            .user_agent(USER_AGENT)
            .build()
            .map_err(|_| TagDatabaseError::HttpClient)
    }

    fn fetch_gzip_csv(&self, client: &Client, url: &str) -> Result<Vec<u8>, TagDatabaseError> {
        let response = client
            .get(url)
            .send()
            .map_err(|_| TagDatabaseError::HttpRequest)?;
        if response.url().scheme() != "https"
            || response.url().host_str() != Some(DB_IP_DOWNLOAD_HOST)
        {
            return Err(TagDatabaseError::RedirectRejected);
        }
        if !response.status().is_success() {
            return Err(TagDatabaseError::HttpStatus {
                status: response.status().as_u16(),
            });
        }
        let compressed = read_response_bounded(response, self.config.max_compressed_bytes)?;
        decompress_gzip(&compressed, self.config.max_decompressed_bytes)
    }

    fn persist_pair(
        &self,
        metadata: &DatasetMetadata,
        country: &[u8],
        asn: &[u8],
    ) -> Result<(), TagDatabaseError> {
        fs::create_dir_all(self.root.join(PAIRS_DIRECTORY_NAME)).map_err(|error| {
            TagDatabaseError::Io {
                operation: "create directory",
                kind: error.kind(),
            }
        })?;
        let pairs_root = self.root.join(PAIRS_DIRECTORY_NAME);
        let (pair_dir, pair_name) = create_staging_pair_dir(&pairs_root, metadata.release)?;
        let final_dir = pairs_root.join(pair_name);
        let mut pair_published = false;
        let result = (|| {
            write_synced_file(&pair_dir.join(COUNTRY_FILE_NAME), country)?;
            write_synced_file(&pair_dir.join(ASN_FILE_NAME), asn)?;
            fs::rename(&pair_dir, &final_dir).map_err(|error| TagDatabaseError::Io {
                operation: "publish pair directory",
                kind: error.kind(),
            })?;
            pair_published = true;

            let manifest = DatasetManifest {
                format_version: CACHE_FORMAT_VERSION,
                metadata: metadata.clone(),
                pair_dir: final_dir
                    .file_name()
                    .and_then(|value| value.to_str())
                    .ok_or(TagDatabaseError::Serialization)?
                    .to_owned(),
                country_bytes: country.len(),
                asn_bytes: asn.len(),
                country_sha256: sha256_hex(country),
                asn_sha256: sha256_hex(asn),
            };
            let bytes =
                serde_json::to_vec(&manifest).map_err(|_| TagDatabaseError::Serialization)?;
            if bytes.len() > MAX_MANIFEST_BYTES {
                return Err(TagDatabaseError::ManifestTooLarge {
                    actual: bytes.len() as u64,
                    maximum: MAX_MANIFEST_BYTES,
                });
            }
            atomic_write(&self.manifest_path(), &bytes)
        })();
        if result.is_err() {
            // A pair that has not been named by the manifest is never usable;
            // cleanup is best effort so the previous manifest remains intact.
            let _ = fs::remove_dir_all(&pair_dir);
            if pair_published {
                let _ = fs::remove_dir_all(&final_dir);
            }
        } else {
            cleanup_old_pairs(
                &pairs_root,
                final_dir.file_name().and_then(|value| value.to_str()),
            );
        }
        result
    }
}

fn metadata_for(release: DbIpRelease, source: &DbIpLiteSource) -> DatasetMetadata {
    DatasetMetadata {
        release,
        source: DB_IP_LITE_SOURCE.to_owned(),
        source_url: DB_IP_LITE_ATTRIBUTION_URL.to_owned(),
        license: DB_IP_LITE_LICENSE.to_owned(),
        license_url: DB_IP_LITE_LICENSE_URL.to_owned(),
        attribution: DB_IP_LITE_ATTRIBUTION.to_owned(),
        country_ranges: source.country_range_count(),
        asn_ranges: source.asn_range_count(),
    }
}

fn validate_manifest(manifest: &DatasetManifest) -> Result<(), TagDatabaseError> {
    if manifest.format_version != CACHE_FORMAT_VERSION {
        return Err(TagDatabaseError::ManifestInvalid(format!(
            "format version {} is unsupported",
            manifest.format_version
        )));
    }
    manifest.metadata.release.validate()?;
    if manifest.metadata.source != DB_IP_LITE_SOURCE
        || manifest.metadata.source_url != DB_IP_LITE_ATTRIBUTION_URL
        || manifest.metadata.license != DB_IP_LITE_LICENSE
        || manifest.metadata.license_url != DB_IP_LITE_LICENSE_URL
        || manifest.metadata.attribution != DB_IP_LITE_ATTRIBUTION
    {
        return Err(TagDatabaseError::ManifestInvalid(
            "dataset source or license metadata does not match DB-IP Lite".to_owned(),
        ));
    }
    if !is_safe_component(&manifest.pair_dir)
        || !manifest.pair_dir.starts_with("pair-")
        || manifest.country_bytes > MAX_DB_IP_CSV_BYTES
        || manifest.asn_bytes > MAX_DB_IP_CSV_BYTES
        || !is_sha256_hex(&manifest.country_sha256)
        || !is_sha256_hex(&manifest.asn_sha256)
    {
        return Err(TagDatabaseError::CachePairInvalid { field: "pair_dir" });
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_safe_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn create_staging_pair_dir(
    pairs_root: &Path,
    release: DbIpRelease,
) -> Result<(PathBuf, String), TagDatabaseError> {
    static NEXT_PAIR_ID: AtomicU64 = AtomicU64::new(0);
    let clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for _ in 0..32 {
        let id = NEXT_PAIR_ID.fetch_add(1, Ordering::Relaxed);
        let pair_name = format!("pair-{release}-{}-{clock}-{id}", std::process::id());
        let staging_name = format!(".staging-{pair_name}");
        let path = pairs_root.join(staging_name);
        match fs::create_dir(&path) {
            Ok(()) => return Ok((path, pair_name)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(TagDatabaseError::Io {
                    operation: "create staging directory",
                    kind: error.kind(),
                })
            }
        }
    }
    Err(TagDatabaseError::Io {
        operation: "allocate staging directory",
        kind: io::ErrorKind::AlreadyExists,
    })
}

fn cleanup_old_pairs(pairs_root: &Path, keep: Option<&str>) {
    let Ok(entries) = fs::read_dir(pairs_root) else {
        return;
    };
    let mut pairs = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if file_type.is_dir() && name.starts_with("pair-") && Some(name) != keep {
            let modified = entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .unwrap_or(UNIX_EPOCH);
            pairs.push((modified, path));
        } else if file_type.is_dir() && name.starts_with(".staging-") {
            let _ = fs::remove_dir_all(path);
        }
    }
    pairs.sort_unstable_by(|left, right| right.0.cmp(&left.0));
    for (_, path) in pairs
        .into_iter()
        .skip(MAX_CACHED_PAIR_DIRS.saturating_sub(1))
    {
        let _ = fs::remove_dir_all(path);
    }
}

fn ensure_size(actual: usize, maximum: usize) -> Result<(), TagDatabaseError> {
    if actual > maximum {
        return Err(TagDatabaseError::DecompressedTooLarge { actual, maximum });
    }
    Ok(())
}

fn read_response_bounded(response: Response, maximum: usize) -> Result<Vec<u8>, TagDatabaseError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(TagDatabaseError::ResponseTooLarge {
            actual: response.content_length().unwrap_or(u64::MAX),
            maximum,
        });
    }
    let mut bytes = Vec::new();
    response
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| TagDatabaseError::ResponseRead)?;
    if bytes.len() > maximum {
        return Err(TagDatabaseError::ResponseTooLarge {
            actual: bytes.len() as u64,
            maximum,
        });
    }
    Ok(bytes)
}

fn decompress_gzip(bytes: &[u8], maximum: usize) -> Result<Vec<u8>, TagDatabaseError> {
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut output = Vec::new();
    decoder
        .take(maximum as u64 + 1)
        .read_to_end(&mut output)
        .map_err(|_| TagDatabaseError::Decompression)?;
    if output.len() > maximum {
        return Err(TagDatabaseError::DecompressedTooLarge {
            actual: output.len(),
            maximum,
        });
    }
    Ok(output)
}

fn read_optional_bounded_file(
    path: &Path,
    maximum: usize,
) -> Result<Option<Vec<u8>>, TagDatabaseError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(TagDatabaseError::Io {
                operation: "open file",
                kind: error.kind(),
            })
        }
    };
    read_file_contents(&mut file, maximum).map(Some)
}

fn read_bounded_file(path: &Path, maximum: usize) -> Result<Vec<u8>, TagDatabaseError> {
    let mut file = File::open(path).map_err(|error| TagDatabaseError::Io {
        operation: "open file",
        kind: error.kind(),
    })?;
    read_file_contents(&mut file, maximum)
}

fn read_file_contents(file: &mut File, maximum: usize) -> Result<Vec<u8>, TagDatabaseError> {
    if let Ok(length) = file.metadata().map(|metadata| metadata.len()) {
        if length > maximum as u64 {
            return Err(TagDatabaseError::LocalFileTooLarge {
                actual: length,
                maximum,
            });
        }
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| TagDatabaseError::ResponseRead)?;
    if bytes.len() > maximum {
        return Err(TagDatabaseError::LocalFileTooLarge {
            actual: bytes.len() as u64,
            maximum,
        });
    }
    Ok(bytes)
}

fn write_synced_file(path: &Path, bytes: &[u8]) -> Result<(), TagDatabaseError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| TagDatabaseError::Io {
            operation: "create cache file",
            kind: error.kind(),
        })?;
    if let Err(error) = file.write_all(bytes) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(TagDatabaseError::Io {
            operation: "write cache file",
            kind: error.kind(),
        });
    }
    if let Err(error) = file.sync_all() {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(TagDatabaseError::Io {
            operation: "sync cache file",
            kind: error.kind(),
        });
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), TagDatabaseError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| TagDatabaseError::Io {
        operation: "create manifest directory",
        kind: error.kind(),
    })?;

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
    let file_name = path.file_name().ok_or(TagDatabaseError::Serialization)?;
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
            Err(error) => {
                return Err(TagDatabaseError::Io {
                    operation: "create manifest temporary file",
                    kind: error.kind(),
                })
            }
        }
    }
    let temporary_path = temporary_path.ok_or(TagDatabaseError::Io {
        operation: "allocate manifest temporary file",
        kind: io::ErrorKind::AlreadyExists,
    })?;
    let mut temporary_file = temporary_file.expect("temporary path and file are paired");
    if let Err(error) = temporary_file.write_all(bytes) {
        drop(temporary_file);
        let _ = fs::remove_file(&temporary_path);
        return Err(TagDatabaseError::Io {
            operation: "write manifest",
            kind: error.kind(),
        });
    }
    if let Err(error) = temporary_file.sync_all() {
        drop(temporary_file);
        let _ = fs::remove_file(&temporary_path);
        return Err(TagDatabaseError::Io {
            operation: "sync manifest",
            kind: error.kind(),
        });
    }
    drop(temporary_file);
    let result = atomic_replace(&temporary_path, path);
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

#[cfg(not(windows))]
fn atomic_replace(temporary_path: &Path, destination: &Path) -> Result<(), TagDatabaseError> {
    fs::rename(temporary_path, destination).map_err(|error| TagDatabaseError::Io {
        operation: "publish manifest",
        kind: error.kind(),
    })
}

#[cfg(windows)]
fn atomic_replace(temporary_path: &Path, destination: &Path) -> Result<(), TagDatabaseError> {
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
    if destination.exists() {
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
        .map_err(|_| TagDatabaseError::Io {
            operation: "replace manifest",
            kind: io::Error::last_os_error().kind(),
        })
    } else {
        unsafe {
            MoveFileExW(
                PCWSTR(temporary_wide.as_ptr()),
                PCWSTR(destination_wide.as_ptr()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
        .map_err(|_| TagDatabaseError::Io {
            operation: "publish manifest",
            kind: io::Error::last_os_error().kind(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::destination_tags::{DestinationTagStatus, SourceLookup};
    use flate2::{write::GzEncoder, Compression};
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempDirectory {
        path: PathBuf,
    }

    impl TempDirectory {
        fn new() -> Self {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            let base = std::env::temp_dir();
            for _ in 0..128 {
                let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
                let path = base.join(format!("vapour-dbip-tags-{}-{id}", std::process::id()));
                match fs::create_dir(&path) {
                    Ok(()) => return Self { path },
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("cannot create test directory: {error}"),
                }
            }
            panic!("could not allocate test directory");
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn release() -> DbIpRelease {
        DbIpRelease::new(2026, 9).expect("valid release fixture")
    }

    fn country_csv() -> &'static [u8] {
        b"1.1.1.0,1.1.1.255,AU\n2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US\n"
    }

    fn asn_csv() -> &'static [u8] {
        b"1.1.1.0,1.1.1.255,13335,\"Cloudflare, Inc.\"\n2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,15169,Google\n"
    }

    #[test]
    fn release_urls_are_fixed_to_the_official_monthly_host() {
        let release = release();
        assert_eq!(
            release.country_url().unwrap(),
            "https://download.db-ip.com/free/dbip-country-lite-2026-09.csv.gz"
        );
        assert_eq!(
            release.asn_url().unwrap(),
            "https://download.db-ip.com/free/dbip-asn-lite-2026-09.csv.gz"
        );
        assert!("2026-09".parse::<DbIpRelease>().is_ok());
        assert!("2026-13".parse::<DbIpRelease>().is_err());
    }

    #[test]
    fn current_release_uses_the_utc_calendar() {
        let current = DbIpRelease::current_utc().expect("system clock should be available");
        assert!((2000..=2100).contains(&current.year()));
        assert!((1..=12).contains(&current.month()));
    }

    #[test]
    fn unix_days_convert_to_expected_calendar_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(10_957), (2000, 1, 1));
        assert_eq!(civil_from_days(18_262), (2020, 1, 1));
    }

    #[test]
    fn installs_and_reloads_an_atomic_validated_pair() {
        let directory = TempDirectory::new();
        let database = TagDatabase::new(&directory.path);
        let installed = database
            .install_local_csv(release(), country_csv(), asn_csv())
            .unwrap();
        let DatasetStatus::Ready(metadata) = &installed.status else {
            panic!("fixture should be ready");
        };
        assert_eq!(metadata.country_ranges, 2);
        assert_eq!(metadata.asn_ranges, 2);
        assert_eq!(metadata.license, DB_IP_LITE_LICENSE);

        let lookup = installed
            .source()
            .lookup("1.1.1.1".parse().expect("fixture IP"));
        let SourceLookup::Found(tags) = lookup else {
            panic!("fixture should have local tags");
        };
        assert_eq!(tags.country_code.as_deref(), Some("AU"));
        assert_eq!(tags.organization.as_deref(), Some("Cloudflare, Inc."));

        let loaded = database.load_last_good();
        assert_eq!(loaded.status, installed.status);
        let cached = loaded
            .cache()
            .lookup("2001:4860:4860::8888".parse().unwrap());
        assert_eq!(cached.status, DestinationTagStatus::Known);
        assert_eq!(cached.tags.unwrap().asn, Some(15169));
    }

    #[test]
    fn invalid_pair_preserves_the_last_good_manifest() {
        let directory = TempDirectory::new();
        let database = TagDatabase::new(&directory.path);
        let installed = database
            .install_local_csv(release(), country_csv(), asn_csv())
            .unwrap();
        let invalid_asn = b"1.1.1.0,1.1.1.255,not-an-asn,Cloudflare\n";
        assert!(matches!(
            database.install_local_csv(release(), country_csv(), invalid_asn),
            Err(TagDatabaseError::Dataset(DataLoadError::InvalidAsn { .. }))
        ));
        let loaded = database.load_last_good();
        assert_eq!(loaded.status, installed.status);
    }

    #[test]
    fn local_gzip_install_is_bounded_and_offline() {
        let directory = TempDirectory::new();
        let country_path = directory.path.join("country.csv.gz");
        let asn_path = directory.path.join("asn.csv.gz");
        for (path, bytes) in [
            (country_path.as_path(), country_csv()),
            (asn_path.as_path(), asn_csv()),
        ] {
            let file = File::create(path).unwrap();
            let mut encoder = GzEncoder::new(file, Compression::default());
            encoder.write_all(bytes).unwrap();
            encoder.finish().unwrap();
        }
        let cache_root = directory.path.join("cache");
        let database = TagDatabase::new(&cache_root);
        let snapshot = database
            .install_local_gzip_files(release(), &country_path, &asn_path)
            .unwrap();
        assert!(matches!(snapshot.status, DatasetStatus::Ready(_)));
    }

    #[test]
    fn missing_database_is_explicitly_unavailable() {
        let directory = TempDirectory::new();
        let snapshot = TagDatabase::new(&directory.path).load_last_good();
        assert_eq!(
            snapshot.status,
            DatasetStatus::Unavailable {
                reason: DatasetUnavailableReason::NotInstalled
            }
        );
        assert_eq!(
            snapshot.cache().lookup("8.8.8.8".parse().unwrap()).status,
            DestinationTagStatus::Unavailable
        );
    }

    #[test]
    fn invalid_manifest_is_explicitly_unavailable_and_diagnosable() {
        let directory = TempDirectory::new();
        fs::create_dir_all(&directory.path).unwrap();
        fs::write(directory.path.join(MANIFEST_FILE_NAME), b"not-json").unwrap();
        let database = TagDatabase::new(&directory.path);
        assert_eq!(
            database.load_last_good().status,
            DatasetStatus::Unavailable {
                reason: DatasetUnavailableReason::CacheInvalid
            }
        );
        assert!(matches!(
            database.try_load_last_good(),
            Err(TagDatabaseError::ManifestInvalid(_))
        ));
    }

    #[test]
    #[ignore = "requires official DB-IP gzip artifacts in VAPOUR_DBIP_COUNTRY_GZ and VAPOUR_DBIP_ASN_GZ"]
    fn official_local_artifacts_load_and_report_counts_only() {
        let country = PathBuf::from(
            std::env::var_os("VAPOUR_DBIP_COUNTRY_GZ")
                .expect("VAPOUR_DBIP_COUNTRY_GZ must point to the downloaded country archive"),
        );
        let asn = PathBuf::from(
            std::env::var_os("VAPOUR_DBIP_ASN_GZ")
                .expect("VAPOUR_DBIP_ASN_GZ must point to the downloaded ASN archive"),
        );
        let directory = TempDirectory::new();
        let snapshot = TagDatabase::new(directory.path.join("cache"))
            .install_local_gzip_files(release(), &country, &asn)
            .expect("official local DB-IP artifacts should validate");
        let DatasetStatus::Ready(metadata) = snapshot.status else {
            panic!("official artifacts should be ready");
        };
        println!(
            "DB-IP local artifacts: country_ranges={}, asn_ranges={}",
            metadata.country_ranges, metadata.asn_ranges
        );
    }
}
