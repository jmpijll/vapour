//! Local, privacy-preserving destination country and organization tags.
//!
//! This module never sends an address to a network service.  It separates
//! deterministic address classification from an optional local data source.
//! The default source has no data and therefore returns `unavailable`; a
//! caller can inject a prefix table or load DB-IP Lite's locally supplied CSV
//! files.  This keeps the lookup useful without inventing country or owner
//! values from an address prefix or a hostname.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt,
    fs::File,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

pub const PREFIX_TABLE_SOURCE: &str = "offline_prefix_table";
pub const NO_LOCAL_DATA_SOURCE: &str = "no_local_data";
pub const DB_IP_LITE_SOURCE: &str = "db_ip_lite_offline_csv";
/// Attribution text required when DB-IP Lite data is displayed or used.
pub const DB_IP_LITE_ATTRIBUTION: &str = "IP Geolocation by DB-IP";
pub const DB_IP_LITE_ATTRIBUTION_URL: &str = "https://db-ip.com";

/// Hard bound for an injected offline prefix table.
pub const MAX_PREFIX_RECORDS: usize = 65_536;

/// Bounds each locally supplied DB-IP CSV before parsing it.  The current
/// Lite country and ASN downloads are below this limit, while a damaged or
/// unexpected file cannot allocate without bound.
pub const MAX_DB_IP_CSV_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_DB_IP_RANGE_RECORDS: usize = 1_000_000;

/// Default and hard maximum number of cached public-address results.
pub const DEFAULT_CACHE_ENTRIES: usize = 1_024;
pub const MAX_CACHE_ENTRIES: usize = 8_192;

/// Cache entries are observations of a changing external dataset.  A caller
/// may choose shorter TTLs, but cannot make a stale result live indefinitely.
pub const MAX_CACHE_TTL_SECONDS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum IpClassification {
    /// A globally usable unicast address eligible for a data-source lookup.
    Public,
    /// RFC 1918 IPv4 space or IPv6 unique-local space.
    Private,
    Loopback,
    LinkLocal,
    /// IPv4 shared address space (100.64.0.0/10).
    Shared,
    Multicast,
    Unspecified,
    /// Documentation-only ranges such as TEST-NET and 2001:db8::/32.
    Documentation,
    /// Other reserved or protocol-only ranges.
    Reserved,
}

impl IpClassification {
    pub fn is_public(self) -> bool {
        self == Self::Public
    }
}

/// Classify an address before consulting any external or injected data.
///
/// Only `Public` results are sent to a data source.  The special ranges are
/// intentionally conservative: they are returned without country or owner
/// tags even if a caller's table happens to contain a matching record.
pub fn classify_ip(ip: IpAddr) -> IpClassification {
    match ip {
        IpAddr::V4(ip) => classify_ipv4(ip),
        IpAddr::V6(ip) => classify_ipv6(ip),
    }
}

fn classify_ipv4(ip: Ipv4Addr) -> IpClassification {
    let octets = ip.octets();
    let first = octets[0];
    let second = octets[1];

    if ip.is_unspecified() {
        return IpClassification::Unspecified;
    }
    if ip.is_loopback() {
        return IpClassification::Loopback;
    }
    if ip.is_private() {
        return IpClassification::Private;
    }
    if ip.is_link_local() {
        return IpClassification::LinkLocal;
    }
    if ip.is_multicast() {
        return IpClassification::Multicast;
    }
    if ip.is_broadcast() {
        return IpClassification::Reserved;
    }
    if first == 100 && (64..=127).contains(&second) {
        return IpClassification::Shared;
    }
    if is_ipv4_documentation(ip) {
        return IpClassification::Documentation;
    }
    if is_ipv4_reserved(ip) {
        return IpClassification::Reserved;
    }

    IpClassification::Public
}

fn classify_ipv6(ip: Ipv6Addr) -> IpClassification {
    let segments = ip.segments();
    let first = segments[0];

    if ip.is_unspecified() {
        return IpClassification::Unspecified;
    }
    if ip.is_loopback() {
        return IpClassification::Loopback;
    }
    if ip.is_multicast() {
        return IpClassification::Multicast;
    }
    // fc00::/7, Unique Local Address space.
    if first & 0xfe00 == 0xfc00 {
        return IpClassification::Private;
    }
    // fe80::/10, link-local unicast space.
    if first & 0xffc0 == 0xfe80 {
        return IpClassification::LinkLocal;
    }
    if is_ipv6_documentation(ip) {
        return IpClassification::Documentation;
    }
    if is_ipv6_reserved(ip) {
        return IpClassification::Reserved;
    }

    IpClassification::Public
}

fn is_ipv4_documentation(ip: Ipv4Addr) -> bool {
    let value = u32::from_be_bytes(ip.octets());
    (0xc000_0200..=0xc000_02ff).contains(&value)
        || (0xc633_6400..=0xc633_64ff).contains(&value)
        || (0xcb00_7100..=0xcb00_71ff).contains(&value)
}

fn is_ipv4_reserved(ip: Ipv4Addr) -> bool {
    let value = u32::from_be_bytes(ip.octets());
    // 0.0.0.0/8 and 240.0.0.0/4 are protocol/reserved space.  The
    // specific broadcast address was handled above for readability.
    (value <= 0x00ff_ffff)
        || (value & 0xf000_0000 == 0xf000_0000)
        // IANA protocol-only 192.0.0.0/24.
        || (value & 0xffff_ff00 == 0xc000_0000)
        // 192.88.99.0/24, 6to4 relay anycast.
        || (value & 0xffff_ff00 == 0xc058_6300)
        // AS112 and AMT special-purpose service ranges.
        || (value & 0xffff_ff00 == 0xc01f_c400)
        || (value & 0xffff_ff00 == 0xc034_c100)
        || (value & 0xffff_ff00 == 0xc0af_3000)
        // 198.18.0.0/15, benchmark testing.
        || (value & 0xfffe_0000 == 0xc612_0000)
}

fn is_ipv6_documentation(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x3fff && segments[1] < 0x1000)
}

fn is_ipv6_reserved(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    // IPv4-compatible and IPv4-mapped forms are representation or
    // translation addresses rather than independent public endpoints.
    let ipv4_compatible = segments[..6].iter().all(|segment| *segment == 0);
    let ipv4_mapped = segments[..5].iter().all(|segment| *segment == 0) && segments[5] == 0xffff;
    let mapped_or_compatible = ipv4_compatible || ipv4_mapped;
    if mapped_or_compatible {
        return true;
    }

    // IANA special-purpose ranges: discard-only, protocol, benchmarking,
    // documentation, and service prefixes.  They are not useful country or
    // organization evidence even when a packet can technically be routed.
    (segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0)
        || (segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 1)
        || (segments[0] == 0x2001 && segments[1] == 0)
        || (segments[0] == 0x2001 && segments[1] == 1 && segments[2] == 0)
        || (segments[0] == 0x2001 && segments[1] == 2 && segments[2] == 0)
        || (segments[0] == 0x2001 && segments[1] == 3)
        || (segments[0] == 0x2001 && segments[1] == 4 && segments[2] == 0x0112)
        || (segments[0] == 0x2001 && (0x0010..=0x001f).contains(&segments[1]))
        || (segments[0] == 0x2001 && (0x0020..=0x002f).contains(&segments[1]))
        || (segments[0] == 0x2001 && (0x0030..=0x003f).contains(&segments[1]))
        || (segments[0] == 0x2620 && segments[1] == 0x004f && segments[2] == 0x8000)
        || (segments[0] == 0x3fff && segments[1] < 0x1000)
        || segments[0] == 0x5f00
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DestinationTags {
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub organization: Option<String>,
    pub asn: Option<u32>,
}

impl DestinationTags {
    /// Construct a validated, normalized tag record for an offline source.
    /// Empty fields are allowed individually, but at least one tag is
    /// required; an empty record cannot establish a known result.
    pub fn new(
        country_code: Option<String>,
        country_name: Option<String>,
        organization: Option<String>,
        asn: Option<u32>,
    ) -> Result<Self, TagValidationError> {
        normalize_tags(Self {
            country_code,
            country_name,
            organization,
            asn,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.country_code.is_none()
            && self.country_name.is_none()
            && self.organization.is_none()
            && self.asn.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagValidationError {
    EmptyTags,
    InvalidCountryCode,
    EmptyText { field: &'static str },
    TextTooLong { field: &'static str, maximum: usize },
    ControlCharacter { field: &'static str },
    InvalidAsn,
}

impl fmt::Display for TagValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTags => f.write_str("destination tag record is empty"),
            Self::InvalidCountryCode => {
                f.write_str("country code must contain exactly two ASCII letters")
            }
            Self::EmptyText { field } => write!(f, "destination {field} is empty"),
            Self::TextTooLong { field, maximum } => {
                write!(f, "destination {field} exceeds {maximum} bytes")
            }
            Self::ControlCharacter { field } => {
                write!(f, "destination {field} contains a control character")
            }
            Self::InvalidAsn => f.write_str("ASN must be nonzero"),
        }
    }
}

impl std::error::Error for TagValidationError {}

fn normalize_tags(tags: DestinationTags) -> Result<DestinationTags, TagValidationError> {
    let country_code = match tags.country_code {
        Some(value) => {
            let value = value.trim();
            if value.len() != 2 || !value.bytes().all(|byte| byte.is_ascii_alphabetic()) {
                return Err(TagValidationError::InvalidCountryCode);
            }
            Some(value.to_ascii_uppercase())
        }
        None => None,
    };
    let country_name = normalize_text(tags.country_name, "country_name", 128)?;
    let organization = normalize_text(tags.organization, "organization", 256)?;
    if matches!(tags.asn, Some(0)) {
        return Err(TagValidationError::InvalidAsn);
    }

    let normalized = DestinationTags {
        country_code,
        country_name,
        organization,
        asn: tags.asn,
    };
    if normalized.is_empty() {
        return Err(TagValidationError::EmptyTags);
    }
    Ok(normalized)
}

fn normalize_text(
    value: Option<String>,
    field: &'static str,
    maximum: usize,
) -> Result<Option<String>, TagValidationError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Err(TagValidationError::EmptyText { field });
    }
    if value.len() > maximum {
        return Err(TagValidationError::TextTooLong { field, maximum });
    }
    if value.chars().any(char::is_control) {
        return Err(TagValidationError::ControlCharacter { field });
    }
    Ok(Some(value.to_owned()))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct IpPrefix {
    pub network: IpAddr,
    pub prefix_len: u8,
}

impl IpPrefix {
    pub fn new(network: IpAddr, prefix_len: u8) -> Result<Self, PrefixError> {
        match network {
            IpAddr::V4(address) if prefix_len <= 32 => Ok(Self {
                network: IpAddr::V4(normalize_ipv4(address, prefix_len)),
                prefix_len,
            }),
            IpAddr::V6(address) if prefix_len <= 128 => Ok(Self {
                network: IpAddr::V6(normalize_ipv6(address, prefix_len)),
                prefix_len,
            }),
            IpAddr::V4(_) => Err(PrefixError::PrefixTooLong {
                length: prefix_len,
                maximum: 32,
            }),
            IpAddr::V6(_) => Err(PrefixError::PrefixTooLong {
                length: prefix_len,
                maximum: 128,
            }),
        }
    }

    pub fn parse(value: &str) -> Result<Self, PrefixError> {
        let value = value.trim();
        let (address, length) = value.split_once('/').ok_or(PrefixError::InvalidFormat)?;
        if address.is_empty() || length.is_empty() || length.contains('/') {
            return Err(PrefixError::InvalidFormat);
        }
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| PrefixError::InvalidAddress)?;
        let prefix_len = length
            .parse::<u8>()
            .map_err(|_| PrefixError::InvalidPrefixLength)?;
        Self::new(address, prefix_len)
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => mask_ipv4(ip, self.prefix_len) == network,
            (IpAddr::V6(network), IpAddr::V6(ip)) => mask_ipv6(ip, self.prefix_len) == network,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PrefixError {
    InvalidFormat,
    InvalidAddress,
    InvalidPrefixLength,
    PrefixTooLong { length: u8, maximum: u8 },
}

impl fmt::Display for PrefixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => f.write_str("prefix must use address/length notation"),
            Self::InvalidAddress => f.write_str("prefix contains an invalid IP address"),
            Self::InvalidPrefixLength => f.write_str("prefix length is not an unsigned integer"),
            Self::PrefixTooLong { length, maximum } => {
                write!(
                    f,
                    "prefix length {length} exceeds the {maximum}-bit address capacity"
                )
            }
        }
    }
}

impl std::error::Error for PrefixError {}

fn normalize_ipv4(address: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    mask_ipv4(address, prefix_len)
}

fn mask_ipv4(address: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let value = u32::from_be_bytes(address.octets());
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    Ipv4Addr::from(value & mask)
}

fn normalize_ipv6(address: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    mask_ipv6(address, prefix_len)
}

fn mask_ipv6(address: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    let value = u128::from_be_bytes(address.octets());
    let mask = if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    };
    Ipv6Addr::from(value & mask)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrefixRecord {
    pub prefix: IpPrefix,
    pub tags: DestinationTags,
}

#[derive(Debug, Clone)]
pub struct PrefixTable {
    records: Vec<PrefixRecord>,
    max_records: usize,
}

impl Default for PrefixTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PrefixTable {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            max_records: MAX_PREFIX_RECORDS,
        }
    }

    pub fn with_max_records(max_records: usize) -> Result<Self, PrefixTableError> {
        if max_records == 0 || max_records > MAX_PREFIX_RECORDS {
            return Err(PrefixTableError::InvalidCapacity {
                maximum: MAX_PREFIX_RECORDS,
            });
        }
        Ok(Self {
            records: Vec::new(),
            max_records,
        })
    }

    pub fn insert(
        &mut self,
        prefix: IpPrefix,
        tags: DestinationTags,
    ) -> Result<(), PrefixTableError> {
        let tags = normalize_tags(tags).map_err(PrefixTableError::InvalidTags)?;
        if let Some(record) = self
            .records
            .iter_mut()
            .find(|record| record.prefix == prefix)
        {
            record.tags = tags;
            return Ok(());
        }
        if self.records.len() >= self.max_records {
            return Err(PrefixTableError::CapacityExceeded {
                maximum: self.max_records,
            });
        }
        self.records.push(PrefixRecord { prefix, tags });
        Ok(())
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<DestinationTags> {
        self.records
            .iter()
            .filter(|record| record.prefix.contains(ip))
            .max_by_key(|record| record.prefix.prefix_len)
            .map(|record| record.tags.clone())
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrefixTableError {
    InvalidCapacity { maximum: usize },
    CapacityExceeded { maximum: usize },
    InvalidTags(TagValidationError),
}

impl fmt::Display for PrefixTableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCapacity { maximum } => {
                write!(f, "prefix table capacity must be between 1 and {maximum}")
            }
            Self::CapacityExceeded { maximum } => {
                write!(f, "prefix table capacity of {maximum} records was reached")
            }
            Self::InvalidTags(error) => write!(f, "invalid prefix table tags: {error}"),
        }
    }
}

impl std::error::Error for PrefixTableError {}

/// Offline DB-IP Lite source backed by the provider's uncompressed CSV
/// exports.  The country and ASN files are optional and are joined locally by
/// address; no address is sent to DB-IP or any other service.
#[derive(Debug, Clone, Default)]
pub struct DbIpLiteSource {
    country: IpRangeTable,
    asn: IpRangeTable,
    country_loaded: bool,
    asn_loaded: bool,
}

impl DbIpLiteSource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load one or both DB-IP Lite CSV files from memory.  `country_csv` uses
    /// the documented `ip_start,ip_end,country` columns.  `asn_csv` uses the
    /// documented `ip_start,ip_end,as_number,as_organization` columns.
    pub fn from_csv(
        country_csv: Option<&[u8]>,
        asn_csv: Option<&[u8]>,
    ) -> Result<Self, DataLoadError> {
        let country = match country_csv {
            Some(bytes) => parse_db_ip_country_csv(bytes)?,
            None => IpRangeTable::default(),
        };
        let asn = match asn_csv {
            Some(bytes) => parse_db_ip_asn_csv(bytes)?,
            None => IpRangeTable::default(),
        };
        Ok(Self {
            country,
            asn,
            country_loaded: country_csv.is_some(),
            asn_loaded: asn_csv.is_some(),
        })
    }

    pub fn from_country_csv(bytes: &[u8]) -> Result<Self, DataLoadError> {
        Self::from_csv(Some(bytes), None)
    }

    pub fn from_asn_csv(bytes: &[u8]) -> Result<Self, DataLoadError> {
        Self::from_csv(None, Some(bytes))
    }

    /// Load uncompressed local CSV files.  DB-IP's compressed downloads are
    /// deliberately rejected here because this crate does not carry a
    /// decompressor; callers can decompress a verified download before
    /// passing its bytes to `from_csv`.
    pub fn from_files(
        country_path: Option<&Path>,
        asn_path: Option<&Path>,
    ) -> Result<Self, DataLoadError> {
        let country = match country_path {
            Some(path) => Some(read_db_ip_file(path)?),
            None => None,
        };
        let asn = match asn_path {
            Some(path) => Some(read_db_ip_file(path)?),
            None => None,
        };
        Self::from_csv(country.as_deref(), asn.as_deref())
    }

    pub fn country_range_count(&self) -> usize {
        self.country.len()
    }

    pub fn asn_range_count(&self) -> usize {
        self.asn.len()
    }

    pub fn has_data(&self) -> bool {
        !self.country.is_empty() || !self.asn.is_empty()
    }

    /// Whether at least one local DB-IP file was successfully loaded.  This
    /// is separate from `has_data`: a valid file containing only DB-IP's
    /// `ZZ` unknown-country rows is available but has no usable country
    /// ranges.
    pub fn is_available(&self) -> bool {
        self.country_loaded || self.asn_loaded
    }
}

#[derive(Debug, Clone, Default)]
struct IpRangeTable {
    ipv4: Vec<IpRangeRecord>,
    ipv6: Vec<IpRangeRecord>,
}

#[derive(Debug, Clone)]
struct IpRangeRecord {
    start: u128,
    end: u128,
    tags: DestinationTags,
}

impl IpRangeTable {
    fn push(
        &mut self,
        start: IpAddr,
        end: IpAddr,
        tags: DestinationTags,
    ) -> Result<(), DataLoadError> {
        if self.len() >= MAX_DB_IP_RANGE_RECORDS {
            return Err(DataLoadError::TooManyRecords {
                maximum: MAX_DB_IP_RANGE_RECORDS,
            });
        }
        let (records, start, end) = match (start, end) {
            (IpAddr::V4(start), IpAddr::V4(end)) => (
                &mut self.ipv4,
                u32::from_be_bytes(start.octets()) as u128,
                u32::from_be_bytes(end.octets()) as u128,
            ),
            (IpAddr::V6(start), IpAddr::V6(end)) => (
                &mut self.ipv6,
                u128::from_be_bytes(start.octets()),
                u128::from_be_bytes(end.octets()),
            ),
            _ => return Err(DataLoadError::AddressFamilyMismatch),
        };
        if start > end {
            return Err(DataLoadError::InvalidRange);
        }
        records.push(IpRangeRecord { start, end, tags });
        Ok(())
    }

    fn finish(&mut self) -> Result<(), DataLoadError> {
        for records in [&mut self.ipv4, &mut self.ipv6] {
            records.sort_unstable_by_key(|record| (record.start, record.end));
            if records.windows(2).any(|pair| pair[1].start <= pair[0].end) {
                return Err(DataLoadError::OverlappingRanges);
            }
        }
        Ok(())
    }

    fn lookup(&self, ip: IpAddr) -> Option<&DestinationTags> {
        match ip {
            IpAddr::V4(ip) => lookup_range(&self.ipv4, u32::from_be_bytes(ip.octets()) as u128),
            IpAddr::V6(ip) => lookup_range(&self.ipv6, u128::from_be_bytes(ip.octets())),
        }
    }

    fn len(&self) -> usize {
        self.ipv4.len() + self.ipv6.len()
    }

    fn is_empty(&self) -> bool {
        self.ipv4.is_empty() && self.ipv6.is_empty()
    }
}

fn lookup_range<'a>(records: &'a [IpRangeRecord], value: u128) -> Option<&'a DestinationTags> {
    let index = records.partition_point(|record| record.start <= value);
    let record = records.get(index.checked_sub(1)?)?;
    (value <= record.end).then_some(&record.tags)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataLoadError {
    InputTooLarge {
        actual: usize,
        maximum: usize,
    },
    InvalidUtf8,
    LineTooLong {
        line: usize,
        maximum: usize,
    },
    CsvSyntax {
        line: usize,
    },
    MissingFields {
        line: usize,
        expected_at_least: usize,
        actual: usize,
    },
    UnexpectedFields {
        line: usize,
        expected: usize,
        actual: usize,
    },
    InvalidIp {
        line: usize,
        field: &'static str,
    },
    InvalidAsn {
        line: usize,
    },
    InvalidRange,
    AddressFamilyMismatch,
    OverlappingRanges,
    TooManyRecords {
        maximum: usize,
    },
    InvalidTags {
        line: usize,
        error: TagValidationError,
    },
    Io {
        kind: std::io::ErrorKind,
    },
    CompressedInputUnsupported,
}

impl fmt::Display for DataLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { actual, maximum } => {
                write!(f, "DB-IP CSV is {actual} bytes; maximum is {maximum}")
            }
            Self::InvalidUtf8 => f.write_str("DB-IP CSV is not UTF-8"),
            Self::LineTooLong { line, maximum } => {
                write!(f, "DB-IP CSV line {line} exceeds {maximum} bytes")
            }
            Self::CsvSyntax { line } => write!(f, "invalid CSV syntax on line {line}"),
            Self::MissingFields {
                line,
                expected_at_least,
                actual,
            } => write!(
                f,
                "DB-IP CSV line {line} has {actual} fields; at least {expected_at_least} are required"
            ),
            Self::UnexpectedFields {
                line,
                expected,
                actual,
            } => write!(
                f,
                "DB-IP CSV line {line} has {actual} fields; exactly {expected} are required"
            ),
            Self::InvalidIp { line, field } => {
                write!(f, "DB-IP CSV line {line} has an invalid {field} address")
            }
            Self::InvalidAsn { line } => write!(f, "DB-IP CSV line {line} has an invalid ASN"),
            Self::InvalidRange => f.write_str("DB-IP CSV contains an invalid address range"),
            Self::AddressFamilyMismatch => {
                f.write_str("DB-IP CSV range endpoints use different address families")
            }
            Self::OverlappingRanges => f.write_str("DB-IP CSV contains overlapping ranges"),
            Self::TooManyRecords { maximum } => {
                write!(f, "DB-IP CSV exceeds the {maximum}-record bound")
            }
            Self::InvalidTags { line, error } => {
                write!(f, "DB-IP CSV line {line} has invalid tags: {error}")
            }
            Self::Io { kind } => write!(f, "could not read DB-IP CSV: {kind:?}"),
            Self::CompressedInputUnsupported => {
                f.write_str("compressed DB-IP CSV is unsupported; pass decompressed bytes")
            }
        }
    }
}

impl std::error::Error for DataLoadError {}

const MAX_DB_IP_CSV_LINE_BYTES: usize = 4_096;

fn read_db_ip_file(path: &Path) -> Result<Vec<u8>, DataLoadError> {
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("gz"))
    {
        return Err(DataLoadError::CompressedInputUnsupported);
    }
    let file = File::open(path).map_err(|error| DataLoadError::Io { kind: error.kind() })?;
    if let Ok(length) = file.metadata().map(|metadata| metadata.len()) {
        if length > MAX_DB_IP_CSV_BYTES as u64 {
            return Err(DataLoadError::InputTooLarge {
                actual: usize::try_from(length).unwrap_or(usize::MAX),
                maximum: MAX_DB_IP_CSV_BYTES,
            });
        }
    }
    // Read one byte beyond the accepted size so a file that grows after an
    // optional metadata check is still rejected without an unbounded read.
    let mut bytes = Vec::new();
    file.take((MAX_DB_IP_CSV_BYTES as u64) + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| DataLoadError::Io { kind: error.kind() })?;
    if bytes.len() > MAX_DB_IP_CSV_BYTES {
        return Err(DataLoadError::InputTooLarge {
            actual: bytes.len(),
            maximum: MAX_DB_IP_CSV_BYTES,
        });
    }
    Ok(bytes)
}

fn parse_db_ip_country_csv(bytes: &[u8]) -> Result<IpRangeTable, DataLoadError> {
    let text = parse_db_ip_text(bytes)?;
    let mut table = IpRangeTable::default();
    for (line_index, line) in text.lines().enumerate() {
        let line_number = line_index + 1;
        if line.len() > MAX_DB_IP_CSV_LINE_BYTES {
            return Err(DataLoadError::LineTooLong {
                line: line_number,
                maximum: MAX_DB_IP_CSV_LINE_BYTES,
            });
        }
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let fields =
            parse_csv_record(line).map_err(|_| DataLoadError::CsvSyntax { line: line_number })?;
        if is_db_ip_header(&fields) {
            continue;
        }
        if fields.len() < 3 {
            return Err(DataLoadError::MissingFields {
                line: line_number,
                expected_at_least: 3,
                actual: fields.len(),
            });
        }
        if fields.len() > 3 {
            return Err(DataLoadError::UnexpectedFields {
                line: line_number,
                expected: 3,
                actual: fields.len(),
            });
        }
        let start = parse_csv_ip(&fields[0], line_number, "start")?;
        let end = parse_csv_ip(&fields[1], line_number, "end")?;
        // DB-IP uses the ISO-style `ZZ` code for an address with no country
        // assignment.  Retaining that row would turn an unknown result into
        // a misleading known country, so leave the range uncovered.
        if fields[2].trim().eq_ignore_ascii_case("ZZ") {
            continue;
        }
        let tags =
            DestinationTags::new(Some(fields[2].clone()), None, None, None).map_err(|error| {
                DataLoadError::InvalidTags {
                    line: line_number,
                    error,
                }
            })?;
        table.push(start, end, tags)?;
    }
    table.finish()?;
    Ok(table)
}

fn parse_db_ip_asn_csv(bytes: &[u8]) -> Result<IpRangeTable, DataLoadError> {
    let text = parse_db_ip_text(bytes)?;
    let mut table = IpRangeTable::default();
    for (line_index, line) in text.lines().enumerate() {
        let line_number = line_index + 1;
        if line.len() > MAX_DB_IP_CSV_LINE_BYTES {
            return Err(DataLoadError::LineTooLong {
                line: line_number,
                maximum: MAX_DB_IP_CSV_LINE_BYTES,
            });
        }
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let fields =
            parse_csv_record(line).map_err(|_| DataLoadError::CsvSyntax { line: line_number })?;
        if is_db_ip_header(&fields) {
            continue;
        }
        if fields.len() < 4 {
            return Err(DataLoadError::MissingFields {
                line: line_number,
                expected_at_least: 4,
                actual: fields.len(),
            });
        }
        if fields.len() > 4 {
            return Err(DataLoadError::UnexpectedFields {
                line: line_number,
                expected: 4,
                actual: fields.len(),
            });
        }
        let start = parse_csv_ip(&fields[0], line_number, "start")?;
        let end = parse_csv_ip(&fields[1], line_number, "end")?;
        let asn = if fields[2].trim().is_empty() {
            None
        } else {
            let value = fields[2]
                .trim()
                .parse::<u32>()
                .ok()
                .filter(|value| *value != 0)
                .ok_or(DataLoadError::InvalidAsn { line: line_number })?;
            Some(value)
        };
        let organization = if fields[3].trim().is_empty() {
            None
        } else {
            Some(fields[3].clone())
        };
        let tags = DestinationTags::new(None, None, organization, asn).map_err(|error| {
            DataLoadError::InvalidTags {
                line: line_number,
                error,
            }
        })?;
        table.push(start, end, tags)?;
    }
    table.finish()?;
    Ok(table)
}

fn parse_db_ip_text(bytes: &[u8]) -> Result<&str, DataLoadError> {
    if bytes.len() > MAX_DB_IP_CSV_BYTES {
        return Err(DataLoadError::InputTooLarge {
            actual: bytes.len(),
            maximum: MAX_DB_IP_CSV_BYTES,
        });
    }
    std::str::from_utf8(bytes).map_err(|_| DataLoadError::InvalidUtf8)
}

fn is_db_ip_header(fields: &[String]) -> bool {
    fields
        .first()
        .map(|value| value.trim_start_matches('\u{feff}').trim())
        .is_some_and(|value| value.eq_ignore_ascii_case("ip_start"))
}

fn parse_csv_ip(value: &str, line: usize, field: &'static str) -> Result<IpAddr, DataLoadError> {
    value
        .trim()
        .trim_start_matches('\u{feff}')
        .parse::<IpAddr>()
        .map_err(|_| DataLoadError::InvalidIp { line, field })
}

fn parse_csv_record(line: &str) -> Result<Vec<String>, ()> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut closed_quote = false;
    let mut characters = line.chars().peekable();
    while let Some(character) = characters.next() {
        if quoted {
            match character {
                '"' if characters.peek() == Some(&'"') => {
                    field.push('"');
                    characters.next();
                }
                '"' => {
                    quoted = false;
                    closed_quote = true;
                }
                _ => field.push(character),
            }
            continue;
        }
        if closed_quote {
            match character {
                ',' => {
                    fields.push(std::mem::take(&mut field));
                    closed_quote = false;
                }
                character if character.is_whitespace() => {}
                _ => return Err(()),
            }
            continue;
        }
        match character {
            ',' => fields.push(std::mem::take(&mut field)),
            '"' if field.trim().is_empty() => {
                field.clear();
                quoted = true;
            }
            '"' => return Err(()),
            _ => field.push(character),
        }
    }
    if quoted {
        return Err(());
    }
    fields.push(field);
    Ok(fields)
}

impl DestinationTagSource for DbIpLiteSource {
    fn source_name(&self) -> &'static str {
        DB_IP_LITE_SOURCE
    }

    fn lookup(&self, ip: IpAddr) -> SourceLookup {
        let country = self.country.lookup(ip);
        let asn = self.asn.lookup(ip);
        if country.is_none() && asn.is_none() {
            return if self.is_available() {
                SourceLookup::NotFound
            } else {
                SourceLookup::Unavailable
            };
        }

        let tags = DestinationTags::new(
            country.and_then(|value| value.country_code.clone()),
            country.and_then(|value| value.country_name.clone()),
            asn.and_then(|value| value.organization.clone()),
            asn.and_then(|value| value.asn),
        );
        match tags {
            Ok(tags) => SourceLookup::Found(tags),
            Err(_) => SourceLookup::NotFound,
        }
    }
}

/// Result supplied by a local data source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SourceLookup {
    Found(DestinationTags),
    NotFound,
    Unavailable,
}

/// A source must be local or otherwise privacy-reviewed by its caller.  The
/// trait intentionally receives one IP and returns data without prescribing a
/// file format, HTTP client, or update mechanism.
pub trait DestinationTagSource: Send + Sync {
    fn source_name(&self) -> &'static str;
    fn lookup(&self, ip: IpAddr) -> SourceLookup;
}

impl DestinationTagSource for PrefixTable {
    fn source_name(&self) -> &'static str {
        PREFIX_TABLE_SOURCE
    }

    fn lookup(&self, ip: IpAddr) -> SourceLookup {
        self.lookup(ip)
            .map(SourceLookup::Found)
            .unwrap_or(SourceLookup::NotFound)
    }
}

/// Default source used when no offline dataset has been installed.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoLocalDataSource;

impl DestinationTagSource for NoLocalDataSource {
    fn source_name(&self) -> &'static str {
        NO_LOCAL_DATA_SOURCE
    }

    fn lookup(&self, _ip: IpAddr) -> SourceLookup {
        SourceLookup::Unavailable
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DestinationTagStatus {
    Known,
    Unknown,
    Unavailable,
    Private,
    Special,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DestinationTagLookup {
    pub classification: IpClassification,
    pub status: DestinationTagStatus,
    pub tags: Option<DestinationTags>,
    pub source: Option<String>,
    pub cached: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheConfig {
    pub max_entries: usize,
    pub positive_ttl: Duration,
    pub negative_ttl: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_CACHE_ENTRIES,
            positive_ttl: Duration::from_secs(300),
            negative_ttl: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CacheConfigError {
    ZeroCapacity,
    CapacityTooLarge { maximum: usize },
    TtlTooLong { maximum_seconds: u64 },
}

impl fmt::Display for CacheConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroCapacity => f.write_str("destination tag cache capacity cannot be zero"),
            Self::CapacityTooLarge { maximum } => {
                write!(f, "destination tag cache capacity exceeds {maximum}")
            }
            Self::TtlTooLong { maximum_seconds } => {
                write!(
                    f,
                    "destination tag cache TTL exceeds {maximum_seconds} seconds"
                )
            }
        }
    }
}

impl std::error::Error for CacheConfigError {}

#[derive(Clone)]
struct CachedValue {
    status: DestinationTagStatus,
    tags: Option<DestinationTags>,
    source: Option<String>,
}

struct CacheEntry {
    value: CachedValue,
    expires_at: Instant,
}

pub struct DestinationTagCache {
    source: Arc<dyn DestinationTagSource>,
    entries: Mutex<HashMap<IpAddr, CacheEntry>>,
    config: CacheConfig,
}

impl fmt::Debug for DestinationTagCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DestinationTagCache")
            .field("source", &self.source.source_name())
            .field("entries", &self.entries.lock().len())
            .field("config", &self.config)
            .finish()
    }
}

impl Default for DestinationTagCache {
    fn default() -> Self {
        Self::new(Arc::new(NoLocalDataSource))
    }
}

impl DestinationTagCache {
    pub fn new(source: Arc<dyn DestinationTagSource>) -> Self {
        Self::with_config(source, CacheConfig::default())
            .expect("the default destination tag cache configuration is valid")
    }

    pub fn with_config(
        source: Arc<dyn DestinationTagSource>,
        config: CacheConfig,
    ) -> Result<Self, CacheConfigError> {
        validate_cache_config(config)?;
        Ok(Self {
            source,
            entries: Mutex::new(HashMap::new()),
            config,
        })
    }

    pub fn source_name(&self) -> &'static str {
        self.source.source_name()
    }

    pub fn lookup(&self, ip: IpAddr) -> DestinationTagLookup {
        let classification = classify_ip(ip);
        if !classification.is_public() {
            return DestinationTagLookup {
                classification,
                status: if classification == IpClassification::Private {
                    DestinationTagStatus::Private
                } else {
                    DestinationTagStatus::Special
                },
                tags: None,
                source: None,
                cached: false,
            };
        }

        let now = Instant::now();
        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.get(&ip) {
                if entry.expires_at > now {
                    return result_from_cached(classification, &entry.value, true);
                }
            }
            entries.remove(&ip);
        }

        let source_name = self.source.source_name().to_owned();
        let (status, tags) = match self.source.lookup(ip) {
            SourceLookup::Found(tags) => match normalize_tags(tags) {
                Ok(tags) => (DestinationTagStatus::Known, Some(tags)),
                Err(_) => (DestinationTagStatus::Unknown, None),
            },
            SourceLookup::NotFound => (DestinationTagStatus::Unknown, None),
            SourceLookup::Unavailable => (DestinationTagStatus::Unavailable, None),
        };
        let value = CachedValue {
            status,
            tags,
            source: Some(source_name),
        };
        let ttl = if status == DestinationTagStatus::Known {
            self.config.positive_ttl
        } else {
            self.config.negative_ttl
        };
        let result = result_from_cached(classification, &value, false);

        let mut entries = self.entries.lock();
        if entries.len() >= self.config.max_entries && !entries.contains_key(&ip) {
            let oldest = entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(cached_ip, _)| *cached_ip);
            if let Some(oldest) = oldest {
                entries.remove(&oldest);
            }
        }
        entries.insert(
            ip,
            CacheEntry {
                value,
                expires_at: now + ttl,
            },
        );
        result
    }

    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        self.entries.lock().clear();
    }
}

fn validate_cache_config(config: CacheConfig) -> Result<(), CacheConfigError> {
    if config.max_entries == 0 {
        return Err(CacheConfigError::ZeroCapacity);
    }
    if config.max_entries > MAX_CACHE_ENTRIES {
        return Err(CacheConfigError::CapacityTooLarge {
            maximum: MAX_CACHE_ENTRIES,
        });
    }
    let maximum_ttl = Duration::from_secs(MAX_CACHE_TTL_SECONDS);
    if config.positive_ttl > maximum_ttl || config.negative_ttl > maximum_ttl {
        return Err(CacheConfigError::TtlTooLong {
            maximum_seconds: MAX_CACHE_TTL_SECONDS,
        });
    }
    Ok(())
}

fn result_from_cached(
    classification: IpClassification,
    value: &CachedValue,
    cached: bool,
) -> DestinationTagLookup {
    DestinationTagLookup {
        classification,
        status: value.status,
        tags: value.tags.clone(),
        source: value.source.clone(),
        cached,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("valid fixture IP")
    }

    fn tags(country: &str, organization: &str, asn: u32) -> DestinationTags {
        DestinationTags::new(
            Some(country.into()),
            None,
            Some(organization.into()),
            Some(asn),
        )
        .expect("valid fixture tags")
    }

    #[derive(Default)]
    struct CountingUnknownSource {
        calls: AtomicUsize,
    }

    impl DestinationTagSource for CountingUnknownSource {
        fn source_name(&self) -> &'static str {
            "counting_unknown"
        }

        fn lookup(&self, _ip: IpAddr) -> SourceLookup {
            self.calls.fetch_add(1, Ordering::Relaxed);
            SourceLookup::NotFound
        }
    }

    #[test]
    fn classifies_private_and_special_addresses_without_source_calls() {
        let source = Arc::new(CountingUnknownSource::default());
        let cache = DestinationTagCache::new(source.clone());

        let private = cache.lookup(ip("192.168.1.10"));
        assert_eq!(private.classification, IpClassification::Private);
        assert_eq!(private.status, DestinationTagStatus::Private);
        assert!(private.tags.is_none());

        let special = cache.lookup(ip("127.0.0.1"));
        assert_eq!(special.classification, IpClassification::Loopback);
        assert_eq!(special.status, DestinationTagStatus::Special);
        assert_eq!(source.calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn classifies_iana_service_and_documentation_ranges_as_special() {
        let source = Arc::new(CountingUnknownSource::default());
        let cache = DestinationTagCache::new(source.clone());

        for (value, classification) in [
            ("192.31.196.1", IpClassification::Reserved),
            ("192.52.193.1", IpClassification::Reserved),
            ("198.19.255.255", IpClassification::Reserved),
            ("2001:0:1::1", IpClassification::Reserved),
            ("2001:3::1", IpClassification::Reserved),
            ("3fff::1", IpClassification::Documentation),
            ("5f00::1", IpClassification::Reserved),
        ] {
            let result = cache.lookup(ip(value));
            assert_eq!(result.classification, classification, "{value}");
            assert_eq!(result.status, DestinationTagStatus::Special, "{value}");
            assert!(result.tags.is_none(), "{value}");
        }
        assert_eq!(
            cache.lookup(ip("2001:4860::1")).classification,
            IpClassification::Public
        );
        assert_eq!(source.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn unknown_public_result_is_cached_and_has_no_fabricated_tags() {
        let source = Arc::new(CountingUnknownSource::default());
        let cache = DestinationTagCache::new(source.clone());

        let first = cache.lookup(ip("8.8.8.8"));
        assert_eq!(first.classification, IpClassification::Public);
        assert_eq!(first.status, DestinationTagStatus::Unknown);
        assert!(first.tags.is_none());
        assert!(!first.cached);

        let second = cache.lookup(ip("8.8.8.8"));
        assert!(second.cached);
        assert_eq!(source.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn ipv6_prefix_lookup_returns_only_loaded_tags() {
        let mut table = PrefixTable::new();
        table
            .insert(
                IpPrefix::parse("2001:4860::/32").unwrap(),
                tags("US", "Google", 15169),
            )
            .unwrap();
        let cache = DestinationTagCache::new(Arc::new(table));

        let result = cache.lookup(ip("2001:4860:4860::8888"));
        assert_eq!(result.classification, IpClassification::Public);
        assert_eq!(result.status, DestinationTagStatus::Known);
        assert_eq!(
            result.tags.as_ref().and_then(|value| value.asn),
            Some(15169)
        );
        assert_eq!(
            result.tags.as_ref().unwrap().country_code.as_deref(),
            Some("US")
        );

        let documentation = cache.lookup(ip("2001:db8::1"));
        assert_eq!(
            documentation.classification,
            IpClassification::Documentation
        );
        assert_eq!(documentation.status, DestinationTagStatus::Special);
        assert!(documentation.tags.is_none());
    }

    #[test]
    fn prefix_table_uses_longest_matching_prefix_and_normalizes_network() {
        let mut table = PrefixTable::new();
        table
            .insert(
                IpPrefix::parse("0.0.0.0/0").unwrap(),
                tags("US", "default", 64500),
            )
            .unwrap();
        table
            .insert(
                IpPrefix::parse("8.8.8.200/24").unwrap(),
                tags("US", "Google", 15169),
            )
            .unwrap();
        assert_eq!(table.len(), 2);
        assert_eq!(table.lookup(ip("8.8.8.8")).unwrap().asn, Some(15169));
        assert_eq!(table.lookup(ip("9.9.9.9")).unwrap().asn, Some(64500));
        assert_eq!(
            IpPrefix::parse("8.8.8.200/24").unwrap().network,
            ip("8.8.8.0")
        );
    }

    #[test]
    fn cache_is_bounded_and_expiring_results_are_requeried() {
        let source = Arc::new(CountingUnknownSource::default());
        let config = CacheConfig {
            max_entries: 8,
            positive_ttl: Duration::from_secs(60),
            negative_ttl: Duration::ZERO,
        };
        let cache = DestinationTagCache::with_config(source.clone(), config).unwrap();

        for value in 0..256u32 {
            cache.lookup(IpAddr::V4(Ipv4Addr::from(0x0b00_0000 | value)));
        }
        assert!(cache.len() <= 8);
        let calls_after_fill = source.calls.load(Ordering::Relaxed);
        assert!(calls_after_fill >= 8);

        cache.lookup(ip("8.8.8.8"));
        cache.lookup(ip("8.8.8.8"));
        assert!(source.calls.load(Ordering::Relaxed) >= calls_after_fill + 2);
    }

    #[test]
    fn rejects_invalid_prefixes_and_untrusted_tags() {
        assert_eq!(
            IpPrefix::parse("8.8.8.8").unwrap_err(),
            PrefixError::InvalidFormat
        );
        assert!(matches!(
            IpPrefix::parse("8.8.8.8/33"),
            Err(PrefixError::PrefixTooLong { .. })
        ));
        assert!(matches!(
            DestinationTags::new(None, None, None, None),
            Err(TagValidationError::EmptyTags)
        ));
        assert!(matches!(
            DestinationTags::new(Some("USA".into()), None, None, None),
            Err(TagValidationError::InvalidCountryCode)
        ));
        assert!(matches!(
            DestinationTagCache::with_config(
                Arc::new(NoLocalDataSource),
                CacheConfig {
                    max_entries: 1,
                    positive_ttl: Duration::from_secs(MAX_CACHE_TTL_SECONDS)
                        + Duration::from_nanos(1),
                    negative_ttl: Duration::ZERO,
                }
            ),
            Err(CacheConfigError::TtlTooLong { .. })
        ));
    }

    #[test]
    fn invalid_or_unavailable_source_data_never_becomes_known() {
        #[derive(Default)]
        struct InvalidSource;

        impl DestinationTagSource for InvalidSource {
            fn source_name(&self) -> &'static str {
                "invalid_fixture"
            }

            fn lookup(&self, _ip: IpAddr) -> SourceLookup {
                SourceLookup::Found(DestinationTags {
                    country_code: Some("USA".into()),
                    country_name: None,
                    organization: None,
                    asn: None,
                })
            }
        }

        let cache = DestinationTagCache::new(Arc::new(InvalidSource));
        let result = cache.lookup(ip("8.8.8.8"));
        assert_eq!(result.status, DestinationTagStatus::Unknown);
        assert!(result.tags.is_none());
    }

    #[test]
    fn db_ip_lite_csv_lookup_joins_country_and_asn_offline() {
        let country = br#"ip_start,ip_end,country
1.1.1.0,1.1.1.255,AU
2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US
"#;
        let asn = br#"ip_start,ip_end,as_number,as_organization
1.1.1.0,1.1.1.255,13335,"Cloudflare, Inc."
2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,15169,Google
"#;
        let source = DbIpLiteSource::from_csv(Some(country), Some(asn)).unwrap();
        assert_eq!(source.country_range_count(), 2);
        assert_eq!(source.asn_range_count(), 2);

        let cache = DestinationTagCache::new(Arc::new(source));
        let ipv4 = cache.lookup(ip("1.1.1.1"));
        assert_eq!(ipv4.status, DestinationTagStatus::Known);
        assert_eq!(
            ipv4.tags.as_ref().unwrap().country_code.as_deref(),
            Some("AU")
        );
        assert_eq!(
            ipv4.tags.as_ref().unwrap().organization.as_deref(),
            Some("Cloudflare, Inc.")
        );
        assert_eq!(ipv4.tags.as_ref().unwrap().asn, Some(13335));

        let ipv6 = cache.lookup(ip("2001:4860:4860::8888"));
        assert_eq!(ipv6.status, DestinationTagStatus::Known);
        assert_eq!(
            ipv6.tags.as_ref().unwrap().country_code.as_deref(),
            Some("US")
        );
        assert_eq!(ipv6.tags.as_ref().unwrap().asn, Some(15169));
    }

    #[test]
    fn db_ip_lite_country_only_and_unknown_ranges_are_explicit() {
        let source =
            DbIpLiteSource::from_country_csv(
                b"\xEF\xBB\xBFip_start,ip_end,country\n10.10.0.0,10.10.0.255,US\n8.8.8.0,8.8.8.255,US\n",
            )
                .unwrap();
        let cache = DestinationTagCache::new(Arc::new(source));

        let private = cache.lookup(ip("10.10.0.1"));
        assert_eq!(private.status, DestinationTagStatus::Private);
        assert!(private.tags.is_none());

        let known = cache.lookup(ip("8.8.8.8"));
        assert_eq!(known.status, DestinationTagStatus::Known);
        assert_eq!(known.tags.unwrap().country_code.as_deref(), Some("US"));

        let unknown = cache.lookup(ip("9.9.9.9"));
        assert_eq!(unknown.status, DestinationTagStatus::Unknown);
        assert!(unknown.tags.is_none());
    }

    #[test]
    fn db_ip_unknown_country_rows_do_not_become_known() {
        let source = DbIpLiteSource::from_country_csv(b"1.1.1.0,1.1.1.255,ZZ\n").unwrap();
        assert!(source.is_available());
        assert!(!source.has_data());
        let result = DestinationTagCache::new(Arc::new(source)).lookup(ip("1.1.1.1"));
        assert_eq!(result.status, DestinationTagStatus::Unknown);
        assert!(result.tags.is_none());
    }

    #[test]
    fn db_ip_lite_loader_rejects_overlap_and_malformed_rows() {
        let overlap = b"1.1.1.0,1.1.1.10,US\n1.1.1.10,1.1.1.20,AU\n";
        assert_eq!(
            DbIpLiteSource::from_country_csv(overlap).unwrap_err(),
            DataLoadError::OverlappingRanges
        );
        let malformed = b"1.1.1.0,1.1.1.255\n";
        assert!(matches!(
            DbIpLiteSource::from_country_csv(malformed),
            Err(DataLoadError::MissingFields { .. })
        ));
        assert_eq!(
            DbIpLiteSource::from_files(Some(Path::new("fixture.csv.gz")), None).unwrap_err(),
            DataLoadError::CompressedInputUnsupported
        );
    }
}
