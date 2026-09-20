//! Privacy-friendly Windows Wi-Fi connection quality collection.
//!
//! This module deliberately uses only `wlan_intf_opcode_realtime_connection_quality`.
//! It does not query SSID/BSSID, enumerate nearby networks, or use the
//! location-sensitive legacy connection/BSS APIs. The realtime opcode was
//! added to the Windows SDK after the `windows` 0.58 bindings, so the narrow
//! ABI declarations below mirror the Windows SDK 10.0.26100.0 `wlanapi.h`
//! definitions instead of depending on generated bindings that are not
//! present in this crate version.

use serde::{Deserialize, Serialize};
use std::fmt;

pub const SOURCE: &str = "windows_wlan_realtime_connection_quality";

/// The realtime API's documentation calls these fields rates but does not
/// state their unit. The older `WLAN_ASSOCIATION_ATTRIBUTES` documentation
/// says Kbits/second, but applying that statement to this newer structure
/// would be an inference. Keep the raw values and expose this uncertainty to
/// callers rather than converting them to throughput or link speed.
pub const REALTIME_RATE_UNIT: &str = "unspecified_by_microsoft";

/// Microsoft documents `ulChannelCenterFrequencyMhz` as kHz despite the
/// historical `Mhz` suffix in the SDK field name.
pub const CENTER_FREQUENCY_UNIT: &str = "kHz";

/// Microsoft documents realtime link RSSI in dBm.
pub const RSSI_UNIT: &str = "dBm";

/// Microsoft does not specify a unit for `ulBandwidth` in the realtime link
/// structure, so it is preserved as a raw value.
pub const BANDWIDTH_UNIT: &str = "unspecified_by_microsoft";

const REALTIME_CONNECTION_QUALITY_OPCODE: i32 = 19;
const WLAN_RATE_SET_MAX_LENGTH: usize = 126;
const MAX_LINKS: usize = 256;
const MAX_INTERFACES: usize = 256;
const MAX_PAYLOAD_SIZE: usize = 8 * 1024 * 1024;

// These private declarations mirror the C ABI in the Windows SDK. They are
// also used for the parser offsets, which keeps the variable-tail arithmetic
// tied to the ABI rather than to hand-written magic numbers.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawGuid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawWlanRateSet {
    rate_set_length: u32,
    rates: [u16; WLAN_RATE_SET_MAX_LENGTH],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawWlanRealtimeConnectionQualityLinkInfo {
    link_id: u8,
    channel_center_frequency_mhz: u32,
    bandwidth: u32,
    rssi: i32,
    rate_set: RawWlanRateSet,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawWlanRealtimeConnectionQuality {
    phy_type: u32,
    link_quality: u32,
    rx_rate: u32,
    tx_rate: u32,
    is_mlo_connection: i32,
    number_of_links: u32,
    links: [RawWlanRealtimeConnectionQualityLinkInfo; 1],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawWlanInterfaceInfo {
    interface_guid: RawGuid,
    // The description is intentionally never read. Keeping the field in the
    // ABI mirror lets us step through the returned fixed-size records without
    // collecting or exposing an interface name.
    interface_description: [u16; 256],
    state: i32,
}

#[repr(C)]
struct RawWlanInterfaceInfoList {
    number_of_items: u32,
    index: u32,
    interface_info: [RawWlanInterfaceInfo; 1],
}

const QUALITY_HEADER_SIZE: usize = std::mem::size_of::<RawWlanRealtimeConnectionQuality>()
    - std::mem::size_of::<RawWlanRealtimeConnectionQualityLinkInfo>();
const QUALITY_LINK_SIZE: usize = std::mem::size_of::<RawWlanRealtimeConnectionQualityLinkInfo>();
const RATE_SET_LENGTH_OFFSET: usize =
    std::mem::size_of::<RawWlanRealtimeConnectionQualityLinkInfo>()
        - std::mem::size_of::<RawWlanRateSet>();

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WifiQualityCollectionStatus {
    Measured,
    Partial,
    Unsupported,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WifiQualityStatus {
    Measured,
    Disconnected,
    Unsupported,
    PermissionDenied,
    QueryFailed,
    InvalidPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WifiQualitySnapshot {
    pub source: String,
    pub sampled_at_unix_ms: u64,
    pub status: WifiQualityCollectionStatus,
    pub interfaces: Vec<WifiQualityInterface>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WifiQualityInterface {
    /// A local interface identifier. It is returned so callers can join the
    /// sample with their own adapter table; it is never logged by this module.
    pub interface_guid: String,
    pub interface_state: String,
    pub interface_state_code: i32,
    pub status: WifiQualityStatus,
    pub error_code: Option<u32>,
    pub error_message: Option<String>,
    pub link_quality_percent: Option<u32>,
    pub rx_rate_raw: Option<u32>,
    pub tx_rate_raw: Option<u32>,
    /// Always `unspecified_by_microsoft` for successful realtime samples.
    pub rate_unit: Option<String>,
    pub phy_type_code: Option<u32>,
    pub phy_type: Option<String>,
    pub is_mlo_connection: Option<bool>,
    pub links: Vec<WifiQualityLink>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WifiQualityLink {
    pub link_id: u8,
    pub center_frequency_khz: u32,
    pub bandwidth_raw: u32,
    /// Always `unspecified_by_microsoft`; no unit conversion is attempted.
    pub bandwidth_unit: String,
    pub rssi_dbm: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PayloadError {
    TooLarge { actual: usize, maximum: usize },
    TooShort { expected: usize, actual: usize },
    TooManyLinks(u32),
    LinkTailTruncated { declared: u32, available: usize },
    InvalidQuality(u32),
    InvalidRateSetLength { link_index: usize, length: u32 },
    ArithmeticOverflow,
}

impl fmt::Display for PayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { actual, maximum } => {
                write!(
                    f,
                    "realtime payload is {actual} bytes; maximum is {maximum}"
                )
            }
            Self::TooShort { expected, actual } => {
                write!(
                    f,
                    "realtime payload is {actual} bytes; at least {expected} are required"
                )
            }
            Self::TooManyLinks(count) => {
                write!(f, "realtime payload declares too many links: {count}")
            }
            Self::LinkTailTruncated {
                declared,
                available,
            } => write!(
                f,
                "realtime payload declares {declared} links but contains {available} complete links"
            ),
            Self::InvalidQuality(value) => {
                write!(f, "realtime link quality is outside 0..=100: {value}")
            }
            Self::InvalidRateSetLength { link_index, length } => write!(
                f,
                "realtime link {link_index} declares an invalid rate-set length: {length}"
            ),
            Self::ArithmeticOverflow => f.write_str("realtime payload size arithmetic overflowed"),
        }
    }
}

impl std::error::Error for PayloadError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WifiQualityError {
    UnsupportedPlatform,
    Unsupported { operation: String, error_code: u32 },
    Api { operation: String, error_code: u32 },
    InvalidInterfaceList { count: u32 },
}

impl fmt::Display for WifiQualityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                f.write_str("Windows Wi-Fi quality collection is unsupported on this platform")
            }
            Self::Unsupported {
                operation,
                error_code,
            } => {
                write!(
                    f,
                    "{operation} does not support the realtime quality opcode (error {error_code})"
                )
            }
            Self::Api {
                operation,
                error_code,
            } => write!(f, "{operation} failed with Windows error {error_code}"),
            Self::InvalidInterfaceList { count } => {
                write!(
                    f,
                    "WlanEnumInterfaces returned too many interfaces: {count}"
                )
            }
        }
    }
}

impl std::error::Error for WifiQualityError {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedQuality {
    phy_type_code: u32,
    link_quality_percent: u32,
    rx_rate_raw: u32,
    tx_rate_raw: u32,
    is_mlo_connection: bool,
    links: Vec<ParsedLink>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedLink {
    link_id: u8,
    center_frequency_khz: u32,
    bandwidth_raw: u32,
    rssi_dbm: i32,
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, PayloadError> {
    let end = offset
        .checked_add(4)
        .ok_or(PayloadError::ArithmeticOverflow)?;
    let value: [u8; 4] = bytes
        .get(offset..end)
        .ok_or(PayloadError::TooShort {
            expected: end,
            actual: bytes.len(),
        })?
        .try_into()
        .map_err(|_| PayloadError::TooShort {
            expected: end,
            actual: bytes.len(),
        })?;
    Ok(u32::from_le_bytes(value))
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32, PayloadError> {
    let end = offset
        .checked_add(4)
        .ok_or(PayloadError::ArithmeticOverflow)?;
    let value: [u8; 4] = bytes
        .get(offset..end)
        .ok_or(PayloadError::TooShort {
            expected: end,
            actual: bytes.len(),
        })?
        .try_into()
        .map_err(|_| PayloadError::TooShort {
            expected: end,
            actual: bytes.len(),
        })?;
    Ok(i32::from_le_bytes(value))
}

fn parse_quality_payload(bytes: &[u8]) -> Result<ParsedQuality, PayloadError> {
    if bytes.len() > MAX_PAYLOAD_SIZE {
        return Err(PayloadError::TooLarge {
            actual: bytes.len(),
            maximum: MAX_PAYLOAD_SIZE,
        });
    }
    if bytes.len() < QUALITY_HEADER_SIZE {
        return Err(PayloadError::TooShort {
            expected: QUALITY_HEADER_SIZE,
            actual: bytes.len(),
        });
    }

    let phy_type_code = read_u32(bytes, 0)?;
    let link_quality_percent = read_u32(bytes, 4)?;
    if link_quality_percent > 100 {
        return Err(PayloadError::InvalidQuality(link_quality_percent));
    }
    let rx_rate_raw = read_u32(bytes, 8)?;
    let tx_rate_raw = read_u32(bytes, 12)?;
    let is_mlo_connection = read_i32(bytes, 16)? != 0;
    let declared_links = read_u32(bytes, 20)?;
    if declared_links > MAX_LINKS as u32 {
        return Err(PayloadError::TooManyLinks(declared_links));
    }
    let link_count = declared_links as usize;
    let available_links = (bytes.len() - QUALITY_HEADER_SIZE) / QUALITY_LINK_SIZE;
    if link_count > available_links {
        return Err(PayloadError::LinkTailTruncated {
            declared: declared_links,
            available: available_links,
        });
    }

    // The count cap above makes this multiplication bounded, but retain the
    // checked arithmetic so the parser remains safe if the cap changes.
    let required_size = QUALITY_HEADER_SIZE
        .checked_add(
            link_count
                .checked_mul(QUALITY_LINK_SIZE)
                .ok_or(PayloadError::ArithmeticOverflow)?,
        )
        .ok_or(PayloadError::ArithmeticOverflow)?;
    if bytes.len() < required_size {
        return Err(PayloadError::LinkTailTruncated {
            declared: declared_links,
            available: available_links,
        });
    }

    let mut links = Vec::with_capacity(link_count);
    for index in 0..link_count {
        let offset = QUALITY_HEADER_SIZE + index * QUALITY_LINK_SIZE;
        let rate_set_length = read_u32(bytes, offset + RATE_SET_LENGTH_OFFSET)?;
        if rate_set_length > WLAN_RATE_SET_MAX_LENGTH as u32 {
            return Err(PayloadError::InvalidRateSetLength {
                link_index: index,
                length: rate_set_length,
            });
        }
        links.push(ParsedLink {
            link_id: bytes[offset],
            center_frequency_khz: read_u32(bytes, offset + 4)?,
            bandwidth_raw: read_u32(bytes, offset + 8)?,
            rssi_dbm: read_i32(bytes, offset + 12)?,
        });
    }

    Ok(ParsedQuality {
        phy_type_code,
        link_quality_percent,
        rx_rate_raw,
        tx_rate_raw,
        is_mlo_connection,
        links,
    })
}

fn phy_type_name(code: u32) -> String {
    match code {
        0 => "unknown".into(),
        1 => "fhss".into(),
        2 => "dsss".into(),
        3 => "irbaseband".into(),
        4 => "ofdm".into(),
        5 => "hrdsss".into(),
        6 => "erp".into(),
        7 => "ht".into(),
        8 => "vht".into(),
        9 => "dmg".into(),
        10 => "he".into(),
        11 => "eht".into(),
        value if value >= 0x8000_0000 => format!("ihv({value:#010x})"),
        value => format!("unknown({value})"),
    }
}

fn interface_state_name(code: i32) -> String {
    match code {
        0 => "not_ready".into(),
        1 => "connected".into(),
        2 => "ad_hoc_network_formed".into(),
        3 => "disconnecting".into(),
        4 => "disconnected".into(),
        5 => "associating".into(),
        6 => "discovering".into(),
        7 => "authenticating".into(),
        value => format!("unknown({value})"),
    }
}

fn aggregate_status(interfaces: &[WifiQualityInterface]) -> WifiQualityCollectionStatus {
    if interfaces.is_empty() {
        return WifiQualityCollectionStatus::Unavailable;
    }
    let measured = interfaces
        .iter()
        .filter(|item| item.status == WifiQualityStatus::Measured)
        .count();
    if measured == interfaces.len() {
        WifiQualityCollectionStatus::Measured
    } else if measured > 0 {
        WifiQualityCollectionStatus::Partial
    } else if interfaces
        .iter()
        .all(|item| item.status == WifiQualityStatus::Unsupported)
    {
        WifiQualityCollectionStatus::Unsupported
    } else {
        WifiQualityCollectionStatus::Unavailable
    }
}

fn unix_timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .unwrap_or(u64::MAX)
}

fn is_unsupported_error(error: u32) -> bool {
    // ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED,
    // ERROR_CALL_NOT_IMPLEMENTED, and ERROR_REVISION_MISMATCH.
    matches!(error, 1 | 50 | 120 | 1306)
}

fn api_error(operation: &str, error_code: u32) -> WifiQualityError {
    if is_unsupported_error(error_code) {
        WifiQualityError::Unsupported {
            operation: operation.into(),
            error_code,
        }
    } else {
        WifiQualityError::Api {
            operation: operation.into(),
            error_code,
        }
    }
}

fn query_status(error_code: u32) -> WifiQualityStatus {
    match error_code {
        1 | 50 | 120 | 1306 => WifiQualityStatus::Unsupported,
        5 | 1314 => WifiQualityStatus::PermissionDenied,
        5023 => WifiQualityStatus::Disconnected,
        _ => WifiQualityStatus::QueryFailed,
    }
}

fn query_error_message(error_code: u32) -> String {
    match error_code {
        1 | 50 | 120 | 1306 => {
            "realtime connection quality is unsupported by this Windows/driver combination".into()
        }
        5 | 1314 => "Windows denied access to the WLAN quality query".into(),
        5023 => "the interface is no longer connected".into(),
        _ => format!("WlanQueryInterface returned Windows error {error_code}"),
    }
}

#[cfg(windows)]
mod windows_backend {
    use super::*;
    use std::ffi::c_void;
    use std::ptr;

    #[link(name = "wlanapi")]
    unsafe extern "system" {
        fn WlanOpenHandle(
            client_version: u32,
            reserved: *mut c_void,
            negotiated_version: *mut u32,
            client_handle: *mut *mut c_void,
        ) -> u32;
        fn WlanCloseHandle(client_handle: *mut c_void, reserved: *mut c_void) -> u32;
        fn WlanEnumInterfaces(
            client_handle: *mut c_void,
            reserved: *mut c_void,
            interface_list: *mut *mut RawWlanInterfaceInfoList,
        ) -> u32;
        fn WlanQueryInterface(
            client_handle: *mut c_void,
            interface_guid: *const RawGuid,
            opcode: i32,
            reserved: *mut c_void,
            data_size: *mut u32,
            data: *mut *mut c_void,
            opcode_value_type: *mut i32,
        ) -> u32;
        fn WlanFreeMemory(memory: *mut c_void);
    }

    struct WlanClient {
        handle: *mut c_void,
    }

    impl WlanClient {
        fn open() -> Result<Self, WifiQualityError> {
            let mut handle = ptr::null_mut();
            let mut negotiated_version = 0;
            let error =
                unsafe { WlanOpenHandle(2, ptr::null_mut(), &mut negotiated_version, &mut handle) };
            if error != 0 {
                return Err(api_error("WlanOpenHandle", error));
            }
            if handle.is_null() {
                return Err(WifiQualityError::Api {
                    operation: "WlanOpenHandle".into(),
                    error_code: 0,
                });
            }
            // The negotiated version is intentionally not used as an OS
            // feature gate. The opcode query below is the runtime capability
            // check, as different Windows/driver combinations can vary.
            let _ = negotiated_version;
            Ok(Self { handle })
        }
    }

    impl Drop for WlanClient {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                let _ = unsafe { WlanCloseHandle(self.handle, ptr::null_mut()) };
                self.handle = ptr::null_mut();
            }
        }
    }

    struct WlanMemory(*mut c_void);

    impl WlanMemory {
        fn new(pointer: *mut c_void) -> Self {
            Self(pointer)
        }
    }

    impl Drop for WlanMemory {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { WlanFreeMemory(self.0) };
                self.0 = ptr::null_mut();
            }
        }
    }

    fn guid_string(guid: &RawGuid) -> String {
        format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            guid.data1,
            guid.data2,
            guid.data3,
            guid.data4[0],
            guid.data4[1],
            guid.data4[2],
            guid.data4[3],
            guid.data4[4],
            guid.data4[5],
            guid.data4[6],
            guid.data4[7],
        )
    }

    fn query_quality(
        client: &WlanClient,
        guid: &RawGuid,
    ) -> Result<ParsedQuality, (WifiQualityStatus, u32, String)> {
        let mut data_size = 0u32;
        let mut data = ptr::null_mut();
        let mut opcode_value_type = 0i32;
        let error = unsafe {
            WlanQueryInterface(
                client.handle,
                guid,
                REALTIME_CONNECTION_QUALITY_OPCODE,
                ptr::null_mut(),
                &mut data_size,
                &mut data,
                &mut opcode_value_type,
            )
        };
        let _memory = WlanMemory::new(data);
        if error != 0 {
            return Err((query_status(error), error, query_error_message(error)));
        }
        if data.is_null() {
            return Err((
                WifiQualityStatus::InvalidPayload,
                0,
                "WlanQueryInterface returned a null payload".into(),
            ));
        }
        let data_size = data_size as usize;
        if data_size > MAX_PAYLOAD_SIZE {
            return Err((
                WifiQualityStatus::InvalidPayload,
                0,
                PayloadError::TooLarge {
                    actual: data_size,
                    maximum: MAX_PAYLOAD_SIZE,
                }
                .to_string(),
            ));
        }
        let bytes = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), data_size) };
        parse_quality_payload(bytes)
            .map_err(|error| (WifiQualityStatus::InvalidPayload, 0, error.to_string()))
    }

    pub(super) fn collect() -> Result<WifiQualitySnapshot, WifiQualityError> {
        let client = WlanClient::open()?;
        let mut list = ptr::null_mut();
        let error = unsafe { WlanEnumInterfaces(client.handle, ptr::null_mut(), &mut list) };
        let _list_memory = WlanMemory::new(list.cast());
        if error != 0 {
            return Err(api_error("WlanEnumInterfaces", error));
        }
        if list.is_null() {
            return Err(WifiQualityError::Api {
                operation: "WlanEnumInterfaces".into(),
                error_code: 0,
            });
        }

        let count = unsafe { (*list).number_of_items };
        if count > MAX_INTERFACES as u32 {
            return Err(WifiQualityError::InvalidInterfaceList { count });
        }
        let count = count as usize;
        let first =
            unsafe { std::ptr::addr_of!((*list).interface_info).cast::<RawWlanInterfaceInfo>() };
        let interfaces = unsafe { std::slice::from_raw_parts(first, count) };
        let mut result = Vec::with_capacity(count);
        for item in interfaces {
            let interface_guid = guid_string(&item.interface_guid);
            let state_code = item.state;
            let interface_state = interface_state_name(state_code);
            if state_code != 1 {
                result.push(WifiQualityInterface {
                    interface_guid,
                    interface_state,
                    interface_state_code: state_code,
                    status: WifiQualityStatus::Disconnected,
                    error_code: None,
                    error_message: Some(
                        "the interface is not connected; realtime quality is unavailable".into(),
                    ),
                    link_quality_percent: None,
                    rx_rate_raw: None,
                    tx_rate_raw: None,
                    rate_unit: None,
                    phy_type_code: None,
                    phy_type: None,
                    is_mlo_connection: None,
                    links: Vec::new(),
                });
                continue;
            }

            match query_quality(&client, &item.interface_guid) {
                Ok(quality) => result.push(WifiQualityInterface {
                    interface_guid,
                    interface_state,
                    interface_state_code: state_code,
                    status: WifiQualityStatus::Measured,
                    error_code: None,
                    error_message: None,
                    link_quality_percent: Some(quality.link_quality_percent),
                    rx_rate_raw: Some(quality.rx_rate_raw),
                    tx_rate_raw: Some(quality.tx_rate_raw),
                    rate_unit: Some(REALTIME_RATE_UNIT.into()),
                    phy_type_code: Some(quality.phy_type_code),
                    phy_type: Some(phy_type_name(quality.phy_type_code)),
                    is_mlo_connection: Some(quality.is_mlo_connection),
                    links: quality
                        .links
                        .into_iter()
                        .map(|link| WifiQualityLink {
                            link_id: link.link_id,
                            center_frequency_khz: link.center_frequency_khz,
                            bandwidth_raw: link.bandwidth_raw,
                            bandwidth_unit: BANDWIDTH_UNIT.into(),
                            rssi_dbm: link.rssi_dbm,
                        })
                        .collect(),
                }),
                Err((status, error_code, error_message)) => result.push(WifiQualityInterface {
                    interface_guid,
                    interface_state,
                    interface_state_code: state_code,
                    status,
                    error_code: (error_code != 0).then_some(error_code),
                    error_message: Some(error_message),
                    link_quality_percent: None,
                    rx_rate_raw: None,
                    tx_rate_raw: None,
                    rate_unit: None,
                    phy_type_code: None,
                    phy_type: None,
                    is_mlo_connection: None,
                    links: Vec::new(),
                }),
            }
        }

        Ok(WifiQualitySnapshot {
            source: SOURCE.into(),
            sampled_at_unix_ms: unix_timestamp_ms(),
            status: aggregate_status(&result),
            interfaces: result,
        })
    }
}

/// Collect a bounded realtime quality sample for every WLAN interface.
///
/// On Windows, a failure opening or enumerating the WLAN client is returned as
/// an explicit error. Per-interface query failures are retained in the
/// snapshot with a status such as `unsupported`, `disconnected`, or
/// `invalid_payload`, so one driver does not erase observations for another.
#[cfg(windows)]
pub fn collect() -> Result<WifiQualitySnapshot, WifiQualityError> {
    windows_backend::collect()
}

#[cfg(not(windows))]
pub fn collect() -> Result<WifiQualitySnapshot, WifiQualityError> {
    Err(WifiQualityError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_i32(bytes: &mut [u8], offset: usize, value: i32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn payload_with_links(link_count: usize) -> Vec<u8> {
        let size = QUALITY_HEADER_SIZE + link_count * QUALITY_LINK_SIZE;
        let mut bytes = vec![0; size];
        put_u32(&mut bytes, 0, 11); // DOT11_PHY_TYPE_EHT
        put_u32(&mut bytes, 4, 87); // link quality percentage
        put_u32(&mut bytes, 8, 1_234); // documented raw realtime rate
        put_u32(&mut bytes, 12, 5_678); // documented raw realtime rate
        put_u32(&mut bytes, 16, 1); // BOOL bIsMLOConnection
        put_u32(&mut bytes, 20, link_count as u32);
        for index in 0..link_count {
            let offset = QUALITY_HEADER_SIZE + index * QUALITY_LINK_SIZE;
            bytes[offset] = index as u8;
            put_u32(&mut bytes, offset + 4, 5_180_000 + index as u32 * 20_000);
            put_u32(&mut bytes, offset + 8, 160);
            put_i32(&mut bytes, offset + 12, -48 - index as i32);
            put_u32(&mut bytes, offset + 16, 2); // two USHORT rates in the fixed WLAN_RATE_SET
        }
        bytes
    }

    #[test]
    fn parses_quality_and_variable_link_tail_without_identifiers() {
        let parsed = parse_quality_payload(&payload_with_links(2)).expect("valid quality payload");

        assert_eq!(parsed.phy_type_code, 11);
        assert_eq!(parsed.link_quality_percent, 87);
        assert_eq!(parsed.rx_rate_raw, 1_234);
        assert_eq!(parsed.tx_rate_raw, 5_678);
        assert!(parsed.is_mlo_connection);
        assert_eq!(parsed.links.len(), 2);
        assert_eq!(parsed.links[0].link_id, 0);
        assert_eq!(parsed.links[0].center_frequency_khz, 5_180_000);
        assert_eq!(parsed.links[0].bandwidth_raw, 160);
        assert_eq!(parsed.links[0].rssi_dbm, -48);
        assert_eq!(parsed.links[1].center_frequency_khz, 5_200_000);
    }

    #[test]
    fn rejects_payload_shorter_than_fixed_header() {
        let error = parse_quality_payload(&[0; QUALITY_HEADER_SIZE - 1]).unwrap_err();
        assert_eq!(
            error,
            PayloadError::TooShort {
                expected: QUALITY_HEADER_SIZE,
                actual: QUALITY_HEADER_SIZE - 1
            }
        );
    }

    #[test]
    fn rejects_link_count_that_exceeds_returned_bytes() {
        let mut bytes = payload_with_links(1);
        put_u32(&mut bytes, 20, 2);

        let error = parse_quality_payload(&bytes).unwrap_err();
        assert_eq!(
            error,
            PayloadError::LinkTailTruncated {
                declared: 2,
                available: 1
            }
        );
    }

    #[test]
    fn rejects_quality_outside_documented_percentage_range() {
        let mut bytes = payload_with_links(1);
        put_u32(&mut bytes, 4, 101);

        let error = parse_quality_payload(&bytes).unwrap_err();
        assert_eq!(error, PayloadError::InvalidQuality(101));
    }

    #[test]
    fn rejects_rate_set_length_outside_fixed_array() {
        let mut bytes = payload_with_links(1);
        put_u32(
            &mut bytes,
            QUALITY_HEADER_SIZE + 16,
            (WLAN_RATE_SET_MAX_LENGTH + 1) as u32,
        );

        let error = parse_quality_payload(&bytes).unwrap_err();
        assert_eq!(
            error,
            PayloadError::InvalidRateSetLength {
                link_index: 0,
                length: WLAN_RATE_SET_MAX_LENGTH as u32 + 1
            }
        );
    }

    #[test]
    fn rejects_excessive_link_count_before_multiplication() {
        let mut bytes = payload_with_links(0);
        put_u32(&mut bytes, 20, MAX_LINKS as u32 + 1);

        let error = parse_quality_payload(&bytes).unwrap_err();
        assert_eq!(error, PayloadError::TooManyLinks(MAX_LINKS as u32 + 1));
    }

    #[test]
    fn raw_layout_matches_windows_sdk_26100_variable_tail() {
        assert_eq!(std::mem::size_of::<RawGuid>(), 16);
        assert_eq!(std::mem::size_of::<RawWlanInterfaceInfo>(), 532);
        assert_eq!(std::mem::size_of::<RawWlanInterfaceInfoList>(), 540);
        assert_eq!(std::mem::size_of::<RawWlanRateSet>(), 256);
        assert_eq!(
            std::mem::size_of::<RawWlanRealtimeConnectionQualityLinkInfo>(),
            272
        );
        assert_eq!(std::mem::size_of::<RawWlanRealtimeConnectionQuality>(), 296);
        assert_eq!(QUALITY_HEADER_SIZE, 24);
        assert_eq!(QUALITY_LINK_SIZE, 272);
        assert_eq!(RATE_SET_LENGTH_OFFSET, 16);
    }

    #[test]
    fn classifies_disconnected_and_unsupported_query_errors_explicitly() {
        assert_eq!(query_status(5023), WifiQualityStatus::Disconnected);
        assert_eq!(query_status(50), WifiQualityStatus::Unsupported);
        assert_eq!(query_status(120), WifiQualityStatus::Unsupported);
        assert_eq!(query_status(5), WifiQualityStatus::PermissionDenied);
        assert_eq!(query_status(1168), WifiQualityStatus::QueryFailed);
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "Reads the live WLAN API; run explicitly on Windows"]
    fn live_wifi_quality_reports_counts_and_status_without_names() {
        let result = collect();
        match result {
            Ok(snapshot) => {
                let measured = snapshot
                    .interfaces
                    .iter()
                    .filter(|interface| interface.status == WifiQualityStatus::Measured)
                    .count();
                let links = snapshot
                    .interfaces
                    .iter()
                    .map(|interface| interface.links.len())
                    .sum::<usize>();
                let mut status_counts = BTreeMap::new();
                let mut error_code_counts = BTreeMap::new();
                for (index, interface) in snapshot.interfaces.iter().enumerate() {
                    *status_counts
                        .entry(format!("{:?}", interface.status))
                        .or_insert(0usize) += 1;
                    if let Some(error_code) = interface.error_code {
                        *error_code_counts.entry(error_code).or_insert(0usize) += 1;
                    }
                    println!(
                        "Wi-Fi quality interface[{}] status={:?} error_code={:?}",
                        index, interface.status, interface.error_code
                    );
                }
                println!(
                    "Wi-Fi quality status={:?}, interfaces={}, measured={}, links={}, statuses={:?}, error_codes={:?}",
                    snapshot.status,
                    snapshot.interfaces.len(),
                    measured,
                    links,
                    status_counts,
                    error_code_counts
                );
            }
            Err(WifiQualityError::Unsupported { error_code, .. }) => {
                println!("Wi-Fi quality status=unsupported, error_code={error_code}")
            }
            Err(WifiQualityError::UnsupportedPlatform) => {
                println!("Wi-Fi quality status=unsupported_platform")
            }
            Err(WifiQualityError::Api { error_code, .. }) => {
                println!("Wi-Fi quality status=api_error, error_code={error_code}")
            }
            Err(WifiQualityError::InvalidInterfaceList { count }) => {
                println!("Wi-Fi quality status=invalid_interface_list, count={count}")
            }
        }
    }
}
