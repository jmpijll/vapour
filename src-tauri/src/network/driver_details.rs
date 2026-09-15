//! Read-only driver metadata for the Windows network adapters.
//!
//! The adapter table exposes the connection GUID, while the signed-driver
//! WMI class exposes provider, version and DriverVer date.  The two classes
//! are joined by the PnP device identifier in a fixed PowerShell/CIM query.
//! The caller is expected to cache this slower collector; this module never
//! runs it from a per-second sampler.

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt};

pub const SOURCE: &str = "windows_cim_win32_pnpsigneddriver";

const MAX_STDOUT_BYTES: usize = 1 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 64 * 1024;
const MAX_RECORDS: usize = 2048;
const MAX_FIELD_BYTES: usize = 512;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriverDetails {
    pub source: String,
    pub provider: Option<String>,
    pub version: Option<String>,
    pub date: Option<String>,
}

/// Collection-level failures are deliberately coarse so command output,
/// paths and device identifiers never become part of the API or logs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DriverDetailsError {
    UnsupportedPlatform,
    Unavailable,
    QueryFailed,
    TimedOut,
    OutputLimitExceeded,
    InvalidOutput,
    TooManyRecords,
}

impl fmt::Display for DriverDetailsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedPlatform => {
                "Windows driver details are unsupported on this platform"
            }
            Self::Unavailable => "Windows driver details are unavailable",
            Self::QueryFailed => "Windows driver details query failed",
            Self::TimedOut => "Windows driver details query timed out",
            Self::OutputLimitExceeded => "Windows driver details query output exceeded its limit",
            Self::InvalidOutput => "Windows driver details query returned invalid output",
            Self::TooManyRecords => "Windows driver details query returned too many records",
        })
    }
}

impl std::error::Error for DriverDetailsError {}

#[derive(Debug, Deserialize)]
struct RawEnvelope {
    #[serde(default)]
    records: Option<Vec<RawRecord>>,
}

#[derive(Debug, Deserialize)]
struct RawRecord {
    #[serde(default, alias = "Guid", alias = "GUID")]
    guid: Option<String>,
    #[serde(default, alias = "Provider", alias = "DriverProviderName")]
    provider: Option<String>,
    #[serde(default, alias = "Version", alias = "DriverVersion")]
    version: Option<String>,
    #[serde(default, alias = "Date", alias = "DriverDate")]
    date: Option<String>,
}

/// Return the canonical form used by the native adapter details (`Debug` on
/// a Windows GUID): uppercase hexadecimal, hyphens, and no braces.
pub fn normalize_guid(value: &str) -> Option<String> {
    let value = value.trim();
    let bytes = value.as_bytes();
    let body = match (bytes.first().copied(), bytes.last().copied()) {
        (Some(b'{'), Some(b'}')) if bytes.len() >= 2 => &bytes[1..bytes.len() - 1],
        (Some(b'{'), _) | (_, Some(b'}')) => return None,
        _ => bytes,
    };
    if body.len() != 36
        || ![8, 13, 18, 23]
            .into_iter()
            .all(|offset| body.get(offset) == Some(&b'-'))
    {
        return None;
    }
    if body
        .iter()
        .enumerate()
        .any(|(index, byte)| index != 8 && index != 13 && index != 18 && index != 23 && !byte.is_ascii_hexdigit())
    {
        return None;
    }
    Some(
        body.iter()
            .map(|byte| byte.to_ascii_uppercase() as char)
            .collect(),
    )
}

fn bounded_field(value: Option<String>) -> Option<String> {
    let value = value?;
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_FIELD_BYTES
        || value.chars().any(char::is_control)
    {
        return None;
    }
    Some(value.to_owned())
}

fn parse_records(bytes: &[u8]) -> Result<HashMap<String, DriverDetails>, DriverDetailsError> {
    if bytes.len() > MAX_STDOUT_BYTES {
        return Err(DriverDetailsError::OutputLimitExceeded);
    }
    // Windows PowerShell normally emits UTF-8 after the script sets its
    // output encoding.  Accept its optional UTF-8 BOM as well.
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let envelope: RawEnvelope =
        serde_json::from_slice(bytes).map_err(|_| DriverDetailsError::InvalidOutput)?;
    let records = envelope.records.ok_or(DriverDetailsError::InvalidOutput)?;
    if records.len() > MAX_RECORDS {
        return Err(DriverDetailsError::TooManyRecords);
    }

    let mut values = HashMap::with_capacity(records.len());
    for record in records {
        let Some(guid) = record.guid.as_deref().and_then(normalize_guid) else {
            // A malformed row must not make valid adapters disappear, but if
            // every row is malformed the caller receives Unavailable below.
            continue;
        };
        values.entry(guid).or_insert_with(|| DriverDetails {
            source: SOURCE.into(),
            provider: bounded_field(record.provider),
            version: bounded_field(record.version),
            date: bounded_field(record.date),
        });
    }
    if values.is_empty() {
        return Err(DriverDetailsError::Unavailable);
    }
    Ok(values)
}

#[cfg(windows)]
mod windows_backend {
    use super::*;
    use std::{
        io::{self, Read},
        os::windows::{
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
            process::CommandExt,
        },
        path::PathBuf,
        process::{Child, Command, Stdio},
        thread::{self, JoinHandle},
        time::{Duration, Instant},
    };
    use windows::{
        core::PCWSTR,
        Win32::{
            Foundation::HANDLE,
            System::JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
                TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JobObjectExtendedLimitInformation,
            },
        },
    };

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const QUERY_TIMEOUT: Duration = Duration::from_secs(8);
    const POLL_INTERVAL: Duration = Duration::from_millis(10);
    const READER_CLEANUP_TIMEOUT: Duration = Duration::from_millis(250);
    const READER_POLL_INTERVAL: Duration = Duration::from_millis(5);

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }

    // This is a fixed script.  No adapter GUID, PnP identifier or other
    // runtime string is interpolated into PowerShell source or arguments.
    const POWERSHELL_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$adapters = @(Get-CimInstance -ClassName Win32_NetworkAdapter -Property @('GUID', 'PNPDeviceID') -ErrorAction Stop)
$drivers = @(Get-CimInstance -ClassName Win32_PnPSignedDriver -Property @('DeviceID', 'DriverProviderName', 'DriverVersion', 'DriverDate') -ErrorAction Stop)

$driverByDevice = @{}
foreach ($driver in $drivers) {
    $deviceId = [string]$driver.DeviceID
    if ([string]::IsNullOrWhiteSpace($deviceId)) { continue }
    if (-not $driverByDevice.ContainsKey($deviceId)) {
        $driverByDevice[$deviceId] = $driver
    }
}

$records = @(
    foreach ($adapter in $adapters) {
        $guid = [string]$adapter.GUID
        if ([string]::IsNullOrWhiteSpace($guid)) { continue }

        $driver = $null
        $deviceId = [string]$adapter.PNPDeviceID
        if (-not [string]::IsNullOrWhiteSpace($deviceId)) {
            $driver = $driverByDevice[$deviceId]
        }

        [pscustomobject]@{
            guid = $guid
            provider = if ($null -ne $driver) { [string]$driver.DriverProviderName } else { $null }
            version = if ($null -ne $driver) { [string]$driver.DriverVersion } else { $null }
            date = if ($null -ne $driver) { [string]$driver.DriverDate } else { $null }
        }
    }
)

[pscustomobject]@{ records = @($records) } | ConvertTo-Json -Compress -Depth 3
"#;

struct LimitedOutput {
    bytes: Vec<u8>,
    exceeded: bool,
}

fn read_limited<R: Read>(mut reader: R, limit: usize) -> io::Result<LimitedOutput> {
    let mut bytes = Vec::with_capacity(limit.min(8192));
    let mut buffer = [0u8; 8192];
    let mut exceeded = false;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = limit.saturating_sub(bytes.len());
        let copied = read.min(remaining);
        bytes.extend_from_slice(&buffer[..copied]);
        if copied < read {
            exceeded = true;
            break;
        }
    }
    Ok(LimitedOutput { bytes, exceeded })
}

fn spawn_reader<R: Read + Send + 'static>(
    name: &'static str,
    reader: R,
    limit: usize,
) -> io::Result<JoinHandle<io::Result<LimitedOutput>>> {
    thread::Builder::new()
        .name(name.into())
        .spawn(move || read_limited(reader, limit))
}

struct ChildJob {
    handle: OwnedHandle,
}

impl ChildJob {
    fn attach(child: &Child) -> Option<Self> {
        unsafe {
            let result = (|| -> windows::core::Result<Self> {
                let job = OwnedHandle::from_raw_handle(CreateJobObjectW(None, PCWSTR::null())?.0);
                let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
                limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                SetInformationJobObject(
                    HANDLE(job.as_raw_handle()),
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of_val(&limits) as u32,
                )?;
                AssignProcessToJobObject(
                    HANDLE(job.as_raw_handle()),
                    HANDLE(child.as_raw_handle()),
                )?;
                Ok(Self { handle: job })
            })();
            result.ok()
        }
    }

    fn terminate(&self) {
        unsafe {
            let _ = TerminateJobObject(HANDLE(self.handle.as_raw_handle()), 1);
        }
    }
}

fn terminate_child(child: &mut Child, job: Option<&ChildJob>) {
    if let Some(job) = job {
        job.terminate();
    }
    // A job contains PowerShell and any descendants.  Do not wait here:
    // WaitForSingleObject through Child::wait could extend the hard query
    // deadline if a descendant retains a pipe handle.
    let _ = child.kill();
}

fn join_reader(
    reader: JoinHandle<io::Result<LimitedOutput>>,
) -> Result<LimitedOutput, DriverDetailsError> {
    reader
        .join()
        .map_err(|_| DriverDetailsError::QueryFailed)?
        .map_err(|_| DriverDetailsError::QueryFailed)
}

fn join_reader_bounded(
    reader: JoinHandle<io::Result<LimitedOutput>>,
    job: &ChildJob,
) -> Result<LimitedOutput, DriverDetailsError> {
    let wait_until_finished = |reader: &JoinHandle<io::Result<LimitedOutput>>| {
        let deadline = Instant::now() + READER_CLEANUP_TIMEOUT;
        while !reader.is_finished() && Instant::now() < deadline {
            thread::sleep(READER_POLL_INTERVAL);
        }
        reader.is_finished()
    };
    if !wait_until_finished(&reader) {
        job.terminate();
        if !wait_until_finished(&reader) {
            // The job has already been terminated.  Dropping this handle
            // keeps the collector bounded even if a platform pipe remains
            // open unexpectedly.
            drop(reader);
            return Err(DriverDetailsError::QueryFailed);
        }
    }
    join_reader(reader)
}

fn system_directory() -> Result<PathBuf, DriverDetailsError> {
    let mut buffer = vec![0u16; 512];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(DriverDetailsError::Unavailable);
    }
    let path = String::from_utf16(&buffer[..length])
        .map(PathBuf::from)
        .map_err(|_| DriverDetailsError::Unavailable)?;
    path.is_absolute()
        .then_some(path)
        .ok_or(DriverDetailsError::Unavailable)
}

fn run_query() -> Result<Vec<u8>, DriverDetailsError> {
    let system_directory = system_directory()?;
    let powershell = system_directory
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    let mut child = Command::new(powershell)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            POWERSHELL_SCRIPT,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                DriverDetailsError::Unavailable
            } else {
                DriverDetailsError::QueryFailed
            }
        })?;
    let job = match ChildJob::attach(&child) {
        Some(job) => job,
        None => {
            // Without containment, a timeout could leave a CIM descendant
            // alive.  Fail closed instead of using an unbounded process-tree
            // helper or wait call.
            let _ = child.kill();
            return Err(DriverDetailsError::QueryFailed);
        }
    };

    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            terminate_child(&mut child, Some(&job));
            return Err(DriverDetailsError::QueryFailed);
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            terminate_child(&mut child, Some(&job));
            return Err(DriverDetailsError::QueryFailed);
        }
    };
    let stdout_reader = match spawn_reader("vapour-driver-stdout", stdout, MAX_STDOUT_BYTES) {
        Ok(reader) => reader,
        Err(_) => {
            terminate_child(&mut child, Some(&job));
            return Err(DriverDetailsError::QueryFailed);
        }
    };
    let stderr_reader = match spawn_reader("vapour-driver-stderr", stderr, MAX_STDERR_BYTES) {
        Ok(reader) => reader,
        Err(_) => {
            terminate_child(&mut child, Some(&job));
            let _ = join_reader_bounded(stdout_reader, &job);
            return Err(DriverDetailsError::QueryFailed);
        }
    };

    let deadline = Instant::now() + QUERY_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                terminate_child(&mut child, Some(&job));
                let _ = join_reader_bounded(stdout_reader, &job);
                let _ = join_reader_bounded(stderr_reader, &job);
                return Err(DriverDetailsError::TimedOut);
            }
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(_) => {
                terminate_child(&mut child, Some(&job));
                let _ = join_reader_bounded(stdout_reader, &job);
                let _ = join_reader_bounded(stderr_reader, &job);
                return Err(DriverDetailsError::QueryFailed);
            }
        }
    };

    let stdout = match join_reader_bounded(stdout_reader, &job) {
        Ok(stdout) => stdout,
        Err(error) => {
            job.terminate();
            let _ = join_reader_bounded(stderr_reader, &job);
            return Err(error);
        }
    };
    let stderr = match join_reader_bounded(stderr_reader, &job) {
        Ok(stderr) => stderr,
        Err(error) => return Err(error),
    };
    if stdout.exceeded || stderr.exceeded {
        return Err(DriverDetailsError::OutputLimitExceeded);
    }
    if !status.success() {
        return Err(DriverDetailsError::QueryFailed);
    }
    Ok(stdout.bytes)
}

pub fn collect() -> Result<HashMap<String, DriverDetails>, DriverDetailsError> {
    parse_records(&run_query()?)
}
}

#[cfg(windows)]
pub fn collect() -> Result<HashMap<String, DriverDetails>, DriverDetailsError> {
    windows_backend::collect()
}

#[cfg(not(windows))]
pub fn collect() -> Result<HashMap<String, DriverDetails>, DriverDetailsError> {
    Err(DriverDetailsError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_guid_for_interface_join() {
        assert_eq!(
            normalize_guid(" {01234567-89ab-cdef-0123-456789abcdef} "),
            Some("01234567-89AB-CDEF-0123-456789ABCDEF".into())
        );
        assert!(normalize_guid("01234567-89ab-cdef-0123-456789abcde").is_none());
        assert!(normalize_guid("{01234567-89ab-cdef-0123-456789abcdef").is_none());
    }

    #[test]
    fn maps_provider_version_and_date_by_guid() {
        let json = br#"{
            "records": [
                {
                    "guid": "{01234567-89ab-cdef-0123-456789abcdef}",
                    "provider": "Example Networks",
                    "version": "4.5.6.7",
                    "date": "2024-01-25"
                }
            ]
        }"#;
        let values = parse_records(json).unwrap();
        let detail = values.get("01234567-89AB-CDEF-0123-456789ABCDEF").unwrap();
        assert_eq!(detail.provider.as_deref(), Some("Example Networks"));
        assert_eq!(detail.version.as_deref(), Some("4.5.6.7"));
        assert_eq!(detail.date.as_deref(), Some("2024-01-25"));
        assert_eq!(detail.source, SOURCE);
    }

    #[test]
    fn keeps_adapter_when_driver_fields_are_unavailable() {
        let json = br#"{"records":[{"guid":"01234567-89AB-CDEF-0123-456789ABCDEF","provider":null,"version":"","date":null}]}"#;
        let values = parse_records(json).unwrap();
        let detail = values.get("01234567-89AB-CDEF-0123-456789ABCDEF").unwrap();
        assert!(detail.provider.is_none());
        assert!(detail.version.is_none());
        assert!(detail.date.is_none());
    }

    #[test]
    fn invalid_or_empty_result_is_unavailable() {
        assert_eq!(
            parse_records(br#"{"records":[]}"#),
            Err(DriverDetailsError::Unavailable)
        );
        assert_eq!(
            parse_records(br#"{"records":[{"guid":"not-a-guid"}]}"#),
            Err(DriverDetailsError::Unavailable)
        );
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "Reads live Windows CIM driver metadata; run explicitly"]
    fn live_driver_details_counts_only() {
        match collect() {
            Ok(values) => println!("Driver detail records: {}", values.len()),
            Err(error) => println!("Driver detail collection unavailable: {error}"),
        }
    }
}
