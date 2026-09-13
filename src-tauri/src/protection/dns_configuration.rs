//! Read, plan, and (when explicitly called by the controller) restore
//! per-interface Windows DNS settings.
//!
//! The native API used here is GetInterfaceDnsSettings /
//! SetInterfaceDnsSettings from iphlpapi.dll. A snapshot includes every
//! interface returned by GetIfTable2; disconnected and tunnel interfaces are
//! intentionally retained so a caller can make that policy decision
//! explicitly. This module never chooses an upstream DNS server.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::IpAddr,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

pub const SOURCE: &str = "windows_iphelper_interface_dns";
pub const JOURNAL_FORMAT_VERSION: u32 = 1;
pub const MAX_ADAPTERS: usize = 512;
pub const MAX_DNS_SERVERS: usize = 16;
pub const MAX_NATIVE_STRING_CHARS: usize = 4096;
pub const MAX_JOURNAL_BYTES: usize = 256 * 1024;
pub const LOOPBACK_IPV4: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
pub const LOOPBACK_IPV6: IpAddr = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsUnavailableReason {
    QueryFailed { code: u32 },
    InvalidData,
    Unsupported,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsSetting {
    /// No adapter-specific name server is configured; Windows resolves via
    /// DHCP, policy, or another system-managed source.
    Automatic,
    /// The exact static adapter name-server list returned by Windows.
    Static { servers: Vec<IpAddr> },
    /// The stack could not be read. It is never treated as automatic.
    Unavailable { reason: DnsUnavailableReason },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsFamily {
    Ipv4,
    Ipv6,
}

impl DnsFamily {
    fn is_ipv6(&self) -> bool {
        matches!(self, Self::Ipv6)
    }

    fn accepts(&self, address: IpAddr) -> bool {
        match self {
            Self::Ipv4 => address.is_ipv4(),
            Self::Ipv6 => address.is_ipv6(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdapterDnsSnapshot {
    pub interface_guid: String,
    pub interface_index: u32,
    pub interface_type: u32,
    pub operational_status: u32,
    pub media_connect_state: u32,
    pub ipv4: DnsSetting,
    pub ipv6: DnsSetting,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DnsSnapshot {
    pub source: String,
    pub sampled_at_unix_secs: u64,
    pub adapters: Vec<AdapterDnsSnapshot>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DnsOperation {
    pub interface_guid: String,
    pub interface_index: u32,
    pub family: DnsFamily,
    pub original: DnsSetting,
    pub desired_servers: Vec<IpAddr>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsSkipReason {
    NoLoopbackServer,
    AlreadyApplied,
    Unavailable(DnsUnavailableReason),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DnsSkippedStack {
    pub interface_guid: String,
    pub family: DnsFamily,
    pub reason: DnsSkipReason,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DnsApplyPlan {
    pub generation: String,
    pub operations: Vec<DnsOperation>,
    pub skipped: Vec<DnsSkippedStack>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DnsJournalStack {
    /// The setting captured immediately before this stack was changed.
    pub original: DnsSetting,
    /// Restore only while the current value still matches this list.
    pub applied_servers: Vec<IpAddr>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DnsJournalAdapter {
    pub interface_guid: String,
    pub interface_index: u32,
    pub interface_type: u32,
    pub operational_status: u32,
    pub media_connect_state: u32,
    pub ipv4: Option<DnsJournalStack>,
    pub ipv6: Option<DnsJournalStack>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DnsRecoveryJournal {
    pub format_version: u32,
    pub source: String,
    pub generation: String,
    pub created_at_unix_secs: u64,
    pub adapters: Vec<DnsJournalAdapter>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DnsApplyResult {
    pub generation: String,
    pub attempted_stack_count: usize,
    pub changed_stack_count: usize,
    pub skipped_stack_count: usize,
    pub journal_present: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DnsRestoreResult {
    pub restored_stack_count: usize,
    pub skipped_stack_count: usize,
    pub remaining: Vec<DnsRestoreIssue>,
    pub journal_removed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DnsRestoreIssue {
    pub interface_guid: String,
    pub family: DnsFamily,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsConfigurationError {
    UnsupportedPlatform,
    InvalidSnapshot(String),
    InvalidLoopbackServer {
        address: String,
    },
    NoApplicableStacks,
    JournalAlreadyExists,
    JournalMissing,
    JournalTooLarge {
        actual: u64,
        maximum: usize,
    },
    JournalIo(String),
    JournalInvalid(String),
    NativeSnapshot {
        code: u32,
    },
    NativeQuery {
        interface_guid: String,
        family: DnsFamily,
        code: u32,
    },
    NativeSet {
        interface_guid: String,
        family: DnsFamily,
        code: u32,
    },
    ApplyFailed {
        interface_guid: String,
        family: DnsFamily,
        code: u32,
        changed_stack_count: usize,
        rollback_failures: Vec<DnsRestoreIssue>,
    },
    ApplyPreconditionFailed {
        interface_guid: String,
        family: DnsFamily,
        changed_stack_count: usize,
        rollback_failures: Vec<DnsRestoreIssue>,
    },
    RestoreIncomplete {
        restored_stack_count: usize,
        skipped_stack_count: usize,
        remaining: Vec<DnsRestoreIssue>,
    },
    JournalCleanupFailed {
        restored_stack_count: usize,
        path_error: String,
    },
}

impl fmt::Display for DnsConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                write!(formatter, "Windows DNS configuration is unavailable on this platform")
            }
            Self::InvalidSnapshot(reason) => write!(formatter, "DNS snapshot is invalid: {reason}"),
            Self::InvalidLoopbackServer { address } => {
                write!(formatter, "DNS server {address:?} is not an approved loopback listener")
            }
            Self::NoApplicableStacks => {
                write!(formatter, "the snapshot contains no applicable DNS stacks")
            }
            Self::JournalAlreadyExists => write!(
                formatter,
                "a DNS recovery journal already exists; restore it before replacing the generation"
            ),
            Self::JournalMissing => write!(formatter, "DNS recovery journal is missing"),
            Self::JournalTooLarge { actual, maximum } => {
                write!(formatter, "DNS recovery journal is {actual} bytes; maximum is {maximum}")
            }
            Self::JournalIo(reason) => {
                write!(formatter, "DNS recovery journal I/O failed: {reason}")
            }
            Self::JournalInvalid(reason) => {
                write!(formatter, "DNS recovery journal is invalid: {reason}")
            }
            Self::NativeSnapshot { code } => {
                write!(formatter, "Windows DNS interface enumeration failed ({code})")
            }
            Self::NativeQuery {
                interface_guid,
                family,
                code,
            } => write!(
                formatter,
                "Windows DNS read failed for {family:?} on interface {interface_guid:?} ({code})"
            ),
            Self::NativeSet {
                interface_guid,
                family,
                code,
            } => write!(
                formatter,
                "Windows DNS update failed for {family:?} on interface {interface_guid:?} ({code})"
            ),
            Self::ApplyFailed {
                interface_guid,
                family,
                code,
                changed_stack_count,
                rollback_failures,
            } => write!(
                formatter,
                "DNS update failed for {family:?} on interface {interface_guid:?} ({code}); {changed_stack_count} stacks changed and {} rollback operations failed",
                rollback_failures.len()
            ),
            Self::ApplyPreconditionFailed {
                interface_guid,
                family,
                changed_stack_count,
                rollback_failures,
            } => write!(
                formatter,
                "DNS update stopped because {family:?} on interface {interface_guid:?} changed before it was written; {changed_stack_count} stacks changed and {} rollback operations failed",
                rollback_failures.len()
            ),
            Self::RestoreIncomplete {
                restored_stack_count,
                skipped_stack_count,
                remaining,
            } => write!(
                formatter,
                "DNS restore incomplete: {restored_stack_count} restored, {skipped_stack_count} skipped, {} remain in the journal",
                remaining.len()
            ),
            Self::JournalCleanupFailed {
                restored_stack_count,
                path_error,
            } => write!(
                formatter,
                "DNS settings restored for {restored_stack_count} stacks, but the recovery journal could not be removed: {path_error}"
            ),
        }
    }
}

impl std::error::Error for DnsConfigurationError {}

/// Read all interface rows and both address-family DNS settings.
///
/// Disconnected, VPN, and currently-down interfaces are included. A stack
/// that cannot be queried is represented by Unavailable and is never
/// silently converted to Automatic.
pub fn snapshot() -> Result<DnsSnapshot, DnsConfigurationError> {
    #[cfg(windows)]
    {
        return windows_backend::snapshot();
    }
    #[cfg(not(windows))]
    {
        Err(DnsConfigurationError::UnsupportedPlatform)
    }
}

/// Build a deterministic, side-effect-free loopback update plan.
///
/// Only 127.0.0.1 and ::1 are accepted. A family without a requested
/// loopback listener is left unchanged and appears in skipped.
pub fn plan(
    snapshot: &DnsSnapshot,
    desired_servers: &[IpAddr],
) -> Result<DnsApplyPlan, DnsConfigurationError> {
    validate_snapshot(snapshot)?;
    let desired = normalized_loopback_servers(desired_servers)?;

    let mut adapters: Vec<&AdapterDnsSnapshot> = snapshot.adapters.iter().collect();
    adapters.sort_by(|left, right| left.interface_guid.cmp(&right.interface_guid));

    let mut operations = Vec::new();
    let mut skipped = Vec::new();
    for adapter in adapters {
        let guid = canonical_guid(&adapter.interface_guid)
            .map_err(|reason| DnsConfigurationError::InvalidSnapshot(reason.to_owned()))?;
        append_stack_plan(
            &mut operations,
            &mut skipped,
            adapter,
            &guid,
            DnsFamily::Ipv4,
            &adapter.ipv4,
            desired.iter().copied().filter(IpAddr::is_ipv4).collect(),
        );
        append_stack_plan(
            &mut operations,
            &mut skipped,
            adapter,
            &guid,
            DnsFamily::Ipv6,
            &adapter.ipv6,
            desired.iter().copied().filter(IpAddr::is_ipv6).collect(),
        );
    }

    let generation = generation_for(snapshot, &desired)?;
    if operations.is_empty()
        && !skipped
            .iter()
            .any(|entry| matches!(entry.reason, DnsSkipReason::AlreadyApplied))
    {
        return Err(DnsConfigurationError::NoApplicableStacks);
    }
    Ok(DnsApplyPlan {
        generation,
        operations,
        skipped,
    })
}

fn append_stack_plan(
    operations: &mut Vec<DnsOperation>,
    skipped: &mut Vec<DnsSkippedStack>,
    adapter: &AdapterDnsSnapshot,
    guid: &str,
    family: DnsFamily,
    original: &DnsSetting,
    desired: Vec<IpAddr>,
) {
    if desired.is_empty() {
        skipped.push(DnsSkippedStack {
            interface_guid: guid.to_owned(),
            family,
            reason: DnsSkipReason::NoLoopbackServer,
        });
        return;
    }

    match original {
        DnsSetting::Static { servers } if servers == &desired => skipped.push(DnsSkippedStack {
            interface_guid: guid.to_owned(),
            family,
            reason: DnsSkipReason::AlreadyApplied,
        }),
        DnsSetting::Automatic | DnsSetting::Static { .. } => operations.push(DnsOperation {
            interface_guid: guid.to_owned(),
            interface_index: adapter.interface_index,
            family,
            original: original.clone(),
            desired_servers: desired,
        }),
        DnsSetting::Unavailable { reason } => skipped.push(DnsSkippedStack {
            interface_guid: guid.to_owned(),
            family,
            reason: DnsSkipReason::Unavailable(reason.clone()),
        }),
    }
}

/// Install a plan and persist its recovery journal before the first native
/// mutation. Callers must explicitly choose when to invoke this function.
pub fn apply(
    snapshot: &DnsSnapshot,
    desired_servers: &[IpAddr],
    journal_path: &Path,
) -> Result<DnsApplyResult, DnsConfigurationError> {
    let plan = plan(snapshot, desired_servers)?;
    if plan.operations.is_empty() {
        return Ok(DnsApplyResult {
            generation: plan.generation,
            attempted_stack_count: 0,
            changed_stack_count: 0,
            skipped_stack_count: plan.skipped.len(),
            journal_present: false,
        });
    }
    if read_journal(journal_path)?.is_some() {
        return Err(DnsConfigurationError::JournalAlreadyExists);
    }

    #[cfg(not(windows))]
    {
        let _ = (plan, journal_path);
        return Err(DnsConfigurationError::UnsupportedPlatform);
    }

    #[cfg(windows)]
    {
        let journal = journal_from_plan(snapshot, &plan)?;
        persist_new_journal(journal_path, &journal)?;

        let mut changed: Vec<&DnsOperation> = Vec::with_capacity(plan.operations.len());
        for operation in &plan.operations {
            let guid = windows_backend::parse_guid(&operation.interface_guid)
                .map_err(|reason| DnsConfigurationError::InvalidSnapshot(reason.to_owned()))?;
            let current = match windows_backend::get_stack(guid, operation.family.clone()) {
                Ok(current) => current,
                Err(error) => {
                    let mut rollback_failures = Vec::new();
                    for previous in changed.iter().rev() {
                        if let Err(rollback) = windows_backend::set_original(previous) {
                            rollback_failures.push(DnsRestoreIssue {
                                interface_guid: previous.interface_guid.clone(),
                                family: previous.family.clone(),
                                reason: rollback.to_string(),
                            });
                        }
                    }
                    let code = match error {
                        DnsConfigurationError::NativeQuery { code, .. } => code,
                        DnsConfigurationError::NativeSet { code, .. } => code,
                        _ => 0,
                    };
                    return Err(DnsConfigurationError::ApplyFailed {
                        interface_guid: operation.interface_guid.clone(),
                        family: operation.family.clone(),
                        code,
                        changed_stack_count: changed.len(),
                        rollback_failures,
                    });
                }
            };
            if current != operation.original {
                let mut rollback_failures = Vec::new();
                for previous in changed.iter().rev() {
                    if let Err(rollback) = windows_backend::set_original(previous) {
                        rollback_failures.push(DnsRestoreIssue {
                            interface_guid: previous.interface_guid.clone(),
                            family: previous.family.clone(),
                            reason: rollback.to_string(),
                        });
                    }
                }
                return Err(DnsConfigurationError::ApplyPreconditionFailed {
                    interface_guid: operation.interface_guid.clone(),
                    family: operation.family.clone(),
                    changed_stack_count: changed.len(),
                    rollback_failures,
                });
            }
            match windows_backend::set_operation(operation) {
                Ok(()) => {
                    changed.push(operation);
                    match windows_backend::get_stack(guid, operation.family.clone()) {
                        Ok(observed)
                            if observed
                                == (DnsSetting::Static {
                                    servers: operation.desired_servers.clone(),
                                }) => {}
                        Ok(_) => {
                            let mut rollback_failures = Vec::new();
                            for previous in changed.iter().rev() {
                                if let Err(rollback) = windows_backend::set_original(previous) {
                                    rollback_failures.push(DnsRestoreIssue {
                                        interface_guid: previous.interface_guid.clone(),
                                        family: previous.family.clone(),
                                        reason: rollback.to_string(),
                                    });
                                }
                            }
                            return Err(DnsConfigurationError::ApplyFailed {
                                interface_guid: operation.interface_guid.clone(),
                                family: operation.family.clone(),
                                code: 0,
                                changed_stack_count: changed.len(),
                                rollback_failures,
                            });
                        }
                        Err(error) => {
                            let code = match error {
                                DnsConfigurationError::NativeQuery { code, .. } => code,
                                _ => 0,
                            };
                            let mut rollback_failures = Vec::new();
                            for previous in changed.iter().rev() {
                                if let Err(rollback) = windows_backend::set_original(previous) {
                                    rollback_failures.push(DnsRestoreIssue {
                                        interface_guid: previous.interface_guid.clone(),
                                        family: previous.family.clone(),
                                        reason: rollback.to_string(),
                                    });
                                }
                            }
                            return Err(DnsConfigurationError::ApplyFailed {
                                interface_guid: operation.interface_guid.clone(),
                                family: operation.family.clone(),
                                code,
                                changed_stack_count: changed.len(),
                                rollback_failures,
                            });
                        }
                    }
                }
                Err(error) => {
                    let mut rollback_failures = Vec::new();
                    for previous in changed.iter().rev() {
                        if let Err(rollback) = windows_backend::set_original(previous) {
                            rollback_failures.push(DnsRestoreIssue {
                                interface_guid: previous.interface_guid.clone(),
                                family: previous.family.clone(),
                                reason: rollback.to_string(),
                            });
                        }
                    }
                    return Err(match error {
                        DnsConfigurationError::NativeSet {
                            interface_guid,
                            family,
                            code,
                        } => DnsConfigurationError::ApplyFailed {
                            interface_guid,
                            family,
                            code,
                            changed_stack_count: changed.len(),
                            rollback_failures,
                        },
                        other => other,
                    });
                }
            }
        }

        Ok(DnsApplyResult {
            generation: plan.generation,
            attempted_stack_count: plan.operations.len(),
            changed_stack_count: changed.len(),
            skipped_stack_count: plan.skipped.len(),
            journal_present: true,
        })
    }
}

/// Restore only journaled stacks that still contain the loopback values owned
/// by this generation. If an adapter disappeared or a user changed a value,
/// it remains in the journal and the error reports the partial cleanup.
pub fn restore(journal_path: &Path) -> Result<DnsRestoreResult, DnsConfigurationError> {
    #[cfg(not(windows))]
    {
        let _ = journal_path;
        return Err(DnsConfigurationError::UnsupportedPlatform);
    }

    #[cfg(windows)]
    {
        let journal = read_journal(journal_path)?.ok_or(DnsConfigurationError::JournalMissing)?;
        let mut restored_stack_count = 0;
        let mut skipped_stack_count = 0;
        let mut remaining = Vec::new();

        for adapter in &journal.adapters {
            let guid = match windows_backend::parse_guid(&adapter.interface_guid) {
                Ok(guid) => guid,
                Err(reason) => {
                    for family in present_families(adapter) {
                        remaining.push(DnsRestoreIssue {
                            interface_guid: adapter.interface_guid.clone(),
                            family,
                            reason: reason.to_owned(),
                        });
                    }
                    continue;
                }
            };

            for (family, stack) in [
                (DnsFamily::Ipv4, adapter.ipv4.as_ref()),
                (DnsFamily::Ipv6, adapter.ipv6.as_ref()),
            ] {
                let Some(stack) = stack else {
                    continue;
                };
                match windows_backend::get_stack(guid, family.clone()) {
                    Ok(current) if current == stack.original => {
                        // A previous attempt may have restored this stack
                        // successfully but failed while cleaning up the
                        // journal. It is no longer unresolved.
                        restored_stack_count += 1;
                    }
                    Ok(current)
                        if current
                            == (DnsSetting::Static {
                                servers: stack.applied_servers.clone(),
                            }) =>
                    {
                        match restore_owned_setting(
                            &stack.original,
                            &stack.applied_servers,
                            || {
                                windows_backend::get_stack(guid, family.clone())
                                    .map_err(|e| e.to_string())
                            },
                            |setting| {
                                windows_backend::set_setting(guid, family.clone(), setting)
                                    .map_err(|e| e.to_string())
                            },
                        ) {
                            Ok(()) => restored_stack_count += 1,
                            Err(error) => remaining.push(DnsRestoreIssue {
                                interface_guid: adapter.interface_guid.clone(),
                                family,
                                reason: error.to_string(),
                            }),
                        }
                    }
                    Ok(_) => {
                        skipped_stack_count += 1;
                        remaining.push(DnsRestoreIssue {
                            interface_guid: adapter.interface_guid.clone(),
                            family,
                            reason: "current DNS value no longer matches the Vapour generation"
                                .to_owned(),
                        });
                    }
                    Err(error) => {
                        skipped_stack_count += 1;
                        remaining.push(DnsRestoreIssue {
                            interface_guid: adapter.interface_guid.clone(),
                            family,
                            reason: error.to_string(),
                        });
                    }
                }
            }
        }

        if !remaining.is_empty() {
            return Err(DnsConfigurationError::RestoreIncomplete {
                restored_stack_count,
                skipped_stack_count,
                remaining,
            });
        }

        match fs::remove_file(journal_path) {
            Ok(()) => Ok(DnsRestoreResult {
                restored_stack_count,
                skipped_stack_count,
                remaining,
                journal_removed: true,
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                Err(DnsConfigurationError::JournalCleanupFailed {
                    restored_stack_count,
                    path_error: "journal disappeared before cleanup".to_owned(),
                })
            }
            Err(error) => Err(DnsConfigurationError::JournalCleanupFailed {
                restored_stack_count,
                path_error: error.to_string(),
            }),
        }
    }
}

/// Read and validate a recovery journal without changing adapter settings.
pub fn read_journal(path: &Path) -> Result<Option<DnsRecoveryJournal>, DnsConfigurationError> {
    let Some(bytes) = read_bounded_file(path)? else {
        return Ok(None);
    };
    let journal: DnsRecoveryJournal = serde_json::from_slice(&bytes)
        .map_err(|error| DnsConfigurationError::JournalInvalid(error.to_string()))?;
    validate_journal(&journal)?;
    Ok(Some(journal))
}

fn validate_snapshot(snapshot: &DnsSnapshot) -> Result<(), DnsConfigurationError> {
    if snapshot.source != SOURCE {
        return Err(DnsConfigurationError::InvalidSnapshot(
            "unexpected DNS snapshot source".to_owned(),
        ));
    }
    if snapshot.adapters.len() > MAX_ADAPTERS {
        return Err(DnsConfigurationError::InvalidSnapshot(
            "interface count exceeds the bounded limit".to_owned(),
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for adapter in &snapshot.adapters {
        let guid = canonical_guid(&adapter.interface_guid)
            .map_err(|reason| DnsConfigurationError::InvalidSnapshot(reason.to_owned()))?;
        if !seen.insert(guid) {
            return Err(DnsConfigurationError::InvalidSnapshot(
                "duplicate interface GUID".to_owned(),
            ));
        }
        if adapter.interface_index == 0 {
            return Err(DnsConfigurationError::InvalidSnapshot(
                "interface index is zero".to_owned(),
            ));
        }
        validate_setting(&adapter.ipv4, &DnsFamily::Ipv4)?;
        validate_setting(&adapter.ipv6, &DnsFamily::Ipv6)?;
    }
    Ok(())
}

fn validate_setting(setting: &DnsSetting, family: &DnsFamily) -> Result<(), DnsConfigurationError> {
    if let DnsSetting::Static { servers } = setting {
        if servers.is_empty() || servers.len() > MAX_DNS_SERVERS {
            return Err(DnsConfigurationError::InvalidSnapshot(
                "static DNS server count is outside the bounded range".to_owned(),
            ));
        }
        if servers.iter().any(|server| !family.accepts(*server)) {
            return Err(DnsConfigurationError::InvalidSnapshot(
                "static DNS server family does not match its stack".to_owned(),
            ));
        }
    }
    Ok(())
}

fn normalized_loopback_servers(
    desired_servers: &[IpAddr],
) -> Result<Vec<IpAddr>, DnsConfigurationError> {
    if desired_servers.is_empty() || desired_servers.len() > 2 {
        return Err(DnsConfigurationError::InvalidLoopbackServer {
            address: "the loopback DNS list must contain one IPv4 and/or one IPv6 listener"
                .to_owned(),
        });
    }
    let mut servers = desired_servers.to_vec();
    for server in &servers {
        if *server != LOOPBACK_IPV4 && *server != LOOPBACK_IPV6 {
            return Err(DnsConfigurationError::InvalidLoopbackServer {
                address: server.to_string(),
            });
        }
    }
    servers.sort_unstable();
    servers.dedup();
    Ok(servers)
}

fn generation_for(
    snapshot: &DnsSnapshot,
    desired: &[IpAddr],
) -> Result<String, DnsConfigurationError> {
    #[derive(Serialize)]
    struct GenerationInput<'a> {
        snapshot: &'a DnsSnapshot,
        desired: &'a [IpAddr],
    }
    let bytes = serde_json::to_vec(&GenerationInput { snapshot, desired })
        .map_err(|error| DnsConfigurationError::InvalidSnapshot(error.to_string()))?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn journal_from_plan(
    snapshot: &DnsSnapshot,
    plan: &DnsApplyPlan,
) -> Result<DnsRecoveryJournal, DnsConfigurationError> {
    let mut grouped: BTreeMap<String, DnsJournalAdapter> = BTreeMap::new();
    for operation in &plan.operations {
        let adapter = snapshot
            .adapters
            .iter()
            .find(|adapter| {
                canonical_guid(&adapter.interface_guid)
                    .map(|guid| guid == operation.interface_guid)
                    .unwrap_or(false)
            })
            .ok_or_else(|| {
                DnsConfigurationError::InvalidSnapshot(
                    "plan refers to an interface absent from the snapshot".to_owned(),
                )
            })?;
        let entry = grouped
            .entry(operation.interface_guid.clone())
            .or_insert_with(|| DnsJournalAdapter {
                interface_guid: operation.interface_guid.clone(),
                interface_index: adapter.interface_index,
                interface_type: adapter.interface_type,
                operational_status: adapter.operational_status,
                media_connect_state: adapter.media_connect_state,
                ipv4: None,
                ipv6: None,
            });
        let stack = DnsJournalStack {
            original: operation.original.clone(),
            applied_servers: operation.desired_servers.clone(),
        };
        match operation.family {
            DnsFamily::Ipv4 => entry.ipv4 = Some(stack),
            DnsFamily::Ipv6 => entry.ipv6 = Some(stack),
        }
    }
    let journal = DnsRecoveryJournal {
        format_version: JOURNAL_FORMAT_VERSION,
        source: SOURCE.to_owned(),
        generation: plan.generation.clone(),
        created_at_unix_secs: now_unix_secs(),
        adapters: grouped.into_values().collect(),
    };
    validate_journal(&journal)?;
    Ok(journal)
}

fn present_families(adapter: &DnsJournalAdapter) -> Vec<DnsFamily> {
    let mut families = Vec::with_capacity(2);
    if adapter.ipv4.is_some() {
        families.push(DnsFamily::Ipv4);
    }
    if adapter.ipv6.is_some() {
        families.push(DnsFamily::Ipv6);
    }
    families
}

fn validate_journal(journal: &DnsRecoveryJournal) -> Result<(), DnsConfigurationError> {
    if journal.format_version != JOURNAL_FORMAT_VERSION {
        return Err(DnsConfigurationError::JournalInvalid(
            "unsupported recovery journal version".to_owned(),
        ));
    }
    if journal.source != SOURCE {
        return Err(DnsConfigurationError::JournalInvalid(
            "unexpected recovery journal source".to_owned(),
        ));
    }
    if journal.generation.len() != 64
        || !journal
            .generation
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(DnsConfigurationError::JournalInvalid(
            "generation is not a SHA-256 hexadecimal value".to_owned(),
        ));
    }
    if journal.adapters.is_empty() || journal.adapters.len() > MAX_ADAPTERS {
        return Err(DnsConfigurationError::JournalInvalid(
            "journal adapter count is outside the bounded range".to_owned(),
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for adapter in &journal.adapters {
        let guid = canonical_guid(&adapter.interface_guid)
            .map_err(|reason| DnsConfigurationError::JournalInvalid(reason.to_owned()))?;
        if !seen.insert(guid) {
            return Err(DnsConfigurationError::JournalInvalid(
                "journal contains a duplicate interface GUID".to_owned(),
            ));
        }
        if adapter.interface_index == 0 || (adapter.ipv4.is_none() && adapter.ipv6.is_none()) {
            return Err(DnsConfigurationError::JournalInvalid(
                "journal adapter has no usable identity or stack".to_owned(),
            ));
        }
        validate_journal_stack(adapter.ipv4.as_ref(), &DnsFamily::Ipv4)?;
        validate_journal_stack(adapter.ipv6.as_ref(), &DnsFamily::Ipv6)?;
    }
    Ok(())
}

fn validate_journal_stack(
    stack: Option<&DnsJournalStack>,
    family: &DnsFamily,
) -> Result<(), DnsConfigurationError> {
    let Some(stack) = stack else {
        return Ok(());
    };
    validate_setting(&stack.original, family)
        .map_err(|error| DnsConfigurationError::JournalInvalid(error.to_string()))?;
    if stack.applied_servers.is_empty()
        || stack.applied_servers.len() > 2
        || stack.applied_servers.iter().any(|server| {
            !family.accepts(*server) || (*server != LOOPBACK_IPV4 && *server != LOOPBACK_IPV6)
        })
    {
        return Err(DnsConfigurationError::JournalInvalid(
            "journal applied DNS list is not an approved loopback value".to_owned(),
        ));
    }
    if matches!(stack.original, DnsSetting::Unavailable { .. }) {
        return Err(DnsConfigurationError::JournalInvalid(
            "unavailable DNS settings cannot be placed in a recovery journal".to_owned(),
        ));
    }
    Ok(())
}

fn read_bounded_file(path: &Path) -> Result<Option<Vec<u8>>, DnsConfigurationError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(DnsConfigurationError::JournalIo(error.to_string())),
    };
    if let Ok(metadata) = file.metadata() {
        if metadata.len() > MAX_JOURNAL_BYTES as u64 {
            return Err(DnsConfigurationError::JournalTooLarge {
                actual: metadata.len(),
                maximum: MAX_JOURNAL_BYTES,
            });
        }
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_JOURNAL_BYTES.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| DnsConfigurationError::JournalIo(error.to_string()))?;
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(DnsConfigurationError::JournalTooLarge {
            actual: bytes.len() as u64,
            maximum: MAX_JOURNAL_BYTES,
        });
    }
    Ok(Some(bytes))
}

#[cfg(windows)]
fn persist_new_journal(
    path: &Path,
    journal: &DnsRecoveryJournal,
) -> Result<(), DnsConfigurationError> {
    let bytes = serde_json::to_vec(journal)
        .map_err(|error| DnsConfigurationError::JournalInvalid(error.to_string()))?;
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(DnsConfigurationError::JournalTooLarge {
            actual: bytes.len() as u64,
            maximum: MAX_JOURNAL_BYTES,
        });
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| DnsConfigurationError::JournalIo(error.to_string()))?;
    let file_name = path.file_name().ok_or_else(|| {
        DnsConfigurationError::JournalIo("journal path must contain a file name".to_owned())
    })?;

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
            Err(error) => return Err(DnsConfigurationError::JournalIo(error.to_string())),
        }
    }
    let temporary_path = temporary_path.ok_or_else(|| {
        DnsConfigurationError::JournalIo("could not allocate a journal temporary file".to_owned())
    })?;
    let mut temporary_file = temporary_file.expect("temporary journal path and file are paired");
    if let Err(error) = temporary_file
        .write_all(&bytes)
        .and_then(|_| temporary_file.sync_all())
    {
        drop(temporary_file);
        let _ = fs::remove_file(&temporary_path);
        return Err(DnsConfigurationError::JournalIo(error.to_string()));
    }
    drop(temporary_file);

    let result = atomic_install_new(&temporary_path, path)
        .map_err(|error| DnsConfigurationError::JournalIo(error.to_string()));
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

#[cfg(windows)]
fn atomic_install_new(temporary_path: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::{
        core::PCWSTR,
        Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH},
    };
    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
    let temporary = wide(temporary_path);
    let destination = wide(destination);
    unsafe {
        MoveFileExW(
            PCWSTR(temporary.as_ptr()),
            PCWSTR(destination.as_ptr()),
            MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(|_| io::Error::last_os_error())
}

/// Re-read immediately before restoration and verify the result. Windows has
/// no compare-and-set DNS API; an external writer can still race the setter,
/// but a change already visible here must never be overwritten by rollback.
fn restore_owned_setting(
    original: &DnsSetting,
    applied: &[IpAddr],
    mut read: impl FnMut() -> Result<DnsSetting, String>,
    mut write: impl FnMut(&DnsSetting) -> Result<(), String>,
) -> Result<(), String> {
    let current = read()?;
    if &current == original {
        return Ok(());
    }
    if current
        != (DnsSetting::Static {
            servers: applied.to_vec(),
        })
    {
        return Err("current DNS value no longer matches the Vapour generation".into());
    }
    write(original)?;
    if &read()? != original {
        return Err("Windows did not retain the restored DNS value".into());
    }
    Ok(())
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GuidParts {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

fn canonical_guid(value: &str) -> Result<String, &'static str> {
    let parts = parse_guid_parts(value)?;
    Ok(format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        parts.data1,
        parts.data2,
        parts.data3,
        parts.data4[0],
        parts.data4[1],
        parts.data4[2],
        parts.data4[3],
        parts.data4[4],
        parts.data4[5],
        parts.data4[6],
        parts.data4[7]
    ))
}

fn parse_guid_parts(value: &str) -> Result<GuidParts, &'static str> {
    let value = value.trim();
    let value = value
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .unwrap_or(value);
    if value.len() != 36
        || value.as_bytes().get(8) != Some(&b'-')
        || value.as_bytes().get(13) != Some(&b'-')
        || value.as_bytes().get(18) != Some(&b'-')
        || value.as_bytes().get(23) != Some(&b'-')
    {
        return Err("interface GUID has an invalid shape");
    }
    let data1 = u32::from_str_radix(&value[0..8], 16)
        .map_err(|_| "interface GUID has invalid hexadecimal digits")?;
    let data2 = u16::from_str_radix(&value[9..13], 16)
        .map_err(|_| "interface GUID has invalid hexadecimal digits")?;
    let data3 = u16::from_str_radix(&value[14..18], 16)
        .map_err(|_| "interface GUID has invalid hexadecimal digits")?;
    let mut data4 = [0u8; 8];
    for (index, byte) in data4.iter_mut().enumerate() {
        let start = if index < 2 {
            19 + index * 2
        } else {
            24 + (index - 2) * 2
        };
        *byte = u8::from_str_radix(&value[start..start + 2], 16)
            .map_err(|_| "interface GUID has invalid hexadecimal digits")?;
    }
    Ok(GuidParts {
        data1,
        data2,
        data3,
        data4,
    })
}

#[cfg(windows)]
mod windows_backend {
    use super::*;
    use windows::{
        core::{GUID, PCWSTR, PWSTR},
        Win32::{
            Foundation::{ERROR_PROC_NOT_FOUND, NO_ERROR},
            NetworkManagement::IpHelper::{
                FreeInterfaceDnsSettings, FreeMibTable, GetIfTable2, GetInterfaceDnsSettings,
                SetInterfaceDnsSettings, DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1,
                DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER, MIB_IF_ROW2, MIB_IF_TABLE2,
            },
        },
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum QueryError {
        Code(u32),
        InvalidData,
    }

    // The Windows DNS getter does not accept a family selector (the
    // documented contract says that Flags must be zero on input).  The
    // IPv6 NameServer value is therefore read from the documented
    // Tcpip6 interface registry key below.  These raw declarations avoid
    // enabling a separate windows crate feature just for a read-only query.
    type RegistryHandle = isize;

    const HKEY_LOCAL_MACHINE: RegistryHandle = -2_147_483_646;
    const KEY_READ: u32 = 0x0002_0019;
    const REG_SZ: u32 = 1;
    const ERROR_FILE_NOT_FOUND_CODE: u32 = 2;
    const ERROR_MORE_DATA_CODE: u32 = 234;
    const MAX_REGISTRY_VALUE_BYTES: usize = MAX_NATIVE_STRING_CHARS * 2 + 2;

    #[link(name = "Advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            key: RegistryHandle,
            sub_key: PCWSTR,
            options: u32,
            sam_desired: u32,
            result: *mut RegistryHandle,
        ) -> u32;
        fn RegQueryValueExW(
            key: RegistryHandle,
            value_name: PCWSTR,
            reserved: *mut u32,
            value_type: *mut u32,
            data: *mut u8,
            data_size: *mut u32,
        ) -> u32;
        fn RegCloseKey(key: RegistryHandle) -> u32;
    }

    impl QueryError {
        fn unavailable_reason(self) -> DnsUnavailableReason {
            match self {
                Self::Code(code) if code == ERROR_PROC_NOT_FOUND.0 => {
                    DnsUnavailableReason::Unsupported
                }
                Self::Code(code) => DnsUnavailableReason::QueryFailed { code },
                Self::InvalidData => DnsUnavailableReason::InvalidData,
            }
        }
    }

    pub fn snapshot() -> Result<DnsSnapshot, DnsConfigurationError> {
        unsafe {
            let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
            let result = GetIfTable2(&mut table);
            if result.0 != NO_ERROR.0 {
                return Err(DnsConfigurationError::NativeSnapshot { code: result.0 });
            }
            if table.is_null() {
                return Err(DnsConfigurationError::InvalidSnapshot(
                    "Windows returned a null interface table".to_owned(),
                ));
            }
            let _guard = TableGuard(table);
            let count = (*table).NumEntries as usize;
            if count > MAX_ADAPTERS {
                return Err(DnsConfigurationError::InvalidSnapshot(format!(
                    "Windows returned {count} interfaces; maximum is {MAX_ADAPTERS}"
                )));
            }

            let rows: &[MIB_IF_ROW2] = if count == 0 {
                &[]
            } else {
                std::slice::from_raw_parts((*table).Table.as_ptr(), count)
            };
            let mut adapters = Vec::with_capacity(count);
            for row in rows {
                if row.InterfaceGuid == GUID::zeroed() || row.InterfaceIndex == 0 {
                    continue;
                }
                let guid = format_guid(row.InterfaceGuid);
                let ipv4 = query_stack(row.InterfaceGuid).unwrap_or_else(|error| {
                    DnsSetting::Unavailable {
                        reason: error.unavailable_reason(),
                    }
                });
                let ipv6 = query_registry_stack(row.InterfaceGuid).unwrap_or_else(|error| {
                    DnsSetting::Unavailable {
                        reason: error.unavailable_reason(),
                    }
                });
                adapters.push(AdapterDnsSnapshot {
                    interface_guid: guid,
                    interface_index: row.InterfaceIndex,
                    interface_type: row.Type,
                    operational_status: row.OperStatus.0 as u32,
                    media_connect_state: row.MediaConnectState.0 as u32,
                    ipv4,
                    ipv6,
                });
            }
            Ok(DnsSnapshot {
                source: SOURCE.to_owned(),
                sampled_at_unix_secs: now_unix_secs(),
                adapters,
            })
        }
    }

    struct TableGuard(*mut MIB_IF_TABLE2);

    impl Drop for TableGuard {
        fn drop(&mut self) {
            unsafe {
                if !self.0.is_null() {
                    FreeMibTable(self.0.cast());
                }
            }
        }
    }

    pub fn parse_guid(value: &str) -> Result<GUID, &'static str> {
        let parts = parse_guid_parts(value)?;
        Ok(GUID::from_values(
            parts.data1,
            parts.data2,
            parts.data3,
            parts.data4,
        ))
    }

    fn format_guid(guid: GUID) -> String {
        format!(
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
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
            guid.data4[7]
        )
    }

    /// Query the IPv4 stack through the documented native API.  Get accepts
    /// only Version on input; in particular, Flags must remain zero.
    fn query_stack(guid: GUID) -> Result<DnsSetting, QueryError> {
        unsafe {
            let mut settings = DNS_INTERFACE_SETTINGS::default();
            settings.Version = DNS_INTERFACE_SETTINGS_VERSION1;
            settings.Flags = 0;
            let result = GetInterfaceDnsSettings(guid, &mut settings);
            if result.0 != NO_ERROR.0 {
                return Err(QueryError::Code(result.0));
            }
            let parsed = decode_settings(&settings, &DnsFamily::Ipv4);
            FreeInterfaceDnsSettings(&mut settings);
            parsed
        }
    }

    fn decode_settings(
        settings: &DNS_INTERFACE_SETTINGS,
        family: &DnsFamily,
    ) -> Result<DnsSetting, QueryError> {
        let text = read_pwstr(settings.NameServer)?;
        // Flags is an input selector for Set and is required to be zero for
        // Get.  It is consequently not an ownership/static indicator here;
        // a successful getter may return a non-empty NameServer with Flags=0.
        match text {
            None => Ok(DnsSetting::Automatic),
            Some(text) if text.trim().is_empty() => Ok(DnsSetting::Automatic),
            Some(text) => {
                let servers = parse_server_list(&text, family)?;
                Ok(DnsSetting::Static { servers })
            }
        }
    }

    /// Read the per-family adapter NameServer registry value without
    /// modifying it.  The TCPIP6 value is the documented source for the
    /// IPv6 static list; a missing value on an existing interface key means
    /// that family is automatic, while a missing interface key is reported
    /// as unavailable rather than guessed to be automatic.
    fn query_registry_stack(guid: GUID) -> Result<DnsSetting, QueryError> {
        let guid = format_guid(guid);
        let service = "Tcpip6";
        let sub_key = format!(
            "SYSTEM\\CurrentControlSet\\Services\\{service}\\Parameters\\Interfaces\\{{{guid}}}"
        );
        let sub_key_wide: Vec<u16> = sub_key.encode_utf16().chain(std::iter::once(0)).collect();
        let mut key: RegistryHandle = 0;
        let open_result = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(sub_key_wide.as_ptr()),
                0,
                KEY_READ,
                &mut key,
            )
        };
        if open_result != 0 {
            return Err(QueryError::Code(open_result));
        }
        if key == 0 {
            return Err(QueryError::InvalidData);
        }
        let _key_guard = RegistryKey(key);

        let value_name: Vec<u16> = "NameServer"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut value_type = 0u32;
        let mut value_size = 0u32;
        let query_result = unsafe {
            RegQueryValueExW(
                key,
                PCWSTR(value_name.as_ptr()),
                std::ptr::null_mut(),
                &mut value_type,
                std::ptr::null_mut(),
                &mut value_size,
            )
        };
        if query_result == ERROR_FILE_NOT_FOUND_CODE {
            return Ok(DnsSetting::Automatic);
        }
        if query_result != 0 {
            return Err(QueryError::Code(query_result));
        }
        if value_type != REG_SZ {
            return Err(QueryError::InvalidData);
        }
        if value_size == 0 {
            return Ok(DnsSetting::Automatic);
        }
        if value_size as usize > MAX_REGISTRY_VALUE_BYTES || value_size % 2 != 0 {
            return Err(QueryError::InvalidData);
        }

        let mut bytes = vec![0u8; value_size as usize];
        let mut actual_size = value_size;
        let query_result = unsafe {
            RegQueryValueExW(
                key,
                PCWSTR(value_name.as_ptr()),
                std::ptr::null_mut(),
                &mut value_type,
                bytes.as_mut_ptr(),
                &mut actual_size,
            )
        };
        if query_result == ERROR_MORE_DATA_CODE || query_result != 0 {
            return Err(QueryError::Code(query_result));
        }
        if value_type != REG_SZ
            || actual_size == 0
            || actual_size as usize > bytes.len()
            || actual_size % 2 != 0
        {
            return Err(QueryError::InvalidData);
        }

        let units: Vec<u16> = bytes[..actual_size as usize]
            .chunks_exact(2)
            .map(|pair| u16::from_ne_bytes([pair[0], pair[1]]))
            .collect();
        let Some(terminator) = units.iter().position(|unit| *unit == 0) else {
            return Err(QueryError::InvalidData);
        };
        if units[terminator + 1..].iter().any(|unit| *unit != 0) {
            return Err(QueryError::InvalidData);
        }
        let text = String::from_utf16(&units[..terminator]).map_err(|_| QueryError::InvalidData)?;
        if text.trim().is_empty() {
            Ok(DnsSetting::Automatic)
        } else {
            let servers = parse_server_list(&text, &DnsFamily::Ipv6)?;
            Ok(DnsSetting::Static { servers })
        }
    }

    struct RegistryKey(RegistryHandle);

    impl Drop for RegistryKey {
        fn drop(&mut self) {
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }

    fn read_pwstr(pointer: PWSTR) -> Result<Option<String>, QueryError> {
        if pointer.0.is_null() {
            return Ok(None);
        }
        unsafe {
            for length in 0..MAX_NATIVE_STRING_CHARS {
                if pointer.0.add(length).read() == 0 {
                    let slice = std::slice::from_raw_parts(pointer.0, length);
                    return String::from_utf16(slice)
                        .map(Some)
                        .map_err(|_| QueryError::InvalidData);
                }
            }
        }
        Err(QueryError::InvalidData)
    }

    fn parse_server_list(text: &str, family: &DnsFamily) -> Result<Vec<IpAddr>, QueryError> {
        let mut servers = Vec::new();
        for token in
            text.split(|character: char| character == ',' || character.is_ascii_whitespace())
        {
            if token.is_empty() {
                continue;
            }
            let address = token
                .parse::<IpAddr>()
                .map_err(|_| QueryError::InvalidData)?;
            if !family.accepts(address) || servers.len() >= MAX_DNS_SERVERS {
                return Err(QueryError::InvalidData);
            }
            servers.push(address);
        }
        if servers.is_empty() {
            return Err(QueryError::InvalidData);
        }
        Ok(servers)
    }

    pub fn set_operation(operation: &DnsOperation) -> Result<(), DnsConfigurationError> {
        let guid = parse_guid(&operation.interface_guid)
            .map_err(|reason| DnsConfigurationError::InvalidSnapshot(reason.to_owned()))?;
        set_setting(
            guid,
            operation.family.clone(),
            &DnsSetting::Static {
                servers: operation.desired_servers.clone(),
            },
        )
    }

    pub fn set_original(operation: &DnsOperation) -> Result<(), String> {
        let guid = parse_guid(&operation.interface_guid).map_err(str::to_owned)?;
        restore_owned_setting(
            &operation.original,
            &operation.desired_servers,
            || get_stack(guid, operation.family.clone()).map_err(|e| e.to_string()),
            |setting| {
                set_setting(guid, operation.family.clone(), setting).map_err(|e| e.to_string())
            },
        )
    }

    pub fn get_stack(guid: GUID, family: DnsFamily) -> Result<DnsSetting, DnsConfigurationError> {
        let queried = match family.clone() {
            DnsFamily::Ipv4 => query_stack(guid),
            DnsFamily::Ipv6 => query_registry_stack(guid),
        };
        queried.map_err(|error| match error {
            QueryError::Code(code) => DnsConfigurationError::NativeQuery {
                interface_guid: format_guid(guid),
                family,
                code,
            },
            QueryError::InvalidData => DnsConfigurationError::InvalidSnapshot(
                "Windows returned malformed DNS interface data".to_owned(),
            ),
        })
    }

    pub fn set_setting(
        guid: GUID,
        family: DnsFamily,
        setting: &DnsSetting,
    ) -> Result<(), DnsConfigurationError> {
        let servers = match setting {
            DnsSetting::Automatic => Vec::new(),
            DnsSetting::Static { servers } => servers.clone(),
            DnsSetting::Unavailable { .. } => {
                return Err(DnsConfigurationError::InvalidSnapshot(
                    "cannot write an unavailable DNS setting".to_owned(),
                ))
            }
        };
        if servers.len() > MAX_DNS_SERVERS || servers.iter().any(|server| !family.accepts(*server))
        {
            return Err(DnsConfigurationError::InvalidSnapshot(
                "DNS server list is outside the bounded family-specific range".to_owned(),
            ));
        }

        // An empty, terminated NameServer string asks Windows to remove an
        // adapter-specific list and resume its automatic/DHCP behavior.
        let text = servers
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        let mut wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let mut settings = DNS_INTERFACE_SETTINGS::default();
        settings.Version = DNS_INTERFACE_SETTINGS_VERSION1;
        settings.Flags = DNS_SETTING_NAMESERVER as u64
            | if family.is_ipv6() {
                DNS_SETTING_IPV6 as u64
            } else {
                0
            };
        settings.NameServer = PWSTR(wide.as_mut_ptr());
        let result = unsafe { SetInterfaceDnsSettings(guid, &settings) };
        if result.0 == NO_ERROR.0 {
            Ok(())
        } else {
            Err(DnsConfigurationError::NativeSet {
                interface_guid: format_guid(guid),
                family,
                code: result.0,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rollback_preserves_external_dns_changes_and_verifies_its_write() {
        let original = DnsSetting::Automatic;
        let owned = DnsSetting::Static {
            servers: vec![LOOPBACK_IPV4],
        };
        let external = DnsSetting::Static {
            servers: vec!["192.0.2.53".parse().unwrap()],
        };
        let mut writes = 0;
        assert!(restore_owned_setting(
            &original,
            &[LOOPBACK_IPV4],
            || Ok(external.clone()),
            |_| {
                writes += 1;
                Ok(())
            }
        )
        .is_err());
        assert_eq!(writes, 0);
        assert!(restore_owned_setting(
            &original,
            &[LOOPBACK_IPV4],
            || Ok(original.clone()),
            |_| {
                writes += 1;
                Ok(())
            }
        )
        .is_ok());
        assert_eq!(writes, 0);
        // A successful native setter is insufficient if policy overrides it.
        assert!(restore_owned_setting(
            &original,
            &[LOOPBACK_IPV4],
            || Ok(owned.clone()),
            |_| {
                writes += 1;
                Ok(())
            }
        )
        .is_err());
        assert_eq!(writes, 1);
        let mut reads = [owned, original.clone()].into_iter();
        assert!(restore_owned_setting(
            &original,
            &[LOOPBACK_IPV4],
            || Ok(reads.next().unwrap()),
            |_| {
                writes += 1;
                Ok(())
            }
        )
        .is_ok());
        assert_eq!(writes, 2);
    }
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    fn adapter(guid: &str, index: u32) -> AdapterDnsSnapshot {
        AdapterDnsSnapshot {
            interface_guid: guid.to_owned(),
            interface_index: index,
            interface_type: 6,
            operational_status: 2,
            media_connect_state: 2,
            ipv4: DnsSetting::Automatic,
            ipv6: DnsSetting::Static {
                servers: vec!["2001:4860:4860::8888".parse().unwrap()],
            },
        }
    }

    fn test_snapshot() -> DnsSnapshot {
        DnsSnapshot {
            source: SOURCE.to_owned(),
            sampled_at_unix_secs: 1,
            adapters: vec![
                adapter("11111111-2222-3333-4455-66778899AABB", 1),
                AdapterDnsSnapshot {
                    interface_guid: "AAAAAAAA-BBBB-CCCC-DDEE-FF0011223344".to_owned(),
                    interface_index: 2,
                    interface_type: 131,
                    operational_status: 1,
                    media_connect_state: 1,
                    ipv4: DnsSetting::Unavailable {
                        reason: DnsUnavailableReason::QueryFailed { code: 5 },
                    },
                    ipv6: DnsSetting::Automatic,
                },
            ],
        }
    }

    #[test]
    fn plan_keeps_static_and_automatic_modes_for_each_family() {
        let result = plan(&test_snapshot(), &[LOOPBACK_IPV4, LOOPBACK_IPV6]).unwrap();
        assert_eq!(result.operations.len(), 3);
        let ipv4 = result
            .operations
            .iter()
            .find(|operation| operation.interface_guid.starts_with("11111111"))
            .unwrap();
        assert_eq!(ipv4.family, DnsFamily::Ipv4);
        assert_eq!(ipv4.original, DnsSetting::Automatic);
        let ipv6 = result
            .operations
            .iter()
            .find(|operation| {
                operation.interface_guid.starts_with("11111111")
                    && operation.family == DnsFamily::Ipv6
            })
            .unwrap();
        assert_eq!(
            ipv6.original,
            DnsSetting::Static {
                servers: vec!["2001:4860:4860::8888".parse().unwrap()]
            }
        );
        assert!(result.skipped.iter().any(|entry| {
            entry.interface_guid.starts_with("AAAAAAAA")
                && entry.family == DnsFamily::Ipv4
                && matches!(entry.reason, DnsSkipReason::Unavailable(_))
        }));
    }

    #[test]
    fn plan_includes_disconnected_and_tunnel_adapters_without_filtering() {
        let result = plan(&test_snapshot(), &[LOOPBACK_IPV4]).unwrap();
        assert_eq!(result.operations.len(), 1);
        assert_eq!(result.operations[0].interface_index, 1);
        assert!(result.skipped.iter().any(|entry| {
            entry.interface_guid.starts_with("AAAAAAAA") && entry.family == DnsFamily::Ipv4
        }));
        assert!(result.skipped.iter().any(|entry| {
            entry.interface_guid.starts_with("11111111")
                && entry.family == DnsFamily::Ipv6
                && matches!(entry.reason, DnsSkipReason::NoLoopbackServer)
        }));
    }

    #[test]
    fn plan_rejects_arbitrary_upstream_and_invalid_family_values() {
        assert!(matches!(
            plan(&test_snapshot(), &["8.8.8.8".parse().unwrap()]),
            Err(DnsConfigurationError::InvalidLoopbackServer { .. })
        ));
        let mut malformed = test_snapshot();
        malformed.adapters[0].ipv4 = DnsSetting::Static {
            servers: vec!["::1".parse().unwrap()],
        };
        assert!(matches!(
            plan(&malformed, &[LOOPBACK_IPV4]),
            Err(DnsConfigurationError::InvalidSnapshot(_))
        ));
    }

    #[test]
    fn already_applied_values_are_skipped_without_claiming_ownership() {
        let mut snapshot = test_snapshot();
        snapshot.adapters.truncate(1);
        snapshot.adapters[0].ipv4 = DnsSetting::Static {
            servers: vec![LOOPBACK_IPV4],
        };
        let result = plan(&snapshot, &[LOOPBACK_IPV4]).unwrap();
        assert!(result.operations.is_empty());
        assert!(result.skipped.iter().any(|entry| {
            entry.interface_guid.starts_with("11111111")
                && entry.family == DnsFamily::Ipv4
                && matches!(entry.reason, DnsSkipReason::AlreadyApplied)
        }));
    }

    #[test]
    fn journal_round_trip_preserves_original_and_applied_values() {
        let snapshot = test_snapshot();
        let plan = plan(&snapshot, &[LOOPBACK_IPV4, LOOPBACK_IPV6]).unwrap();
        let journal = journal_from_plan(&snapshot, &plan).unwrap();
        let bytes = serde_json::to_vec(&journal).unwrap();
        assert!(bytes.len() < MAX_JOURNAL_BYTES);
        let restored: DnsRecoveryJournal = serde_json::from_slice(&bytes).unwrap();
        validate_journal(&restored).unwrap();
        assert_eq!(restored, journal);
        let static_stack = restored
            .adapters
            .iter()
            .find(|adapter| adapter.interface_guid.starts_with("11111111"))
            .unwrap()
            .ipv6
            .as_ref()
            .unwrap();
        assert_eq!(
            static_stack.original,
            DnsSetting::Static {
                servers: vec!["2001:4860:4860::8888".parse().unwrap()]
            }
        );
        assert_eq!(static_stack.applied_servers, vec![LOOPBACK_IPV6]);
    }

    #[test]
    fn journal_validation_rejects_unknown_generation_or_unavailable_original() {
        let snapshot = test_snapshot();
        let plan = plan(&snapshot, &[LOOPBACK_IPV4]).unwrap();
        let mut journal = journal_from_plan(&snapshot, &plan).unwrap();
        journal.generation = "not-a-generation".to_owned();
        assert!(matches!(
            validate_journal(&journal),
            Err(DnsConfigurationError::JournalInvalid(_))
        ));

        let mut journal = journal_from_plan(&snapshot, &plan).unwrap();
        journal
            .adapters
            .iter_mut()
            .find(|adapter| adapter.interface_guid.starts_with("11111111"))
            .unwrap()
            .ipv4
            .as_mut()
            .unwrap()
            .original = DnsSetting::Unavailable {
            reason: DnsUnavailableReason::InvalidData,
        };
        journal.generation = "a".repeat(64);
        assert!(matches!(
            validate_journal(&journal),
            Err(DnsConfigurationError::JournalInvalid(_))
        ));
    }

    #[test]
    fn read_journal_rejects_files_over_the_bound_before_parsing() {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "vapour-dns-journal-bound-{}-{id}.json",
            std::process::id()
        ));
        fs::write(&path, vec![b'x'; MAX_JOURNAL_BYTES + 1]).unwrap();
        assert!(matches!(
            read_journal(&path),
            Err(DnsConfigurationError::JournalTooLarge { .. })
        ));
        let _ = fs::remove_file(path);
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "read-only Windows DNS enumeration; run explicitly on an isolated host"]
    fn live_snapshot_reports_counts_without_identifiers() {
        let value = snapshot().expect("read-only Windows DNS snapshot should succeed");
        let static_stacks = value
            .adapters
            .iter()
            .flat_map(|adapter| [&adapter.ipv4, &adapter.ipv6])
            .filter(|setting| matches!(setting, DnsSetting::Static { .. }))
            .count();
        let unavailable_stacks = value
            .adapters
            .iter()
            .flat_map(|adapter| [&adapter.ipv4, &adapter.ipv6])
            .filter(|setting| matches!(setting, DnsSetting::Unavailable { .. }))
            .count();
        println!(
            "read-only DNS snapshot: adapters={}, static_stacks={}, unavailable_stacks={}",
            value.adapters.len(),
            static_stacks,
            unavailable_stacks
        );
    }
}
