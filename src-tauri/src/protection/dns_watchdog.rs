//! Crash-recovery watchdog for the per-interface DNS recovery journal.
//!
//! The parent process launches this same executable in an internal watchdog
//! mode after it has selected its fixed app-data journal path. The watchdog
//! receives the parent PID and its FILETIME creation value, opens that exact
//! process, verifies the creation value, and waits on the resulting handle.
//! It never polls a PID and therefore cannot mistake a reused PID for the
//! original parent. No DNS operation is attempted until that verified handle
//! is signalled as exited.
//!
//! Integration contract:
//! - `parent_creation_time_100ns` is the `GetProcessTimes` creation FILETIME
//!   represented as `(dwHighDateTime << 32) | dwLowDateTime`.
//! - The caller supplies an absolute path selected internally from the app's
//!   fixed app-data directory. It must not be a path accepted from a UI or
//!   arbitrary user input.
//! - The parent should first try `dns_configuration::restore`, wait for its
//!   journal to disappear, and then exit. If the process crashes or that
//!   planned shutdown restore fails, this watchdog performs the bounded
//!   recovery loop after the verified process handle signals termination.
//! - The helper should be launched with `CREATE_NO_WINDOW` (and hidden startup
//!   information if a shell launch path is used). It should inherit the
//!   parent's token/elevation; this module never prompts for UAC or changes
//!   privileges.

use super::dns_configuration::{self, DnsConfigurationError, DnsRestoreResult};
use std::{
    fmt,
    path::{Component, Path},
    time::Duration,
};

/// Maximum number of journal reads/restore attempts after the parent exits.
/// A persistent error is returned after this bound instead of keeping a
/// hidden helper alive indefinitely.
pub const MAX_RESTORE_ATTEMPTS: u32 = 8;

/// Delay between bounded restore attempts. Native DNS calls themselves are
/// synchronous; the retry count and delay keep the watchdog's recovery phase
/// bounded even when the network stack is unavailable.
pub const RESTORE_RETRY_DELAY: Duration = Duration::from_millis(250);

/// The wait interval is only a responsiveness bound while the verified
/// process handle remains signalled as alive. It does not turn into PID
/// polling and does not limit the parent's lifetime.
pub const PARENT_WAIT_SLICE_MS: u32 = 500;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsWatchdogError {
    UnsupportedPlatform,
    InvalidParentIdentity,
    InvalidJournalPath(String),
    ParentOpen { code: u32 },
    ParentCreationTime { code: u32 },
    ParentWait { code: u32 },
    ReadyFailed { reason: String },
}

impl fmt::Display for DnsWatchdogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                write!(formatter, "DNS recovery watchdog requires Windows")
            }
            Self::InvalidParentIdentity => write!(
                formatter,
                "watchdog parent PID and creation FILETIME must both be non-zero"
            ),
            Self::InvalidJournalPath(reason) => {
                write!(
                    formatter,
                    "DNS watchdog journal path is not trusted: {reason}"
                )
            }
            Self::ParentOpen { code } => {
                write!(
                    formatter,
                    "watchdog could not open the parent process ({code})"
                )
            }
            Self::ParentCreationTime { code } => write!(
                formatter,
                "watchdog could not query the parent creation time ({code})"
            ),
            Self::ParentWait { code } => {
                write!(
                    formatter,
                    "watchdog could not wait on the parent process ({code})"
                )
            }
            Self::ReadyFailed { reason } => {
                write!(formatter, "watchdog readiness signal failed: {reason}")
            }
        }
    }
}

impl std::error::Error for DnsWatchdogError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsWatchdogOutcome {
    /// The PID currently names a different process. No journal was read for
    /// restoration and no DNS mutation was attempted.
    ParentIdentityMismatch,
    /// The verified parent exited and no valid recovery journal remains.
    ParentExitedWithoutJournal,
    /// The journal was restored and removed by the owned DNS module.
    Restored {
        attempts: u32,
        result: DnsRestoreResult,
    },
    /// The bounded retry budget was exhausted. The journal remains available
    /// for a later trusted recovery attempt, and the caller must surface this
    /// as a persistent recovery error.
    PersistentRestoreFailure { attempts: u32, last_error: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParentWaitState {
    Alive,
    Exited,
}

/// Compare the creation value obtained from the opened process with the value
/// captured by the parent before launch. Equality is required; a missing or
/// zero value is never accepted.
pub fn parent_identity_matches(expected_creation_time_100ns: u64, observed: Option<u64>) -> bool {
    expected_creation_time_100ns != 0 && observed == Some(expected_creation_time_100ns)
}

/// The only state in which a watchdog may restore is an exited, verified
/// parent with a journal that is present and valid.
pub fn should_restore_after_parent_exit(
    parent_state: ParentWaitState,
    journal_present: bool,
) -> bool {
    matches!(parent_state, ParentWaitState::Exited) && journal_present
}

/// Run the crash-recovery helper for a verified parent process.
///
/// This function is intentionally the only entry point that can invoke
/// `dns_configuration::restore`. Callers should expose it only through an
/// internal same-executable CLI mode and pass the fixed app-data journal path
/// selected by trusted startup code.
pub fn run(
    parent_pid: u32,
    parent_creation_time_100ns: u64,
    journal_path: &Path,
) -> Result<DnsWatchdogOutcome, DnsWatchdogError> {
    run_with_ready(parent_pid, parent_creation_time_100ns, journal_path, || {
        Ok(())
    })
}

/// Run the watchdog and invoke `ready` after the parent handle has been
/// opened and its creation FILETIME has been verified. The callback is a
/// readiness/handshake hook only; it runs before the wait and before any
/// possible DNS restore. A callback error terminates the helper without
/// reading or mutating DNS settings.
pub fn run_with_ready<F>(
    parent_pid: u32,
    parent_creation_time_100ns: u64,
    journal_path: &Path,
    ready: F,
) -> Result<DnsWatchdogOutcome, DnsWatchdogError>
where
    F: FnOnce() -> Result<(), String>,
{
    validate_inputs(parent_pid, parent_creation_time_100ns, journal_path)?;

    #[cfg(not(windows))]
    {
        let _ = (parent_pid, parent_creation_time_100ns, journal_path, ready);
        Err(DnsWatchdogError::UnsupportedPlatform)
    }

    #[cfg(windows)]
    {
        windows_backend::run(parent_pid, parent_creation_time_100ns, journal_path, ready)
    }
}

fn validate_inputs(
    parent_pid: u32,
    parent_creation_time_100ns: u64,
    journal_path: &Path,
) -> Result<(), DnsWatchdogError> {
    if parent_pid == 0 || parent_creation_time_100ns == 0 {
        return Err(DnsWatchdogError::InvalidParentIdentity);
    }
    if !journal_path.is_absolute() {
        return Err(DnsWatchdogError::InvalidJournalPath(
            "the path must be absolute".to_owned(),
        ));
    }
    if journal_path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(DnsWatchdogError::InvalidJournalPath(
            "parent-directory components are not accepted".to_owned(),
        ));
    }
    if journal_path.file_name().is_none() {
        return Err(DnsWatchdogError::InvalidJournalPath(
            "the path must name a journal file".to_owned(),
        ));
    }
    Ok(())
}

fn restore_after_exit(journal_path: &Path) -> Result<DnsWatchdogOutcome, DnsWatchdogError> {
    let mut last_error = None;
    for attempt in 1..=MAX_RESTORE_ATTEMPTS {
        match dns_configuration::read_journal(journal_path) {
            Ok(None) => return Ok(DnsWatchdogOutcome::ParentExitedWithoutJournal),
            Ok(Some(_)) => {}
            Err(error) if !retryable_read_error(&error) => {
                return Ok(DnsWatchdogOutcome::PersistentRestoreFailure {
                    attempts: attempt,
                    last_error: error.to_string(),
                });
            }
            Err(error) => {
                last_error = Some(error.to_string());
                if attempt == MAX_RESTORE_ATTEMPTS {
                    break;
                }
                std::thread::sleep(RESTORE_RETRY_DELAY);
                continue;
            }
        }

        match dns_configuration::restore(journal_path) {
            Ok(result) if result.journal_removed => {
                return Ok(DnsWatchdogOutcome::Restored {
                    attempts: attempt,
                    result,
                });
            }
            Ok(result) => {
                last_error = Some(format!(
                    "DNS restore returned without removing its journal: {result:?}"
                ));
            }
            Err(DnsConfigurationError::JournalMissing) => {
                return Ok(DnsWatchdogOutcome::ParentExitedWithoutJournal);
            }
            Err(error) if !retryable_restore_error(&error) => {
                return Ok(DnsWatchdogOutcome::PersistentRestoreFailure {
                    attempts: attempt,
                    last_error: error.to_string(),
                });
            }
            Err(error) => {
                last_error = Some(error.to_string());
            }
        }

        if attempt < MAX_RESTORE_ATTEMPTS {
            std::thread::sleep(RESTORE_RETRY_DELAY);
        }
    }

    Ok(DnsWatchdogOutcome::PersistentRestoreFailure {
        attempts: MAX_RESTORE_ATTEMPTS,
        last_error: last_error.unwrap_or_else(|| "DNS restore retry budget exhausted".to_owned()),
    })
}

fn retryable_read_error(error: &DnsConfigurationError) -> bool {
    matches!(error, DnsConfigurationError::JournalIo(_))
}

fn retryable_restore_error(error: &DnsConfigurationError) -> bool {
    matches!(
        error,
        DnsConfigurationError::JournalIo(_)
            | DnsConfigurationError::RestoreIncomplete { .. }
            | DnsConfigurationError::JournalCleanupFailed { .. }
    )
}

#[cfg(windows)]
mod windows_backend {
    use super::*;
    use windows::Win32::{
        Foundation::{
            CloseHandle, GetLastError, FILETIME, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        System::Threading::{
            GetProcessTimes, OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_SYNCHRONIZE,
        },
    };

    pub fn run<F>(
        parent_pid: u32,
        parent_creation_time_100ns: u64,
        journal_path: &Path,
        ready: F,
    ) -> Result<DnsWatchdogOutcome, DnsWatchdogError>
    where
        F: FnOnce() -> Result<(), String>,
    {
        if parent_pid == std::process::id() {
            return Err(DnsWatchdogError::InvalidParentIdentity);
        }

        let access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE;
        let handle = unsafe { OpenProcess(access, false, parent_pid) }.map_err(|error| {
            DnsWatchdogError::ParentOpen {
                code: error.code().0 as u32,
            }
        })?;
        let guard = ProcessHandle(handle);
        let observed_creation = process_creation_time(guard.0)
            .map_err(|code| DnsWatchdogError::ParentCreationTime { code })?;
        if !parent_identity_matches(parent_creation_time_100ns, Some(observed_creation)) {
            return Ok(DnsWatchdogOutcome::ParentIdentityMismatch);
        }

        ready().map_err(|reason| DnsWatchdogError::ReadyFailed { reason })?;

        loop {
            let result = unsafe { WaitForSingleObject(guard.0, PARENT_WAIT_SLICE_MS) };
            if result == WAIT_OBJECT_0 {
                break;
            }
            if result == WAIT_TIMEOUT {
                continue;
            }
            let code = if result == WAIT_FAILED {
                unsafe { GetLastError().0 }
            } else {
                result.0
            };
            return Err(DnsWatchdogError::ParentWait { code });
        }

        restore_after_exit(journal_path)
    }

    fn process_creation_time(handle: HANDLE) -> Result<u64, u32> {
        unsafe {
            let (mut creation, mut exit, mut kernel, mut user) = (
                FILETIME::default(),
                FILETIME::default(),
                FILETIME::default(),
                FILETIME::default(),
            );
            GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user)
                .map_err(|error| error.code().0 as u32)?;
            Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
        }
    }

    struct ProcessHandle(HANDLE);

    impl Drop for ProcessHandle {
        fn drop(&mut self) {
            unsafe {
                if !self.0.is_invalid() {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
    };

    #[test]
    fn creation_time_mismatch_is_rejected_without_an_observed_identity() {
        assert!(!parent_identity_matches(42, None));
        assert!(!parent_identity_matches(42, Some(41)));
        assert!(parent_identity_matches(42, Some(42)));
        assert!(!parent_identity_matches(0, Some(0)));
    }

    #[test]
    fn restore_requires_verified_parent_exit_and_a_present_journal() {
        assert!(!should_restore_after_parent_exit(
            ParentWaitState::Alive,
            true
        ));
        assert!(!should_restore_after_parent_exit(
            ParentWaitState::Exited,
            false
        ));
        assert!(should_restore_after_parent_exit(
            ParentWaitState::Exited,
            true
        ));
    }

    #[test]
    fn invalid_parent_or_relative_journal_is_rejected_before_platform_work() {
        let absolute = std::env::temp_dir().join("vapour-dns-recovery.json");
        assert!(matches!(
            validate_inputs(0, 1, &absolute),
            Err(DnsWatchdogError::InvalidParentIdentity)
        ));
        assert!(matches!(
            validate_inputs(1, 1, PathBuf::from("journal.json").as_path()),
            Err(DnsWatchdogError::InvalidJournalPath(_))
        ));
        assert!(validate_inputs(1, 1, &absolute).is_ok());
    }

    #[test]
    fn retry_budget_is_fixed_and_bounded() {
        assert_eq!(MAX_RESTORE_ATTEMPTS, 8);
        assert!(RESTORE_RETRY_DELAY <= Duration::from_secs(1));
    }

    #[cfg(windows)]
    fn spawn_hidden_test_child() -> std::process::Child {
        use std::os::windows::process::CommandExt;

        // CREATE_NO_WINDOW keeps the deterministic numeric-loopback helper
        // out of the user's desktop. Ping uses a numeric address, so this
        // test does not query or mutate DNS configuration.
        let mut command = std::process::Command::new("cmd.exe");
        command.args(["/D", "/S", "/C", "ping.exe -n 3 127.0.0.1 >NUL"]);
        command.creation_flags(0x0800_0000);
        command.spawn().expect("hidden local child should launch")
    }

    #[cfg(windows)]
    fn child_creation_time(pid: u32) -> u64 {
        use windows::Win32::{
            Foundation::{CloseHandle, FILETIME},
            System::Threading::{
                GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_SYNCHRONIZE,
            },
        };

        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                false,
                pid,
            )
        }
        .expect("child process should be queryable");
        let mut creation = FILETIME::default();
        let (mut exit, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        let result = unsafe {
            GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user)
        };
        unsafe {
            let _ = CloseHandle(handle);
        }
        result.expect("child creation time should be readable");
        (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime)
    }

    #[cfg(windows)]
    fn test_journal(label: &str, pid: u32) -> PathBuf {
        std::env::temp_dir().join(format!(
            "vapour-dns-watchdog-{label}-{}-{pid}.json",
            std::process::id()
        ))
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "read-only watchdog wait; run explicitly on an isolated host"]
    fn live_ready_runs_while_child_is_alive_and_waits_for_exit_without_dns_mutation() {
        use std::{
            sync::mpsc,
            thread,
            time::Duration,
        };

        let mut child = spawn_hidden_test_child();
        let parent_pid = child.id();
        let parent_creation = child_creation_time(parent_pid);
        let journal_path = test_journal("wait", parent_pid);
        let _ = fs::remove_file(&journal_path);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let watcher_journal = journal_path.clone();
        let watcher = thread::spawn(move || {
            let result = run_with_ready(
                parent_pid,
                parent_creation,
                &watcher_journal,
                || {
                    ready_tx
                        .send(())
                        .map_err(|_| "ready receiver closed".to_owned())
                },
            );
            let _ = done_tx.send(result.clone());
            result
        });

        if ready_rx.recv_timeout(Duration::from_secs(3)).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            let _ = watcher.join();
            panic!("watchdog readiness callback did not run");
        }
        assert!(
            child
                .try_wait()
                .expect("child state should be queryable")
                .is_none(),
            "readiness must be observed while the child remains alive"
        );
        assert!(
            done_rx
                .recv_timeout(Duration::from_millis(200))
                .is_err(),
            "watchdog returned before the verified child exited"
        );

        let outcome = done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("watchdog should finish after the bounded child exits")
            .expect("watchdog should not fail while waiting for the child");
        assert_eq!(outcome, DnsWatchdogOutcome::ParentExitedWithoutJournal);
        assert!(fs::symlink_metadata(&journal_path).is_err());
        assert!(child.wait().expect("child should be reaped").success());
        assert!(watcher.join().expect("watchdog thread should join").is_ok());
        let _ = fs::remove_file(journal_path);
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "read-only watchdog callback boundary; run explicitly on an isolated host"]
    fn live_ready_failure_stops_before_wait_or_restore() {
        let mut child = spawn_hidden_test_child();
        let parent_pid = child.id();
        let parent_creation = child_creation_time(parent_pid);
        let journal_path = test_journal("callback-failure", parent_pid);
        let sentinel = b"watchdog callback sentinel";
        fs::write(&journal_path, sentinel).expect("sentinel journal should be writable");
        let result = run_with_ready(parent_pid, parent_creation, &journal_path, || {
            Err("controlled readiness failure".to_owned())
        });
        assert_eq!(
            result,
            Err(DnsWatchdogError::ReadyFailed {
                reason: "controlled readiness failure".to_owned()
            })
        );
        assert_eq!(fs::read(&journal_path).expect("sentinel should remain"), sentinel);
        assert!(
            child
                .try_wait()
                .expect("child state should be queryable")
                .is_none(),
            "callback failure must return before waiting for the child"
        );
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_file(journal_path);
    }
}
