//! Same-executable launcher for the crash-recovery DNS watchdog.
//!
//! The launcher captures this process's PID and creation FILETIME itself,
//! starts the current executable with only the internal watchdog switch and
//! those two numeric values, and waits for the strict JSON readiness line.
//! No journal path is accepted from a caller. The watchdog is deliberately
//! not killed from `Drop`: once readiness has completed it is the crash
//! recovery owner until the caller explicitly verifies that the trusted
//! journal is gone and disarms it.

use serde::Deserialize;
use std::{
    io::Read,
    process::{Child, ChildStdout, Command, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

const WATCHDOG_SWITCH: &str = "--vapour-dns-watchdog";
pub const MAX_READY_LINE_BYTES: usize = 4096;
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const CLEANUP_POLL: Duration = Duration::from_millis(10);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyMessage {
    status: String,
}

/// A live same-executable watchdog whose process handle is intentionally
/// retained until the caller has restored and verified the DNS journal.
pub struct DnsWatchdogProcess {
    child: Option<Child>,
}

impl DnsWatchdogProcess {
    /// Start the hidden watchdog and wait for its bounded readiness handshake.
    /// A failure leaves no returned live handle and is safe to handle before
    /// any DNS setting is changed.
    pub fn start() -> Result<Self, String> {
        #[cfg(not(windows))]
        {
            Err("DNS watchdog process is supported only on Windows".to_owned())
        }

        #[cfg(windows)]
        {
            let (parent_pid, parent_creation) = windows_backend::current_identity()?;
            let executable = std::env::current_exe()
                .map_err(|error| format!("cannot resolve the current executable: {error}"))?;
            if !executable.is_absolute() {
                return Err("current executable path is not absolute".to_owned());
            }

            let creation_flags = windows_backend::creation_flags()?;
            let pid_text = parent_pid.to_string();
            let creation_text = parent_creation.to_string();
            let mut command = Command::new(&executable);
            command
                .arg(WATCHDOG_SWITCH)
                .arg(&pid_text)
                .arg(&creation_text)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .creation_flags(creation_flags);

            let mut child = command
                .spawn()
                .map_err(|error| format!("cannot start DNS watchdog: {error}"))?;
            if let Err(error) = windows_backend::verify_independent(&child) {
                let stopped = terminate_child_bounded(&mut child);
                return Err(if stopped {
                    error
                } else {
                    format!("{error}; watchdog cleanup was incomplete")
                });
            }
            let stdout = match child.stdout.take() {
                Some(stdout) => stdout,
                None => {
                    let stopped = terminate_child_bounded(&mut child);
                    return Err(if stopped {
                        "DNS watchdog did not provide a stdout pipe".to_owned()
                    } else {
                        "DNS watchdog did not provide a stdout pipe and cleanup was incomplete"
                            .to_owned()
                    });
                }
            };
            let (receiver, reader) = match spawn_ready_reader(stdout) {
                Ok(value) => value,
                Err(error) => {
                    let stopped = terminate_child_bounded(&mut child);
                    return Err(if stopped {
                        format!("{error}; watchdog cleanup completed")
                    } else {
                        format!("{error}; watchdog cleanup was incomplete")
                    });
                }
            };

            let ready = await_ready(&receiver, Instant::now() + READY_TIMEOUT);
            if let Err(error) = ready {
                let stopped = terminate_child_bounded(&mut child);
                let reader_finished = join_reader_bounded(reader);
                return Err(if stopped {
                    if reader_finished {
                        error
                    } else {
                        format!("{error}; readiness reader cleanup was incomplete")
                    }
                } else {
                    format!(
                        "{error}; watchdog cleanup was incomplete{}",
                        if reader_finished {
                            ""
                        } else {
                            " and readiness reader cleanup was incomplete"
                        }
                    )
                });
            }
            let reader_finished = join_reader_bounded(reader);
            if !reader_finished {
                let stopped = terminate_child_bounded(&mut child);
                return Err(if stopped {
                    "DNS watchdog readiness reader did not finish within the cleanup bound"
                        .to_owned()
                } else {
                    "DNS watchdog readiness reader and process cleanup were incomplete".to_owned()
                });
            }

            match child.try_wait() {
                Ok(Some(status)) => {
                    let code = status
                        .code()
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "terminated".to_owned());
                    Err(format!(
                        "DNS watchdog exited before launch completed ({code})"
                    ))
                }
                Ok(None) => Ok(Self { child: Some(child) }),
                Err(error) => {
                    let stopped = terminate_child_bounded(&mut child);
                    Err(if stopped {
                        format!("cannot inspect DNS watchdog after readiness: {error}")
                    } else {
                        format!(
                            "cannot inspect DNS watchdog after readiness: {error}; cleanup was incomplete"
                        )
                    })
                }
            }
        }
    }

    /// Poll the watchdog process without killing it. A stopped child is
    /// reaped and reported as not alive.
    pub fn is_alive(&mut self) -> Result<bool, String> {
        let Some(child) = self.child.as_mut() else {
            return Ok(false);
        };
        match child.try_wait() {
            Ok(Some(_)) => {
                self.child = None;
                Ok(false)
            }
            Ok(None) => Ok(true),
            Err(error) => Err(format!("cannot inspect DNS watchdog: {error}")),
        }
    }

    /// Verify the fixed trusted journal is absent, then terminate the helper
    /// with a bounded wait. If the journal remains or termination cannot be
    /// confirmed, the child handle stays armed so `Drop` cannot accidentally
    /// remove crash protection.
    pub fn disarm_after_restore(&mut self) -> Result<(), String> {
        #[cfg(not(windows))]
        {
            Err("DNS watchdog process is supported only on Windows".to_owned())
        }

        #[cfg(windows)]
        {
            let journal = super::dns_storage::trusted_journal_path()
                .map_err(|error| format!("cannot resolve trusted DNS journal: {error}"))?;
            match super::dns_configuration::read_journal(&journal)
                .map_err(|error| format!("cannot verify trusted DNS journal: {error}"))?
            {
                Some(_) => return Err("trusted DNS recovery journal is still present".to_owned()),
                None => {}
            }

            let Some(mut child) = self.child.take() else {
                return Ok(());
            };
            if terminate_child_bounded(&mut child) {
                Ok(())
            } else {
                self.child = Some(child);
                Err("DNS watchdog did not stop within the cleanup bound".to_owned())
            }
        }
    }
}

impl Drop for DnsWatchdogProcess {
    fn drop(&mut self) {
        // Dropping a process handle does not terminate the child. This is
        // intentional: an armed watchdog must survive parent unwinding or a
        // crash until the journal has been independently restored and checked.
        let _ = self.child.take();
    }
}

fn parse_ready_line(line: &[u8]) -> Result<(), String> {
    if line.len().saturating_add(1) > MAX_READY_LINE_BYTES {
        return Err(format!(
            "DNS watchdog readiness line exceeds {MAX_READY_LINE_BYTES} bytes"
        ));
    }
    if line.first() != Some(&b'{') || line.last() != Some(&b'}') {
        return Err("DNS watchdog readiness is not a strict JSON object".to_owned());
    }
    let message: ReadyMessage = serde_json::from_slice(line)
        .map_err(|error| format!("invalid DNS watchdog readiness JSON: {error}"))?;
    if message.status != "ready" {
        return Err("DNS watchdog readiness status was not ready".to_owned());
    }
    Ok(())
}

fn read_ready_line(reader: &mut impl Read) -> Result<(), String> {
    let mut line = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        let count = reader
            .read(&mut byte)
            .map_err(|error| format!("reading DNS watchdog readiness failed: {error}"))?;
        if count == 0 {
            return Err("DNS watchdog exited before readiness".to_owned());
        }
        if count != 1 {
            return Err("DNS watchdog readiness reader returned an invalid byte count".to_owned());
        }
        if byte[0] == b'\n' {
            return parse_ready_line(&line);
        }
        if line.len().saturating_add(1) >= MAX_READY_LINE_BYTES {
            return Err(format!(
                "DNS watchdog readiness line exceeds {MAX_READY_LINE_BYTES} bytes"
            ));
        }
        line.push(byte[0]);
    }
}

fn spawn_ready_reader(
    stdout: ChildStdout,
) -> Result<(Receiver<Result<(), String>>, JoinHandle<()>), String> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = thread::Builder::new()
        .name("vapour-dns-watchdog-ready".to_owned())
        .spawn(move || {
            let mut stdout = stdout;
            let result = read_ready_line(&mut stdout);
            let _ = sender.send(result);
        })
        .map_err(|error| format!("cannot create DNS watchdog readiness reader: {error}"))?;
    Ok((receiver, reader))
}

fn await_ready(receiver: &Receiver<Result<(), String>>, deadline: Instant) -> Result<(), String> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("DNS watchdog readiness deadline exceeded".to_owned());
        }
        match receiver.recv_timeout(remaining.min(Duration::from_millis(100))) {
            Ok(result) => return result,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => {
                return Err("DNS watchdog readiness reader disconnected".to_owned())
            }
        }
    }
}

fn join_reader_bounded(reader: JoinHandle<()>) -> bool {
    let deadline = Instant::now() + CLEANUP_TIMEOUT;
    while !reader.is_finished() && Instant::now() < deadline {
        thread::sleep(CLEANUP_POLL);
    }
    if reader.is_finished() {
        reader.join().is_ok()
    } else {
        // Detach a reader that did not stop within the bound. The child is
        // terminated before this path is used during failed startup.
        drop(reader);
        false
    }
}

fn terminate_child_bounded(child: &mut Child) -> bool {
    let _ = child.kill();
    let deadline = Instant::now() + CLEANUP_TIMEOUT;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) => thread::sleep(CLEANUP_POLL),
            Err(_) => return false,
        }
    }
    matches!(child.try_wait(), Ok(Some(_)))
}

#[cfg(windows)]
mod windows_backend {
    use std::{os::windows::io::AsRawHandle, process::Child};
    use windows::Win32::{
        Foundation::{BOOL, FILETIME, HANDLE},
        System::{
            JobObjects::IsProcessInJob,
            Threading::{
                GetCurrentProcess, GetCurrentProcessId, GetProcessTimes, CREATE_BREAKAWAY_FROM_JOB,
                CREATE_NO_WINDOW,
            },
        },
    };

    pub(super) fn current_identity() -> Result<(u32, u64), String> {
        let pid = unsafe { GetCurrentProcessId() };
        let creation = process_creation_time(unsafe { GetCurrentProcess() })?;
        if pid == 0 || creation == 0 {
            return Err("current process identity was empty".to_owned());
        }
        Ok((pid, creation))
    }

    pub(super) fn creation_flags() -> Result<u32, String> {
        let mut in_job = BOOL(0);
        unsafe {
            IsProcessInJob(GetCurrentProcess(), HANDLE::default(), &mut in_job)
                .map_err(|error| format!("cannot determine current job membership: {error}"))?;
        }
        let mut flags = CREATE_NO_WINDOW.0;
        if in_job.0 != 0 {
            // If the containing job denies breakaway, CreateProcess fails;
            // the caller therefore never reaches DNS mutation with a helper
            // that would silently die with the parent job.
            flags |= CREATE_BREAKAWAY_FROM_JOB.0;
        }
        Ok(flags)
    }

    pub(super) fn verify_independent(child: &Child) -> Result<(), String> {
        let mut in_job = BOOL(0);
        unsafe {
            IsProcessInJob(
                HANDLE(child.as_raw_handle()),
                HANDLE::default(),
                &mut in_job,
            )
            .map_err(|error| format!("cannot verify watchdog job independence: {error}"))?;
        }
        if in_job.0 != 0 {
            return Err(
                "DNS watchdog remains in a process job; independent recovery is unavailable".into(),
            );
        }
        Ok(())
    }

    fn process_creation_time(handle: HANDLE) -> Result<u64, String> {
        let (mut creation, mut exit, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        unsafe {
            GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user)
                .map_err(|error| format!("cannot query current process creation time: {error}"))?;
        }
        Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Cursor,
        sync::mpsc::sync_channel,
        time::{Duration, Instant},
    };

    #[test]
    fn ready_parser_requires_the_exact_ready_object() {
        assert!(parse_ready_line(br#"{"status":"ready"}"#).is_ok());
        for line in [
            br#"{"status":"stopped"}"#.as_slice(),
            br#"{"status":"ready","extra":true}"#.as_slice(),
            br#" {"status":"ready"}"#.as_slice(),
            br#"{"status":"ready"} "#.as_slice(),
            b"not-json".as_slice(),
        ] {
            assert!(parse_ready_line(line).is_err(), "accepted {line:?}");
        }
    }

    #[test]
    fn ready_reader_rejects_early_exit_and_oversized_lines() {
        let mut early = Cursor::new(Vec::<u8>::new());
        assert!(read_ready_line(&mut early).is_err());

        let mut oversized = Cursor::new(vec![b'x'; MAX_READY_LINE_BYTES]);
        assert!(read_ready_line(&mut oversized).is_err());
    }

    #[test]
    fn ready_wait_has_a_deadline_when_child_is_silent() {
        let (_sender, receiver) = sync_channel::<Result<(), String>>(1);
        let deadline = Instant::now() + Duration::from_millis(5);
        let error = await_ready(&receiver, deadline).expect_err("silent child must time out");
        assert!(error.contains("readiness deadline"));
    }
}
