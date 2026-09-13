//! Supervision for the loopback DNS filtering companion.
//!
//! The companion is an embedded, source-built executable. This module keeps
//! its lifecycle deliberately small: it extracts one hash-named executable,
//! verifies the bytes while holding a read-only Windows handle, sends one
//! bounded JSON command, and supervises the child in a kill-on-close job.
//! Starting the proxy never changes the machine's DNS settings.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[cfg(windows)]
use std::os::windows::{
    fs::OpenOptionsExt,
    io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle},
};

#[cfg(windows)]
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::HANDLE,
        Security::*,
        System::{
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
                SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            },
            Threading::*,
        },
    },
};

const ENGINE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vapour-dnsproxy.exe"));

const MAX_RULE_TEXT_BYTES: usize = 8 * 1024 * 1024;
const MAX_COMMAND_BYTES: usize = 2 * MAX_RULE_TEXT_BYTES + 64 * 1024;
const MAX_STATUS_LINE_BYTES: usize = 64 * 1024;
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const STOP_TIMEOUT: Duration = Duration::from_secs(3);
const READER_CLEANUP_TIMEOUT: Duration = Duration::from_millis(250);
const READER_POLL_INTERVAL: Duration = Duration::from_millis(5);
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
#[cfg(windows)]
const FILE_SHARE_READ: u32 = 0x0000_0001;

/// Configuration sent to the companion's start command.
///
/// The upstream must be a numeric IP address and port. The listen address is
/// restricted to loopback; port zero asks the OS for an ephemeral port.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DnsProcessConfig {
    pub upstream: String,
    #[serde(default)]
    pub listen_address: String,
    #[serde(default)]
    pub listen_port: u16,
    #[serde(default)]
    pub rules: String,
}

/// The addresses reported by the companion after both loopback listeners are
/// ready. The field names intentionally match the companion status JSON.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DnsProcessStatus {
    pub udp_addr: String,
    pub tcp_addr: String,
    pub rules_count: u64,
}

#[derive(Serialize)]
struct StartCommand<'a> {
    op: &'static str,
    config: &'a DnsProcessConfig,
}

#[derive(Serialize)]
struct ReloadCommand<'a> {
    op: &'static str,
    rules: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireStatus {
    status: String,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    udp_addr: Option<String>,
    #[serde(default)]
    tcp_addr: Option<String>,
    #[serde(default)]
    rules_count: Option<u64>,
}

enum ReaderEvent {
    Line(Vec<u8>),
    Eof,
    Error(String),
}

enum ReloadFailure {
    /// The companion parsed the request and deliberately kept the current
    /// engine. The process and its previous status remain usable.
    Rejected(String),
    /// The response stream or child state is no longer trustworthy. The
    /// manager must remove and contain the process before returning.
    Uncertain(String),
}

struct EngineImage {
    path: PathBuf,
    file: File,
}

#[cfg(windows)]
struct ManagedChild {
    process: OwnedHandle,
    stdin: Option<File>,
    stdout: Option<File>,
}

#[cfg(not(windows))]
struct ManagedChild;

#[cfg(windows)]
struct SpawnedChild {
    child: ManagedChild,
    thread: OwnedHandle,
}

#[cfg(windows)]
impl ManagedChild {
    fn try_wait(&self) -> Result<Option<u32>, String> {
        let mut code = 0u32;
        unsafe {
            GetExitCodeProcess(HANDLE(self.process.as_raw_handle()), &mut code)
                .map_err(|error| format!("cannot inspect DNS proxy process: {error}"))?;
        }
        Ok((code != 259).then_some(code))
    }

    fn kill(&self) {
        unsafe {
            let _ = TerminateProcess(HANDLE(self.process.as_raw_handle()), 1);
        }
    }
}

#[cfg(not(windows))]
impl ManagedChild {
    fn try_wait(&self) -> Result<Option<u32>, String> {
        Err("DNS proxy supervision is only supported on Windows".to_owned())
    }

    fn kill(&self) {}
}

struct Running {
    child: ManagedChild,
    stdin: Option<File>,
    events: Receiver<ReaderEvent>,
    reader: Option<JoinHandle<io::Result<()>>>,
    // Keeping this handle open prevents another process from replacing,
    // deleting, or opening the verified executable for write on Windows.
    _engine_file: File,
    job: ChildJob,
    status: Option<DnsProcessStatus>,
}

/// Owns at most one loopback DNS companion process.
///
/// The manager is independent of Tauri state. The caller supplies its
/// app-data directory and can expose start, status, and stop through its
/// command layer.
pub struct DnsProcessManager {
    appdata_path: PathBuf,
    running: Arc<Mutex<Option<Running>>>,
}

impl DnsProcessManager {
    pub fn new(appdata_path: PathBuf) -> Self {
        Self {
            appdata_path,
            running: Arc::new(Mutex::new(None)),
        }
    }

    /// Extract, verify, start, and wait for both companion listeners.
    pub fn start(&self, config: DnsProcessConfig) -> Result<DnsProcessStatus, String> {
        let mut slot = self
            .running
            .lock()
            .map_err(|_| "DNS process state is poisoned".to_owned())?;
        let stale = match slot.as_mut() {
            None => false,
            Some(running) => match running.child.try_wait() {
                Ok(None) => {
                    return Err("DNS proxy is already running".to_owned());
                }
                Ok(Some(_)) => true,
                Err(error) => {
                    return Err(format!("cannot inspect existing DNS proxy: {error}"));
                }
            },
        };
        if stale {
            let mut previous = slot
                .take()
                .expect("a stale process was present in the state slot");
            cleanup_reader(&mut previous, false);
        }
        if slot.is_some() {
            return Err("DNS proxy is already running".to_owned());
        }

        let mut running = Running::launch(&self.appdata_path, config)?;
        let status = match running.wait_ready() {
            Ok(status) => status,
            Err(error) => {
                force_terminate(&mut running);
                cleanup_reader(&mut running, false);
                return Err(error);
            }
        };
        running.status = Some(status.clone());
        *slot = Some(running);
        Ok(status)
    }

    /// Return the last ready status while the child remains alive.
    pub fn status(&self) -> Result<Option<DnsProcessStatus>, String> {
        let mut slot = self
            .running
            .lock()
            .map_err(|_| "DNS process state is poisoned".to_owned())?;
        let child_result = match slot.as_mut() {
            Some(running) => running.child.try_wait(),
            None => return Ok(None),
        };
        match child_result {
            Ok(None) => Ok(slot.as_ref().and_then(|running| running.status.clone())),
            Ok(Some(exit)) => {
                let message = format!("DNS proxy stopped unexpectedly ({})", exit);
                let dead = slot.take();
                drop(dead);
                Err(message)
            }
            Err(error) => Err(format!("cannot inspect DNS proxy: {error}")),
        }
    }

    /// Ask the companion to stop and enforce a bounded three-second deadline.
    pub fn stop(&self) -> Result<(), String> {
        let running = self
            .running
            .lock()
            .map_err(|_| "DNS process state is poisoned".to_owned())?
            .take();
        let Some(running) = running else {
            return Ok(());
        };
        stop_running(running, true)
    }

    /// Replace the active rule text and wait for the companion's bounded
    /// acknowledgement. Manager operations are serialized by the state lock.
    /// A structured `error` response is a rejected update and leaves the
    /// existing process and status available. Malformed output, a timeout, or
    /// process failure makes the state uncertain, so the child is terminated
    /// and reaped before the error is returned.
    pub fn reload(&self, rules: String) -> Result<DnsProcessStatus, String> {
        let command = encode_reload_command(&rules)?;
        let mut slot = self
            .running
            .lock()
            .map_err(|_| "DNS process state is poisoned".to_owned())?;
        let mut running = slot
            .take()
            .ok_or_else(|| "DNS proxy is not running".to_owned())?;

        match running.reload(command) {
            Ok(status) => {
                *slot = Some(running);
                Ok(status)
            }
            Err(ReloadFailure::Rejected(error)) => {
                *slot = Some(running);
                Err(error)
            }
            Err(ReloadFailure::Uncertain(error)) => {
                terminate_and_reap(&mut running);
                Err(error)
            }
        }
    }

    /// Parse a rule list in a separate ephemeral-port companion process. This
    /// is intended for cache validation and never touches this manager's
    /// active child or status.
    pub fn validate_rules(&self, rules: &str) -> Result<u64, String> {
        if rules.is_empty() || rules.as_bytes().len() > MAX_RULE_TEXT_BYTES {
            return Err("DNS filter is empty or exceeds its size limit".to_owned());
        }
        let validation_path = self.appdata_path.join("rule-validation");
        let validator = DnsProcessManager::new(validation_path);
        let status = validator.start(DnsProcessConfig {
            upstream: "127.0.0.1:9".to_owned(),
            listen_address: "127.0.0.1".to_owned(),
            // Port zero requests an OS-assigned high ephemeral port and
            // avoids requiring administrative privileges for validation.
            listen_port: 0,
            rules: rules.to_owned(),
        })?;
        validator.stop()?;
        Ok(status.rules_count)
    }
}

impl Drop for DnsProcessManager {
    fn drop(&mut self) {
        let running = self.running.lock().ok().and_then(|mut slot| slot.take());
        if let Some(running) = running {
            let _ = stop_running(running, true);
        }
    }
}

impl Running {
    fn launch(appdata_path: &Path, config: DnsProcessConfig) -> Result<Self, String> {
        validate_config(&config)?;
        let start_command = encode_start_command(&config)?;

        #[cfg(not(windows))]
        {
            let _ = (appdata_path, start_command);
            return Err("DNS proxy supervision is only supported on Windows".to_owned());
        }

        #[cfg(windows)]
        {
            let engine = extract_engine(appdata_path)?;
            let elevated = crate::firewall::FirewallManager::is_elevated();
            let SpawnedChild { mut child, thread } = spawn_companion(&engine.path, elevated)?;
            let job = match ChildJob::attach(&child) {
                Ok(job) => job,
                Err(error) => {
                    terminate_child(&mut child, None);
                    return Err(error);
                }
            };

            if elevated {
                if let Err(error) = verify_child_token_medium_or_lower(&child) {
                    terminate_child(&mut child, Some(&job));
                    return Err(format!(
                        "DNS proxy child token was not demoted to medium or lower: {error}"
                    ));
                }
            }

            if unsafe { ResumeThread(HANDLE(thread.as_raw_handle())) } == u32::MAX {
                terminate_child(&mut child, Some(&job));
                return Err("cannot resume DNS proxy process".to_owned());
            }
            drop(thread);

            let stdin = match child.stdin.take() {
                Some(stdin) => stdin,
                None => {
                    terminate_child(&mut child, Some(&job));
                    return Err("DNS proxy stdin pipe was not created".to_owned());
                }
            };
            let stdout = match child.stdout.take() {
                Some(stdout) => stdout,
                None => {
                    terminate_child(&mut child, Some(&job));
                    return Err("DNS proxy stdout pipe was not created".to_owned());
                }
            };
            let (events, reader) = match spawn_reader(stdout) {
                Ok(value) => value,
                Err(error) => {
                    terminate_child(&mut child, Some(&job));
                    return Err(format!("cannot supervise DNS proxy output: {error}"));
                }
            };

            let mut running = Self {
                child,
                stdin: Some(stdin),
                events,
                reader: Some(reader),
                _engine_file: engine.file,
                job,
                status: None,
            };

            let stdin = running
                .stdin
                .take()
                .ok_or_else(|| "DNS proxy stdin pipe was not created".to_owned())?;
            match write_pipe_bounded(
                stdin,
                start_command,
                Instant::now() + READY_TIMEOUT,
                &mut running.child,
                &running.job,
                "DNS proxy configuration write",
            ) {
                Ok(stdin) => {
                    running.stdin = Some(stdin);
                }
                Err(error) => {
                    force_terminate(&mut running);
                    cleanup_reader(&mut running, false);
                    return Err(error);
                }
            }

            Ok(running)
        }
    }

    fn wait_ready(&mut self) -> Result<DnsProcessStatus, String> {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                force_terminate(self);
                cleanup_reader(self, false);
                return Err("DNS proxy did not become ready within 10 seconds".to_owned());
            }

            match self
                .events
                .recv_timeout(remaining.min(Duration::from_millis(100)))
            {
                Ok(ReaderEvent::Line(line)) => match parse_wire_status(&line) {
                    Ok(status) if status.status == "ready" => {
                        let status = ready_status(status)?;
                        self.status = Some(status.clone());
                        return Ok(status);
                    }
                    Ok(status) if status.status == "error" => {
                        return Err(wire_error(&status));
                    }
                    Ok(status) if status.status == "stopped" => {
                        return Err("DNS proxy stopped before becoming ready".to_owned());
                    }
                    Ok(status) => {
                        return Err(format!(
                            "DNS proxy reported unsupported status {:?}",
                            status.status
                        ));
                    }
                    Err(error) => return Err(error),
                },
                Ok(ReaderEvent::Error(error)) => {
                    return Err(format!("DNS proxy output failed: {error}"));
                }
                Ok(ReaderEvent::Eof) => {
                    return Err("DNS proxy output closed before becoming ready".to_owned());
                }
                Err(RecvTimeoutError::Timeout) => match self.child.try_wait() {
                    Ok(None) => continue,
                    Ok(Some(exit)) => {
                        return Err(format!("DNS proxy exited before becoming ready ({})", exit));
                    }
                    Err(error) => return Err(format!("cannot inspect DNS proxy: {error}")),
                },
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(
                        "DNS proxy output channel disconnected before becoming ready".to_owned(),
                    );
                }
            }
        }
    }

    fn reload(&mut self, command: Vec<u8>) -> Result<DnsProcessStatus, ReloadFailure> {
        let deadline = Instant::now() + READY_TIMEOUT;
        let stdin = self.stdin.take().ok_or_else(|| {
            ReloadFailure::Uncertain("DNS proxy stdin pipe is unavailable".to_owned())
        })?;
        self.stdin = Some(
            write_pipe_bounded(
                stdin,
                command,
                deadline,
                &mut self.child,
                &self.job,
                "DNS proxy reload command write",
            )
            .map_err(ReloadFailure::Uncertain)?,
        );

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ReloadFailure::Uncertain(
                    "DNS proxy reload did not respond within 10 seconds".to_owned(),
                ));
            }

            match self
                .events
                .recv_timeout(remaining.min(Duration::from_millis(100)))
            {
                Ok(ReaderEvent::Line(line)) => {
                    let status = parse_wire_status(&line).map_err(ReloadFailure::Uncertain)?;
                    match status.status.as_str() {
                        "updated" => {
                            let mut current = self.status.clone().ok_or_else(|| {
                                ReloadFailure::Uncertain(
                                    "DNS proxy reload succeeded before a ready status".to_owned(),
                                )
                            })?;
                            current.rules_count = status.rules_count.unwrap_or(0);
                            self.status = Some(current.clone());
                            return Ok(current);
                        }
                        "error" => {
                            return Err(ReloadFailure::Rejected(format!(
                                "DNS proxy rejected rule reload: {}",
                                wire_error(&status)
                            )));
                        }
                        "stopped" => {
                            return Err(ReloadFailure::Uncertain(
                                "DNS proxy stopped while reloading rules".to_owned(),
                            ));
                        }
                        other => {
                            return Err(ReloadFailure::Uncertain(format!(
                                "DNS proxy reported unsupported reload status {other:?}"
                            )));
                        }
                    }
                }
                Ok(ReaderEvent::Error(error)) => {
                    return Err(ReloadFailure::Uncertain(format!(
                        "DNS proxy output failed during reload: {error}"
                    )));
                }
                Ok(ReaderEvent::Eof) => {
                    return Err(ReloadFailure::Uncertain(
                        "DNS proxy output closed during reload".to_owned(),
                    ));
                }
                Err(RecvTimeoutError::Timeout) => match self.child.try_wait() {
                    Ok(None) => continue,
                    Ok(Some(exit)) => {
                        return Err(ReloadFailure::Uncertain(format!(
                            "DNS proxy exited during reload ({exit})"
                        )));
                    }
                    Err(error) => {
                        return Err(ReloadFailure::Uncertain(format!(
                            "cannot inspect DNS proxy during reload: {error}"
                        )));
                    }
                },
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(ReloadFailure::Uncertain(
                        "DNS proxy output channel disconnected during reload".to_owned(),
                    ));
                }
            }
        }
    }
}

fn validate_config(config: &DnsProcessConfig) -> Result<(), String> {
    let upstream = config.upstream.trim();
    let upstream_addr = SocketAddr::from_str(upstream)
        .map_err(|error| format!("upstream must be an explicit IP:port: {error}"))?;
    if upstream_addr.port() == 0 {
        return Err("upstream port must be between 1 and 65535".to_owned());
    }

    let listen_address = if config.listen_address.trim().is_empty() {
        "127.0.0.1"
    } else {
        config.listen_address.trim()
    };
    let listen_ip = IpAddr::from_str(listen_address)
        .map_err(|error| format!("listen_address must be a loopback IP address: {error}"))?;
    if !listen_ip.is_loopback() {
        return Err("listen_address must be a loopback IP address".to_owned());
    }

    if config.rules.as_bytes().len() > MAX_RULE_TEXT_BYTES {
        return Err(format!(
            "rules exceed the {} byte limit",
            MAX_RULE_TEXT_BYTES
        ));
    }

    // Serialize once here so the same bounded representation is sent after
    // extraction and child creation.
    encode_start_command(config)?;
    Ok(())
}

fn encode_start_command(config: &DnsProcessConfig) -> Result<Vec<u8>, String> {
    let mut command = serde_json::to_vec(&StartCommand {
        op: "start",
        config,
    })
    .map_err(|error| format!("cannot encode DNS proxy configuration: {error}"))?;
    command.push(b'\n');
    if command.len() > MAX_COMMAND_BYTES {
        return Err(format!(
            "DNS proxy configuration exceeds the {} byte limit",
            MAX_COMMAND_BYTES
        ));
    }
    Ok(command)
}

fn encode_reload_command(rules: &str) -> Result<Vec<u8>, String> {
    if rules.as_bytes().len() > MAX_RULE_TEXT_BYTES {
        return Err(format!(
            "rules exceed the {} byte limit",
            MAX_RULE_TEXT_BYTES
        ));
    }
    let mut command = serde_json::to_vec(&ReloadCommand {
        op: "reload",
        rules,
    })
    .map_err(|error| format!("cannot encode DNS proxy reload: {error}"))?;
    command.push(b'\n');
    if command.len() > MAX_COMMAND_BYTES {
        return Err(format!(
            "DNS proxy reload exceeds the {} byte limit",
            MAX_COMMAND_BYTES
        ));
    }
    Ok(command)
}

fn extract_engine(appdata_path: &Path) -> Result<EngineImage, String> {
    if !appdata_path.is_absolute() {
        return Err("DNS proxy app-data path must be absolute".to_owned());
    }
    fs::create_dir_all(appdata_path)
        .map_err(|error| format!("cannot create DNS proxy app-data directory: {error}"))?;

    let hash = sha256_hex(ENGINE);
    let path = appdata_path.join(format!("vapour-dnsproxy-{hash}.exe"));
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut file) => {
            let result = (|| -> io::Result<()> {
                file.write_all(ENGINE)?;
                file.sync_all()
            })();
            drop(file);
            if let Err(error) = result {
                let _ = fs::remove_file(&path);
                return Err(format!("cannot extract DNS proxy executable: {error}"));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(format!("cannot create DNS proxy executable: {error}"));
        }
    }

    let mut file = open_shared_read(&path)
        .map_err(|error| format!("cannot open extracted DNS proxy executable: {error}"))?;
    verify_engine(&mut file)?;
    Ok(EngineImage { path, file })
}

#[cfg(windows)]
fn open_shared_read(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
}

#[cfg(not(windows))]
fn open_shared_read(path: &Path) -> io::Result<File> {
    File::open(path)
}

fn verify_engine(file: &mut File) -> Result<(), String> {
    let expected_len = u64::try_from(ENGINE.len())
        .map_err(|_| "embedded DNS proxy executable is too large".to_owned())?;
    let actual_len = file
        .metadata()
        .map_err(|error| format!("cannot inspect extracted DNS proxy executable: {error}"))?
        .len();
    if actual_len != expected_len {
        return Err(format!(
            "DNS proxy executable length mismatch: expected {expected_len}, got {actual_len}"
        ));
    }

    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("cannot seek extracted DNS proxy executable: {error}"))?;
    let mut actual = Vec::with_capacity(ENGINE.len());
    file.take(expected_len.saturating_add(1))
        .read_to_end(&mut actual)
        .map_err(|error| format!("cannot read extracted DNS proxy executable: {error}"))?;
    if actual.len() != ENGINE.len() || actual.as_slice() != ENGINE {
        return Err("DNS proxy executable content verification failed".to_owned());
    }
    if Sha256::digest(&actual).as_slice() != Sha256::digest(ENGINE).as_slice() {
        return Err("DNS proxy executable hash verification failed".to_owned());
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("cannot rewind extracted DNS proxy executable: {error}"))?;
    Ok(())
}

#[cfg(windows)]
#[repr(C)]
struct NativeSecurityAttributes {
    n_length: u32,
    lp_security_descriptor: *mut core::ffi::c_void,
    b_inherit_handle: i32,
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreatePipe(
        read_pipe: *mut HANDLE,
        write_pipe: *mut HANDLE,
        pipe_attributes: *const NativeSecurityAttributes,
        size: u32,
    ) -> i32;
    fn SetHandleInformation(handle: HANDLE, mask: u32, flags: u32) -> i32;
}

#[cfg(windows)]
const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;

#[cfg(windows)]
fn anonymous_pipe() -> Result<(OwnedHandle, OwnedHandle), String> {
    let attributes = NativeSecurityAttributes {
        n_length: std::mem::size_of::<NativeSecurityAttributes>() as u32,
        lp_security_descriptor: std::ptr::null_mut(),
        b_inherit_handle: 1,
    };
    let mut read_pipe = HANDLE::default();
    let mut write_pipe = HANDLE::default();
    if unsafe { CreatePipe(&mut read_pipe, &mut write_pipe, &attributes, 0) } == 0 {
        return Err(format!(
            "cannot create DNS proxy pipe: {}",
            io::Error::last_os_error()
        ));
    }
    Ok((
        unsafe { OwnedHandle::from_raw_handle(read_pipe.0) },
        unsafe { OwnedHandle::from_raw_handle(write_pipe.0) },
    ))
}

#[cfg(windows)]
fn make_non_inheritable(handle: &OwnedHandle) -> Result<(), String> {
    if unsafe { SetHandleInformation(HANDLE(handle.as_raw_handle()), HANDLE_FLAG_INHERIT, 0) } == 0
    {
        return Err(format!(
            "cannot mark DNS proxy pipe private: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn caller_linked_primary_token() -> Result<OwnedHandle, String> {
    unsafe {
        let mut caller_token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut caller_token)
            .map_err(|error| format!("cannot open the current process token: {error}"))?;
        let caller_token = OwnedHandle::from_raw_handle(caller_token.0);

        let mut linked = TOKEN_LINKED_TOKEN::default();
        let mut return_length = 0u32;
        GetTokenInformation(
            HANDLE(caller_token.as_raw_handle()),
            TokenLinkedToken,
            Some((&mut linked as *mut TOKEN_LINKED_TOKEN).cast()),
            std::mem::size_of::<TOKEN_LINKED_TOKEN>() as u32,
            &mut return_length,
        )
        .map_err(|error| {
            format!("cannot obtain the current token's linked limited token: {error}")
        })?;
        if linked.LinkedToken.is_invalid() {
            return Err(
                "the current elevated token has no linked limited token; refusing DNS proxy launch"
                    .to_owned(),
            );
        }

        // GetTokenInformation returns an owned primary token handle in this
        // record. Keep the linked token itself so CreateProcessAsUserW can
        // recognize it as the restricted version of this caller's token and
        // avoid requiring SeAssignPrimaryTokenPrivilege.
        Ok(OwnedHandle::from_raw_handle(linked.LinkedToken.0))
    }
}

#[cfg(windows)]
fn verify_child_token_medium_or_lower(child: &ManagedChild) -> Result<(), String> {
    // SECURITY_MANDATORY_MEDIUM_RID is 0x2000 in the Windows security
    // headers. A lower-or-equal integrity SID is required even when the
    // token's elevation flag is clear, because a filtered token can retain a
    // non-medium integrity level.
    const MEDIUM_INTEGRITY_RID: u32 = 0x2000;

    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(
            HANDLE(child.process.as_raw_handle()),
            TOKEN_QUERY,
            &mut token,
        )
        .map_err(|error| format!("cannot open DNS proxy process token: {error}"))?;
        let token = OwnedHandle::from_raw_handle(token.0);

        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_length = 0u32;
        GetTokenInformation(
            HANDLE(token.as_raw_handle()),
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        )
        .map_err(|error| format!("cannot inspect DNS proxy token elevation: {error}"))?;
        if elevation.TokenIsElevated != 0 {
            return Err("TokenIsElevated is set".to_owned());
        }

        let mut needed = 0u32;
        let _ = GetTokenInformation(
            HANDLE(token.as_raw_handle()),
            TokenIntegrityLevel,
            None,
            0,
            &mut needed,
        );
        let header_size = std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32;
        if needed < header_size || needed > 64 * 1024 {
            return Err(format!("invalid integrity information size {needed} bytes"));
        }

        // Vec<usize> supplies alignment suitable for TOKEN_MANDATORY_LABEL;
        // the SID bytes referenced by the structure are returned in the same
        // buffer by GetTokenInformation.
        let word_size = std::mem::size_of::<usize>();
        let words = (needed as usize + word_size - 1) / word_size;
        let mut information = vec![0usize; words];
        GetTokenInformation(
            HANDLE(token.as_raw_handle()),
            TokenIntegrityLevel,
            Some(information.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
        .map_err(|error| format!("cannot read DNS proxy token integrity: {error}"))?;

        let label = &*(information.as_ptr().cast::<TOKEN_MANDATORY_LABEL>());
        let sid = label.Label.Sid;
        if sid.is_invalid() {
            return Err("DNS proxy token has no integrity SID".to_owned());
        }
        let count = GetSidSubAuthorityCount(sid);
        if count.is_null() || *count == 0 {
            return Err("DNS proxy token integrity SID has no subauthority".to_owned());
        }
        let rid = GetSidSubAuthority(sid, (*count - 1) as u32);
        if rid.is_null() {
            return Err("DNS proxy token integrity SID has no RID".to_owned());
        }
        let rid = *rid;
        if rid > MEDIUM_INTEGRITY_RID {
            return Err(format!(
                "integrity RID {rid} is above medium ({MEDIUM_INTEGRITY_RID})"
            ));
        }
        Ok(())
    }
}

#[cfg(windows)]
fn spawn_companion(path: &Path, elevated: bool) -> Result<SpawnedChild, String> {
    let (child_stdin_read, parent_stdin_write) = anonymous_pipe()?;
    let (parent_stdout_read, child_stdout_write) = anonymous_pipe()?;
    make_non_inheritable(&parent_stdin_write)?;
    make_non_inheritable(&parent_stdout_read)?;

    let application = path
        .to_string_lossy()
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut command_line = format!("\"{}\"", path.display())
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let parent_directory = path
        .parent()
        .ok_or_else(|| "DNS proxy executable has no parent directory".to_owned())?;
    let directory = parent_directory
        .to_string_lossy()
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut attribute_size = 0usize;
    unsafe {
        let _ = InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST::default(),
            1,
            0,
            &mut attribute_size,
        );
    }
    if attribute_size == 0 {
        return Err("cannot size DNS proxy process attributes".to_owned());
    }
    let mut attribute_buffer = vec![0u8; attribute_size];
    let attribute_list = LPPROC_THREAD_ATTRIBUTE_LIST(attribute_buffer.as_mut_ptr().cast());
    unsafe {
        InitializeProcThreadAttributeList(attribute_list, 1, 0, &mut attribute_size)
            .map_err(|error| format!("cannot initialize DNS proxy process attributes: {error}"))?;
    }
    let stdio_handles = [
        HANDLE(child_stdin_read.as_raw_handle()),
        HANDLE(child_stdout_write.as_raw_handle()),
    ];
    let attribute_result = unsafe {
        UpdateProcThreadAttribute(
            attribute_list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            Some(stdio_handles.as_ptr().cast()),
            std::mem::size_of_val(&stdio_handles),
            None,
            None,
        )
    };
    if let Err(error) = attribute_result {
        unsafe {
            DeleteProcThreadAttributeList(attribute_list);
        }
        return Err(format!(
            "cannot restrict DNS proxy inherited handles: {error}"
        ));
    }
    let startup = STARTUPINFOEXW {
        StartupInfo: STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: stdio_handles[0],
            hStdOutput: stdio_handles[1],
            // The verified companion does not write stderr for a valid start
            // command. Reusing its output keeps STARTF_USESTDHANDLES valid.
            hStdError: stdio_handles[1],
            ..Default::default()
        },
        lpAttributeList: attribute_list,
    };
    let mut process_info = PROCESS_INFORMATION::default();
    let creation_flags =
        PROCESS_CREATION_FLAGS(CREATE_NO_WINDOW) | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT;
    let result = if elevated {
        let token = caller_linked_primary_token()?;
        unsafe {
            // CreateProcessAsUserW accepts STARTUPINFOEX and the restricted
            // handle list while applying the desktop user's primary token.
            CreateProcessAsUserW(
                HANDLE(token.as_raw_handle()),
                PCWSTR(application.as_ptr()),
                PWSTR(command_line.as_mut_ptr()),
                None,
                None,
                true,
                creation_flags,
                None,
                PCWSTR(directory.as_ptr()),
                &startup.StartupInfo as *const STARTUPINFOW,
                &mut process_info,
            )
        }
    } else {
        unsafe {
            CreateProcessW(
                PCWSTR(application.as_ptr()),
                PWSTR(command_line.as_mut_ptr()),
                None,
                None,
                true,
                creation_flags,
                None,
                PCWSTR(directory.as_ptr()),
                &startup.StartupInfo as *const STARTUPINFOW,
                &mut process_info,
            )
        }
    };
    unsafe {
        DeleteProcThreadAttributeList(attribute_list);
    }
    result.map_err(|error| format!("cannot start DNS proxy: {error}"))?;

    let process = unsafe { OwnedHandle::from_raw_handle(process_info.hProcess.0) };
    let thread = unsafe { OwnedHandle::from_raw_handle(process_info.hThread.0) };
    let stdin = unsafe { File::from_raw_handle(parent_stdin_write.into_raw_handle()) };
    let stdout = unsafe { File::from_raw_handle(parent_stdout_read.into_raw_handle()) };
    Ok(SpawnedChild {
        child: ManagedChild {
            process,
            stdin: Some(stdin),
            stdout: Some(stdout),
        },
        thread,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn parse_wire_status(line: &[u8]) -> Result<WireStatus, String> {
    serde_json::from_slice(line).map_err(|error| {
        format!(
            "invalid DNS proxy status JSON ({} bytes): {error}",
            line.len()
        )
    })
}

fn ready_status(status: WireStatus) -> Result<DnsProcessStatus, String> {
    let udp_addr = status
        .udp_addr
        .ok_or_else(|| "DNS proxy ready status omitted udp_addr".to_owned())?;
    validate_ready_address("udp_addr", &udp_addr)?;
    let tcp_addr = status
        .tcp_addr
        .ok_or_else(|| "DNS proxy ready status omitted tcp_addr".to_owned())?;
    validate_ready_address("tcp_addr", &tcp_addr)?;
    Ok(DnsProcessStatus {
        udp_addr,
        tcp_addr,
        rules_count: status.rules_count.unwrap_or(0),
    })
}

fn validate_ready_address(name: &str, address: &str) -> Result<(), String> {
    let parsed = SocketAddr::from_str(address)
        .map_err(|error| format!("DNS proxy ready {name} is invalid: {error}"))?;
    if !parsed.ip().is_loopback() {
        return Err(format!("DNS proxy ready {name} is not loopback"));
    }
    if parsed.port() == 0 {
        return Err(format!("DNS proxy ready {name} has port zero"));
    }
    Ok(())
}

fn wire_error(status: &WireStatus) -> String {
    status
        .error
        .as_deref()
        .filter(|error| !error.trim().is_empty())
        .map_or_else(
            || "DNS proxy reported an error without a message".to_owned(),
            ToOwned::to_owned,
        )
}

fn stop_running(mut running: Running, send_stop: bool) -> Result<(), String> {
    let mut first_error = None;
    let deadline = Instant::now() + STOP_TIMEOUT;
    if send_stop {
        let send_result = if let Some(stdin) = running.stdin.take() {
            write_pipe_bounded(
                stdin,
                b"{\"op\":\"stop\"}\n".to_vec(),
                deadline,
                &mut running.child,
                &running.job,
                "DNS proxy stop command write",
            )
            .map(|_| ())
        } else {
            Err("DNS proxy stdin pipe is unavailable".to_owned())
        };
        if let Err(error) = send_result {
            first_error = Some(error);
        }
    } else {
        // Closing stdin is the companion's documented parent-pipe shutdown
        // signal. Dropping the handle must happen before waiting for output.
        let _ = running.stdin.take();
    }

    let mut stopped = false;
    if first_error.is_none() {
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match running
                .events
                .recv_timeout(remaining.min(Duration::from_millis(100)))
            {
                Ok(ReaderEvent::Line(line)) => match parse_wire_status(&line) {
                    Ok(status) if status.status == "stopped" => {
                        stopped = true;
                        break;
                    }
                    Ok(status) if status.status == "error" => {
                        first_error.get_or_insert_with(|| wire_error(&status));
                    }
                    Ok(_) => {}
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                },
                Ok(ReaderEvent::Error(error)) => {
                    first_error.get_or_insert(format!("DNS proxy output failed: {error}"));
                    break;
                }
                Ok(ReaderEvent::Eof) => {
                    break;
                }
                Err(RecvTimeoutError::Timeout) => {
                    if let Ok(Some(_)) = running.child.try_wait() {
                        break;
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    break;
                }
            }
        }
    }

    let mut child_exited = false;
    if stopped {
        while Instant::now() < deadline {
            match running.child.try_wait() {
                Ok(Some(_)) => {
                    child_exited = true;
                    break;
                }
                Ok(None) => thread::sleep(CHILD_POLL_INTERVAL),
                Err(error) => {
                    first_error.get_or_insert(format!("cannot inspect DNS proxy: {error}"));
                    break;
                }
            }
        }
    } else if let Ok(Some(_)) = running.child.try_wait() {
        child_exited = true;
    }

    if !stopped || !child_exited {
        force_terminate(&mut running);
    }
    cleanup_reader(&mut running, false);

    if let Some(error) = first_error {
        return Err(error);
    }
    if !stopped {
        return Err("DNS proxy did not report stopped within 3 seconds".to_owned());
    }
    if !child_exited {
        return Err("DNS proxy did not exit within 3 seconds".to_owned());
    }
    Ok(())
}

fn write_pipe_bounded(
    mut stdin: File,
    payload: Vec<u8>,
    deadline: Instant,
    child: &mut ManagedChild,
    job: &ChildJob,
    operation: &str,
) -> Result<File, String> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = thread::Builder::new()
        .name("vapour-dnsproxy-stdin".to_owned())
        .spawn(move || {
            if let Err(error) = stdin.write_all(&payload).and_then(|_| stdin.flush()) {
                let _ = sender.send(Err(error.to_string()));
            } else {
                let _ = sender.send(Ok(stdin));
            }
            Ok(())
        })
        .map_err(|error| {
            terminate_child(child, Some(job));
            format!("cannot create {operation} worker: {error}")
        })?;
    let mut worker = Some(worker);

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            terminate_child(child, Some(job));
            join_worker_bounded(worker.take().expect("worker is present"));
            return Err(format!("{operation} exceeded its deadline"));
        }

        match receiver.recv_timeout(remaining.min(Duration::from_millis(100))) {
            Ok(Ok(stdin)) => {
                join_worker_bounded(worker.take().expect("worker is present"));
                return Ok(stdin);
            }
            Ok(Err(error)) => {
                join_worker_bounded(worker.take().expect("worker is present"));
                return Err(format!("{operation} failed: {error}"));
            }
            Err(RecvTimeoutError::Timeout) => match child.try_wait() {
                Ok(None) => continue,
                Ok(Some(_)) => {
                    join_worker_bounded(worker.take().expect("worker is present"));
                    return Err(format!("{operation} failed because DNS proxy exited"));
                }
                Err(error) => {
                    terminate_child(child, Some(job));
                    join_worker_bounded(worker.take().expect("worker is present"));
                    return Err(format!(
                        "cannot inspect DNS proxy during {operation}: {error}"
                    ));
                }
            },
            Err(RecvTimeoutError::Disconnected) => {
                terminate_child(child, Some(job));
                join_worker_bounded(worker.take().expect("worker is present"));
                return Err(format!("{operation} worker disconnected"));
            }
        }
    }
}

fn join_worker_bounded(worker: JoinHandle<io::Result<()>>) {
    let deadline = Instant::now() + READER_CLEANUP_TIMEOUT;
    while !worker.is_finished() && Instant::now() < deadline {
        thread::sleep(READER_POLL_INTERVAL);
    }
    if worker.is_finished() {
        let _ = worker.join();
    }
}

fn force_terminate(running: &mut Running) {
    running.job.terminate();
    let _ = running.child.kill();
}

fn terminate_and_reap(running: &mut Running) {
    force_terminate(running);
    let deadline = Instant::now() + STOP_TIMEOUT;
    while Instant::now() < deadline {
        match running.child.try_wait() {
            Ok(Some(_)) | Err(_) => break,
            Ok(None) => thread::sleep(CHILD_POLL_INTERVAL),
        }
    }
    cleanup_reader(running, false);
}

fn cleanup_reader(running: &mut Running, terminate_first: bool) {
    if terminate_first {
        force_terminate(running);
    }
    let Some(reader) = running.reader.take() else {
        return;
    };

    let deadline = Instant::now() + READER_CLEANUP_TIMEOUT;
    while !reader.is_finished() && Instant::now() < deadline {
        thread::sleep(READER_POLL_INTERVAL);
    }
    if reader.is_finished() {
        let _ = reader.join();
    }
    // A detached reader is bounded cleanup: its child pipe is no longer part
    // of manager state, and the job has already been terminated on timeout.
}

fn read_status_line(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte)? {
            0 if line.is_empty() => return Ok(None),
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "DNS proxy closed an unterminated status line",
                ));
            }
            1 if byte[0] == b'\n' => return Ok(Some(line)),
            1 => {
                if line.len() >= MAX_STATUS_LINE_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "DNS proxy status line exceeds the size limit",
                    ));
                }
                line.push(byte[0]);
            }
            _ => unreachable!("one-byte read returned more than one byte"),
        }
    }
}

fn spawn_reader(stdout: File) -> io::Result<(Receiver<ReaderEvent>, JoinHandle<io::Result<()>>)> {
    let (sender, receiver) = mpsc::sync_channel(8);
    let reader = thread::Builder::new()
        .name("vapour-dnsproxy-status".to_owned())
        .spawn(move || reader_loop(stdout, sender))?;
    Ok((receiver, reader))
}

fn reader_loop(mut stdout: File, sender: SyncSender<ReaderEvent>) -> io::Result<()> {
    loop {
        match read_status_line(&mut stdout) {
            Ok(Some(line)) => {
                if sender.send(ReaderEvent::Line(line)).is_err() {
                    return Ok(());
                }
            }
            Ok(None) => {
                let _ = sender.send(ReaderEvent::Eof);
                return Ok(());
            }
            Err(error) => {
                let message = error.to_string();
                let _ = sender.send(ReaderEvent::Error(message));
                return Err(error);
            }
        }
    }
}

#[cfg(windows)]
struct ChildJob {
    handle: OwnedHandle,
}

#[cfg(windows)]
impl ChildJob {
    fn attach(child: &ManagedChild) -> Result<Self, String> {
        let result = unsafe {
            (|| -> windows::core::Result<Self> {
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
                    HANDLE(child.process.as_raw_handle()),
                )?;
                Ok(Self { handle: job })
            })()
        };
        result.map_err(|error| format!("cannot contain DNS proxy process: {error}"))
    }

    fn terminate(&self) {
        unsafe {
            let _ = TerminateJobObject(HANDLE(self.handle.as_raw_handle()), 1);
        }
    }
}

#[cfg(not(windows))]
struct ChildJob;

#[cfg(not(windows))]
impl ChildJob {
    fn attach(_child: &ManagedChild) -> Result<Self, String> {
        Err("DNS proxy supervision is only supported on Windows".to_owned())
    }

    fn terminate(&self) {}
}

fn terminate_child(child: &mut ManagedChild, job: Option<&ChildJob>) {
    if let Some(job) = job {
        job.terminate();
    }
    let _ = child.kill();
}

impl Drop for Running {
    fn drop(&mut self) {
        force_terminate(self);
        cleanup_reader(self, false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::UdpSocket,
        sync::atomic::{AtomicU64, Ordering},
    };

    #[cfg(windows)]
    use std::{
        sync::{
            atomic::{AtomicBool, AtomicUsize},
            Arc,
        },
        thread::{self, JoinHandle},
    };

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    fn test_directory(label: &str) -> PathBuf {
        let serial = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "vapour-dns-process-{label}-{}-{serial}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        path
    }

    fn config(upstream: SocketAddr) -> DnsProcessConfig {
        DnsProcessConfig {
            upstream: upstream.to_string(),
            listen_address: "127.0.0.1".to_owned(),
            listen_port: 0,
            rules: "||ads.example^\n@@||allowed.ads.example^".to_owned(),
        }
    }

    #[cfg(windows)]
    struct SyntheticUpstream {
        address: SocketAddr,
        queries: Arc<AtomicUsize>,
        stopping: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
    }

    #[cfg(windows)]
    impl SyntheticUpstream {
        fn start() -> Self {
            let socket = UdpSocket::bind("127.0.0.1:0").expect("bind synthetic DNS upstream");
            socket
                .set_read_timeout(Some(Duration::from_millis(100)))
                .expect("set synthetic upstream timeout");
            let address = socket.local_addr().expect("synthetic upstream address");
            let queries = Arc::new(AtomicUsize::new(0));
            let stopping = Arc::new(AtomicBool::new(false));
            let worker_queries = Arc::clone(&queries);
            let worker_stopping = Arc::clone(&stopping);
            let worker = thread::spawn(move || {
                let mut packet = [0u8; 4096];
                while !worker_stopping.load(Ordering::Acquire) {
                    let (length, peer) = match socket.recv_from(&mut packet) {
                        Ok(value) => value,
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) =>
                        {
                            continue
                        }
                        Err(_) => break,
                    };
                    if let Some(reply) = synthetic_dns_response(&packet[..length]) {
                        worker_queries.fetch_add(1, Ordering::AcqRel);
                        let _ = socket.send_to(&reply, peer);
                    }
                }
            });
            Self {
                address,
                queries,
                stopping,
                worker: Some(worker),
            }
        }

        fn address(&self) -> SocketAddr {
            self.address
        }

        fn query_count(&self) -> usize {
            self.queries.load(Ordering::Acquire)
        }
    }

    #[cfg(windows)]
    impl Drop for SyntheticUpstream {
        fn drop(&mut self) {
            self.stopping.store(true, Ordering::Release);
            if let Ok(wakeup) = UdpSocket::bind("127.0.0.1:0") {
                let _ = wakeup.send_to(&[0u8; 12], self.address);
            }
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    #[cfg(windows)]
    fn dns_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in name.trim_end_matches('.').split('.') {
            let bytes = label.as_bytes();
            assert!(!bytes.is_empty() && bytes.len() <= 63);
            packet.push(bytes.len() as u8);
            packet.extend_from_slice(bytes);
        }
        packet.push(0);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet
    }

    #[cfg(windows)]
    fn dns_question_end(packet: &[u8]) -> Option<usize> {
        if packet.len() < 12 {
            return None;
        }
        let mut index = 12usize;
        loop {
            let length = *packet.get(index)? as usize;
            index = index.checked_add(1)?;
            if length == 0 {
                break;
            }
            if length > 63 || index.checked_add(length)? > packet.len() {
                return None;
            }
            index += length;
        }
        index.checked_add(4).filter(|end| *end <= packet.len())
    }

    #[cfg(windows)]
    fn synthetic_dns_response(query: &[u8]) -> Option<Vec<u8>> {
        let question_end = dns_question_end(query)?;
        let qtype = u16::from_be_bytes([query[question_end - 4], query[question_end - 3]]);
        let rdata: &[u8] = match qtype {
            1 => &[192, 0, 2, 42],
            28 => &[
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42,
            ],
            _ => return None,
        };
        let mut response = Vec::with_capacity(question_end + 16 + rdata.len());
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&[0x81, 0x80]);
        response.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
        response.extend_from_slice(&query[12..question_end]);
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&qtype.to_be_bytes());
        response.extend_from_slice(&[0, 1, 0, 0, 0, 30]);
        response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        response.extend_from_slice(rdata);
        Some(response)
    }

    #[cfg(windows)]
    fn query_udp(address: SocketAddr, name: &str, qtype: u16) -> Vec<u8> {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind DNS query socket");
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("set DNS query timeout");
        let query = dns_query(name, qtype);
        socket.send_to(&query, address).expect("send DNS query");
        let mut response = vec![0u8; 4096];
        let (length, _) = socket
            .recv_from(&mut response)
            .expect("receive DNS response");
        response.truncate(length);
        response
    }

    #[cfg(windows)]
    fn response_rcode(response: &[u8]) -> u8 {
        assert!(response.len() >= 12);
        response[3] & 0x0f
    }

    #[cfg(windows)]
    fn response_answer_count(response: &[u8]) -> u16 {
        assert!(response.len() >= 8);
        u16::from_be_bytes([response[6], response[7]])
    }

    #[cfg(windows)]
    fn plain_token_probe_child(
        executable: &Path,
        token: &OwnedHandle,
        _sentinels: &[OwnedHandle],
    ) -> Result<(SpawnedChild, u32), String> {
        let (child_stdin_read, parent_stdin_write) = anonymous_pipe()?;
        let (parent_stdout_read, child_stdout_write) = anonymous_pipe()?;
        make_non_inheritable(&parent_stdin_write)?;
        make_non_inheritable(&parent_stdout_read)?;

        let application = executable
            .to_string_lossy()
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut command_line = format!("\"{}\" /c exit 0", executable.display())
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let directory = executable
            .parent()
            .ok_or_else(|| "probe executable has no parent directory".to_owned())?
            .to_string_lossy()
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let startup = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: HANDLE(child_stdin_read.as_raw_handle()),
            hStdOutput: HANDLE(child_stdout_write.as_raw_handle()),
            hStdError: HANDLE(child_stdout_write.as_raw_handle()),
            ..Default::default()
        };
        let mut process_info = PROCESS_INFORMATION::default();
        let creation_flags = PROCESS_CREATION_FLAGS(CREATE_NO_WINDOW) | CREATE_SUSPENDED;
        unsafe {
            CreateProcessWithTokenW(
                HANDLE(token.as_raw_handle()),
                CREATE_PROCESS_LOGON_FLAGS(0),
                PCWSTR(application.as_ptr()),
                PWSTR(command_line.as_mut_ptr()),
                creation_flags,
                None,
                PCWSTR(directory.as_ptr()),
                &startup,
                &mut process_info,
            )
            .map_err(|error| format!("plain CreateProcessWithTokenW probe failed: {error}"))?;
        }
        drop(child_stdin_read);
        drop(child_stdout_write);

        let process = unsafe { OwnedHandle::from_raw_handle(process_info.hProcess.0) };
        let thread = unsafe { OwnedHandle::from_raw_handle(process_info.hThread.0) };
        let mut handle_count = 0u32;
        unsafe {
            GetProcessHandleCount(HANDLE(process.as_raw_handle()), &mut handle_count)
                .map_err(|error| format!("cannot count probe child handles: {error}"))?;
        }
        Ok((
            SpawnedChild {
                child: ManagedChild {
                    process,
                    stdin: Some(unsafe {
                        File::from_raw_handle(parent_stdin_write.into_raw_handle())
                    }),
                    stdout: Some(unsafe {
                        File::from_raw_handle(parent_stdout_read.into_raw_handle())
                    }),
                },
                thread,
            },
            handle_count,
        ))
    }

    #[cfg(windows)]
    fn plain_token_probe_handle_count(
        token: &OwnedHandle,
        with_sentinels: bool,
    ) -> Result<u32, String> {
        let mut sentinels = Vec::new();
        if with_sentinels {
            // These handles are deliberately inheritable and are never put in
            // STARTUPINFO. A changed child handle count proves ambient
            // inheritance rather than standard-handle duplication.
            for _ in 0..8 {
                let (read, write) = anonymous_pipe()?;
                sentinels.push(read);
                sentinels.push(write);
            }
        }
        let executable = std::env::var_os("ComSpec")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows\System32\cmd.exe"));
        let (mut spawned, count) = plain_token_probe_child(&executable, token, &sentinels)?;
        terminate_child(&mut spawned.child, None);
        unsafe {
            let _ = WaitForSingleObject(HANDLE(spawned.child.process.as_raw_handle()), 5_000);
        }
        drop(spawned);
        Ok(count)
    }

    #[test]
    fn rejects_hostname_upstream_before_creating_appdata() {
        let path = test_directory("invalid");
        let manager = DnsProcessManager::new(path.clone());
        let result = manager.start(DnsProcessConfig {
            upstream: "resolver.example.test:53".to_owned(),
            listen_address: "127.0.0.1".to_owned(),
            listen_port: 0,
            rules: String::new(),
        });
        assert!(result
            .expect_err("hostname upstream must be rejected")
            .contains("explicit IP"));
        assert!(!path.exists());
    }

    #[test]
    fn reload_command_is_bounded_before_state_access() {
        let command = encode_reload_command("||ads.example^").expect("small reload command");
        assert!(command.ends_with(b"\n"));
        assert!(serde_json::from_slice::<serde_json::Value>(&command[..command.len() - 1]).is_ok());
        assert!(encode_reload_command(&"x".repeat(MAX_RULE_TEXT_BYTES + 1)).is_err());
    }

    #[test]
    #[ignore = "requires a Windows desktop token and the real embedded companion; run with --include-ignored"]
    fn starts_real_companion_and_reports_both_loopback_addresses() {
        let upstream = UdpSocket::bind("127.0.0.1:0").expect("reserve an explicit test upstream");
        let path = test_directory("startup");
        let manager = DnsProcessManager::new(path.clone());

        let status = manager
            .start(config(upstream.local_addr().unwrap()))
            .expect("real DNS companion should start");

        let udp: SocketAddr = status.udp_addr.parse().expect("valid UDP address");
        let tcp: SocketAddr = status.tcp_addr.parse().expect("valid TCP address");
        assert!(udp.ip().is_loopback() && udp.port() != 0);
        assert!(tcp.ip().is_loopback() && tcp.port() != 0);
        assert_eq!(manager.status().unwrap(), Some(status));
        assert!(fs::read_dir(&path)
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry.path().extension().is_some_and(|ext| ext == "exe")));

        manager
            .stop()
            .expect("companion should stop via JSON command");
        assert_eq!(manager.status().unwrap(), None);
        let _ = fs::remove_dir_all(path);
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires an unelevated Windows desktop token and the real companion"]
    fn reload_changes_live_udp_rules_and_preserves_rejected_update() {
        assert!(
            !crate::firewall::FirewallManager::is_elevated(),
            "run this lifecycle test from an unelevated app token"
        );
        let upstream = SyntheticUpstream::start();
        let path = test_directory("reload");
        let manager = DnsProcessManager::new(path.clone());
        let initial = manager
            .start(DnsProcessConfig {
                upstream: upstream.address().to_string(),
                listen_address: "127.0.0.1".to_owned(),
                listen_port: 0,
                rules: "||old.example.test^\n@@||allowed.example.test^".to_owned(),
            })
            .expect("real DNS companion should start");
        assert_eq!(initial.rules_count, 2);

        let blocked = query_udp(
            initial
                .udp_addr
                .parse()
                .expect("valid UDP listener address"),
            "old.example.test",
            1,
        );
        assert_eq!(response_rcode(&blocked), 3);
        assert_eq!(response_answer_count(&blocked), 0);
        assert_eq!(upstream.query_count(), 0);

        let allowed = query_udp(
            initial
                .udp_addr
                .parse()
                .expect("valid UDP listener address"),
            "allowed.example.test",
            1,
        );
        assert_eq!(response_rcode(&allowed), 0);
        assert_eq!(response_answer_count(&allowed), 1);
        assert_eq!(upstream.query_count(), 1);

        // Cache validation uses a second ephemeral-port manager and must not
        // replace or stop this active service.
        assert_eq!(manager.validate_rules("||validation.example.test^"), Ok(1));
        assert_eq!(manager.status(), Ok(Some(initial.clone())));

        let updated = manager
            .reload("||new.example.test^".to_owned())
            .expect("valid reload should be acknowledged");
        assert_eq!(updated.udp_addr, initial.udp_addr);
        assert_eq!(updated.tcp_addr, initial.tcp_addr);
        assert_eq!(updated.rules_count, 1);
        assert_eq!(manager.status(), Ok(Some(updated.clone())));

        let old_now_allowed = query_udp(
            updated
                .udp_addr
                .parse()
                .expect("valid UDP listener address"),
            "old.example.test",
            1,
        );
        assert_eq!(response_rcode(&old_now_allowed), 0);
        assert_eq!(response_answer_count(&old_now_allowed), 1);
        assert_eq!(upstream.query_count(), 2);

        let new_blocked = query_udp(
            updated
                .udp_addr
                .parse()
                .expect("valid UDP listener address"),
            "new.example.test",
            1,
        );
        assert_eq!(response_rcode(&new_blocked), 3);
        assert_eq!(response_answer_count(&new_blocked), 0);
        assert_eq!(upstream.query_count(), 2);

        let rejected = manager.reload("192.0.2.1 arbitrary.example.test".to_owned());
        assert!(rejected
            .expect_err("unsupported host target must be rejected")
            .contains("rejected rule reload"));
        assert_eq!(manager.status(), Ok(Some(updated.clone())));

        let still_blocked = query_udp(
            updated
                .udp_addr
                .parse()
                .expect("valid UDP listener address"),
            "new.example.test",
            1,
        );
        assert_eq!(response_rcode(&still_blocked), 3);
        assert_eq!(upstream.query_count(), 2);

        manager.stop().expect("stop reloaded DNS companion");
        assert_eq!(manager.status(), Ok(None));
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    #[ignore = "requires a Windows desktop token and the real embedded companion; run with --include-ignored"]
    fn closing_stdin_stops_real_companion_within_bounded_cleanup() {
        let upstream = UdpSocket::bind("127.0.0.1:0").expect("reserve an explicit test upstream");
        let path = test_directory("eof");
        let manager = DnsProcessManager::new(path.clone());
        let _status = manager
            .start(config(upstream.local_addr().unwrap()))
            .expect("real DNS companion should start");

        let running = manager
            .running
            .lock()
            .unwrap()
            .take()
            .expect("test has a running companion");
        stop_running(running, false).expect("closing stdin should stop the companion");
        assert_eq!(manager.status().unwrap(), None);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    #[ignore = "requires an elevated interactive app and a medium desktop token; run explicitly"]
    fn elevated_manager_launches_with_medium_desktop_token() {
        assert!(
            crate::firewall::FirewallManager::is_elevated(),
            "run this demotion test from an elevated app token"
        );
        let upstream = UdpSocket::bind("127.0.0.1:0").expect("reserve an explicit test upstream");
        let path = test_directory("demoted");
        let engine = extract_engine(&path).expect("extract embedded companion");
        let SpawnedChild { mut child, thread } =
            spawn_companion(&engine.path, true).expect("launch with the desktop token");
        let job = match ChildJob::attach(&child) {
            Ok(job) => job,
            Err(error) => {
                terminate_child(&mut child, None);
                panic!("contain demoted DNS proxy: {error}");
            }
        };
        verify_child_token_medium_or_lower(&child)
            .unwrap_or_else(|error| panic!("child token was not demoted: {error}"));
        if unsafe { ResumeThread(HANDLE(thread.as_raw_handle())) } == u32::MAX {
            terminate_child(&mut child, Some(&job));
            panic!("resume demoted DNS proxy");
        }
        drop(thread);
        let stdin = child.stdin.take().expect("demoted stdin pipe");
        let stdout = child.stdout.take().expect("demoted stdout pipe");
        let (events, reader) = spawn_reader(stdout).expect("demoted stdout reader");
        let mut running = Running {
            child,
            stdin: Some(stdin),
            events,
            reader: Some(reader),
            _engine_file: engine.file,
            job,
            status: None,
        };
        let command = encode_start_command(&config(upstream.local_addr().unwrap()))
            .expect("encode demoted start command");
        let stdin = running.stdin.take().expect("demoted stdin handle");
        let stdin = write_pipe_bounded(
            stdin,
            command,
            Instant::now() + READY_TIMEOUT,
            &mut running.child,
            &running.job,
            "demoted DNS proxy configuration write",
        )
        .expect("send demoted start command");
        running.stdin = Some(stdin);
        let status = running.wait_ready().expect("demoted DNS proxy ready");
        assert!(status.udp_addr.starts_with("127.0.0.1:"));
        stop_running(running, true).expect("stop demoted DNS proxy");
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    #[ignore = "requires an elevated interactive app; probes plain CreateProcessWithTokenW handle inheritance"]
    fn elevated_plain_token_probe_does_not_inherit_ambient_handles() {
        assert!(
            crate::firewall::FirewallManager::is_elevated(),
            "run this handle-inheritance probe from an elevated app token"
        );
        let token = caller_linked_primary_token().expect("obtain the linked limited token");
        let baseline = plain_token_probe_handle_count(&token, false)
            .expect("plain token probe without sentinel handles");
        let with_sentinels = plain_token_probe_handle_count(&token, true)
            .expect("plain token probe with sentinel handles");
        assert_eq!(
            with_sentinels, baseline,
            "plain CreateProcessWithTokenW inherited an ambient sentinel handle"
        );
    }
}
