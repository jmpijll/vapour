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
const FLOW_TIMEOUT: Duration = Duration::from_secs(2);
const QUIESCE_TIMEOUT: Duration = Duration::from_secs(6);
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
    pub dual_stack: bool,
    #[serde(default)]
    pub rules: String,
}

/// Configuration for the transparent companion mode.  The companion binds
/// the requested local addresses itself; each address receives eight
/// controller-owned UDP and TCP upstream slots.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct TransparentDnsConfig {
    pub(crate) listen_addresses: Vec<String>,
    pub(crate) listen_port: u16,
    pub(crate) rules: String,
}

/// A reserved source endpoint owned by one transparent listener address.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpstreamSlot {
    pub(crate) id: usize,
    pub(crate) udp_addr: String,
    pub(crate) tcp_addr: String,
}

/// One exact reflected flow authorization to install in the companion.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct TransparentFlowRegistration {
    pub(crate) protocol: String,
    pub(crate) peer: String,
    pub(crate) local: String,
    pub(crate) resolver: String,
    pub(crate) slot: usize,
    pub(crate) lifetime_ms: u64,
}

/// The addresses reported by the companion after both loopback listeners are
/// ready. The field names intentionally match the companion status JSON.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DnsProcessStatus {
    pub udp_addr: String,
    pub tcp_addr: String,
    pub udp_addrs: Vec<String>,
    pub tcp_addrs: Vec<String>,
    pub rules_count: u64,
    pub(crate) slots: Vec<UpstreamSlot>,
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

#[derive(Serialize)]
struct TransparentStartCommand<'a> {
    op: &'static str,
    config: TransparentStartConfig<'a>,
}

#[derive(Serialize)]
struct TransparentStartConfig<'a> {
    transparent: bool,
    listen_addresses: &'a [String],
    listen_port: u16,
    rules: &'a str,
}

#[derive(Serialize)]
struct FlowCommand<'a> {
    op: &'static str,
    flow: &'a TransparentFlowRegistration,
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
    udp_addrs: Option<Vec<String>>,
    #[serde(default)]
    tcp_addrs: Option<Vec<String>>,
    #[serde(default)]
    rules_count: Option<u64>,
    #[serde(default)]
    slots: Option<Vec<UpstreamSlot>>,
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

/// Typed outcome for a transparent live reload. A rejection is an ordinary
/// rule-validation failure and leaves the active generation usable; an
/// uncertain outcome means the owner must close interception before stopping
/// the retained companion.
pub(crate) enum TransparentReloadError {
    Rejected(String),
    Uncertain(String),
}

enum StartSpec {
    Legacy(DnsProcessConfig),
    Transparent(TransparentDnsConfig),
}

impl StartSpec {
    fn launch(&self, appdata_path: &Path) -> Result<Running, String> {
        match self {
            Self::Legacy(config) => Running::launch(appdata_path, config.clone()),
            Self::Transparent(config) => Running::launch_transparent(appdata_path, config),
        }
    }

    fn validate_ready(&self, status: &DnsProcessStatus) -> Result<(), String> {
        match self {
            Self::Legacy(config) => validate_listeners(
                status,
                &config.listen_address,
                config.listen_port,
                config.dual_stack,
                &config.upstream,
            ),
            Self::Transparent(config) => validate_transparent_listeners(status, config),
        }
    }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Quiescence {
    Active,
    Quiesced,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlState {
    Certain,
    Uncertain,
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
    quiescence: Quiescence,
    control: ControlState,
    pending_writer: Option<JoinHandle<io::Result<()>>>,
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
        self.start_with(StartSpec::Legacy(config))
    }

    /// Extract, verify, start, and wait for the transparent companion.
    pub(crate) fn start_transparent(
        &self,
        config: TransparentDnsConfig,
    ) -> Result<DnsProcessStatus, String> {
        self.start_with(StartSpec::Transparent(config))
    }

    fn start_with(&self, spec: StartSpec) -> Result<DnsProcessStatus, String> {
        let mut slot = self
            .running
            .lock()
            .map_err(|_| "DNS process state is poisoned".to_owned())?;
        require_active(slot.as_ref())?;
        let stale = match slot.as_mut() {
            None => false,
            Some(running) => match running.child.try_wait() {
                Ok(None) => {
                    return Err("DNS proxy is already running".to_owned());
                }
                Ok(Some(exit)) if running.is_transparent() => {
                    running.control = ControlState::Uncertain;
                    return Err(format!(
                        "DNS proxy stopped unexpectedly ({exit}); explicit stop is required before restart"
                    ));
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

        let mut running = spec.launch(&self.appdata_path)?;
        let ready = running
            .wait_ready()
            .and_then(|status| spec.validate_ready(&status).map(|()| status));
        let status = match ready {
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
                if slot.as_ref().is_some_and(Running::is_transparent) {
                    if let Some(running) = slot.as_mut() {
                        running.control = ControlState::Uncertain;
                    }
                } else if slot
                    .as_ref()
                    .is_some_and(|running| running.quiescence == Quiescence::Active)
                {
                    let dead = slot.take();
                    drop(dead);
                }
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
    /// existing process and status available. For transparent mode, malformed
    /// output, a timeout, or process failure retains the child and reservations
    /// in an uncertain state until explicit stop; legacy mode keeps its
    /// terminating failure behavior.
    pub fn reload(&self, rules: String) -> Result<DnsProcessStatus, String> {
        let command = encode_reload_command(&rules)?;
        let mut slot = self
            .running
            .lock()
            .map_err(|_| "DNS process state is poisoned".to_owned())?;
        require_active(slot.as_ref())?;
        let mut running = slot
            .take()
            .ok_or_else(|| "DNS proxy is not running".to_owned())?;
        let transparent = running.is_transparent();

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
                if transparent {
                    running.control = ControlState::Uncertain;
                    *slot = Some(running);
                } else {
                    terminate_and_reap(&mut running);
                }
                Err(error)
            }
        }
    }

    /// Reload a transparent companion while preserving the distinction
    /// between a structured rule rejection and an uncertain control channel.
    /// The latter retains the child and its reserved ports until the session
    /// owner closes interception and explicitly stops this manager.
    pub(crate) fn reload_transparent(
        &self,
        rules: String,
    ) -> Result<DnsProcessStatus, TransparentReloadError> {
        let command = encode_reload_command(&rules).map_err(TransparentReloadError::Rejected)?;
        let mut slot = self.running.lock().map_err(|_| {
            TransparentReloadError::Uncertain("DNS process state is poisoned".into())
        })?;
        if let Err(error) = require_active(slot.as_ref()) {
            return Err(TransparentReloadError::Uncertain(error));
        }
        let mut running = slot.take().ok_or_else(|| {
            TransparentReloadError::Uncertain("DNS proxy is not running".to_owned())
        })?;
        if !running.is_transparent() {
            *slot = Some(running);
            return Err(TransparentReloadError::Uncertain(
                "transparent reload requires a transparent DNS companion".to_owned(),
            ));
        }

        match running.reload(command) {
            Ok(status) => {
                *slot = Some(running);
                Ok(status)
            }
            Err(ReloadFailure::Rejected(error)) => {
                *slot = Some(running);
                Err(TransparentReloadError::Rejected(error))
            }
            Err(ReloadFailure::Uncertain(error)) => {
                running.control = ControlState::Uncertain;
                *slot = Some(running);
                Err(TransparentReloadError::Uncertain(error))
            }
        }
    }

    /// Add one exact reflected flow authorization to a running transparent
    /// companion.  A structured error leaves the child and its current status
    /// available; malformed output, a timeout, or child failure retains the
    /// transparent owner in an uncertain state until explicit stop.
    pub(crate) fn register_flow(&self, flow: TransparentFlowRegistration) -> Result<(), String> {
        self.flow_command("register", flow)
    }

    /// Permanently release one exact reflected flow authorization.
    pub(crate) fn release_flow(&self, flow: TransparentFlowRegistration) -> Result<(), String> {
        self.flow_command("release", flow)
    }

    fn flow_command(
        &self,
        operation: &'static str,
        flow: TransparentFlowRegistration,
    ) -> Result<(), String> {
        let command = encode_flow_command(operation, &flow)?;
        let mut slot = self
            .running
            .lock()
            .map_err(|_| "DNS process state is poisoned".to_owned())?;
        require_active(slot.as_ref())?;
        let mut running = slot
            .take()
            .ok_or_else(|| "DNS proxy is not running".to_owned())?;
        let transparent = running.is_transparent();

        match running.flow_command(command, operation) {
            Ok(()) => {
                *slot = Some(running);
                Ok(())
            }
            Err(ReloadFailure::Rejected(error)) => {
                *slot = Some(running);
                Err(error)
            }
            Err(ReloadFailure::Uncertain(error)) => {
                if transparent {
                    running.control = ControlState::Uncertain;
                    *slot = Some(running);
                } else {
                    terminate_and_reap(&mut running);
                }
                Err(error)
            }
        }
    }

    /// Stop admission while retaining the child and its socket reservations.
    /// On any uncertainty the owner must close interception before calling
    /// stop. In particular, this path must not use the terminating pipe writer.
    pub(crate) fn quiesce(&self) -> Result<(), String> {
        let mut slot = self
            .running
            .lock()
            .map_err(|_| "DNS process state is poisoned")?;
        let running = slot.as_mut().ok_or("DNS proxy is not running")?;
        if running.control == ControlState::Uncertain {
            return Err(
                "DNS companion control state is uncertain; stop interception before stopping the companion"
                    .into(),
            );
        }
        match running.quiescence {
            Quiescence::Quiesced => return Ok(()),
            Quiescence::Uncertain => {
                return Err(
                    "DNS quiescence is uncertain; stop interception before stopping the companion"
                        .into(),
                )
            }
            Quiescence::Active => {}
        }
        if running
            .status
            .as_ref()
            .is_none_or(|status| status.slots.is_empty())
        {
            return Err("quiesce requires a transparent DNS companion".into());
        }
        running.quiescence = Quiescence::Uncertain;
        let deadline = Instant::now() + QUIESCE_TIMEOUT;
        let result = running.write_quiesce(deadline).and_then(|()| {
            running.wait_command_ack("quiesce", "quiesced", deadline, QUIESCE_TIMEOUT)
        });
        match result {
            Ok(()) => {
                running.quiescence = Quiescence::Quiesced;
                Ok(())
            }
            Err(ReloadFailure::Rejected(error) | ReloadFailure::Uncertain(error)) => Err(error),
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
            dual_stack: false,
            rules: rules.to_owned(),
        })?;
        validator.stop()?;
        Ok(status.rules_count)
    }
}

fn require_active(running: Option<&Running>) -> Result<(), String> {
    if running.is_some_and(|running| running.control == ControlState::Uncertain) {
        return Err("DNS companion control state is uncertain; stop before retrying".into());
    }
    if running.is_some_and(|running| running.quiescence != Quiescence::Active) {
        return Err("DNS companion is quiescing or quiesced".into());
    }
    Ok(())
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
    fn is_transparent(&self) -> bool {
        self.status
            .as_ref()
            .is_some_and(|status| !status.slots.is_empty())
    }

    fn launch(appdata_path: &Path, config: DnsProcessConfig) -> Result<Self, String> {
        validate_config(&config)?;
        let start_command = encode_start_command(&config)?;

        Self::launch_command(appdata_path, start_command)
    }

    fn launch_transparent(
        appdata_path: &Path,
        config: &TransparentDnsConfig,
    ) -> Result<Self, String> {
        validate_transparent_config(config)?;
        let start_command = encode_transparent_start_command(config)?;

        Self::launch_command(appdata_path, start_command)
    }

    fn launch_command(appdata_path: &Path, start_command: Vec<u8>) -> Result<Self, String> {
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
                quiescence: Quiescence::Active,
                control: ControlState::Certain,
                pending_writer: None,
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
                        validate_ready_status(&status)?;
                        let status = ready_status(status)?;
                        self.status = Some(status.clone());
                        return Ok(status);
                    }
                    Ok(status) if status.status == "error" => {
                        validate_error_status(&status, "startup")?;
                        return Err(wire_error(&status));
                    }
                    Ok(status) if status.status == "stopped" => {
                        validate_empty_status(&status, "stopped")?;
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
        let timeout = READY_TIMEOUT;
        let deadline = Instant::now() + timeout;
        if self.is_transparent() {
            self.write_retained_control(command, deadline, "DNS proxy reload command write")?;
        } else {
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
        }

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ReloadFailure::Uncertain(format!(
                    "DNS proxy reload did not respond within {} seconds",
                    timeout.as_secs()
                )));
            }

            match self
                .events
                .recv_timeout(remaining.min(Duration::from_millis(100)))
            {
                Ok(ReaderEvent::Line(line)) => {
                    let status = parse_wire_status(&line).map_err(ReloadFailure::Uncertain)?;
                    match status.status.as_str() {
                        "updated" => {
                            validate_updated_status(&status).map_err(ReloadFailure::Uncertain)?;
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
                            validate_error_status(&status, "reload")
                                .map_err(ReloadFailure::Uncertain)?;
                            return Err(ReloadFailure::Rejected(format!(
                                "DNS proxy rejected rule reload: {}",
                                wire_error(&status)
                            )));
                        }
                        "stopped" => {
                            validate_empty_status(&status, "stopped")
                                .map_err(ReloadFailure::Uncertain)?;
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

    fn flow_command(&mut self, command: Vec<u8>, operation: &str) -> Result<(), ReloadFailure> {
        let deadline = Instant::now() + FLOW_TIMEOUT;
        if self.is_transparent() {
            self.write_retained_control(command, deadline, "DNS proxy flow command write")?;
        } else {
            let stdin = self.stdin.take().ok_or_else(|| {
                ReloadFailure::Uncertain("DNS proxy stdin is unavailable".to_owned())
            })?;
            self.stdin = Some(
                write_pipe_bounded(
                    stdin,
                    command,
                    deadline,
                    &mut self.child,
                    &self.job,
                    "DNS proxy flow command write",
                )
                .map_err(ReloadFailure::Uncertain)?,
            );
        }

        let expected = if operation == "register" {
            "registered"
        } else {
            "released"
        };
        self.wait_command_ack(operation, expected, deadline, FLOW_TIMEOUT)
    }

    fn write_quiesce(&mut self, deadline: Instant) -> Result<(), ReloadFailure> {
        self.write_retained_control(
            b"{\"op\":\"quiesce\"}\n".to_vec(),
            deadline,
            "DNS quiesce command write",
        )
    }

    fn write_retained_control(
        &mut self,
        payload: Vec<u8>,
        deadline: Instant,
        operation: &str,
    ) -> Result<(), ReloadFailure> {
        if self.pending_writer.is_some() {
            return Err(ReloadFailure::Uncertain(
                "DNS proxy control writer is already pending".to_owned(),
            ));
        }
        let mut writer = self
            .stdin
            .as_ref()
            .ok_or_else(|| ReloadFailure::Uncertain("DNS proxy stdin is unavailable".into()))?
            .try_clone()
            .map_err(|error| {
                ReloadFailure::Uncertain(format!("cannot retain {operation} pipe: {error}"))
            })?;
        let (sender, receiver) = mpsc::sync_channel(1);
        // The original stdin stays in Running even if this worker fails or
        // times out. Closing only the clone cannot send EOF to the companion.
        let worker = thread::Builder::new()
            .name("vapour-dns-control".into())
            .spawn(move || {
                let result = writer.write_all(&payload).and_then(|()| writer.flush());
                drop(writer);
                let _ = sender.send(result.map_err(|error| error.to_string()));
                Ok(())
            })
            .map_err(|error| {
                ReloadFailure::Uncertain(format!("cannot start {operation} worker: {error}"))
            })?;
        self.pending_writer = Some(worker);
        match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(result) => {
                join_worker_bounded(self.pending_writer.take().expect("control writer present"));
                result.map_err(|error| {
                    ReloadFailure::Uncertain(format!("{operation} failed: {error}"))
                })
            }
            Err(RecvTimeoutError::Timeout) => Err(ReloadFailure::Uncertain(format!(
                "{operation} is uncertain: writer deadline expired"
            ))),
            Err(RecvTimeoutError::Disconnected) => {
                let worker = self.pending_writer.take().expect("control writer present");
                join_worker_bounded(worker);
                Err(ReloadFailure::Uncertain(format!(
                    "{operation} is uncertain: writer disconnected"
                )))
            }
        }
    }

    fn wait_command_ack(
        &mut self,
        operation: &str,
        expected: &str,
        deadline: Instant,
        timeout: Duration,
    ) -> Result<(), ReloadFailure> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ReloadFailure::Uncertain(format!(
                    "DNS proxy {operation} command did not respond within {} seconds",
                    timeout.as_secs()
                )));
            }

            match self
                .events
                .recv_timeout(remaining.min(Duration::from_millis(100)))
            {
                Ok(ReaderEvent::Line(line)) => {
                    let status = parse_wire_status(&line).map_err(ReloadFailure::Uncertain)?;
                    match status.status.as_str() {
                        value if value == expected => {
                            validate_empty_status(&status, operation)
                                .map_err(ReloadFailure::Uncertain)?;
                            return Ok(());
                        }
                        "error" => {
                            validate_error_status(&status, operation)
                                .map_err(ReloadFailure::Uncertain)?;
                            return Err(ReloadFailure::Rejected(format!(
                                "DNS proxy rejected {operation} flow: {}",
                                wire_error(&status)
                            )));
                        }
                        "stopped" => {
                            validate_empty_status(&status, "stopped")
                                .map_err(ReloadFailure::Uncertain)?;
                            return Err(ReloadFailure::Uncertain(format!(
                                "DNS proxy stopped while processing {operation} flow"
                            )));
                        }
                        other => {
                            return Err(ReloadFailure::Uncertain(format!(
                                "DNS proxy reported unsupported {operation} flow status {other:?}"
                            )));
                        }
                    }
                }
                Ok(ReaderEvent::Error(error)) => {
                    return Err(ReloadFailure::Uncertain(format!(
                        "DNS proxy output failed during {operation} flow: {error}"
                    )));
                }
                Ok(ReaderEvent::Eof) => {
                    return Err(ReloadFailure::Uncertain(format!(
                        "DNS proxy output closed during {operation} flow"
                    )));
                }
                Err(RecvTimeoutError::Timeout) => match self.child.try_wait() {
                    Ok(None) => continue,
                    Ok(Some(exit)) => {
                        return Err(ReloadFailure::Uncertain(format!(
                            "DNS proxy exited during {operation} flow ({exit})"
                        )));
                    }
                    Err(error) => {
                        return Err(ReloadFailure::Uncertain(format!(
                            "cannot inspect DNS proxy during {operation} flow: {error}"
                        )));
                    }
                },
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(ReloadFailure::Uncertain(format!(
                        "DNS proxy output channel disconnected during {operation} flow"
                    )));
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

fn validate_transparent_config(config: &TransparentDnsConfig) -> Result<(), String> {
    if config.listen_addresses.is_empty() || config.listen_addresses.len() > 16 {
        return Err("transparent DNS requires 1..16 listen addresses".to_owned());
    }
    if config.listen_port == 53 {
        return Err("transparent DNS listen_port must not be 53".to_owned());
    }
    let mut seen = Vec::with_capacity(config.listen_addresses.len());
    for address in &config.listen_addresses {
        let parsed = parse_scoped_ip(address)?;
        if parsed.ip.is_unspecified() || parsed.ip.is_multicast() {
            return Err(format!(
                "transparent listen address {address:?} is not unicast"
            ));
        }
        if parsed.ip.is_ipv4() && parsed.zone.is_some() {
            return Err(format!(
                "transparent IPv4 address {address:?} cannot have a zone"
            ));
        }
        if is_ipv6_link_local(parsed.ip) && parsed.zone.is_none() {
            return Err(format!(
                "transparent link-local address {address:?} requires a zone"
            ));
        }
        if parsed.ip.is_ipv6() && !is_ipv6_link_local(parsed.ip) && parsed.zone.is_some() {
            return Err(format!(
                "transparent zone is only valid for link-local IPv6 address {address:?}"
            ));
        }
        let canonical = parsed.canonical_text();
        if seen.iter().any(|value| value == &canonical) {
            return Err(format!("duplicate transparent listen address {address:?}"));
        }
        seen.push(canonical);
    }
    if config.rules.as_bytes().len() > MAX_RULE_TEXT_BYTES {
        return Err(format!(
            "rules exceed the {} byte limit",
            MAX_RULE_TEXT_BYTES
        ));
    }
    encode_transparent_start_command(config)?;
    Ok(())
}

fn is_ipv6_link_local(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(ip) if ip.is_unicast_link_local())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScopedIp {
    ip: IpAddr,
    zone: Option<String>,
}

impl ScopedIp {
    fn canonical_text(&self) -> String {
        match &self.zone {
            Some(zone) => format!("{}%{zone}", self.ip),
            None => self.ip.to_string(),
        }
    }
}

fn parse_scoped_ip(text: &str) -> Result<ScopedIp, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("transparent listen address is empty".to_owned());
    }
    let (ip_text, zone) = match text.split_once('%') {
        Some((ip_text, zone)) => {
            if ip_text.is_empty() || zone.is_empty() || zone.contains('%') {
                return Err(format!("invalid transparent listen address {text:?}"));
            }
            let index = zone.parse::<u32>().map_err(|_| {
                format!("transparent interface zone must be a positive numeric index: {text:?}")
            })?;
            if index == 0 {
                return Err(format!(
                    "transparent interface zone must be a positive numeric index: {text:?}"
                ));
            }
            let canonical_zone = index.to_string();
            (ip_text, Some(canonical_zone))
        }
        None => (text, None),
    };
    let ip = IpAddr::from_str(ip_text)
        .map_err(|error| format!("invalid transparent listen address {text:?}: {error}"))?;
    if matches!(ip, IpAddr::V6(value) if is_ipv4_mapped(value)) {
        return Err(format!(
            "IPv4-mapped transparent listen address is not allowed: {text:?}"
        ));
    }
    Ok(ScopedIp { ip, zone })
}

fn is_ipv4_mapped(ip: std::net::Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0xffff
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

fn encode_transparent_start_command(config: &TransparentDnsConfig) -> Result<Vec<u8>, String> {
    let mut command = serde_json::to_vec(&TransparentStartCommand {
        op: "start",
        config: TransparentStartConfig {
            transparent: true,
            listen_addresses: &config.listen_addresses,
            listen_port: config.listen_port,
            rules: &config.rules,
        },
    })
    .map_err(|error| format!("cannot encode transparent DNS configuration: {error}"))?;
    command.push(b'\n');
    if command.len() > MAX_COMMAND_BYTES {
        return Err(format!(
            "transparent DNS configuration exceeds the {} byte limit",
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

fn encode_flow_command(
    operation: &'static str,
    flow: &TransparentFlowRegistration,
) -> Result<Vec<u8>, String> {
    if operation != "register" && operation != "release" {
        return Err(format!(
            "unsupported transparent flow operation {operation:?}"
        ));
    }
    let mut command = serde_json::to_vec(&FlowCommand {
        op: operation,
        flow,
    })
    .map_err(|error| format!("cannot encode transparent DNS flow command: {error}"))?;
    command.push(b'\n');
    if command.len() > MAX_COMMAND_BYTES {
        return Err(format!(
            "transparent DNS flow command exceeds the {} byte limit",
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
fn desktop_primary_token() -> Result<OwnedHandle, String> {
    use windows::Win32::UI::WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId};
    unsafe {
        let mut pid = 0u32;
        GetWindowThreadProcessId(GetShellWindow(), Some(&mut pid));
        if pid == 0 {
            return Err("cannot find the desktop user's normal security token".to_owned());
        }

        let shell = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .map_err(|error| format!("cannot open the desktop shell process: {error}"))?;
        let shell = OwnedHandle::from_raw_handle(shell.0);
        let mut token = HANDLE::default();
        OpenProcessToken(
            HANDLE(shell.as_raw_handle()),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
            &mut token,
        )
        .map_err(|error| format!("cannot open the desktop shell token: {error}"))?;
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
        .map_err(|error| format!("cannot inspect the desktop token elevation: {error}"))?;
        if elevation.TokenIsElevated != 0 {
            return Err("the desktop token is elevated; refusing DNS proxy launch".to_owned());
        }

        let mut primary = HANDLE::default();
        DuplicateTokenEx(
            HANDLE(token.as_raw_handle()),
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut primary,
        )
        .map_err(|error| format!("cannot duplicate the desktop token: {error}"))?;
        if primary.is_invalid() {
            return Err("desktop token duplication returned an invalid handle".to_owned());
        }
        let primary = OwnedHandle::from_raw_handle(primary.0);

        let mut token_type = TOKEN_TYPE::default();
        GetTokenInformation(
            HANDLE(primary.as_raw_handle()),
            TokenType,
            Some((&mut token_type as *mut TOKEN_TYPE).cast()),
            std::mem::size_of::<TOKEN_TYPE>() as u32,
            &mut return_length,
        )
        .map_err(|error| format!("cannot query duplicated desktop token type: {error}"))?;
        if token_type != TokenPrimary {
            return Err(format!(
                "duplicated desktop token has unsupported type {}",
                token_type.0
            ));
        }
        Ok(primary)
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
    let token = if elevated {
        Some(desktop_primary_token()?)
    } else {
        None
    };
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
    let result = if let Some(token) = token.as_ref() {
        // CreateProcessWithTokenW uses plain STARTUPINFO. On supported x64
        // Windows it duplicates the supplied standard handles without general
        // inheritable-handle propagation (covered by the native sentinel test).
        let mut plain_startup = startup.StartupInfo;
        plain_startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        unsafe {
            CreateProcessWithTokenW(
                HANDLE(token.as_raw_handle()),
                CREATE_PROCESS_LOGON_FLAGS(0),
                PCWSTR(application.as_ptr()),
                PWSTR(command_line.as_mut_ptr()),
                PROCESS_CREATION_FLAGS(CREATE_NO_WINDOW) | CREATE_SUSPENDED,
                None,
                PCWSTR(directory.as_ptr()),
                &plain_startup,
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
    let udp_addrs = status.udp_addrs.unwrap_or_else(|| vec![udp_addr.clone()]);
    let tcp_addrs = status.tcp_addrs.unwrap_or_else(|| vec![tcp_addr.clone()]);
    for (primary, addresses) in [(&udp_addr, &udp_addrs), (&tcp_addr, &tcp_addrs)] {
        if addresses.is_empty() || addresses.len() > 16 || addresses.first() != Some(primary) {
            return Err("DNS proxy listener list is inconsistent".into());
        }
        for address in addresses {
            validate_ready_address("listener", address)?;
        }
    }
    Ok(DnsProcessStatus {
        udp_addr,
        tcp_addr,
        udp_addrs,
        tcp_addrs,
        rules_count: status.rules_count.unwrap_or(0),
        slots: status.slots.unwrap_or_default(),
    })
}

fn validate_transparent_listeners(
    status: &DnsProcessStatus,
    config: &TransparentDnsConfig,
) -> Result<(), String> {
    validate_transparent_config(config)?;
    let expected = config
        .listen_addresses
        .iter()
        .map(|address| parse_scoped_ip(address))
        .collect::<Result<Vec<_>, _>>()?;
    if status.udp_addrs.len() != expected.len() || status.tcp_addrs.len() != expected.len() {
        return Err("DNS proxy transparent listener count does not match the request".to_owned());
    }

    let mut listener_udp = Vec::with_capacity(expected.len());
    let mut listener_tcp = Vec::with_capacity(expected.len());
    for (index, expected_ip) in expected.iter().enumerate() {
        let udp = parse_scoped_socket_addr(&status.udp_addrs[index])?;
        let tcp = parse_scoped_socket_addr(&status.tcp_addrs[index])?;
        validate_transparent_listener_endpoint(
            "UDP",
            index,
            expected_ip,
            &udp,
            config.listen_port,
        )?;
        validate_transparent_listener_endpoint(
            "TCP",
            index,
            expected_ip,
            &tcp,
            config.listen_port,
        )?;
        listener_udp.push(udp);
        listener_tcp.push(tcp);
    }

    let expected_slot_count = expected
        .len()
        .checked_mul(8)
        .ok_or_else(|| "transparent upstream slot count overflowed".to_owned())?;
    if status.slots.len() != expected_slot_count {
        return Err(format!(
            "DNS proxy reported {} upstream slots, expected {expected_slot_count}",
            status.slots.len()
        ));
    }

    let mut seen_udp = std::collections::HashSet::with_capacity(status.slots.len());
    let mut seen_tcp = std::collections::HashSet::with_capacity(status.slots.len());
    for (index, slot) in status.slots.iter().enumerate() {
        if slot.id != index {
            return Err("DNS proxy upstream slot IDs are not contiguous".to_owned());
        }
        let address_index = index / 8;
        let udp = parse_scoped_socket_addr(&slot.udp_addr)?;
        let tcp = parse_scoped_socket_addr(&slot.tcp_addr)?;
        validate_transparent_slot_endpoint("UDP", index, &expected[address_index], &udp)?;
        validate_transparent_slot_endpoint("TCP", index, &expected[address_index], &tcp)?;
        if !seen_udp.insert(udp.canonical_text()) || !seen_tcp.insert(tcp.canonical_text()) {
            return Err("DNS proxy upstream slot endpoints are duplicated".to_owned());
        }
        if listener_udp
            .iter()
            .any(|listener| listener.canonical_text() == udp.canonical_text())
            || listener_tcp
                .iter()
                .any(|listener| listener.canonical_text() == tcp.canonical_text())
        {
            return Err("DNS proxy upstream slot overlaps a transparent listener".to_owned());
        }
    }
    Ok(())
}

fn validate_transparent_listener_endpoint(
    protocol: &str,
    index: usize,
    expected_ip: &ScopedIp,
    actual: &ScopedSocketAddr,
    requested_port: u16,
) -> Result<(), String> {
    if actual.ip != *expected_ip {
        return Err(format!(
            "DNS proxy {protocol} listener {index} does not match the requested IP/zone"
        ));
    }
    if actual.port == 0 || actual.port == 53 {
        return Err(format!(
            "DNS proxy {protocol} listener {index} has an invalid port"
        ));
    }
    if requested_port != 0 && actual.port != requested_port {
        return Err(format!(
            "DNS proxy {protocol} listener {index} did not bind the requested port"
        ));
    }
    Ok(())
}

fn validate_transparent_slot_endpoint(
    protocol: &str,
    index: usize,
    expected_ip: &ScopedIp,
    actual: &ScopedSocketAddr,
) -> Result<(), String> {
    if actual.ip != *expected_ip || actual.port == 0 || actual.port == 53 {
        return Err(format!(
            "DNS proxy {protocol} upstream slot {index} has an invalid IP/zone/port"
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScopedSocketAddr {
    ip: ScopedIp,
    port: u16,
}

impl ScopedSocketAddr {
    fn canonical_text(&self) -> String {
        if self.ip.ip.is_ipv6() {
            format!("[{}]:{}", self.ip.canonical_text(), self.port)
        } else {
            format!("{}:{}", self.ip.canonical_text(), self.port)
        }
    }
}

fn parse_scoped_socket_addr(text: &str) -> Result<ScopedSocketAddr, String> {
    let text = text.trim();
    let (host, port_text) = if let Some(rest) = text.strip_prefix('[') {
        let close = rest
            .find(']')
            .ok_or_else(|| format!("invalid DNS proxy endpoint {text:?}"))?;
        let host = &rest[..close];
        let port = rest
            .get(close + 1..)
            .and_then(|value| value.strip_prefix(':'))
            .ok_or_else(|| format!("invalid DNS proxy endpoint {text:?}"))?;
        (host, port)
    } else {
        let (host, port) = text
            .rsplit_once(':')
            .ok_or_else(|| format!("invalid DNS proxy endpoint {text:?}"))?;
        if host.contains(':') {
            return Err(format!(
                "IPv6 DNS proxy endpoint must use brackets: {text:?}"
            ));
        }
        (host, port)
    };
    let port = port_text
        .parse::<u16>()
        .map_err(|error| format!("invalid DNS proxy endpoint {text:?}: {error}"))?;
    Ok(ScopedSocketAddr {
        ip: parse_scoped_ip(host)?,
        port,
    })
}

fn validate_listeners(
    status: &DnsProcessStatus,
    listen_address: &str,
    port: u16,
    dual_stack: bool,
    upstream: &str,
) -> Result<(), String> {
    let mut expected: Vec<IpAddr> = if dual_stack {
        vec!["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()]
    } else {
        vec![if listen_address.trim().is_empty() {
            "127.0.0.1"
        } else {
            listen_address.trim()
        }
        .parse()
        .map_err(|_| "invalid expected DNS listener")?]
    };
    expected.sort_unstable();
    let upstream: SocketAddr = upstream
        .trim()
        .parse()
        .map_err(|_| "invalid expected upstream")?;
    for addresses in [&status.udp_addrs, &status.tcp_addrs] {
        let mut observed = Vec::new();
        for address in addresses {
            let address: SocketAddr = address.parse().map_err(|_| "invalid DNS listener")?;
            if address.ip().to_canonical() == upstream.ip().to_canonical()
                && address.port() == upstream.port()
            {
                return Err("DNS proxy upstream points back to its own listener".into());
            }
            if port != 0 && address.port() != port {
                return Err("DNS proxy did not bind the requested port".into());
            }
            observed.push(address.ip());
        }
        observed.sort_unstable();
        if observed != expected {
            return Err("DNS proxy did not bind every requested address family".into());
        }
    }
    Ok(())
}

fn validate_ready_address(name: &str, address: &str) -> Result<(), String> {
    let parsed = parse_scoped_socket_addr(address)
        .map_err(|error| format!("DNS proxy ready {name} is invalid: {error}"))?;
    if parsed.port == 0 {
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

fn validate_ready_status(status: &WireStatus) -> Result<(), String> {
    if status.error.is_some() {
        return Err("DNS proxy ready status carried an unexpected error".to_owned());
    }
    Ok(())
}

fn validate_empty_status(status: &WireStatus, context: &str) -> Result<(), String> {
    if status.error.is_some()
        || status.udp_addr.is_some()
        || status.tcp_addr.is_some()
        || status.udp_addrs.is_some()
        || status.tcp_addrs.is_some()
        || status.rules_count.is_some()
        || status.slots.is_some()
    {
        return Err(format!(
            "DNS proxy {context} status carried unexpected fields"
        ));
    }
    Ok(())
}

fn validate_error_status(status: &WireStatus, context: &str) -> Result<(), String> {
    if match status.error.as_deref() {
        None => true,
        Some(error) => error.trim().is_empty(),
    } {
        return Err(format!(
            "DNS proxy {context} error status omitted an error message"
        ));
    }
    if status.udp_addr.is_some()
        || status.tcp_addr.is_some()
        || status.udp_addrs.is_some()
        || status.tcp_addrs.is_some()
        || status.rules_count.is_some()
        || status.slots.is_some()
    {
        return Err(format!(
            "DNS proxy {context} error status carried unexpected fields"
        ));
    }
    Ok(())
}

fn validate_updated_status(status: &WireStatus) -> Result<(), String> {
    if status.error.is_some()
        || status.udp_addr.is_some()
        || status.tcp_addr.is_some()
        || status.udp_addrs.is_some()
        || status.tcp_addrs.is_some()
        || status.slots.is_some()
    {
        return Err("DNS proxy updated status carried an invalid payload".to_owned());
    }
    // The companion serializes a zero count with `omitempty`; in that case
    // an otherwise bare `updated` acknowledgement means zero rules.
    Ok(())
}

fn stop_running(mut running: Running, send_stop: bool) -> Result<(), String> {
    // The owner has now closed interception. Never race a timed-out writer
    // with a second command on the same byte stream.
    if running.pending_writer.is_some()
        || running.control == ControlState::Uncertain
        || running.quiescence == Quiescence::Uncertain
    {
        terminate_and_reap(&mut running);
        return Ok(());
    }
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
                        if let Err(error) = validate_empty_status(&status, "stopped") {
                            first_error.get_or_insert(error);
                        } else {
                            stopped = true;
                        }
                        break;
                    }
                    Ok(status) if status.status == "error" => {
                        match validate_error_status(&status, "stop") {
                            Ok(()) => {
                                first_error.get_or_insert_with(|| wire_error(&status));
                            }
                            Err(error) => {
                                first_error.get_or_insert(error);
                                break;
                            }
                        }
                    }
                    Ok(status) => {
                        first_error.get_or_insert(format!(
                            "DNS proxy reported unsupported stop status {:?}",
                            status.status
                        ));
                        break;
                    }
                    Err(error) => {
                        first_error.get_or_insert(error);
                        break;
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
        if let Some(worker) = self.pending_writer.take() {
            join_worker_bounded(worker);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn listener_readiness_requires_complete_requested_bindings() {
        let wire = serde_json::json!({
            "status":"ready", "udp_addr":"127.0.0.1:5300", "tcp_addr":"127.0.0.1:5300",
            "udp_addrs":["127.0.0.1:5300", "[::1]:5300"],
            "tcp_addrs":["127.0.0.1:5300", "[::1]:5300"], "rules_count":1
        });
        let status = ready_status(serde_json::from_value(wire.clone()).unwrap()).unwrap();
        assert!(validate_listeners(&status, "127.0.0.1", 5300, true, "192.0.2.53:53").is_ok());
        assert!(validate_listeners(&status, "127.0.0.1", 53, true, "192.0.2.53:53").is_err());
        assert!(validate_listeners(&status, "127.0.0.1", 5300, true, "[::1]:5300").is_err());
        assert!(
            validate_listeners(&status, "127.0.0.1", 5300, true, "[::ffff:127.0.0.1]:5300")
                .is_err()
        );
        let mut missing = status.clone();
        missing.tcp_addrs.pop();
        assert!(validate_listeners(&missing, "127.0.0.1", 5300, true, "192.0.2.53:53").is_err());
        let mut duplicate = status;
        duplicate.udp_addrs[1] = duplicate.udp_addrs[0].clone();
        assert!(validate_listeners(&duplicate, "127.0.0.1", 5300, true, "192.0.2.53:53").is_err());
        let mut wrong_primary = wire;
        wrong_primary["udp_addr"] = serde_json::json!("127.0.0.1:5301");
        assert!(ready_status(serde_json::from_value(wrong_primary).unwrap()).is_err());
    }

    #[test]
    fn legacy_single_listener_readiness_cannot_claim_dual_stack() {
        let status = ready_status(
            serde_json::from_value(serde_json::json!({
                "status":"ready", "udp_addr":"127.0.0.1:5300", "tcp_addr":"127.0.0.1:5301"
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(validate_listeners(&status, "", 0, false, "192.0.2.53:53").is_ok());
        assert!(validate_listeners(&status, "", 0, true, "192.0.2.53:53").is_err());
    }
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
            dual_stack: false,
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
        let socket = UdpSocket::bind(if address.is_ipv6() {
            "[::1]:0"
        } else {
            "127.0.0.1:0"
        })
        .expect("bind DNS query socket");
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
    fn query_tcp(address: SocketAddr, name: &str, qtype: u16) -> Vec<u8> {
        let timeout = Duration::from_secs(3);
        let mut socket = std::net::TcpStream::connect_timeout(&address, timeout).unwrap();
        socket.set_read_timeout(Some(timeout)).unwrap();
        socket.set_write_timeout(Some(timeout)).unwrap();
        let query = dns_query(name, qtype);
        socket
            .write_all(&(query.len() as u16).to_be_bytes())
            .unwrap();
        socket.write_all(&query).unwrap();
        let mut size = [0u8; 2];
        socket.read_exact(&mut size).unwrap();
        let mut response = vec![0u8; usize::from(u16::from_be_bytes(size))];
        socket.read_exact(&mut response).unwrap();
        response
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "Starts dual-stack loopback companion with synthetic upstream; no system DNS changes"]
    fn live_dual_stack_filters_udp_tcp_and_reloads_one_engine() {
        let upstream = SyntheticUpstream::start();
        let manager = DnsProcessManager::new(test_directory("dual-stack"));
        let mut input = config(upstream.address);
        input.dual_stack = true;
        let initial = manager
            .start(input)
            .expect("both families must become ready");
        assert_eq!(initial.udp_addrs.len(), 2);
        assert_eq!(initial.tcp_addrs.len(), 2);
        for (addresses, tcp) in [(&initial.udp_addrs, false), (&initial.tcp_addrs, true)] {
            for address in addresses {
                let address: SocketAddr = address.parse().unwrap();
                for (name, rcode) in [("ads.example", 3), ("allowed.ads.example", 0)] {
                    let response = if tcp {
                        query_tcp(address, name, 28)
                    } else {
                        query_udp(address, name, 28)
                    };
                    assert_eq!(response_rcode(&response), rcode);
                    assert_eq!(
                        response_answer_count(&response),
                        if rcode == 0 { 1 } else { 0 }
                    );
                }
            }
        }
        let reloaded = manager.reload("||new.example^".into()).unwrap();
        assert_eq!(initial.udp_addrs, reloaded.udp_addrs);
        assert_eq!(initial.tcp_addrs, reloaded.tcp_addrs);
        for address in &reloaded.udp_addrs {
            assert_eq!(
                response_rcode(&query_udp(address.parse().unwrap(), "new.example", 1)),
                3
            );
        }
        manager.stop().unwrap();
        assert!(manager.status().unwrap().is_none());
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
        plain_token_probe_child_with_command(executable, token, _sentinels, "exit 0")
    }

    #[cfg(windows)]
    fn plain_token_probe_child_with_command(
        executable: &Path,
        token: &OwnedHandle,
        _sentinels: &[OwnedHandle],
        command: &str,
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
        let mut command_line = format!("\"{}\" /c {command}", executable.display())
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
            if let Err(error) =
                GetProcessHandleCount(HANDLE(process.as_raw_handle()), &mut handle_count)
            {
                let _ = TerminateProcess(HANDLE(process.as_raw_handle()), 1);
                WaitForSingleObject(HANDLE(process.as_raw_handle()), 5_000);
                return Err(format!("cannot count probe child handles: {error}"));
            }
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
    fn plain_token_probe_stdio(token: &OwnedHandle) -> Result<Vec<u8>, String> {
        let executable = std::env::var_os("ComSpec")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows\System32\cmd.exe"));
        // `more` copies the redirected stdin to stdout and exits on EOF. This
        // exercises both STARTF_USESTDHANDLES entries without an EX startup
        // structure or an ambient handle list.
        let (mut spawned, _) =
            plain_token_probe_child_with_command(&executable, token, &[], "more")?;
        if let Err(error) = verify_child_token_medium_or_lower(&spawned.child) {
            terminate_child(&mut spawned.child, None);
            return Err(error);
        }

        if unsafe { ResumeThread(HANDLE(spawned.thread.as_raw_handle())) } == u32::MAX {
            terminate_child(&mut spawned.child, None);
            let _ = unsafe {
                WaitForSingleObject(HANDLE(spawned.child.process.as_raw_handle()), 5_000)
            };
            return Err("cannot resume plain token stdio probe".to_owned());
        }
        drop(spawned.thread);

        let mut stdin = spawned
            .child
            .stdin
            .take()
            .ok_or_else(|| "plain token probe stdin pipe was not created".to_owned())?;
        if let Err(error) = stdin.write_all(b"dns-token-stdio-probe\r\n") {
            terminate_child(&mut spawned.child, None);
            let _ = unsafe {
                WaitForSingleObject(HANDLE(spawned.child.process.as_raw_handle()), 5_000)
            };
            return Err(format!("cannot write plain token probe stdin: {error}"));
        }
        drop(stdin);

        let wait =
            unsafe { WaitForSingleObject(HANDLE(spawned.child.process.as_raw_handle()), 5_000) };
        if wait != windows::Win32::Foundation::WAIT_OBJECT_0 {
            terminate_child(&mut spawned.child, None);
            let _ = unsafe {
                WaitForSingleObject(HANDLE(spawned.child.process.as_raw_handle()), 5_000)
            };
            return Err(format!("plain token stdio probe did not exit: {wait:?}"));
        }

        let mut output = Vec::new();
        spawned
            .child
            .stdout
            .take()
            .ok_or_else(|| "plain token probe stdout pipe was not created".to_owned())?
            .read_to_end(&mut output)
            .map_err(|error| format!("cannot read plain token probe stdout: {error}"))?;
        Ok(output)
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
        verify_child_token_medium_or_lower(&spawned.child)?;
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
            dual_stack: false,
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
    fn transparent_start_and_flow_commands_preserve_scoped_wire_shape() {
        let config = TransparentDnsConfig {
            listen_addresses: vec!["127.0.0.1".to_owned(), "fe80::1%3".to_owned()],
            listen_port: 0,
            rules: "||ads.example^".to_owned(),
        };
        validate_transparent_config(&config).expect("valid transparent config");
        let start = encode_transparent_start_command(&config).expect("encode transparent start");
        let start: serde_json::Value = serde_json::from_slice(&start[..start.len() - 1]).unwrap();
        assert_eq!(start["op"], "start");
        assert_eq!(start["config"]["transparent"], true);
        assert_eq!(start["config"]["listen_addresses"][1], "fe80::1%3");

        let flow = TransparentFlowRegistration {
            protocol: "udp".to_owned(),
            peer: "192.0.2.10:53000".to_owned(),
            local: "127.0.0.1:5300".to_owned(),
            resolver: "192.0.2.53:53".to_owned(),
            slot: 7,
            lifetime_ms: 120_000,
        };
        let command = encode_flow_command("register", &flow).expect("encode flow command");
        let command: serde_json::Value =
            serde_json::from_slice(&command[..command.len() - 1]).unwrap();
        assert_eq!(command["op"], "register");
        assert_eq!(command["flow"]["slot"], 7);
        assert_eq!(command["flow"]["lifetime_ms"], 120_000u64);
    }

    #[test]
    fn command_ack_shapes_reject_unexpected_known_fields() {
        let empty = |status: &str| WireStatus {
            status: status.to_owned(),
            error: None,
            udp_addr: None,
            tcp_addr: None,
            udp_addrs: None,
            tcp_addrs: None,
            rules_count: None,
            slots: None,
        };

        let mut registered = empty("registered");
        validate_empty_status(&registered, "register").expect("bare register ack");
        registered.rules_count = Some(1);
        assert!(validate_empty_status(&registered, "register").is_err());

        let mut rejected = empty("error");
        rejected.error = Some("flow is not registered".to_owned());
        validate_error_status(&rejected, "release").expect("bare error ack");
        rejected.slots = Some(Vec::new());
        assert!(validate_error_status(&rejected, "release").is_err());

        let mut updated = empty("updated");
        updated.rules_count = Some(2);
        validate_updated_status(&updated).expect("rules-only reload ack");
        updated.tcp_addr = Some("127.0.0.1:53".to_owned());
        assert!(validate_updated_status(&updated).is_err());
    }

    #[test]
    fn transparent_readiness_requires_exact_zones_and_eight_distinct_slots() {
        let config = TransparentDnsConfig {
            listen_addresses: vec!["fe80::1%3".to_owned()],
            listen_port: 5300,
            rules: String::new(),
        };
        let slots = (0..8)
            .map(|id| UpstreamSlot {
                id,
                udp_addr: format!("[fe80::1%3]:{}", 42000 + id),
                tcp_addr: format!("[fe80::1%3]:{}", 43000 + id),
            })
            .collect();
        let status = DnsProcessStatus {
            udp_addr: "[fe80::1%3]:5300".to_owned(),
            tcp_addr: "[fe80::1%3]:5300".to_owned(),
            udp_addrs: vec!["[fe80::1%3]:5300".to_owned()],
            tcp_addrs: vec!["[fe80::1%3]:5300".to_owned()],
            rules_count: 0,
            slots,
        };
        validate_transparent_listeners(&status, &config).expect("exact scoped readiness");

        let mut wrong_zone = status.clone();
        wrong_zone.udp_addrs[0] = "[fe80::1%4]:5300".to_owned();
        assert!(validate_transparent_listeners(&wrong_zone, &config).is_err());

        let mut missing_slot = status.clone();
        missing_slot.slots.pop();
        assert!(validate_transparent_listeners(&missing_slot, &config).is_err());

        let mut overlapping = status;
        overlapping.slots[0].udp_addr = "[fe80::1%3]:5300".to_owned();
        assert!(validate_transparent_listeners(&overlapping, &config).is_err());
    }

    #[test]
    fn transparent_config_rejects_wildcards_bad_zones_and_reserved_port() {
        for config in [
            TransparentDnsConfig {
                listen_addresses: vec!["0.0.0.0".to_owned()],
                listen_port: 0,
                rules: String::new(),
            },
            TransparentDnsConfig {
                listen_addresses: vec!["127.0.0.1%3".to_owned()],
                listen_port: 0,
                rules: String::new(),
            },
            TransparentDnsConfig {
                listen_addresses: vec!["::1%3".to_owned()],
                listen_port: 0,
                rules: String::new(),
            },
            TransparentDnsConfig {
                listen_addresses: vec!["::ffff:127.0.0.1".to_owned()],
                listen_port: 0,
                rules: String::new(),
            },
            TransparentDnsConfig {
                listen_addresses: vec!["fe80::1".to_owned()],
                listen_port: 0,
                rules: String::new(),
            },
            TransparentDnsConfig {
                listen_addresses: vec!["fe80::1%0".to_owned()],
                listen_port: 0,
                rules: String::new(),
            },
            TransparentDnsConfig {
                listen_addresses: vec!["fe80::1%Ethernet".to_owned()],
                listen_port: 0,
                rules: String::new(),
            },
            TransparentDnsConfig {
                listen_addresses: vec!["127.0.0.1".to_owned()],
                listen_port: 53,
                rules: String::new(),
            },
        ] {
            assert!(validate_transparent_config(&config).is_err());
        }
    }

    #[cfg(windows)]
    fn exercise_transparent_uncertain_control(operation: &str, malformed: bool) {
        let path = test_directory(&format!("transparent-{operation}-uncertain"));
        let manager = DnsProcessManager::new(path.clone());
        let config = TransparentDnsConfig {
            listen_addresses: vec!["127.0.0.1".into()],
            listen_port: 0,
            rules: String::new(),
        };
        let status = manager
            .start_transparent(config.clone())
            .expect("real transparent companion should start unelevated");
        let client = UdpSocket::bind("127.0.0.1:0").expect("bind transparent local client");
        client
            .connect(&status.udp_addr)
            .expect("connect transparent local client");
        let flow = TransparentFlowRegistration {
            protocol: "udp".into(),
            peer: client.local_addr().unwrap().to_string(),
            local: status.udp_addr.clone(),
            resolver: "127.0.0.1:53".into(),
            slot: status.slots[0].id,
            lifetime_ms: 120_000,
        };

        let (sender, injected) = mpsc::sync_channel(1);
        if malformed {
            let line = match operation {
                "register" => br#"{"status":"registered","rules_count":1}"#.to_vec(),
                "reload" => br#"{"status":"updated","tcp_addr":"127.0.0.1:1"}"#.to_vec(),
                _ => panic!("unsupported transparent control operation {operation}"),
            };
            sender
                .send(ReaderEvent::Line(line))
                .expect("inject malformed acknowledgement");
        }
        let actual = {
            let mut state = manager.running.lock().unwrap();
            std::mem::replace(&mut state.as_mut().unwrap().events, injected)
        };

        let issue = |manager: &DnsProcessManager| match operation {
            "register" => manager.register_flow(flow.clone()).map(|()| ()),
            "reload" => manager
                .reload_transparent("||uncertain.example.test^".to_owned())
                .map(|_| ())
                .map_err(|error| match error {
                    TransparentReloadError::Uncertain(error) => error,
                    TransparentReloadError::Rejected(error) => {
                        panic!("uncertain control response was classified as a rule rejection: {error}")
                    }
                }),
            _ => panic!("unsupported transparent control operation {operation}"),
        };
        assert!(
            issue(&manager).is_err(),
            "first {operation} must be uncertain"
        );
        let retry = issue(&manager).expect_err("uncertain command must not be retried");
        assert!(
            retry.contains("uncertain"),
            "retry error must expose uncertain ownership state: {retry}"
        );
        assert!(
            manager.start_transparent(config).is_err(),
            "uncertain transparent owner must not be replaced"
        );
        assert!(manager.status().unwrap().is_some());
        assert_ports_reserved(&status);

        drop(sender);
        manager
            .stop()
            .expect("explicit stop must clean up uncertain transparent owner");
        assert_ports_released(&status);
        drop(actual);
        let _ = fs::remove_dir_all(path);
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "real unelevated companion with local sockets only; no driver or DNS settings"]
    fn transparent_register_malformed_or_timeout_retains_owner_without_retry() {
        for malformed in [true, false] {
            exercise_transparent_uncertain_control("register", malformed);
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "real unelevated companion with local sockets only; no driver or DNS settings"]
    fn transparent_reload_malformed_or_timeout_retains_owner_without_retry() {
        for malformed in [true, false] {
            exercise_transparent_uncertain_control("reload", malformed);
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "real unelevated helper and local sockets only; no interception or DNS settings"]
    fn quiesce_retains_ports_until_explicit_stop() {
        let path = test_directory("quiesce-retention");
        let manager = DnsProcessManager::new(path.clone());
        let status = manager
            .start_transparent(TransparentDnsConfig {
                listen_addresses: vec!["127.0.0.1".into()],
                listen_port: 0,
                rules: "||blocked.example.test^".into(),
            })
            .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.connect(&status.udp_addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let flow = TransparentFlowRegistration {
            protocol: "udp".into(),
            peer: client.local_addr().unwrap().to_string(),
            local: status.udp_addr.clone(),
            resolver: "127.0.0.1:53".into(),
            slot: 0,
            lifetime_ms: 120_000,
        };
        manager.register_flow(flow.clone()).unwrap();
        let query = dns_query("blocked.example.test", 1);
        client.send(&query).unwrap();
        let mut response = [0; 512];
        let n = client.recv(&mut response).unwrap();
        assert_eq!(response_rcode(&response[..n]), 3);
        let mut tcp = std::net::TcpStream::connect(&status.tcp_addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        manager.quiesce().unwrap();
        manager.quiesce().unwrap();
        assert!(manager.register_flow(flow.clone()).is_err());
        assert!(manager.release_flow(flow).is_err());
        assert!(manager.reload(String::new()).is_err());
        assert!(manager.status().unwrap().is_some());
        assert_ports_reserved(&status);
        client
            .set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        client.send(&query).unwrap();
        assert!(client.recv(&mut response).is_err());
        match tcp.read(&mut response) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::BrokenPipe
                ) => {}
            other => panic!("active TCP connection did not stop at the barrier: {other:?}"),
        }
        manager.stop().unwrap();
        assert!(manager.status().unwrap().is_none());
        assert_ports_released(&status);
        let _ = fs::remove_dir_all(path);
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "real unelevated helper with injected acknowledgement failure; no driver"]
    fn quiesce_uncertainty_preserves_child_and_reserved_ports() {
        for malformed in [true, false] {
            let path = test_directory("quiesce-uncertain");
            let manager = DnsProcessManager::new(path.clone());
            let status = manager
                .start_transparent(TransparentDnsConfig {
                    listen_addresses: vec!["127.0.0.1".into()],
                    listen_port: 0,
                    rules: String::new(),
                })
                .unwrap();
            let (sender, injected) = mpsc::sync_channel(1);
            if malformed {
                sender
                    .send(ReaderEvent::Line(
                        br#"{"status":"quiesced","rules_count":1}"#.to_vec(),
                    ))
                    .unwrap();
            }
            let actual = {
                let mut state = manager.running.lock().unwrap();
                std::mem::replace(&mut state.as_mut().unwrap().events, injected)
            };
            assert!(manager.quiesce().is_err());
            assert!(manager.quiesce().is_err());
            assert!(manager.reload(String::new()).is_err());
            assert!(manager.status().unwrap().is_some());
            assert_ports_reserved(&status);
            // Consume the genuine acknowledgement before restoring the stream.
            let event = actual.recv_timeout(QUIESCE_TIMEOUT).unwrap();
            let ReaderEvent::Line(line) = event else {
                panic!("missing real quiesce acknowledgement")
            };
            let ack = parse_wire_status(&line).unwrap();
            assert_eq!(ack.status, "quiesced");
            validate_empty_status(&ack, "quiesce").unwrap();
            {
                let mut state = manager.running.lock().unwrap();
                state.as_mut().unwrap().events = actual;
            }
            drop(sender);
            manager.stop().unwrap();
            assert_ports_released(&status);
            let _ = fs::remove_dir_all(path);
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "real unelevated helper killed deliberately; no driver or system settings"]
    fn quiesce_child_exit_requires_explicit_owner_cleanup() {
        let path = test_directory("quiesce-child-exit");
        let manager = DnsProcessManager::new(path.clone());
        let config = TransparentDnsConfig {
            listen_addresses: vec!["127.0.0.1".into()],
            listen_port: 0,
            rules: String::new(),
        };
        manager.start_transparent(config.clone()).unwrap();
        manager.quiesce().unwrap();
        {
            let mut state = manager.running.lock().unwrap();
            let running = state.as_mut().unwrap();
            assert!(running.pending_writer.is_none());
            // Model death after an uncertain control outcome. The OS releases
            // sockets on death, but health polling must not replace the owner.
            running.quiescence = Quiescence::Uncertain;
            terminate_and_reap(running);
        }
        assert!(manager.status().is_err());
        assert!(manager.running.lock().unwrap().is_some());
        assert!(manager.start_transparent(config.clone()).is_err());
        assert!(manager.running.lock().unwrap().is_some());
        let _ = manager.stop();
        assert!(manager.running.lock().unwrap().is_none());
        manager.start_transparent(config).unwrap();
        manager.stop().unwrap();
        let _ = fs::remove_dir_all(path);
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "real unelevated helper and anonymous pipes only; no driver or system settings"]
    fn stop_with_pending_control_writer_does_not_send_a_second_command() {
        let path = test_directory("quiesce-pending-writer");
        let manager = DnsProcessManager::new(path.clone());
        manager
            .start_transparent(TransparentDnsConfig {
                listen_addresses: vec!["127.0.0.1".into()],
                listen_port: 0,
                rules: String::new(),
            })
            .expect("real transparent companion should start unelevated");

        // Keep a duplicate of the parent's real stdin writer alive while
        // replacing the manager's writer with a private pipe. If
        // stop_running accidentally sends a second command, the private
        // reader below observes it.
        let (stop_reader, stop_writer) = anonymous_pipe().expect("stop-observation pipe");
        let mut stop_reader = unsafe { File::from_raw_handle(stop_reader.into_raw_handle()) };
        let stop_writer = unsafe { File::from_raw_handle(stop_writer.into_raw_handle()) };
        let original_stdin = {
            let mut state = manager.running.lock().unwrap();
            let running = state.as_mut().expect("running transparent companion");
            let original = running
                .stdin
                .as_ref()
                .expect("companion stdin")
                .try_clone()
                .expect("clone companion stdin");
            running.stdin = Some(stop_writer);
            original
        };

        // A large synchronous write to an unread anonymous pipe remains
        // pending. The drainer is released only when explicit stop begins,
        // allowing Running::Drop to join the pending writer in its bounded
        // cleanup window instead of detaching it.
        let (writer_read, writer_write) = anonymous_pipe().expect("writer pipe");
        let writer_read = unsafe { File::from_raw_handle(writer_read.into_raw_handle()) };
        let mut writer = unsafe { File::from_raw_handle(writer_write.into_raw_handle()) };
        let writer_started = Arc::new(AtomicBool::new(false));
        let writer_completed = Arc::new(AtomicBool::new(false));
        let drain_requested = Arc::new(AtomicBool::new(false));
        let writer_started_thread = Arc::clone(&writer_started);
        let writer_completed_thread = Arc::clone(&writer_completed);
        let writer_worker = thread::spawn(move || {
            writer_started_thread.store(true, Ordering::Release);
            let result = writer.write_all(&vec![0x5a; 1024 * 1024]);
            writer_completed_thread.store(true, Ordering::Release);
            result
        });
        while !writer_started.load(Ordering::Acquire) {
            thread::yield_now();
        }
        thread::sleep(Duration::from_millis(50));
        if writer_worker.is_finished() {
            let _ = writer_worker.join();
            panic!("test writer unexpectedly completed before stop");
        }

        let drain_requested_thread = Arc::clone(&drain_requested);
        let drainer = thread::spawn(move || {
            while !drain_requested_thread.load(Ordering::Acquire) {
                thread::sleep(READER_POLL_INTERVAL);
            }
            let mut reader = writer_read;
            let mut buffer = [0u8; 8192];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => return Ok::<(), io::Error>(()),
                    Ok(_) => {}
                    Err(error) => return Err(error),
                }
            }
        });

        {
            let mut state = manager.running.lock().unwrap();
            let running = state.as_mut().expect("running transparent companion");
            running.quiescence = Quiescence::Uncertain;
            running.pending_writer = Some(writer_worker);
        }
        drain_requested.store(true, Ordering::Release);
        let stop_started = Instant::now();
        let stop_result = manager.stop();
        let stop_elapsed = stop_started.elapsed();
        let drain_result = drainer.join();
        let writer_completed = writer_completed.load(Ordering::Acquire);

        // Closing the manager's private writer at stop completion makes this
        // read return EOF. Any stop command would instead be observable here.
        drop(original_stdin);
        let mut observed = Vec::new();
        stop_reader
            .read_to_end(&mut observed)
            .expect("read stop-observation pipe");

        assert!(
            stop_result.is_ok(),
            "pending-writer stop failed: {stop_result:?}"
        );
        assert!(
            drain_result.is_ok(),
            "writer drainer failed: {drain_result:?}"
        );
        assert!(
            writer_completed,
            "pending writer did not complete before cleanup returned"
        );
        assert!(
            stop_elapsed < STOP_TIMEOUT,
            "pending-writer stop exceeded its bounded cleanup window: {stop_elapsed:?}"
        );
        assert!(
            observed.is_empty(),
            "stop wrote a second command while quiesce writer was pending: {observed:?}"
        );
        assert!(manager.running.lock().unwrap().is_none());
        let _ = fs::remove_dir_all(path);
    }

    #[cfg(windows)]
    fn assert_ports_reserved(status: &DnsProcessStatus) {
        for address in status
            .udp_addrs
            .iter()
            .chain(status.slots.iter().map(|slot| &slot.udp_addr))
        {
            assert!(
                UdpSocket::bind(address).is_err(),
                "reserved UDP port was released"
            );
        }
        for address in status
            .tcp_addrs
            .iter()
            .chain(status.slots.iter().map(|slot| &slot.tcp_addr))
        {
            assert!(
                std::net::TcpListener::bind(address).is_err(),
                "reserved TCP port was released"
            );
        }
    }

    #[cfg(windows)]
    fn assert_ports_released(status: &DnsProcessStatus) {
        for address in status
            .udp_addrs
            .iter()
            .chain(status.slots.iter().map(|slot| &slot.udp_addr))
        {
            let _bound =
                UdpSocket::bind(address).expect("UDP endpoint should be released after stop");
        }
        for address in status
            .tcp_addrs
            .iter()
            .chain(status.slots.iter().map(|slot| &slot.tcp_addr))
        {
            let _bound = std::net::TcpListener::bind(address)
                .expect("TCP endpoint should be released after stop");
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires the real unelevated transparent companion; no DNS or system settings are changed"]
    fn starts_real_transparent_companion_registers_and_releases_flow() {
        let path = test_directory("transparent-start");
        let manager = DnsProcessManager::new(path.clone());
        let status = manager
            .start_transparent(TransparentDnsConfig {
                listen_addresses: vec!["127.0.0.1".to_owned()],
                listen_port: 0,
                rules: "||blocked.example.test^".to_owned(),
            })
            .expect("real transparent companion should start unelevated");
        assert_eq!(status.udp_addrs.len(), 1);
        assert_eq!(status.tcp_addrs.len(), 1);
        assert_eq!(status.slots.len(), 8);

        let listener: SocketAddr = status.udp_addrs[0]
            .parse()
            .expect("transparent UDP listener address");
        let filter_config = crate::protection::dns_filter::DnsFilterConfig {
            local_ips: vec![listener.ip()],
            udp_proxy_listeners: status
                .udp_addrs
                .iter()
                .map(|address| address.parse().expect("UDP listener endpoint"))
                .collect(),
            tcp_proxy_listeners: status
                .tcp_addrs
                .iter()
                .map(|address| address.parse().expect("TCP listener endpoint"))
                .collect(),
            udp_upstreams: status
                .slots
                .iter()
                .map(|slot| slot.udp_addr.parse().expect("UDP slot endpoint"))
                .collect(),
            tcp_upstreams: status
                .slots
                .iter()
                .map(|slot| slot.tcp_addr.parse().expect("TCP slot endpoint"))
                .collect(),
        };
        let filters = crate::protection::dns_filter::build_dns_filters(&filter_config)
            .expect("transparent readiness should build complete DNS filters");
        assert_eq!(filters.len(), 1);
        assert!(filters[0].contains(&listener.ip().to_string()));
        let client =
            std::net::UdpSocket::bind("127.0.0.1:0").expect("transparent UDP client socket");
        client
            .connect(listener)
            .expect("transparent UDP client connect");
        let peer = client
            .local_addr()
            .expect("transparent UDP client local address");
        assert_ne!(peer.port(), listener.port());
        let flow = TransparentFlowRegistration {
            protocol: "udp".to_owned(),
            peer: peer.to_string(),
            local: listener.to_string(),
            resolver: "127.0.0.1:53".to_owned(),
            slot: status.slots[0].id,
            lifetime_ms: 120_000,
        };
        manager
            .register_flow(flow.clone())
            .expect("transparent flow should register");
        let mut query = vec![
            0x12, 0x34, // transaction ID
            0x01, 0x00, // recursion desired
            0x00, 0x01, // one question
            0x00, 0x00, // no answers
            0x00, 0x00, // no authority records
            0x00, 0x00, // no additional records
        ];
        for label in ["blocked", "example", "test"] {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.extend_from_slice(&[0, 0, 1, 0, 1]); // root, A, IN
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set DNS response timeout");
        client.send(&query).expect("send authorized DNS query");
        let mut response = [0u8; 2048];
        let response_len = client.recv(&mut response).expect("blocked DNS response");
        assert!(response_len >= 12);
        assert_eq!(&response[..2], &query[..2]);
        assert_eq!(u16::from_be_bytes([response[2], response[3]]) & 0x000f, 3);
        manager
            .release_flow(flow.clone())
            .expect("transparent flow should release");
        assert!(manager.register_flow(flow).is_err());
        assert!(manager
            .status()
            .expect("status after rejected flow")
            .is_some());
        client
            .set_read_timeout(Some(Duration::from_millis(250)))
            .expect("set released DNS timeout");
        client.send(&query).expect("send released DNS query");
        assert!(client.recv(&mut response).is_err());
        manager.stop().expect("transparent companion should stop");
        assert_eq!(manager.status().expect("stopped status"), None);
        let _ = fs::remove_dir_all(path);
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
    #[ignore = "requires a Windows desktop token and the real companion; supports elevated and normal callers"]
    fn reload_changes_live_udp_rules_and_preserves_rejected_update() {
        let upstream = SyntheticUpstream::start();
        let path = test_directory("reload");
        let manager = DnsProcessManager::new(path.clone());
        let initial = manager
            .start(DnsProcessConfig {
                upstream: upstream.address().to_string(),
                listen_address: "127.0.0.1".to_owned(),
                listen_port: 0,
                dual_stack: false,
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
            quiescence: Quiescence::Active,
            control: ControlState::Certain,
            pending_writer: None,
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

    #[cfg(windows)]
    #[test]
    #[ignore = "requires an elevated interactive app; probes desktop-primary CreateProcessWithTokenW stdio and handle inheritance"]
    fn elevated_desktop_primary_plain_token_probe_stdio_and_handles() {
        assert!(
            crate::firewall::FirewallManager::is_elevated(),
            "run this desktop-token probe from an elevated app token"
        );
        let token = desktop_primary_token().expect("obtain the desktop primary token");

        let baseline = plain_token_probe_handle_count(&token, false)
            .expect("plain token probe without sentinel handles");
        let with_sentinels = plain_token_probe_handle_count(&token, true)
            .expect("plain token probe with sentinel handles");
        assert_eq!(
            with_sentinels, baseline,
            "plain CreateProcessWithTokenW inherited an ambient sentinel handle"
        );

        let output = plain_token_probe_stdio(&token).expect("plain token probe stdio");
        let output = String::from_utf8_lossy(&output);
        assert!(
            output.contains("dns-token-stdio-probe"),
            "plain CreateProcessWithTokenW did not round-trip redirected stdio: {output:?}"
        );
    }
}
