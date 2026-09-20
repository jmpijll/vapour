//! Owned runtime for one transparent DNS interception generation.
//!
//! The supervisor owns the companion, active WinDivert handles, and worker
//! joins.  Workers retain an `Arc` to both the companion and their native
//! handle until their receive loop has exited; a bounded stop therefore keeps
//! all resources alive when native receive cannot be interrupted promptly.

use super::{
    dns_divert::ActiveHandle,
    dns_process::{DnsProcessManager, TransparentDnsConfig, TransparentReloadError},
    dns_router::{PacketRouter, RouteError, RoutedPacket},
};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const MAX_PACKET_BYTES: usize = 65_575;
const SUPERVISOR_POLL: Duration = Duration::from_millis(100);
const WORKER_POLL: Duration = Duration::from_millis(5);
const INTERNAL_STOP_TIMEOUT: Duration = Duration::from_secs(15);

static GENERATION_OWNED: AtomicBool = AtomicBool::new(false);

/// Process-local exclusion, retained by detached cleanup as well as workers.
/// A startup error is not permission to overlap the previous generation.
struct GenerationLease {
    gate: &'static AtomicBool,
    cleanup_confirmed: AtomicBool,
}
impl GenerationLease {
    fn acquire() -> Result<Arc<Self>, String> {
        Self::acquire_from(&GENERATION_OWNED)
    }
    fn acquire_from(gate: &'static AtomicBool) -> Result<Arc<Self>, String> {
        gate.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| {
                Arc::new(Self {
                    gate,
                    cleanup_confirmed: AtomicBool::new(false),
                })
            })
            .map_err(|_| "A DNS interception generation is active or still cleaning up".to_owned())
    }
    fn confirm_cleanup(&self) {
        self.cleanup_confirmed.store(true, Ordering::Release);
    }
}
impl Drop for GenerationLease {
    fn drop(&mut self) {
        if self.cleanup_confirmed.load(Ordering::Acquire) {
            self.gate.store(false, Ordering::Release);
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DnsSessionState {
    Starting = 0,
    Running = 1,
    Failed = 2,
    Stopping = 3,
    StopPending = 4,
    Stopped = 5,
}

impl DnsSessionState {
    fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::Starting,
            1 => Self::Running,
            2 => Self::Failed,
            3 => Self::Stopping,
            4 => Self::StopPending,
            5 => Self::Stopped,
            _ => Self::Failed,
        }
    }

    fn is_draining(self) -> bool {
        matches!(
            self,
            Self::Failed | Self::Stopping | Self::StopPending | Self::Stopped
        )
    }
}

struct SessionState {
    state: AtomicU8,
    first_error: Mutex<Option<String>>,
    cleanup_complete: AtomicBool,
    rollover_requested: AtomicBool,
}

impl SessionState {
    fn new() -> Self {
        Self {
            state: AtomicU8::new(DnsSessionState::Starting as u8),
            first_error: Mutex::new(None),
            cleanup_complete: AtomicBool::new(false),
            rollover_requested: AtomicBool::new(false),
        }
    }

    fn load(&self) -> DnsSessionState {
        DnsSessionState::from_raw(self.state.load(Ordering::Acquire))
    }

    fn store(&self, state: DnsSessionState) {
        self.state.store(state as u8, Ordering::Release);
    }

    fn fail(&self, error: impl Into<String>) {
        let error = error.into();
        if let Ok(mut first) = self.first_error.lock() {
            if first.is_none() {
                *first = Some(error);
            }
        }
        if !matches!(self.load(), DnsSessionState::Stopped) {
            self.store(DnsSessionState::Failed);
        }
    }

    fn error(&self) -> Option<String> {
        self.first_error.lock().ok().and_then(|error| error.clone())
    }
}

enum WorkerEvent {
    Exited {
        index: usize,
        result: Result<(), String>,
    },
}

struct SessionCore {
    // Keep native handles before the manager so emergency Arc teardown never
    // releases the companion while an interception handle is still owned.
    handles: Mutex<Vec<Arc<ActiveHandle>>>,
    manager: Arc<DnsProcessManager>,
    router: Mutex<PacketRouter>,
    state: Arc<SessionState>,
    events: Sender<WorkerEvent>,
    clock: Instant,
    drain_enabled: AtomicBool,
    finish_without_drain: AtomicBool,
    shutdown_complete: Mutex<Vec<bool>>,
    // Last field: release admission to a replacement after resource owners.
    // None is used only by tests which create no interception handles.
    _generation: Option<Arc<GenerationLease>>,
}

impl SessionCore {
    fn confirm_cleanup(&self) {
        self.state.cleanup_complete.store(true, Ordering::Release);
        if let Some(generation) = &self._generation {
            generation.confirm_cleanup();
        }
    }
    fn now_ms(&self) -> u64 {
        self.clock.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }

    fn is_draining(&self) -> bool {
        self.state.load().is_draining()
    }

    fn drain_enabled(&self) -> bool {
        self.drain_enabled.load(Ordering::Acquire)
    }

    fn enable_drain(&self) {
        self.drain_enabled.store(true, Ordering::Release);
    }

    fn allow_finish_without_drain(&self) {
        self.finish_without_drain.store(true, Ordering::Release);
    }

    fn finish_without_drain(&self) -> bool {
        self.finish_without_drain.load(Ordering::Acquire)
    }

    fn handles_shutdown(&self) -> bool {
        self.shutdown_complete
            .lock()
            .map(|complete| complete.iter().all(|complete| *complete))
            .unwrap_or(false)
    }

    /// Freeze packet admission before asking the companion to quiesce.  The
    /// router mutex is also the in-flight registration gate: a synchronous
    /// register callback cannot race this transition.
    fn freeze_admission(&self) {
        self.state.store(DnsSessionState::Stopping);
        self.drain_enabled.store(false, Ordering::Release);
        self.finish_without_drain.store(false, Ordering::Release);
        if let Ok(mut router) = self.router.lock() {
            router.stop_admission();
        } else {
            self.state.fail("DNS packet router mutex is poisoned");
        }
    }

    fn shutdown_handles(&self) -> Result<(), String> {
        let handles = self
            .handles
            .lock()
            .map_err(|_| "DNS interception handle mutex is poisoned".to_owned())?
            .clone();
        let mut complete = self
            .shutdown_complete
            .lock()
            .map_err(|_| "DNS interception shutdown mutex is poisoned".to_owned())?;
        if complete.len() != handles.len() {
            return Err("DNS interception handle ownership changed during shutdown".to_owned());
        }
        let mut errors = Vec::new();
        for (index, handle) in handles.iter().enumerate() {
            if complete[index] {
                continue;
            }
            if let Err(error) = handle.shutdown_receive() {
                errors.push(format!("handle {index}: {error}"));
            } else {
                complete[index] = true;
            }
        }
        if errors.is_empty() && complete.iter().all(|complete| *complete) {
            Ok(())
        } else {
            if errors.is_empty() {
                Err("DNS interception receive shutdown is still incomplete".to_owned())
            } else {
                Err(errors.join("; "))
            }
        }
    }

    fn record_worker_failure(&self, error: impl Into<String>) {
        // The supervisor owns the lifecycle transition.  The worker event is
        // the notification; changing state here could make other workers
        // discard packets before the supervisor has frozen router admission.
        let _ = error.into();
    }

    fn route(
        &self,
        packet: &[u8],
        interface: super::dns_flow::Interface,
    ) -> Result<RoutedPacket, RouteError> {
        let mut router = self
            .router
            .lock()
            .map_err(|_| RouteError::Companion("DNS packet router mutex is poisoned".into()))?;
        let now_ms = self.now_ms();
        if self.state.load() == DnsSessionState::Starting {
            // Workers are started before the public Running state is
            // published.  Packets captured during that short hand-off must
            // not register or rewrite flows against a half-started session.
            Ok(RoutedPacket::Discard)
        } else if self.is_draining() && !self.drain_enabled() {
            // Admission is frozen, but shutdown_receive has not yet completed
            // for every handle.  Dropping newly captured packets prevents a
            // stale request from being restored or rewritten before the
            // explicit drain barrier is published.
            Ok(RoutedPacket::Discard)
        } else if self.is_draining() {
            router.drain(packet, interface, now_ms)
        } else {
            let manager = Arc::clone(&self.manager);
            router.route(packet, interface, now_ms, move |flow| {
                manager.register_flow(flow)
            })
        }
    }
}

struct Worker {
    index: usize,
    join: JoinHandle<()>,
}

struct SupervisorOwnership {
    manager: Arc<DnsProcessManager>,
    handles: Vec<Arc<ActiveHandle>>,
    workers: Vec<Worker>,
}

struct RollbackOwnership {
    manager: Arc<DnsProcessManager>,
    workers: Vec<Worker>,
    handles: Vec<Arc<ActiveHandle>>,
}

enum SupervisorCommand {
    Stop(Option<SyncSender<Result<(), String>>>),
    Reload {
        rules: String,
        reply: SyncSender<Result<(), String>>,
    },
}

/// One transparent DNS interception generation.
///
/// The supervisor thread remains the owner of the companion and native
/// handles.  Dropping this value only requests cleanup; it does not detach a
/// worker while its native handle or companion may still be in use.
pub(crate) struct DnsSession {
    command: Sender<SupervisorCommand>,
    state: Arc<SessionState>,
    supervisor: Option<JoinHandle<()>>,
}

impl DnsSession {
    pub(crate) fn generation_owned() -> bool {
        GENERATION_OWNED.load(Ordering::Acquire)
    }
    /// Start the helper, validate its ready bindings, open every disjoint
    /// filter, and start one receive worker per active handle.
    pub(crate) fn start(
        appdata_path: PathBuf,
        divert_runtime: impl AsRef<Path>,
        config: TransparentDnsConfig,
    ) -> Result<Self, String> {
        let generation = GenerationLease::acquire()?;
        let divert_runtime = divert_runtime.as_ref().to_path_buf();
        let state = Arc::new(SessionState::new());
        let manager = Arc::new(DnsProcessManager::new(appdata_path));
        let status = match manager.start_transparent(config) {
            Ok(status) => status,
            Err(error) => {
                let stop_error = manager.stop().err();
                if stop_error.is_none() {
                    generation.confirm_cleanup();
                }
                return Err(join_errors(error, stop_error));
            }
        };
        let router = match PacketRouter::new(&status) {
            Ok(router) => router,
            Err(error) => {
                let stop_error = manager.stop().err();
                if stop_error.is_none() {
                    generation.confirm_cleanup();
                }
                return Err(join_errors(error, stop_error));
            }
        };

        let mut handles = Vec::with_capacity(router.filters().len());
        for (index, filter) in router.filters().iter().enumerate() {
            match ActiveHandle::open(&divert_runtime, filter) {
                Ok(handle) => handles.push(handle),
                Err(error) => {
                    let quiesce_error = manager.quiesce().err();
                    let cleanup = cleanup_unstarted_handles(&handles, quiesce_error.is_none());
                    match cleanup {
                        Ok(()) => {
                            // The helper must not be stopped while any
                            // opened handle still owns its exclusion.
                            drop(handles);
                            let stop_error = manager.stop().err();
                            if stop_error.is_none() {
                                generation.confirm_cleanup();
                            }
                            return Err(join_errors(
                                format!("open DNS interception handle {index}: {error}"),
                                quiesce_error.or(stop_error),
                            ));
                        }
                        Err(cleanup_error) => {
                            let retry_manager = Arc::clone(&manager);
                            let retry_handles = handles;
                            let drain = quiesce_error.is_none();
                            let ownership = Arc::new(Mutex::new(Some((
                                retry_handles,
                                retry_manager,
                                Arc::clone(&generation),
                            ))));
                            let background = Arc::clone(&ownership);
                            if thread::Builder::new()
                                .name("vapour-dns-open-cleanup".to_owned())
                                .spawn(move || {
                                    let (handles, manager, generation) = background
                                        .lock()
                                        .unwrap_or_else(|error| error.into_inner())
                                        .take()
                                        .expect("exclusive cleanup owner");
                                    retry_open_cleanup(manager, handles, drain, generation)
                                })
                                .is_err()
                            {
                                // Retain ownership even if Windows cannot create the cleanup thread.
                                let (handles, manager, generation) = ownership
                                    .lock()
                                    .unwrap_or_else(|error| error.into_inner())
                                    .take()
                                    .expect("cleanup owner after failed spawn");
                                retry_open_cleanup(manager, handles, drain, generation);
                            }
                            return Err(join_errors(
                                format!("open DNS interception handle {index}: {error}"),
                                Some(join_errors(cleanup_error, quiesce_error)),
                            ));
                        }
                    }
                }
            }
        }

        let (events, event_receiver) = mpsc::channel();
        let core = Arc::new(SessionCore {
            handles: Mutex::new(handles.clone()),
            manager: Arc::clone(&manager),
            router: Mutex::new(router),
            state: Arc::clone(&state),
            events,
            clock: Instant::now(),
            drain_enabled: AtomicBool::new(false),
            finish_without_drain: AtomicBool::new(false),
            shutdown_complete: Mutex::new(vec![false; handles.len()]),
            _generation: Some(Arc::clone(&generation)),
        });

        let mut workers = Vec::with_capacity(handles.len());
        for (index, handle) in handles.iter().cloned().enumerate() {
            match spawn_worker(index, handle, Arc::clone(&core)) {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    state.fail(format!("start DNS interception worker {index}: {error}"));
                    let cleanup = rollback_workers(&core, Arc::clone(&manager), workers, handles);
                    return Err(join_errors(
                        format!("start DNS interception worker {index}: {error}"),
                        cleanup.err(),
                    ));
                }
            }
        }
        state.store(DnsSessionState::Running);

        let (command, command_receiver) = mpsc::channel();
        let supervisor_core = Arc::clone(&core);
        let supervisor_state = Arc::clone(&state);
        let supervisor_ownership = Arc::new(Mutex::new(Some(SupervisorOwnership {
            manager: Arc::clone(&manager),
            handles,
            workers,
        })));
        let ownership_for_thread = Arc::clone(&supervisor_ownership);
        let supervisor = thread::Builder::new()
            .name("vapour-dns-session".to_owned())
            .spawn(move || {
                let ownership = ownership_for_thread
                    .lock()
                    .ok()
                    .and_then(|mut ownership| ownership.take());
                let Some(SupervisorOwnership {
                    manager,
                    handles,
                    workers,
                }) = ownership
                else {
                    supervisor_state.fail("DNS session supervisor ownership was lost");
                    return;
                };
                run_supervisor(
                    supervisor_core,
                    manager,
                    handles,
                    workers,
                    command_receiver,
                    event_receiver,
                    supervisor_state,
                )
            })
            .map_err(|error| format!("start DNS session supervisor: {error}"));
        match supervisor {
            Ok(supervisor) => Ok(Self {
                command,
                state,
                supervisor: Some(supervisor),
            }),
            Err(error) => {
                // A failed thread spawn leaves the ownership hand-off in the
                // mailbox.  Recover it before performing the same ordered
                // rollback as a worker startup failure.
                let cleanup = supervisor_ownership
                    .lock()
                    .ok()
                    .and_then(|mut ownership| ownership.take())
                    .map_or_else(
                        || Err("DNS session supervisor ownership was lost".to_owned()),
                        |SupervisorOwnership {
                             manager,
                             handles,
                             workers,
                         }| {
                            rollback_workers(&core, manager, workers, handles)
                        },
                    );
                Err(join_errors(error, cleanup.err()))
            }
        }
    }

    pub(crate) fn state(&self) -> DnsSessionState {
        self.state.load()
    }

    pub(crate) fn last_error(&self) -> Option<String> {
        self.state.error()
    }

    /// Whether native handles and companion reservations have both been
    /// released. Failed/StopPending alone cannot authorize a replacement:
    /// a failed worker may still leave cleanup in progress.
    pub(crate) fn cleanup_complete(&self) -> bool {
        self.state.cleanup_complete.load(Ordering::Acquire)
    }

    pub(crate) fn rollover_requested(&self) -> bool {
        self.state.rollover_requested.load(Ordering::Acquire)
    }

    /// Submit a serialized live rule reload. A caller timeout only bounds the
    /// wait for the acknowledgement; the supervisor keeps processing the
    /// command and retains ownership if the helper reports uncertainty.
    pub(crate) fn reload(&self, rules: String, timeout: Duration) -> Result<(), String> {
        if self.state() != DnsSessionState::Running {
            return Err(format!(
                "DNS rule reload requires a running session (state {:?})",
                self.state()
            ));
        }
        let (reply, result) = mpsc::sync_channel(1);
        if self
            .command
            .send(SupervisorCommand::Reload { rules, reply })
            .is_err()
        {
            return self.state.error().map_or_else(
                || Err("DNS session supervisor is unavailable".to_owned()),
                Err,
            );
        }
        match result.recv_timeout(timeout) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => {
                Err("DNS rule reload is still pending; the active session remains owned".to_owned())
            }
            Err(RecvTimeoutError::Disconnected) => self.state.error().map_or_else(
                || Err("DNS session supervisor stopped unexpectedly".to_owned()),
                Err,
            ),
        }
    }

    /// Request ordered shutdown and wait at most `timeout` for completion.
    /// A timeout leaves the supervisor alive and all resources retained; a
    /// later call can retry the same stop operation.
    pub(crate) fn stop(&self, timeout: Duration) -> Result<(), String> {
        if self.state() == DnsSessionState::Stopped {
            return self.state.error().map_or(Ok(()), |error| Err(error));
        }
        let (reply, result) = mpsc::sync_channel(1);
        if self
            .command
            .send(SupervisorCommand::Stop(Some(reply)))
            .is_err()
        {
            return self.state.error().map_or_else(
                || Err("DNS session supervisor is unavailable".to_owned()),
                Err,
            );
        }
        match result.recv_timeout(timeout) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => Err(
                "DNS session stop is still pending; interception handles and upstream ports remain owned"
                    .to_owned(),
            ),
            Err(RecvTimeoutError::Disconnected) => self
                .state
                .error()
                .map_or_else(
                    || Err("DNS session supervisor stopped unexpectedly".to_owned()),
                    Err,
                ),
        }
    }
}

impl Drop for DnsSession {
    fn drop(&mut self) {
        let _ = self.command.send(SupervisorCommand::Stop(None));
        // The detached supervisor is intentional: it remains the owner of
        // native handles and the helper until every worker has exited.
        let _ = self.supervisor.take();
    }
}

fn spawn_worker(
    index: usize,
    handle: Arc<ActiveHandle>,
    core: Arc<SessionCore>,
) -> Result<Worker, String> {
    let join = thread::Builder::new()
        .name(format!("vapour-dns-receive-{index}"))
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                worker_loop(&handle, &core)
            }))
            .map_err(|_| "DNS interception worker panicked".to_owned())
            .and_then(|result| result);
            if let Err(error) = &result {
                core.record_worker_failure(format!("DNS interception worker {index}: {error}"));
            }
            let _ = core.events.send(WorkerEvent::Exited { index, result });
        })
        .map_err(|error| error.to_string())?;
    Ok(Worker { index, join })
}

fn worker_loop(handle: &ActiveHandle, core: &SessionCore) -> Result<(), String> {
    let mut buffer = vec![0u8; MAX_PACKET_BYTES];
    loop {
        let Some((length, mut address)) = handle.receive(&mut buffer)? else {
            return if core.is_draining() {
                while !core.drain_enabled() && !core.finish_without_drain() {
                    thread::sleep(WORKER_POLL);
                }
                Ok(())
            } else {
                Err("DNS interception receive ended before shutdown".to_owned())
            };
        };

        let interface =
            super::dns_flow::Interface::new(address.interface().0, address.interface().1);
        let action = match core.route(&buffer[..length], interface) {
            Ok(action) => action,
            Err(RouteError::Stopped) => RoutedPacket::Unchanged,
            Err(RouteError::InvalidPacket)
            | Err(RouteError::Reflection(super::dns_flow::FlowError::Packet(_))) => {
                RoutedPacket::Discard
            }
            Err(RouteError::RolloverRequired) => {
                core.state.rollover_requested.store(true, Ordering::Release);
                return Err("DNS session requires a fresh connection generation".into());
            }
            Err(error) => return Err(format!("DNS packet routing failed: {error:?}")),
        };

        match action {
            RoutedPacket::Unchanged => handle.reinject(&buffer[..length], &address)?,
            RoutedPacket::Discard => {}
            RoutedPacket::Inbound {
                mut packet,
                interface,
            } => {
                address.set_interface(interface.index, interface.sub_index);
                address.set_outbound(false);
                handle.send_modified(&mut packet, &mut address)?;
            }
        }
    }
}

fn run_supervisor(
    core: Arc<SessionCore>,
    manager: Arc<DnsProcessManager>,
    mut handles: Vec<Arc<ActiveHandle>>,
    mut workers: Vec<Worker>,
    commands: Receiver<SupervisorCommand>,
    events: Receiver<WorkerEvent>,
    state: Arc<SessionState>,
) {
    let mut stop_requested = false;
    let mut quiesce_attempted = false;
    let mut quiesced = false;
    let mut first_error: Option<String> = None;
    let mut stop_deadline = None;
    let mut waiters: Vec<SyncSender<Result<(), String>>> = Vec::new();

    loop {
        while let Ok(event) = events.try_recv() {
            match event {
                WorkerEvent::Exited { index, result } => {
                    if let Err(error) = result {
                        remember_error(&mut first_error, format!("worker {index}: {error}"));
                        if !stop_requested {
                            state.fail(
                                first_error
                                    .clone()
                                    .unwrap_or_else(|| "DNS worker failed".to_owned()),
                            );
                            stop_requested = true;
                            stop_deadline = Some(Instant::now() + INTERNAL_STOP_TIMEOUT);
                        }
                    } else if !stop_requested {
                        remember_error(
                            &mut first_error,
                            format!("DNS interception worker {index} exited unexpectedly"),
                        );
                        state.fail(
                            first_error
                                .clone()
                                .unwrap_or_else(|| "DNS worker exited".to_owned()),
                        );
                        stop_requested = true;
                        stop_deadline = Some(Instant::now() + INTERNAL_STOP_TIMEOUT);
                    }
                }
            }
        }

        if stop_requested {
            if !quiesce_attempted {
                quiesce_attempted = true;
                state.store(DnsSessionState::Stopping);
                core.freeze_admission();
                match manager.quiesce() {
                    Ok(()) => quiesced = true,
                    Err(error) => {
                        remember_error(&mut first_error, format!("quiesce DNS companion: {error}"));
                    }
                }
            }

            // Retrying is intentional.  A transient shutdown failure must
            // not advance the drain barrier or release the companion while a
            // receive worker can still be inside the native handle.
            if !core.drain_enabled() {
                match core.shutdown_handles() {
                    Ok(()) if quiesced => core.enable_drain(),
                    Ok(()) => core.allow_finish_without_drain(),
                    Err(error) => {
                        remember_error(&mut first_error, format!("shutdown DNS handles: {error}"))
                    }
                }
            }

            let deadline =
                stop_deadline.get_or_insert_with(|| Instant::now() + INTERNAL_STOP_TIMEOUT);
            if core.handles_shutdown() && workers.iter().all(|worker| worker.join.is_finished()) {
                for worker in workers.drain(..) {
                    if worker.join.join().is_err() {
                        remember_error(
                            &mut first_error,
                            format!("DNS interception worker {} panicked", worker.index),
                        );
                    }
                }
                // A worker sends its terminal event immediately before the
                // join returns.  It can therefore race the supervisor's
                // earlier try_recv pass; merge those late failures before
                // publishing a successful terminal state.
                while let Ok(event) = events.try_recv() {
                    match event {
                        WorkerEvent::Exited { index, result } => {
                            if let Err(error) = result {
                                remember_error(
                                    &mut first_error,
                                    format!("worker {index}: {error}"),
                                );
                            }
                        }
                    }
                }
                if let Some(error) = state.error() {
                    remember_error(&mut first_error, error);
                }
                core.handles
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .clear();
                handles.clear();
                match manager.stop() {
                    Ok(()) => core.confirm_cleanup(),
                    Err(error) => {
                        remember_error(&mut first_error, format!("stop DNS companion: {error}"));
                    }
                }
                let result = first_error.clone().map_or(Ok(()), Err);
                if let Some(error) = first_error {
                    state.fail(error);
                }
                state.store(if result.is_ok() {
                    DnsSessionState::Stopped
                } else {
                    DnsSessionState::Failed
                });
                for waiter in waiters.drain(..) {
                    let _ = waiter.send(result.clone());
                }
                return;
            }
            if Instant::now() >= *deadline {
                state.store(DnsSessionState::StopPending);
                let error = first_error.clone().unwrap_or_else(|| {
                    "DNS interception workers did not stop before the bounded deadline".to_owned()
                });
                for waiter in waiters.drain(..) {
                    let _ = waiter.send(Err(error.clone()));
                }
                // Keep polling.  No handle or helper is dropped until all
                // receive workers have actually exited.
                stop_deadline = None;
            }
        } else {
            match manager.status() {
                Ok(Some(_)) => {}
                Ok(None) => {
                    let error = "DNS companion disappeared while interception was active";
                    state.fail(error);
                    remember_error(&mut first_error, error.to_owned());
                    stop_requested = true;
                    stop_deadline = Some(Instant::now() + INTERNAL_STOP_TIMEOUT);
                }
                Err(error) => {
                    state.fail(format!("DNS companion health check failed: {error}"));
                    remember_error(&mut first_error, error);
                    stop_requested = true;
                    stop_deadline = Some(Instant::now() + INTERNAL_STOP_TIMEOUT);
                }
            }
        }

        match commands.recv_timeout(SUPERVISOR_POLL) {
            Ok(SupervisorCommand::Stop(waiter)) => {
                if let Some(waiter) = waiter {
                    waiters.push(waiter);
                }
                stop_requested = true;
                stop_deadline.get_or_insert_with(|| Instant::now() + INTERNAL_STOP_TIMEOUT);
            }
            Ok(SupervisorCommand::Reload { rules, reply }) => {
                if stop_requested || state.load() != DnsSessionState::Running {
                    let _ = reply.send(Err(format!(
                        "DNS rule reload requires a running session (state {:?})",
                        state.load()
                    )));
                    continue;
                }
                match manager.reload_transparent(rules) {
                    Ok(_) => {
                        let _ = reply.send(Ok(()));
                    }
                    Err(TransparentReloadError::Rejected(error)) => {
                        // The companion kept its previous engine. The
                        // session remains Running and may accept another
                        // reload or route new flows.
                        let _ = reply.send(Err(error));
                    }
                    Err(TransparentReloadError::Uncertain(error)) => {
                        remember_error(&mut first_error, error.clone());
                        state.fail(error.clone());
                        let _ = reply.send(Err(error));
                        stop_requested = true;
                        stop_deadline.get_or_insert_with(|| Instant::now() + INTERNAL_STOP_TIMEOUT);
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                stop_requested = true;
                stop_deadline.get_or_insert_with(|| Instant::now() + INTERNAL_STOP_TIMEOUT);
            }
        }
    }
}

fn rollback_workers(
    core: &Arc<SessionCore>,
    manager: Arc<DnsProcessManager>,
    mut workers: Vec<Worker>,
    handles: Vec<Arc<ActiveHandle>>,
) -> Result<(), String> {
    let started_workers = workers.len();
    core.freeze_admission();
    let mut errors = Vec::new();
    let quiesced = match manager.quiesce() {
        Ok(()) => true,
        Err(error) => {
            errors.push(format!("quiesce DNS companion: {error}"));
            false
        }
    };

    // Startup rollback is synchronous while ownership is still local.  Do
    // not stop the helper, or drop the native handles, until shutdown has
    // succeeded for every opened handle.  The normal stop path retries the
    // same idempotent per-handle barrier in its supervisor loop.
    let mut shutdown_ok = false;
    let deadline = Instant::now() + INTERNAL_STOP_TIMEOUT;
    while Instant::now() < deadline {
        match core.shutdown_handles() {
            Ok(()) => {
                shutdown_ok = true;
                break;
            }
            Err(error) => {
                errors.push(format!("shutdown DNS handles: {error}"));
                thread::sleep(WORKER_POLL);
            }
        }
    }

    if shutdown_ok {
        if quiesced {
            core.enable_drain();
        } else {
            core.allow_finish_without_drain();
        }
    }
    if !shutdown_ok {
        // Keep the owner alive rather than releasing an excluded upstream
        // port while a native receive may still be pending.  A caller that
        // hit a startup failure receives an error, but this detached retry
        // owns the same Arc handles and helper until shutdown is complete.
        let retry_workers = std::mem::take(&mut workers);
        launch_retry_rollback(
            Arc::clone(core),
            Arc::clone(&manager),
            retry_workers,
            handles.clone(),
            started_workers,
            quiesced,
            "vapour-dns-startup-cleanup",
        );
        return Err(errors.join("; "));
    }

    if shutdown_ok && quiesced {
        let unstarted = handles.iter().skip(started_workers);
        for (offset, handle) in unstarted.enumerate() {
            if let Err(error) = drain_after_shutdown(handle) {
                errors.push(format!(
                    "drain unstarted handle {}: {error}",
                    started_workers + offset
                ));
            }
        }
    }

    let deadline = Instant::now() + INTERNAL_STOP_TIMEOUT;
    while workers.iter().any(|worker| !worker.join.is_finished()) && Instant::now() < deadline {
        thread::sleep(WORKER_POLL);
    }
    if workers.iter().any(|worker| !worker.join.is_finished()) {
        errors.push("DNS interception workers did not stop during startup rollback".to_owned());
        let retry_workers = std::mem::take(&mut workers);
        launch_retry_rollback(
            Arc::clone(core),
            Arc::clone(&manager),
            retry_workers,
            handles.clone(),
            started_workers,
            quiesced,
            "vapour-dns-startup-worker-cleanup",
        );
        return Err(errors.join("; "));
    }
    for worker in workers.drain(..) {
        if worker.join.join().is_err() {
            errors.push(format!("DNS interception worker {} panicked", worker.index));
        }
    }
    core.handles
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clear();
    drop(handles);
    if let Err(error) = manager.stop() {
        errors.push(format!("stop DNS companion: {error}"));
    } else {
        core.confirm_cleanup();
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn launch_retry_rollback(
    core: Arc<SessionCore>,
    manager: Arc<DnsProcessManager>,
    workers: Vec<Worker>,
    handles: Vec<Arc<ActiveHandle>>,
    started_workers: usize,
    quiesced: bool,
    name: &'static str,
) {
    let ownership = Arc::new(Mutex::new(Some(RollbackOwnership {
        manager,
        workers,
        handles,
    })));
    let ownership_for_thread = Arc::clone(&ownership);
    let thread_core = Arc::clone(&core);
    let result = thread::Builder::new().name(name.to_owned()).spawn(move || {
        let owned = ownership_for_thread
            .lock()
            .ok()
            .and_then(|mut ownership| ownership.take());
        if let Some(RollbackOwnership {
            manager,
            workers,
            handles,
        }) = owned
        {
            retry_rollback(
                thread_core,
                manager,
                workers,
                handles,
                started_workers,
                quiesced,
            );
        }
    });
    if result.is_err() {
        // Thread creation failure must not drop a pending receive owner.  The
        // synchronous fallback may block, but it preserves the same ordering
        // and eventually releases the helper only after all workers finish.
        if let Some(RollbackOwnership {
            manager,
            workers,
            handles,
        }) = ownership
            .lock()
            .ok()
            .and_then(|mut ownership| ownership.take())
        {
            retry_rollback(core, manager, workers, handles, started_workers, quiesced);
        }
    }
}

fn retry_rollback(
    core: Arc<SessionCore>,
    manager: Arc<DnsProcessManager>,
    workers: Vec<Worker>,
    handles: Vec<Arc<ActiveHandle>>,
    started_workers: usize,
    quiesced: bool,
) {
    loop {
        if core.shutdown_handles().is_ok() {
            if quiesced {
                core.enable_drain();
            } else {
                core.allow_finish_without_drain();
            }
            break;
        }
        thread::sleep(WORKER_POLL);
    }
    let mut workers = workers;
    while workers.iter().any(|worker| !worker.join.is_finished()) {
        thread::sleep(WORKER_POLL);
    }
    for worker in workers.drain(..) {
        let _ = worker.join.join();
    }
    if quiesced {
        for handle in handles.iter().skip(started_workers) {
            let _ = drain_after_shutdown(handle);
        }
    }
    core.handles
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clear();
    drop(handles);
    if manager.stop().is_ok() {
        core.confirm_cleanup();
    }
}

fn cleanup_unstarted_handles(handles: &[Arc<ActiveHandle>], drain: bool) -> Result<(), String> {
    let mut shutdown_complete = vec![false; handles.len()];
    cleanup_handles_with_state(handles, drain, &mut shutdown_complete)
}

fn cleanup_handles_with_state(
    handles: &[Arc<ActiveHandle>],
    drain: bool,
    shutdown_complete: &mut [bool],
) -> Result<(), String> {
    if shutdown_complete.len() != handles.len() {
        return Err("DNS interception cleanup ownership changed".to_owned());
    }
    let mut errors = Vec::new();
    for (index, handle) in handles.iter().enumerate() {
        if shutdown_complete[index] {
            continue;
        }
        match handle.shutdown_receive() {
            Ok(()) => shutdown_complete[index] = true,
            Err(error) => {
                errors.push(format!("handle {index}: {error}"));
            }
        }
    }
    if !errors.is_empty() || shutdown_complete.iter().any(|complete| !complete) {
        if errors.is_empty() {
            errors.push("DNS interception receive shutdown is still incomplete".to_owned());
        }
        return Err(errors.join("; "));
    }
    if drain {
        for (index, handle) in handles.iter().enumerate() {
            if let Err(error) = drain_after_shutdown(handle) {
                errors.push(format!("drain handle {index}: {error}"));
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn retry_open_cleanup(
    manager: Arc<DnsProcessManager>,
    handles: Vec<Arc<ActiveHandle>>,
    drain: bool,
    generation: Arc<GenerationLease>,
) {
    let mut shutdown_complete = vec![false; handles.len()];
    loop {
        if cleanup_handles_with_state(&handles, drain, &mut shutdown_complete).is_ok() {
            break;
        }
        thread::sleep(WORKER_POLL);
    }
    drop(handles);
    if manager.stop().is_ok() {
        generation.confirm_cleanup();
    }
    drop(manager);
    drop(generation);
}

fn drain_after_shutdown(handle: &ActiveHandle) -> Result<(), String> {
    let mut buffer = vec![0u8; MAX_PACKET_BYTES];
    loop {
        match handle.receive(&mut buffer) {
            Ok(Some((length, address))) => handle.reinject(&buffer[..length], &address)?,
            Ok(None) => return Ok(()),
            Err(error) => return Err(error),
        }
    }
}

fn remember_error(target: &mut Option<String>, error: String) {
    if target.is_none() {
        *target = Some(error);
    }
}

fn join_errors(primary: String, secondary: Option<String>) -> String {
    match secondary {
        Some(secondary) => format!("{primary}; {secondary}"),
        None => primary,
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::protection::dns_process::TransparentDnsConfig;
    use std::{
        fs,
        sync::mpsc::{self, RecvTimeoutError},
    };

    #[test]
    fn generation_replacement_waits_for_confirmed_cleanup_and_last_owner() {
        static GATE: AtomicBool = AtomicBool::new(false);
        let generation = GenerationLease::acquire_from(&GATE).unwrap();
        let retained = Arc::clone(&generation);
        let (release, wait) = mpsc::channel();
        let worker = thread::spawn(move || {
            wait.recv().unwrap();
            retained.confirm_cleanup();
        });
        drop(generation);
        assert!(GenerationLease::acquire_from(&GATE).is_err());
        release.send(()).unwrap();
        worker.join().unwrap();
        let replacement = GenerationLease::acquire_from(&GATE).unwrap();
        replacement.confirm_cleanup();
        drop(replacement);
        assert!(!GATE.load(Ordering::Acquire));
    }

    #[test]
    fn unconfirmed_cleanup_never_reopens_generation_admission() {
        static GATE: AtomicBool = AtomicBool::new(false);
        drop(GenerationLease::acquire_from(&GATE).unwrap());
        assert!(GenerationLease::acquire_from(&GATE).is_err());
    }

    #[test]
    #[ignore = "real unelevated helper only; no WinDivert handle, driver, or DNS settings"]
    fn stop_timeout_retains_helper_until_blocked_worker_finishes() {
        let directory = std::env::temp_dir().join(format!(
            "vapour-dns-session-stop-order-{}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create a fresh owned test directory");
        let manager = Arc::new(DnsProcessManager::new(directory.clone()));
        let status = manager
            .start_transparent(TransparentDnsConfig {
                listen_addresses: vec!["127.0.0.1".into()],
                listen_port: 0,
                rules: String::new(),
            })
            .expect("real transparent companion should start");
        let router = PacketRouter::new(&status).expect("ready status should build router");
        let (events, event_receiver) = mpsc::channel();
        let state = Arc::new(SessionState::new());
        state.store(DnsSessionState::Running);
        let core = Arc::new(SessionCore {
            handles: Mutex::new(Vec::new()),
            manager: Arc::clone(&manager),
            router: Mutex::new(router),
            state: Arc::clone(&state),
            events: events.clone(),
            clock: Instant::now(),
            drain_enabled: AtomicBool::new(false),
            finish_without_drain: AtomicBool::new(false),
            shutdown_complete: Mutex::new(Vec::new()),
            _generation: None,
        });
        let (release, blocked) = mpsc::channel();
        let retained_core = Arc::clone(&core);
        let worker_events = events.clone();
        let worker = Worker {
            index: 0,
            join: thread::spawn(move || {
                let _retained_core = retained_core;
                blocked.recv().expect("test release");
                worker_events
                    .send(WorkerEvent::Exited {
                        index: 0,
                        result: Err("synthetic receive failure".into()),
                    })
                    .expect("supervisor event receiver");
            }),
        };
        let (commands, command_receiver) = mpsc::channel();
        let supervisor_core = Arc::clone(&core);
        let supervisor_manager = Arc::clone(&manager);
        let supervisor_state = Arc::clone(&state);
        let supervisor = thread::spawn(move || {
            run_supervisor(
                supervisor_core,
                supervisor_manager,
                Vec::new(),
                vec![worker],
                command_receiver,
                event_receiver,
                supervisor_state,
            )
        });

        let (reply, result) = mpsc::sync_channel(1);
        commands
            .send(SupervisorCommand::Stop(Some(reply)))
            .expect("stop command");
        assert!(matches!(
            result.recv_timeout(Duration::from_millis(50)),
            Err(RecvTimeoutError::Timeout)
        ));
        assert!(manager
            .status()
            .expect("helper status while worker is blocked")
            .is_some());
        assert!(!state.cleanup_complete.load(Ordering::Acquire));
        for endpoint in status
            .udp_addrs
            .iter()
            .chain(status.slots.iter().map(|slot| &slot.udp_addr))
        {
            assert!(
                std::net::UdpSocket::bind(endpoint).is_err(),
                "UDP reservation was released while the worker was blocked"
            );
        }
        for endpoint in status
            .tcp_addrs
            .iter()
            .chain(status.slots.iter().map(|slot| &slot.tcp_addr))
        {
            assert!(
                std::net::TcpListener::bind(endpoint).is_err(),
                "TCP reservation was released while the worker was blocked"
            );
        }

        release.send(()).expect("release blocked worker");
        let terminal = result
            .recv_timeout(Duration::from_secs(2))
            .expect("supervisor should finish after worker release");
        assert!(terminal
            .expect_err("late worker failure must make stop fail")
            .contains("synthetic receive failure"));
        supervisor.join().expect("supervisor should not panic");
        assert!(state.cleanup_complete.load(Ordering::Acquire));
        assert!(state
            .error()
            .expect("terminal failure remains available")
            .contains("synthetic receive failure"));
        assert!(manager
            .status()
            .expect("helper status after stop")
            .is_none());
        for endpoint in status
            .udp_addrs
            .iter()
            .chain(status.slots.iter().map(|slot| &slot.udp_addr))
        {
            let _socket = std::net::UdpSocket::bind(endpoint)
                .expect("UDP reservation released after worker exit");
        }
        for endpoint in status
            .tcp_addrs
            .iter()
            .chain(status.slots.iter().map(|slot| &slot.tcp_addr))
        {
            let _socket = std::net::TcpListener::bind(endpoint)
                .expect("TCP reservation released after worker exit");
        }
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    #[ignore = "real unelevated helper only; no WinDivert handle, driver, or DNS settings"]
    fn supervisor_reload_preserves_rejected_rules_and_stops_after_reload() {
        let directory =
            std::env::temp_dir().join(format!("vapour-dns-session-reload-{}", std::process::id()));
        fs::create_dir(&directory).expect("create a fresh owned test directory");
        let manager = Arc::new(DnsProcessManager::new(directory.clone()));
        let initial = manager
            .start_transparent(TransparentDnsConfig {
                listen_addresses: vec!["127.0.0.1".into()],
                listen_port: 0,
                rules: "||old.example.test^".into(),
            })
            .expect("real transparent companion should start");
        let router = PacketRouter::new(&initial).expect("ready status should build router");
        let (events, event_receiver) = mpsc::channel();
        let state = Arc::new(SessionState::new());
        state.store(DnsSessionState::Running);
        let core = Arc::new(SessionCore {
            handles: Mutex::new(Vec::new()),
            manager: Arc::clone(&manager),
            router: Mutex::new(router),
            state: Arc::clone(&state),
            events,
            clock: Instant::now(),
            drain_enabled: AtomicBool::new(false),
            finish_without_drain: AtomicBool::new(false),
            shutdown_complete: Mutex::new(Vec::new()),
            _generation: None,
        });
        let (commands, command_receiver) = mpsc::channel();
        let supervisor_core = Arc::clone(&core);
        let supervisor_manager = Arc::clone(&manager);
        let supervisor_state = Arc::clone(&state);
        let supervisor = thread::spawn(move || {
            run_supervisor(
                supervisor_core,
                supervisor_manager,
                Vec::new(),
                Vec::new(),
                command_receiver,
                event_receiver,
                supervisor_state,
            )
        });
        let session = DnsSession {
            command: commands,
            state,
            supervisor: Some(supervisor),
        };
        assert!(!session.cleanup_complete());

        session
            .reload(
                "||new.example.test^\n||second.example.test^".into(),
                Duration::from_secs(12),
            )
            .expect("valid reload should be acknowledged");
        let updated = manager
            .status()
            .expect("status after accepted reload")
            .expect("transparent helper remains active");
        assert_eq!(updated.udp_addr, initial.udp_addr);
        assert_eq!(updated.tcp_addr, initial.tcp_addr);
        assert_eq!(updated.rules_count, 2);

        let rejected = session
            .reload(
                "192.0.2.1 arbitrary.example.test".into(),
                Duration::from_secs(12),
            )
            .expect_err("invalid replacement must be rejected");
        assert!(rejected.contains("rejected rule reload"));
        assert_eq!(
            manager
                .status()
                .expect("status after rejected reload")
                .expect("helper remains active"),
            updated
        );
        assert_eq!(session.state(), DnsSessionState::Running);

        session
            .stop(Duration::from_secs(3))
            .expect("reload session should stop cleanly");
        assert!(session.cleanup_complete());
        assert!(manager
            .status()
            .expect("status after session stop")
            .is_none());
        let refusal = session
            .reload(
                "||after-stop.example.test^".into(),
                Duration::from_millis(50),
            )
            .expect_err("reload after stop must be refused");
        assert!(refusal.contains("requires a running session"));
        let _ = fs::remove_dir_all(directory);
    }
}
