//! Bounded ownership and reconciliation for transparent DNS generations.
//!
//! The controller deliberately owns one session at a time.  A failed or
//! timed-out stop never authorizes dropping that session: native handles and
//! the companion remain owned until `cleanup_complete` is observed.

use super::{
    dns_process::TransparentDnsConfig,
    dns_session::{DnsSession, DnsSessionState},
};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const MIN_START_INTERVAL: Duration = Duration::from_secs(5);
// The companion permits ten seconds for parsing; allow the serialized
// registration already in flight to finish before that acknowledgement.
const RELOAD_TIMEOUT: Duration = Duration::from_secs(15);
const STOP_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(5 * 60);

/// The compact state consumed by a future worker/UI integration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct DnsGenerationStatus {
    pub(crate) requested: bool,
    pub(crate) running: bool,
    pub(crate) cleanup_pending: bool,
    pub(crate) error: Option<String>,
}

/// The small session surface needed by the controller.  Keeping this behind a
/// trait makes lifecycle tests independent of WinDivert, UAC, and the helper.
pub(crate) trait DnsGenerationSession: Send {
    fn state(&self) -> DnsSessionState;
    fn cleanup_complete(&self) -> bool;
    fn last_error(&self) -> Option<String>;
    fn rollover_requested(&self) -> bool;
    fn reload(&self, rules: &str, timeout: Duration) -> Result<(), String>;
    fn stop(&self, timeout: Duration) -> Result<(), String>;
}

/// Factory boundary used by the dedicated worker and deterministic tests.
pub(crate) trait DnsGenerationFactory: Send {
    fn start(&self, config: TransparentDnsConfig) -> Result<Box<dyn DnsGenerationSession>, String>;
    fn cleanup_pending(&self) -> bool {
        false
    }
}

/// Production factory.  It is intentionally not used by unit tests.
pub(crate) struct NativeDnsGenerationFactory {
    appdata_path: PathBuf,
    divert_runtime: PathBuf,
}

impl NativeDnsGenerationFactory {
    pub(crate) fn new(appdata_path: PathBuf, divert_runtime: impl AsRef<Path>) -> Self {
        Self {
            appdata_path,
            divert_runtime: divert_runtime.as_ref().to_path_buf(),
        }
    }
}

impl DnsGenerationFactory for NativeDnsGenerationFactory {
    fn cleanup_pending(&self) -> bool {
        DnsSession::generation_owned()
    }
    fn start(&self, config: TransparentDnsConfig) -> Result<Box<dyn DnsGenerationSession>, String> {
        DnsSession::start(self.appdata_path.clone(), &self.divert_runtime, config)
            .map(|session| Box::new(session) as Box<dyn DnsGenerationSession>)
    }
}

impl DnsGenerationSession for DnsSession {
    fn state(&self) -> DnsSessionState {
        DnsSession::state(self)
    }

    fn cleanup_complete(&self) -> bool {
        DnsSession::cleanup_complete(self)
    }

    fn last_error(&self) -> Option<String> {
        DnsSession::last_error(self)
    }

    fn rollover_requested(&self) -> bool {
        DnsSession::rollover_requested(self)
    }

    fn reload(&self, rules: &str, timeout: Duration) -> Result<(), String> {
        DnsSession::reload(self, rules.to_owned(), timeout)
    }

    fn stop(&self, timeout: Duration) -> Result<(), String> {
        DnsSession::stop(self, timeout)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Topology {
    addresses: Vec<String>,
    port: u16,
}

#[derive(Clone, Debug)]
struct DesiredConfig {
    topology: Topology,
    rules: String,
}

impl DesiredConfig {
    fn from_config(mut config: TransparentDnsConfig) -> Self {
        // Sort exact strings, retaining IPv6 scope spelling (for example
        // `%12`) and avoiding semantic address parsing here.
        config.listen_addresses.sort();
        config.listen_addresses.dedup();
        Self {
            topology: Topology {
                addresses: config.listen_addresses,
                port: config.listen_port,
            },
            rules: config.rules,
        }
    }

    fn to_config(&self) -> TransparentDnsConfig {
        TransparentDnsConfig {
            listen_addresses: self.topology.addresses.clone(),
            listen_port: self.topology.port,
            rules: self.rules.clone(),
        }
    }
}

struct ActiveGeneration {
    session: Box<dyn DnsGenerationSession>,
    revision: u64,
    topology: Topology,
}

/// Serialized lifecycle controller.  Call `reconcile` from one worker; the
/// method may block for the bounded native reload/stop timeouts.
pub(crate) struct DnsGenerationController {
    factory: Box<dyn DnsGenerationFactory>,
    active: Option<ActiveGeneration>,
    desired: Option<DesiredConfig>,
    desired_revision: u64,
    last_start_at: Option<Instant>,
    next_start_at: Option<Instant>,
    start_failures: u32,
    next_reload_at: Option<Instant>,
    reload_failures: u32,
    stop_requested: bool,
    stop_attempted: bool,
    error: Option<String>,
}

impl DnsGenerationController {
    pub(crate) fn with_factory<F>(factory: F) -> Self
    where
        F: DnsGenerationFactory + 'static,
    {
        Self {
            factory: Box::new(factory),
            active: None,
            desired: None,
            desired_revision: 0,
            last_start_at: None,
            next_start_at: None,
            start_failures: 0,
            next_reload_at: None,
            reload_failures: 0,
            stop_requested: false,
            stop_attempted: false,
            error: None,
        }
    }

    pub(crate) fn new_native(appdata_path: PathBuf, divert_runtime: impl AsRef<Path>) -> Self {
        Self::with_factory(NativeDnsGenerationFactory::new(
            appdata_path,
            divert_runtime,
        ))
    }

    /// Replace the requested configuration.  Canonicalization and revision
    /// tracking happen once here, so the reconciliation tick never compares
    /// or clones the rule text merely to discover that nothing changed.
    pub(crate) fn set_desired(&mut self, desired: Option<TransparentDnsConfig>) {
        let next = desired.map(DesiredConfig::from_config);
        let changed = match (&self.desired, &next) {
            (None, None) => false,
            (Some(old), Some(new)) => old.topology != new.topology || old.rules != new.rules,
            _ => true,
        };
        if !changed {
            return;
        }

        self.desired = next;
        self.desired_revision = self.desired_revision.wrapping_add(1);
        self.next_reload_at = None;
        self.reload_failures = 0;
        self.error = None;
        self.next_start_at = None;
        self.start_failures = 0;

        if self.desired.is_none() {
            self.next_start_at = None;
            self.start_failures = 0;
            self.stop_requested = self.active.is_some();
        } else if let (Some(active), Some(desired)) = (&self.active, &self.desired) {
            // An already-issued stop cannot be canceled by a quick toggle;
            // ownership must still reach the cleanup barrier first.
            if !self.stop_attempted {
                self.stop_requested = active.topology != desired.topology;
            }
        }
    }

    /// Apply the latest desired state.  This is intentionally synchronous so
    /// callers can dedicate one worker to lifecycle ownership.
    pub(crate) fn reconcile(&mut self, now: Instant) {
        if self.desired.is_none() {
            if self.active.is_some() {
                self.stop_requested = true;
                if self.stop_active() {
                    self.stop_requested = false;
                    self.stop_attempted = false;
                    self.error = None;
                }
            }
            return;
        }

        if self.active_is_unhealthy() {
            self.stop_requested = true;
            if self.error.is_none() {
                self.error = self
                    .active
                    .as_ref()
                    .and_then(|active| active.session.last_error())
                    .or_else(|| Some("DNS generation stopped unexpectedly".to_owned()));
            }
        }

        if self.active.is_some() && !self.stop_requested {
            let topology_changed = self
                .desired
                .as_ref()
                .map(|desired| {
                    self.active
                        .as_ref()
                        .map(|active| active.topology != desired.topology)
                        .unwrap_or(false)
                })
                .unwrap_or(false);
            if topology_changed {
                self.stop_requested = true;
            }
        }

        if self.stop_requested {
            if self.stop_active() {
                self.stop_requested = false;
                self.stop_attempted = false;
                if self.desired.is_some() {
                    self.try_start(now);
                }
            }
            return;
        }

        if self.active.is_none() {
            self.try_start(now);
            return;
        }

        let active_revision = self.active.as_ref().map(|active| active.revision);
        if active_revision == Some(self.desired_revision) {
            return;
        }

        // The topology is known equal here; only the rule text changed.
        if self.next_reload_at.is_some_and(|retry_at| now < retry_at) {
            return;
        }
        let Some(desired) = self.desired.as_ref() else {
            return;
        };
        let result = self
            .active
            .as_ref()
            .expect("active generation checked above")
            .session
            .reload(&desired.rules, RELOAD_TIMEOUT);
        match result {
            Ok(()) => {
                if self.active_is_unhealthy() {
                    self.stop_requested = true;
                    return;
                }
                if let Some(active) = self.active.as_mut() {
                    active.revision = self.desired_revision;
                }
                self.next_reload_at = None;
                self.reload_failures = 0;
                self.error = None;
            }
            Err(error) => {
                self.error = Some(error.clone());
                // A parser rejection leaves the current session Running and
                // usable.  An uncertain/failing session must drain first.
                if self.active_is_unhealthy() {
                    self.stop_requested = true;
                    return;
                }
                self.reload_failures = self.reload_failures.saturating_add(1);
                self.next_reload_at = Some(now + retry_delay(self.reload_failures));
            }
        }
    }

    pub(crate) fn status(&self) -> DnsGenerationStatus {
        let requested = self.desired.is_some();
        let unhealthy = self.active_is_unhealthy();
        let cleanup_pending = self
            .active
            .as_ref()
            .map(|active| {
                (self.stop_requested || self.stop_attempted || unhealthy)
                    && !active.session.cleanup_complete()
            })
            .unwrap_or_else(|| self.factory.cleanup_pending());
        let running = requested
            && !cleanup_pending
            && !self.stop_requested
            && !unhealthy
            && self
                .active
                .as_ref()
                .map(|active| active.revision == self.desired_revision)
                .unwrap_or(false);
        DnsGenerationStatus {
            requested,
            running,
            cleanup_pending,
            error: self.error.clone().or_else(|| {
                self.active
                    .as_ref()
                    .and_then(|active| active.session.last_error())
            }),
        }
    }

    fn active_is_unhealthy(&self) -> bool {
        self.active
            .as_ref()
            .map(|active| {
                active.session.rollover_requested()
                    || !matches!(active.session.state(), DnsSessionState::Running)
            })
            .unwrap_or(false)
    }

    /// Stop and remove only after the session confirms cleanup.  The `Err`
    /// result is retained in status, but a confirmed cleanup barrier is still
    /// sufficient to release the old owner.
    fn stop_active(&mut self) -> bool {
        let Some(active) = self.active.as_mut() else {
            self.stop_attempted = false;
            return true;
        };
        self.stop_attempted = true;
        if let Err(error) = active.session.stop(STOP_TIMEOUT) {
            self.error = Some(error);
        }
        if !active.session.cleanup_complete() {
            return false;
        }
        self.active.take();
        self.stop_attempted = false;
        true
    }

    fn try_start(&mut self, now: Instant) {
        if self.factory.cleanup_pending() {
            return;
        }
        if self.next_start_at.is_some_and(|retry_at| now < retry_at)
            || self
                .last_start_at
                .is_some_and(|last| now.saturating_duration_since(last) < MIN_START_INTERVAL)
        {
            return;
        }
        let Some(desired) = self.desired.as_ref() else {
            return;
        };
        self.last_start_at = Some(now);
        let config = desired.to_config();
        match self.factory.start(config) {
            Ok(session) => {
                let topology = desired.topology.clone();
                self.active = Some(ActiveGeneration {
                    session,
                    revision: self.desired_revision,
                    topology,
                });
                self.next_start_at = None;
                self.start_failures = 0;
                if self.active_is_unhealthy() {
                    self.stop_requested = true;
                    self.error = self
                        .active
                        .as_ref()
                        .and_then(|active| active.session.last_error())
                        .or_else(|| Some("DNS generation did not start Running".to_owned()));
                } else {
                    self.error = None;
                }
            }
            Err(error) => {
                self.start_failures = self.start_failures.saturating_add(1);
                self.next_start_at = Some(now + retry_delay(self.start_failures));
                self.error = Some(error);
            }
        }
    }
}

fn retry_delay(failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(6);
    let multiplier = 1u32 << shift;
    (MIN_START_INTERVAL * multiplier).min(MAX_RETRY_DELAY)
}

#[cfg(test)]
#[path = "dns_generation_tests.rs"]
mod tests;
