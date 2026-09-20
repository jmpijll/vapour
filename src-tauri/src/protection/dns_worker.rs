//! One background owner for DNS generation reconciliation. No UI wiring yet.
use super::{
    dns_generation::{
        DnsGenerationController, DnsGenerationFactory, DnsGenerationStatus,
        NativeDnsGenerationFactory,
    },
    dns_process::TransparentDnsConfig,
};
use parking_lot::{Condvar, Mutex};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

const ACTIVE_POLL: Duration = Duration::from_millis(250);

#[derive(Default)]
struct State {
    // Coalesce changes while a bounded start/reload/stop is in flight.
    pending: Option<Option<TransparentDnsConfig>>,
    shutdown: bool,
    result: Option<Result<(), String>>,
    status: DnsGenerationStatus,
}
#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    wake: Condvar,
}

pub(crate) struct DnsGenerationWorker {
    shared: Arc<Shared>,
}
impl DnsGenerationWorker {
    pub(crate) fn new_native(appdata: PathBuf, runtime: impl AsRef<Path>) -> Result<Self, String> {
        Self::with_factory(NativeDnsGenerationFactory::new(appdata, runtime))
    }

    pub(crate) fn with_factory(
        factory: impl DnsGenerationFactory + 'static,
    ) -> Result<Self, String> {
        let shared = Arc::new(Shared::default());
        let owner = shared.clone();
        thread::Builder::new()
            .name("vapour-dns-controller".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run(DnsGenerationController::with_factory(factory), &owner);
                }))
                .map_err(|_| "DNS controller worker panicked; cleanup is unconfirmed".to_owned());
                let mut state = owner.state.lock();
                if let Err(error) = &result {
                    state.status.running = false;
                    state.status.cleanup_pending = true;
                    state.status.error = Some(error.clone());
                }
                state.result = Some(result);
                owner.wake.notify_all();
            })
            .map_err(|error| format!("start DNS controller worker: {error}"))?;
        Ok(Self { shared })
    }

    pub(crate) fn set_desired(&self, desired: Option<TransparentDnsConfig>) -> Result<(), String> {
        let mut state = self.shared.state.lock();
        if state.shutdown || state.result.is_some() {
            return Err("DNS controller worker is stopping or stopped".into());
        }
        if desired.is_none() {
            state.status.cleanup_pending |= state.status.requested;
        }
        state.status.requested = desired.is_some();
        state.status.running = false;
        state.pending = Some(desired);
        self.shared.wake.notify_all();
        Ok(())
    }

    pub(crate) fn status(&self) -> DnsGenerationStatus {
        self.shared.state.lock().status.clone()
    }

    /// Bound the caller's wait, retaining the background owner until cleanup.
    pub(crate) fn stop(&self, timeout: Duration) -> Result<(), String> {
        let started = Instant::now();
        let mut state = self.shared.state.lock();
        request_stop(&mut state);
        self.shared.wake.notify_all();
        loop {
            if let Some(result) = &state.result {
                return result.clone();
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Err("DNS worker cleanup is still pending".into());
            }
            self.shared.wake.wait_for(&mut state, remaining);
        }
    }
}
impl Drop for DnsGenerationWorker {
    fn drop(&mut self) {
        request_stop(&mut self.shared.state.lock());
        self.shared.wake.notify_all();
        // The thread keeps Shared and the controller alive through cleanup.
    }
}
fn request_stop(state: &mut State) {
    state.shutdown = true;
    state.pending = Some(None);
    state.status.cleanup_pending |= state.status.requested;
    state.status.requested = false;
    state.status.running = false;
}

fn run(mut controller: DnsGenerationController, shared: &Shared) {
    loop {
        let change = shared.state.lock().pending.take();
        if let Some(desired) = change {
            controller.set_desired(desired);
        }
        controller.reconcile(Instant::now());
        let actual = controller.status();
        let mut state = shared.state.lock();
        state.status = actual.clone();
        if let Some(requested) = state.pending.as_ref().map(Option::is_some) {
            state.status.requested = requested;
            state.status.running = false;
            if !requested {
                state.status.cleanup_pending |= actual.requested;
            }
        }
        if state.shutdown && state.pending.is_none() && !actual.requested && !actual.cleanup_pending
        {
            return;
        }
        if state.pending.is_some() {
            continue;
        }
        if actual.requested || actual.cleanup_pending {
            shared.wake.wait_for(&mut state, ACTIVE_POLL);
        } else {
            shared.wake.wait(&mut state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protection::{dns_generation::DnsGenerationSession, dns_session::DnsSessionState};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct Probe {
        starts: AtomicUsize,
        stop_called: AtomicBool,
        allow_cleanup: AtomicBool,
        dropped: AtomicBool,
        release_start: Mutex<bool>,
        wake: Condvar,
        panic_start: bool,
    }
    impl Default for Probe {
        fn default() -> Self {
            Self {
                starts: AtomicUsize::new(0),
                stop_called: AtomicBool::new(false),
                allow_cleanup: AtomicBool::new(false),
                dropped: AtomicBool::new(false),
                release_start: Mutex::new(true),
                wake: Condvar::new(),
                panic_start: false,
            }
        }
    }
    struct Factory(Arc<Probe>);
    struct Session(Arc<Probe>);
    impl DnsGenerationFactory for Factory {
        fn start(&self, _: TransparentDnsConfig) -> Result<Box<dyn DnsGenerationSession>, String> {
            self.0.starts.fetch_add(1, Ordering::AcqRel);
            assert!(!self.0.panic_start, "injected factory panic");
            let mut release = self.0.release_start.lock();
            while !*release {
                self.0.wake.wait(&mut release);
            }
            Ok(Box::new(Session(self.0.clone())))
        }
    }
    impl DnsGenerationSession for Session {
        fn state(&self) -> DnsSessionState {
            if self.0.stop_called.load(Ordering::Acquire) {
                DnsSessionState::Stopping
            } else {
                DnsSessionState::Running
            }
        }
        fn cleanup_complete(&self) -> bool {
            self.0.stop_called.load(Ordering::Acquire)
                && self.0.allow_cleanup.load(Ordering::Acquire)
        }
        fn last_error(&self) -> Option<String> {
            None
        }
        fn rollover_requested(&self) -> bool {
            false
        }
        fn reload(&self, _: &str, _: Duration) -> Result<(), String> {
            Ok(())
        }
        fn stop(&self, _: Duration) -> Result<(), String> {
            self.0.stop_called.store(true, Ordering::Release);
            if self.cleanup_complete() {
                Ok(())
            } else {
                Err("pending".into())
            }
        }
    }
    impl Drop for Session {
        fn drop(&mut self) {
            self.0.dropped.store(true, Ordering::Release);
        }
    }
    fn config() -> Option<TransparentDnsConfig> {
        Some(TransparentDnsConfig {
            listen_addresses: vec!["127.0.0.1".into()],
            listen_port: 0,
            rules: "||example.test^".into(),
        })
    }
    fn until(mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while !condition() {
            assert!(Instant::now() < deadline, "worker transition timed out");
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn idle_worker_stops_without_starting_and_cannot_be_reenabled() {
        let p = Arc::new(Probe::default());
        let worker = DnsGenerationWorker::with_factory(Factory(p.clone())).unwrap();
        worker.stop(Duration::from_secs(1)).unwrap();
        assert_eq!(p.starts.load(Ordering::Acquire), 0);
        assert!(worker.set_desired(config()).is_err());
    }
    #[test]
    fn stop_timeout_retains_session_until_cleanup_then_completes() {
        let p = Arc::new(Probe::default());
        let worker = DnsGenerationWorker::with_factory(Factory(p.clone())).unwrap();
        worker.set_desired(config()).unwrap();
        until(|| worker.status().running);
        assert!(worker.stop(Duration::from_millis(20)).is_err());
        assert!(!p.dropped.load(Ordering::Acquire));
        assert!(worker.status().cleanup_pending);
        p.allow_cleanup.store(true, Ordering::Release);
        worker.stop(Duration::from_secs(2)).unwrap();
        assert!(p.dropped.load(Ordering::Acquire));
        assert!(!worker.status().cleanup_pending);
    }
    #[test]
    fn disable_coalesces_changes_while_start_is_in_flight() {
        let p = Arc::new(Probe::default());
        *p.release_start.lock() = false;
        p.allow_cleanup.store(true, Ordering::Release);
        let worker = DnsGenerationWorker::with_factory(Factory(p.clone())).unwrap();
        worker.set_desired(config()).unwrap();
        until(|| p.starts.load(Ordering::Acquire) == 1);
        worker.set_desired(config()).unwrap();
        worker.set_desired(None).unwrap();
        assert!(!worker.status().requested);
        assert!(!worker.status().running);
        *p.release_start.lock() = true;
        p.wake.notify_all();
        until(|| p.dropped.load(Ordering::Acquire));
        worker.stop(Duration::from_secs(2)).unwrap();
        assert_eq!(p.starts.load(Ordering::Acquire), 1);
    }
    #[test]
    fn dropping_handle_keeps_background_owner_until_cleanup() {
        let p = Arc::new(Probe::default());
        let worker = DnsGenerationWorker::with_factory(Factory(p.clone())).unwrap();
        worker.set_desired(config()).unwrap();
        until(|| worker.status().running);
        drop(worker);
        until(|| p.stop_called.load(Ordering::Acquire));
        assert!(!p.dropped.load(Ordering::Acquire));
        p.allow_cleanup.store(true, Ordering::Release);
        until(|| p.dropped.load(Ordering::Acquire));
    }
    #[test]
    fn panic_is_reported_as_failed_cleanup_not_successful_stop() {
        let p = Arc::new(Probe {
            panic_start: true,
            ..Probe::default()
        });
        let worker = DnsGenerationWorker::with_factory(Factory(p)).unwrap();
        worker.set_desired(config()).unwrap();
        until(|| worker.status().error.is_some());
        assert!(worker
            .stop(Duration::from_secs(1))
            .unwrap_err()
            .contains("panicked"));
        assert!(!worker.status().running);
        assert!(worker.status().cleanup_pending);
    }
}
