use super::{
    enforcement,
    updater::{FeedUpdater, UpdateStatus},
};
use parking_lot::Mutex;
use serde::Serialize;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct ProtectionController {
    updater: FeedUpdater,
    operation: Arc<Mutex<()>>,
    stopped: Arc<AtomicBool>,
    update_error: Arc<Mutex<Option<String>>>,
}
#[derive(Serialize)]
pub struct ProtectionStatus {
    pub rules: enforcement::EnforcementStatus,
    pub feed: UpdateStatus,
    pub update_error: Option<String>,
}
impl ProtectionController {
    pub fn new(updater: FeedUpdater) -> Self {
        Self {
            updater,
            operation: Arc::new(Mutex::new(())),
            stopped: Arc::new(AtomicBool::new(false)),
            update_error: Arc::new(Mutex::new(None)),
        }
    }
    pub fn start_updates(&self) -> Result<(), String> {
        let controller = self.clone();
        std::thread::Builder::new()
            .name("vapour-protection-scheduler".into())
            .spawn(move || {
                while !controller.stopped.load(Ordering::Acquire) {
                    let result = (|| {
                        let _guard = controller
                            .operation
                            .try_lock()
                            .ok_or("Protection change already in progress")?;
                        let status = controller.read_status()?;
                        if status.rules.enabled {
                            controller.change_enabled(true)?;
                        }
                        Ok::<(), String>(())
                    })();
                    *controller.update_error.lock() = result.err();
                    for _ in 0..900 {
                        if controller.stopped.load(Ordering::Acquire) {
                            return;
                        }
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
            })
            .map(|_| ())
            .map_err(|_| "Protection scheduler unavailable".into())
    }
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
    }
    pub fn refresh(&self) -> Result<ProtectionStatus, String> {
        let _guard = self
            .operation
            .try_lock()
            .ok_or("Protection change already in progress")?;
        let enabled = self.read_status()?.rules.enabled;
        self.updater.request(true);
        if enabled {
            self.change_enabled(true)
        } else {
            self.read_status()
        }
    }
    pub fn status(&self) -> Result<ProtectionStatus, String> {
        let _guard = self.operation.lock();
        self.read_status()
    }
    fn read_status(&self) -> Result<ProtectionStatus, String> {
        Ok(ProtectionStatus {
            rules: enforcement::status().map_err(|e| e.to_string())?,
            feed: self.updater.status(),
            update_error: self.update_error.lock().clone(),
        })
    }
    /// Blocking operation: invoke only on a dedicated blocking worker.
    pub fn set_enabled(&self, enabled: bool) -> Result<ProtectionStatus, String> {
        let _guard = self
            .operation
            .try_lock()
            .ok_or("Protection change already in progress")?;
        self.change_enabled(enabled)
    }
    fn change_enabled(&self, enabled: bool) -> Result<ProtectionStatus, String> {
        if !crate::firewall::FirewallManager::is_elevated() {
            return Err("Administrator access is required".into());
        }
        if enabled {
            self.updater.request(false);
            let deadline = Instant::now() + Duration::from_secs(40);
            while self.updater.status().refreshing && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
            if self.updater.status().refreshing {
                return Err("Threat feed refresh timed out".into());
            }
            let feed = self
                .updater
                .snapshot()
                .ok_or("No validated threat feed is available")?;
            let applied = enforcement::apply(&feed.endpoints).map_err(|e| e.to_string())?;
            if applied.cleanup_pending {
                return Err("Protection updated, but old rules still need cleanup".into());
            }
        } else {
            let result = enforcement::disable().map_err(|e| e.to_string())?;
            if !result.remaining_owned.is_empty() {
                return Err("Some protection rules could not be removed".into());
            }
        }
        self.read_status()
    }
}
