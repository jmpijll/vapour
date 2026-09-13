//! Background filter retrieval; it never enables filtering or changes DNS.
use super::{
    dns_cache::{self, DnsFilter},
    dns_process::DnsProcessManager,
    download,
};
use parking_lot::Mutex;
use serde::Serialize;
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const FAILURE_RETRY: Duration = Duration::from_secs(15 * 60);

#[derive(Clone, Debug, Serialize)]
pub struct DnsUpdateStatus {
    pub refreshing: bool,
    pub available: bool,
    pub stale: bool,
    pub retrieved_at: Option<u64>,
    pub rules_count: u64,
    pub last_error: Option<String>,
}

#[derive(Default)]
struct State {
    initialized: bool,
    refreshing: bool,
    last_attempt: Option<Instant>,
    filter: Option<Arc<DnsFilter>>,
    error: Option<String>,
}

struct RefreshGuard(Arc<Mutex<State>>);
impl Drop for RefreshGuard {
    fn drop(&mut self) {
        let mut state = self.0.lock();
        if state.refreshing {
            state.refreshing = false;
            state.error = Some("DNS filter worker stopped unexpectedly".into());
        }
    }
}

#[derive(Clone)]
pub struct DnsUpdater {
    path: PathBuf,
    parser: Arc<DnsProcessManager>,
    state: Arc<Mutex<State>>,
}

impl DnsUpdater {
    pub fn new(path: PathBuf, parser: Arc<DnsProcessManager>) -> Self {
        Self {
            path,
            parser,
            state: Arc::new(Mutex::new(State::default())),
        }
    }

    pub fn status(&self) -> DnsUpdateStatus {
        status(&self.state.lock(), unix_now())
    }

    /// Expired in-memory filters cannot bypass the disk cache's age limit.
    /// Arc avoids copying megabytes of rules during status/controller polling.
    pub fn snapshot(&self) -> Option<Arc<DnsFilter>> {
        usable(&self.state.lock(), unix_now())
    }

    /// Call from the controller's periodic tick or an explicit refresh action.
    /// Concurrent requests are coalesced, including forced refreshes.
    pub fn request(&self, force: bool) -> bool {
        let initialize;
        {
            let mut state = self.state.lock();
            if !due(&state, Instant::now(), unix_now(), force) {
                return false;
            }
            initialize = !state.initialized;
            state.refreshing = true;
            state.last_attempt = Some(Instant::now());
        }
        let updater = self.clone();
        if std::thread::Builder::new()
            .name("vapour-dns-filter-update".into())
            .spawn(move || {
                let _reset_on_unwind = RefreshGuard(Arc::clone(&updater.state));
                if initialize {
                    let loaded = dns_cache::load(&updater.path, unix_now(), |rules| {
                        updater.parser.validate_rules(rules)
                    });
                    let mut state = updater.state.lock();
                    state.initialized = true;
                    match loaded {
                        Ok(filter) => state.filter = filter.map(Arc::new),
                        Err(_) => {
                            state.error = Some("Cached DNS filter could not be validated".into())
                        }
                    }
                    // An ordinary startup can use a fresh validated cache without
                    // another download. Explicit refresh still retrieves the source.
                    if !force && state.filter.as_ref().is_some_and(|f| !f.stale(unix_now())) {
                        state.refreshing = false;
                        return;
                    }
                }
                let result = download::fetch_adguard_dns().and_then(|rules| {
                    dns_cache::replace(&updater.path, rules, unix_now(), |rules| {
                        updater.parser.validate_rules(rules)
                    })
                });
                finish(&mut updater.state.lock(), result);
            })
            .is_err()
        {
            let mut state = self.state.lock();
            state.refreshing = false;
            state.error = Some("DNS filter worker unavailable".into());
            return false;
        }
        true
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn usable(state: &State, now: u64) -> Option<Arc<DnsFilter>> {
    state
        .filter
        .as_ref()
        .filter(|f| {
            f.retrieved_at <= now.saturating_add(300)
                && now.saturating_sub(f.retrieved_at) <= dns_cache::MAX_CACHE_AGE_SECS
        })
        .cloned()
}
fn status(state: &State, now: u64) -> DnsUpdateStatus {
    let filter = usable(state, now);
    DnsUpdateStatus {
        refreshing: state.refreshing,
        available: filter.is_some(),
        stale: state.filter.as_ref().is_some_and(|f| f.stale(now)),
        retrieved_at: state.filter.as_ref().map(|f| f.retrieved_at),
        rules_count: filter.as_ref().map_or(0, |f| f.rules_count),
        last_error: state.error.clone(),
    }
}
fn due(state: &State, instant: Instant, now: u64, force: bool) -> bool {
    if state.refreshing {
        return false;
    }
    if force || !state.initialized {
        return state
            .last_attempt
            .is_none_or(|t| force || instant.saturating_duration_since(t) >= FAILURE_RETRY);
    }
    if state
        .last_attempt
        .is_some_and(|t| instant.saturating_duration_since(t) < FAILURE_RETRY)
    {
        return false;
    }
    state.error.is_some() || usable(state, now).is_none_or(|f| f.stale(now))
}
fn finish(state: &mut State, result: Result<DnsFilter, String>) {
    state.refreshing = false;
    match result {
        Ok(filter) => {
            state.filter = Some(Arc::new(filter));
            state.error = None;
        }
        Err(error) => {
            state.error = Some(error.chars().take(1024).collect());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "Downloads official DNS filter into explicit new VAPOUR_DNS_UPDATER_TEST_DIR; no system DNS changes"]
    fn live_updater_validates_download_and_reloads_its_cache() {
        let directory = PathBuf::from(
            std::env::var_os("VAPOUR_DNS_UPDATER_TEST_DIR")
                .expect("explicit isolated output directory required"),
        );
        assert!(directory.is_absolute());
        std::fs::create_dir(&directory).expect("output directory must not already exist");
        let path = directory.join("filter.json");
        let parser = Arc::new(DnsProcessManager::new(directory.join("engine")));
        let wait = |updater: &DnsUpdater| {
            let deadline = Instant::now() + Duration::from_secs(50);
            loop {
                let status = updater.status();
                if !status.refreshing {
                    assert!(status.last_error.is_none(), "{:?}", status.last_error);
                    assert!(status.available);
                    assert!(status.rules_count > 0);
                    return status;
                }
                assert!(
                    Instant::now() < deadline,
                    "DNS updater exceeded test deadline"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        };
        let updater = DnsUpdater::new(path.clone(), Arc::clone(&parser));
        assert!(updater.request(true));
        let downloaded = wait(&updater);
        let cached_bytes = std::fs::read(&path).unwrap();
        let restarted = DnsUpdater::new(path.clone(), parser);
        assert!(restarted.request(false));
        let loaded = wait(&restarted);
        assert_eq!(loaded.rules_count, downloaded.rules_count);
        assert_eq!(loaded.retrieved_at, downloaded.retrieved_at);
        assert_eq!(std::fs::read(path).unwrap(), cached_bytes);
        println!(
            "DNS updater download/cache restart: {} rules",
            loaded.rules_count
        );
    }
    #[test]
    fn worker_panic_releases_refresh_and_retains_retry_backoff() {
        let now = Instant::now();
        let state = Arc::new(Mutex::new(State {
            refreshing: true,
            last_attempt: Some(now),
            ..State::default()
        }));
        let worker_state = Arc::clone(&state);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard = RefreshGuard(worker_state);
            panic!("controlled worker failure");
        }));
        assert!(result.is_err());
        let state = state.lock();
        assert!(!state.refreshing);
        assert!(state.error.is_some());
        assert!(!due(&state, now, 100, false));
        assert!(due(&state, now + FAILURE_RETRY, 100, false));
    }
    fn filter(at: u64) -> DnsFilter {
        // Only fixture construction bypasses the real parser; cache validation
        // and companion tests cover the production download/parser boundary.
        serde_json::from_value(
            serde_json::json!({"version":1,"source":download::ADGUARD_DNS_URL,
            "retrieved_at":at,"hash":"fixture","rules_count":1,"rules":"||ads.example^"}),
        )
        .unwrap()
    }
    #[test]
    fn refresh_coalesces_and_failed_attempts_back_off() {
        let now = Instant::now();
        let mut state = State {
            initialized: true,
            refreshing: true,
            last_attempt: Some(now),
            ..State::default()
        };
        assert!(!due(&state, now, 100, true));
        finish(&mut state, Err("offline".into()));
        assert!(!due(
            &state,
            now + FAILURE_RETRY - Duration::from_secs(1),
            100,
            false
        ));
        assert!(due(&state, now + FAILURE_RETRY, 100, false));
        assert!(due(&state, now, 100, true));
    }
    #[test]
    fn failed_download_preserves_last_good_but_not_forever() {
        let mut state = State::default();
        finish(&mut state, Ok(filter(100)));
        let original = usable(&state, 100).unwrap();
        finish(&mut state, Err("bad replacement".into()));
        assert!(Arc::ptr_eq(&original, &usable(&state, 101).unwrap()));
        assert!(status(&state, 100 + dns_cache::REFRESH_INTERVAL_SECS).stale);
        let expired = status(&state, 101 + dns_cache::MAX_CACHE_AGE_SECS);
        assert!(!expired.available);
        assert_eq!(expired.rules_count, 0);
        assert!(usable(&state, 101 + dns_cache::MAX_CACHE_AGE_SECS).is_none());
    }
    #[test]
    fn fresh_cache_waits_until_daily_refresh_and_clock_rollback_is_rejected() {
        let instant = Instant::now();
        let state = State {
            initialized: true,
            filter: Some(Arc::new(filter(1000))),
            ..State::default()
        };
        assert!(!due(&state, instant, 1001, false));
        assert!(due(
            &state,
            instant,
            1000 + dns_cache::REFRESH_INTERVAL_SECS,
            false
        ));
        assert!(usable(&state, 0).is_none());
    }
}
