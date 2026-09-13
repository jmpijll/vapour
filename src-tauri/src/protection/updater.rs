//! Background feed update state. Enabling enforcement is a separate operation.
use super::{
    cache, download,
    feeds::{ValidatedThreatFeed, FEODO_RECOMMENDED_REFRESH_INTERVAL_SECS},
};
use parking_lot::Mutex;
use serde::Serialize;
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Serialize)]
pub struct UpdateStatus {
    pub refreshing: bool,
    pub available: bool,
    pub stale: bool,
    pub retrieved_at: Option<u64>,
    pub endpoint_count: usize,
    pub last_error: Option<String>,
}
pub struct FeedUpdater {
    path: PathBuf,
    state: Arc<Mutex<State>>,
}
#[derive(Default)]
struct State {
    initialized: bool,
    refreshing: bool,
    last_attempt: Option<Instant>,
    feed: Option<ValidatedThreatFeed>,
    error: Option<String>,
}
impl FeedUpdater {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            state: Arc::new(Mutex::new(State::default())),
        }
    }
    pub fn status(&self) -> UpdateStatus {
        let state = self.state.lock();
        let retrieved_at = state
            .feed
            .as_ref()
            .map(|f| f.metadata.retrieved_at_unix_secs);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        UpdateStatus {
            refreshing: state.refreshing,
            available: state.feed.is_some(),
            stale: retrieved_at.is_some_and(|t| {
                now.saturating_sub(t) > FEODO_RECOMMENDED_REFRESH_INTERVAL_SECS * 2
            }),
            retrieved_at,
            endpoint_count: state.feed.as_ref().map_or(0, |f| f.endpoints.len()),
            last_error: state.error.clone(),
        }
    }
    pub fn snapshot(&self) -> Option<ValidatedThreatFeed> {
        self.state.lock().feed.clone()
    }
    /// Returns false when another request is in flight or the interval has not elapsed.
    /// `force` is for an explicit refresh action; normal polling never bypasses backoff.
    pub fn request(&self, force: bool) -> bool {
        let now = Instant::now();
        let initialize;
        {
            let mut state = self.state.lock();
            if !due(&state, now, force) {
                return false;
            }
            state.refreshing = true;
            state.last_attempt = Some(now);
            initialize = !state.initialized;
        }
        let target = Arc::clone(&self.state);
        let path = self.path.clone();
        if std::thread::Builder::new()
            .name("vapour-threat-update".into())
            .spawn(move || {
                if initialize {
                    let loaded = cache::load_feodo_cache(&path);
                    let mut state = target.lock();
                    state.initialized = true;
                    match loaded {
                        Ok(feed) => state.feed = feed,
                        Err(_) => state.error = Some("Cached feed could not be validated".into()),
                    }
                }
                let result = download::refresh_feodo(&path);
                finish(&mut target.lock(), result);
            })
            .is_err()
        {
            let mut state = self.state.lock();
            state.refreshing = false;
            state.error = Some("Feed worker unavailable".into());
            return false;
        }
        true
    }
}
fn due(state: &State, now: Instant, force: bool) -> bool {
    !state.refreshing
        && (force
            || state.last_attempt.is_none_or(|t| {
                now.saturating_duration_since(t)
                    >= Duration::from_secs(FEODO_RECOMMENDED_REFRESH_INTERVAL_SECS)
            }))
}
fn finish(state: &mut State, result: Result<ValidatedThreatFeed, String>) {
    state.refreshing = false;
    match result {
        Ok(feed) => {
            state.feed = Some(feed);
            state.error = None;
        }
        Err(error) => state.error = Some(error),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn forced_refresh_cannot_overlap_and_failures_back_off() {
        let now = Instant::now();
        let mut state = State {
            refreshing: true,
            last_attempt: Some(now),
            ..Default::default()
        };
        assert!(!due(&state, now, true));
        finish(&mut state, Err("offline".into()));
        assert!(!due(&state, now, false));
        assert!(due(&state, now, true));
        assert!(due(
            &state,
            now + Duration::from_secs(FEODO_RECOMMENDED_REFRESH_INTERVAL_SECS),
            false
        ));
    }
    #[test]
    fn failed_update_keeps_previous_validated_snapshot() {
        let feed = super::super::feeds::parse_feodo_recommended_json(b"[]", 1).unwrap();
        let mut state = State {
            feed: Some(feed.clone()),
            refreshing: true,
            ..Default::default()
        };
        finish(&mut state, Err("offline".into()));
        assert_eq!(state.feed, Some(feed));
        assert_eq!(state.error.as_deref(), Some("offline"));
    }
}
