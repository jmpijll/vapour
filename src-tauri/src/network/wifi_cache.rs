use super::wifi_quality::{self, WifiQualityInterface, WifiQualitySnapshot};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, Instant},
};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiObservation {
    pub status: String,
    pub sampled_at: Option<u64>,
    pub value: Option<WifiQualityInterface>,
}
#[derive(Default)]
pub struct WifiCache {
    connected: BTreeSet<String>,
    revision: u64,
    in_flight: bool,
    started: Option<Instant>,
    completed: Option<Instant>,
    snapshot: Option<WifiQualitySnapshot>,
    failed: bool,
}
fn guid(value: &str) -> String {
    value
        .trim_matches(|c| c == '{' || c == '}')
        .to_ascii_lowercase()
}
impl WifiCache {
    pub fn get(&self, id: &str, connected: bool, now: Instant) -> WifiObservation {
        let status = if !connected {
            "disconnected"
        } else if self
            .completed
            .is_some_and(|t| now.saturating_duration_since(t) >= Duration::from_secs(15))
            || (self.completed.is_none()
                && self
                    .started
                    .is_some_and(|t| now.saturating_duration_since(t) >= Duration::from_secs(15)))
        {
            "stale"
        } else if self.failed {
            "query_failed"
        } else if self.snapshot.is_none() {
            "pending"
        } else {
            "available"
        };
        let snapshot = if connected {
            self.snapshot.as_ref()
        } else {
            None
        };
        let value = snapshot
            .and_then(|s| {
                s.interfaces
                    .iter()
                    .find(|i| guid(&i.interface_guid) == guid(id))
            })
            .cloned();
        WifiObservation {
            status: if status == "available" && value.is_none() {
                "unavailable".into()
            } else {
                status.into()
            },
            sampled_at: snapshot.map(|s| s.sampled_at_unix_ms),
            value,
        }
    }
}
pub fn request(cache: &Arc<Mutex<WifiCache>>, connected: BTreeSet<String>, now: Instant) {
    let connected = connected.into_iter().map(|s| guid(&s)).collect();
    let revision;
    {
        let mut state = cache.lock();
        if state.connected != connected {
            state.connected = connected;
            state.revision = state.revision.wrapping_add(1);
            state.snapshot = None;
            state.completed = None;
            state.failed = false;
            if !state.in_flight {
                state.started = None;
            }
        }
        if state.connected.is_empty()
            || state.in_flight
            || state
                .started
                .is_some_and(|t| now.saturating_duration_since(t) < Duration::from_secs(5))
        {
            return;
        }
        state.started = Some(now);
        state.in_flight = true;
        revision = state.revision;
    }
    let target = Arc::clone(cache);
    if std::thread::Builder::new()
        .name("vapour-wifi-quality".into())
        .spawn(move || {
            let result = wifi_quality::collect();
            let mut state = target.lock();
            state.in_flight = false;
            if state.revision != revision {
                state.started = None;
                return;
            }
            state.completed = Some(Instant::now());
            match result {
                Ok(snapshot) => {
                    state.snapshot = Some(snapshot);
                    state.failed = false;
                }
                Err(_) => {
                    state.snapshot = None;
                    state.failed = true;
                }
            }
        })
        .is_err()
    {
        let mut state = cache.lock();
        state.in_flight = false;
        state.failed = true;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disconnected_does_not_expose_previous_sample_and_hung_query_expires() {
        let now = Instant::now();
        let state = WifiCache {
            started: Some(now),
            in_flight: true,
            ..Default::default()
        };
        assert_eq!(state.get("id", false, now).status, "disconnected");
        assert!(state.get("id", false, now).value.is_none());
        assert_eq!(
            state.get("id", true, now + Duration::from_secs(16)).status,
            "stale"
        );
    }
    #[test]
    fn guid_join_is_case_and_brace_independent() {
        assert_eq!(guid("{ABCD}"), guid("abcd"));
    }
}
