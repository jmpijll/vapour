use super::driver_details::{self, DriverDetails};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverObservation {
    pub status: String,
    pub sampled_at: Option<u64>,
    pub value: Option<DriverDetails>,
}
#[derive(Default)]
pub struct DriverCache {
    started: Option<Instant>,
    completed: Option<Instant>,
    sampled_at: Option<u64>,
    in_flight: bool,
    failed: bool,
    values: HashMap<String, DriverDetails>,
}
impl DriverCache {
    pub fn get(&self, guid: &str, now: Instant) -> DriverObservation {
        let value = driver_details::normalize_guid(guid)
            .and_then(|id| self.values.get(&id))
            .cloned();
        let status = if self.failed {
            "query_failed"
        } else if self
            .completed
            .or(self.started)
            .is_some_and(|t| now.saturating_duration_since(t) >= Duration::from_secs(600))
        {
            "stale"
        } else if self.completed.is_none() {
            "pending"
        } else if value.is_some() {
            "available"
        } else {
            "unavailable"
        };
        DriverObservation {
            status: status.into(),
            sampled_at: self.sampled_at,
            value,
        }
    }
}
pub fn request(cache: &Arc<Mutex<DriverCache>>, now: Instant) {
    {
        let mut state = cache.lock();
        if state.in_flight
            || state
                .started
                .is_some_and(|t| now.saturating_duration_since(t) < Duration::from_secs(300))
        {
            return;
        }
        state.started = Some(now);
        state.in_flight = true;
    }
    let target = Arc::clone(cache);
    if std::thread::Builder::new()
        .name("vapour-driver-details".into())
        .spawn(move || {
            let result = driver_details::collect();
            let mut state = target.lock();
            state.in_flight = false;
            state.completed = Some(Instant::now());
            match result {
                Ok(values) => {
                    state.values = values;
                    state.failed = false;
                    state.sampled_at = Some(
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64,
                    );
                }
                Err(_) => {
                    state.values.clear();
                    state.sampled_at = None;
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
    fn pending_and_stalled_query_are_distinct() {
        let now = Instant::now();
        let state = DriverCache {
            started: Some(now),
            ..Default::default()
        };
        assert_eq!(state.get("unknown", now).status, "pending");
        assert_eq!(
            state.get("unknown", now + Duration::from_secs(601)).status,
            "stale"
        );
    }
    #[test]
    fn absent_adapter_does_not_inherit_another_driver() {
        let now = Instant::now();
        let state = DriverCache {
            completed: Some(now),
            ..Default::default()
        };
        assert_eq!(state.get("unknown", now).status, "unavailable");
        assert!(state.get("unknown", now).value.is_none());
    }
}
