use super::*;
use std::sync::{Arc, Mutex};

struct Scenario {
    state: DnsSessionState,
    cleanup: bool,
    rollover: bool,
    reject_reload: bool,
    fail_start: bool,
    factory_cleanup_pending: bool,
    events: Vec<&'static str>,
}
#[derive(Clone)]
struct Factory(Arc<Mutex<Scenario>>);
struct Session(Arc<Mutex<Scenario>>);
impl DnsGenerationFactory for Factory {
    fn cleanup_pending(&self) -> bool {
        self.0.lock().unwrap().factory_cleanup_pending
    }
    fn start(&self, _: TransparentDnsConfig) -> Result<Box<dyn DnsGenerationSession>, String> {
        let mut s = self.0.lock().unwrap();
        s.events.push("start");
        if s.fail_start {
            return Err("start failed".into());
        }
        s.state = DnsSessionState::Running;
        s.cleanup = false;
        s.rollover = false;
        Ok(Box::new(Session(self.0.clone())))
    }
}
impl DnsGenerationSession for Session {
    fn state(&self) -> DnsSessionState {
        self.0.lock().unwrap().state
    }
    fn cleanup_complete(&self) -> bool {
        self.0.lock().unwrap().cleanup
    }
    fn last_error(&self) -> Option<String> {
        None
    }
    fn rollover_requested(&self) -> bool {
        self.0.lock().unwrap().rollover
    }
    fn reload(&self, _: &str, timeout: Duration) -> Result<(), String> {
        assert!(timeout > Duration::from_secs(10));
        let mut s = self.0.lock().unwrap();
        s.events.push("reload");
        if s.reject_reload {
            Err("rules rejected".into())
        } else {
            Ok(())
        }
    }
    fn stop(&self, _: Duration) -> Result<(), String> {
        let mut s = self.0.lock().unwrap();
        s.events.push("stop");
        if s.cleanup {
            s.state = DnsSessionState::Stopped;
            Ok(())
        } else {
            s.state = DnsSessionState::Stopping;
            Err("cleanup pending".into())
        }
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.0.lock().unwrap().events.push("drop");
    }
}
fn setup() -> (DnsGenerationController, Arc<Mutex<Scenario>>, Instant) {
    let s = Arc::new(Mutex::new(Scenario {
        state: DnsSessionState::Running,
        cleanup: false,
        rollover: false,
        reject_reload: false,
        fail_start: false,
        factory_cleanup_pending: false,
        events: vec![],
    }));
    (
        DnsGenerationController::with_factory(Factory(s.clone())),
        s,
        Instant::now(),
    )
}
fn config(addresses: &[&str], rules: &str) -> Option<TransparentDnsConfig> {
    Some(TransparentDnsConfig {
        listen_addresses: addresses.iter().map(|s| s.to_string()).collect(),
        listen_port: 0,
        rules: rules.into(),
    })
}
fn starts(s: &Arc<Mutex<Scenario>>) -> usize {
    s.lock()
        .unwrap()
        .events
        .iter()
        .filter(|e| **e == "start")
        .count()
}

#[test]
fn reordered_topology_is_unchanged_and_rules_only_reload() {
    let (mut c, s, now) = setup();
    c.set_desired(config(&["127.0.0.1", "::1"], "old"));
    c.reconcile(now);
    c.set_desired(config(&["::1", "127.0.0.1", "::1"], "old"));
    c.reconcile(now);
    assert_eq!(s.lock().unwrap().events, ["start"]);
    c.set_desired(config(&["::1", "127.0.0.1"], "new"));
    assert!(!c.status().running);
    c.reconcile(now);
    assert_eq!(s.lock().unwrap().events, ["start", "reload"]);
    assert!(c.status().running);
}

#[test]
fn rejected_rules_keep_owner_and_retry_with_backoff() {
    let (mut c, s, now) = setup();
    c.set_desired(config(&["127.0.0.1"], "old"));
    c.reconcile(now);
    s.lock().unwrap().reject_reload = true;
    c.set_desired(config(&["127.0.0.1"], "bad"));
    c.reconcile(now);
    c.reconcile(now + Duration::from_secs(4));
    assert_eq!(s.lock().unwrap().events, ["start", "reload"]);
    assert!(!c.status().running);
    assert!(!c.status().cleanup_pending);
    s.lock().unwrap().reject_reload = false;
    c.reconcile(now + Duration::from_secs(5));
    assert_eq!(s.lock().unwrap().events, ["start", "reload", "reload"]);
    assert!(c.status().running);
}

#[test]
fn topology_replacement_waits_for_cleanup_then_drops_before_start() {
    let (mut c, s, now) = setup();
    c.set_desired(config(&["127.0.0.1"], "rules"));
    c.reconcile(now);
    c.set_desired(config(&["127.0.0.2"], "rules"));
    c.reconcile(now + Duration::from_secs(6));
    assert!(c.status().cleanup_pending);
    assert_eq!(starts(&s), 1);
    c.reconcile(now + Duration::from_secs(7));
    assert_eq!(starts(&s), 1);
    s.lock().unwrap().cleanup = true;
    c.reconcile(now + Duration::from_secs(8));
    assert_eq!(
        s.lock().unwrap().events,
        ["start", "stop", "stop", "stop", "drop", "start"]
    );
    assert!(c.status().running);
}

#[test]
fn disable_cancels_replacement_while_cleanup_is_pending() {
    let (mut c, s, now) = setup();
    c.set_desired(config(&["127.0.0.1"], "rules"));
    c.reconcile(now);
    c.set_desired(config(&["127.0.0.2"], "rules"));
    c.reconcile(now);
    c.set_desired(None);
    s.lock().unwrap().cleanup = true;
    c.reconcile(now + Duration::from_secs(10));
    c.reconcile(now + Duration::from_secs(100));
    assert_eq!(starts(&s), 1);
    assert!(!c.status().requested);
    assert!(!c.status().running);
    assert!(!c.status().cleanup_pending);
}

#[test]
fn failed_starts_back_off_but_new_configuration_can_retry_after_minimum_interval() {
    let (mut c, s, now) = setup();
    s.lock().unwrap().fail_start = true;
    c.set_desired(config(&["127.0.0.1"], "old"));
    c.reconcile(now);
    c.reconcile(now + Duration::from_secs(4));
    assert_eq!(starts(&s), 1);
    c.reconcile(now + Duration::from_secs(5));
    assert_eq!(starts(&s), 2);
    c.reconcile(now + Duration::from_secs(14));
    assert_eq!(starts(&s), 2);
    c.set_desired(config(&["127.0.0.1"], "corrected"));
    s.lock().unwrap().fail_start = false;
    c.reconcile(now + Duration::from_secs(14));
    assert_eq!(starts(&s), 3);
    assert!(c.status().running);
}

#[test]
fn exhaustion_and_worker_failure_both_require_cleanup_before_restart() {
    for rollover in [true, false] {
        let (mut c, s, now) = setup();
        c.set_desired(config(&["127.0.0.1"], "rules"));
        c.reconcile(now);
        {
            let mut state = s.lock().unwrap();
            state.rollover = rollover;
            state.state = DnsSessionState::Failed;
        }
        c.reconcile(now + Duration::from_secs(6));
        assert_eq!(starts(&s), 1);
        s.lock().unwrap().cleanup = true;
        c.reconcile(now + Duration::from_secs(7));
        assert_eq!(starts(&s), 2);
        assert!(c.status().running);
    }
}

#[test]
fn failed_start_background_cleanup_prevents_retry_and_remains_visible_when_disabled() {
    let (mut c, s, now) = setup();
    s.lock().unwrap().fail_start = true;
    c.set_desired(config(&["127.0.0.1"], "rules"));
    c.reconcile(now);
    s.lock().unwrap().factory_cleanup_pending = true;
    c.reconcile(now + Duration::from_secs(60));
    assert_eq!(starts(&s), 1);
    assert!(c.status().cleanup_pending);
    c.set_desired(None);
    c.reconcile(now + Duration::from_secs(120));
    assert!(!c.status().requested);
    assert!(c.status().cleanup_pending);
    assert_eq!(starts(&s), 1);
    s.lock().unwrap().factory_cleanup_pending = false;
    assert!(!c.status().cleanup_pending);
}
