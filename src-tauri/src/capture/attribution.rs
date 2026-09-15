//! Conservative offline attribution. No test-flow oracle, timers or driver calls.
//! QPC orders evidence; creation FILETIME is only a process identity discriminator.
//! Reused tuples are deliberately ambiguous until TCP generation evidence exists.
use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub pid: u32,
    pub creation_time_100ns: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flow {
    pub protocol: u8,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}
impl Flow {
    fn valid(&self) -> bool {
        matches!(self.protocol, 6 | 17)
            && self.local.port() != 0 && self.remote.port() != 0
            && !self.local.ip().is_unspecified() && !self.remote.ip().is_unspecified()
            && self.local.is_ipv4() == self.remote.is_ipv4()
    }
    pub(super) fn matches(&self, other: &Self) -> bool {
        self.protocol == other.protocol
            && ((self.local == other.local && self.remote == other.remote)
                || (self.local == other.remote && self.remote == other.local))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind { Connect, Accept, Established, Close, Deleted }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub timestamp_qpc: i64,
    pub endpoint_id: u64,
    pub owner: Identity,
    pub flow: Flow,
    pub kind: EventKind,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict { Selected, Other, Unknown, Ambiguous, Invalid }
struct Interval { event: Event, end: Option<i64> }
pub struct Ledger { events: Vec<Event>, capacity: usize, invalid: bool }
impl Ledger {
    pub fn new(capacity: usize) -> Self {
        Self { events: Vec::new(), capacity, invalid: capacity == 0 }
    }
    pub fn ingest(&mut self, event: Event) -> bool {
        if self.invalid { return false; }
        if event.timestamp_qpc < 0 || event.endpoint_id == 0 || event.owner.pid == 0
            || event.owner.creation_time_100ns == 0 || !event.flow.valid() {
            self.invalid = true;
            return false;
        }
        if self.events.contains(&event) { return true; }
        if self.events.len() >= self.capacity {
            self.invalid = true;
            return false;
        }
        self.events.push(event);
        true
    }
    pub fn classify(&self, flow: &Flow, at: i64, selected: Identity) -> Verdict {
        self.classify_any(flow, at, &[selected])
    }
    pub fn classify_any(&self, flow: &Flow, at: i64, selected: &[Identity]) -> Verdict {
        if self.invalid || !flow.valid() || at < 0 || selected.is_empty()
            || selected.iter().any(|owner| owner.pid == 0 || owner.creation_time_100ns == 0) {
            return Verdict::Invalid;
        }
        // Events after the packet cannot authorize or taint it. Offline replay
        // accepts arbitrarily ordered arrival, then uses native event timestamps.
        let mut events: Vec<_> = self.events.iter().filter(|e|
            e.timestamp_qpc <= at && e.flow.matches(flow)).copied().collect();
        events.sort_by_key(|e| (e.timestamp_qpc, match e.kind {
            EventKind::Connect | EventKind::Accept => 0,
            EventKind::Established => 1,
            EventKind::Close | EventKind::Deleted => 2,
        }));
        if events.is_empty() { return Verdict::Unknown; }
        // An endpoint identity changing owner or tuple cannot silently preserve
        // an earlier generation, even if its closing event was lost.
        for e in &events {
            if self.events.iter().any(|other| other.timestamp_qpc <= at
                && other.endpoint_id == e.endpoint_id
                && (other.owner != e.owner
                    || (other.flow != e.flow
                        && !(e.flow.protocol == 17
                            && other.flow.protocol == 17
                            && other.flow.local == e.flow.local
                            && other.owner == e.owner)))) {
                return Verdict::Ambiguous;
            }
        }
        let mut intervals: Vec<Interval> = Vec::new();
        let mut closed: Vec<Event> = Vec::new();
        for event in events {
            let same = |i: &Interval| i.event.endpoint_id == event.endpoint_id
                && i.event.owner == event.owner && i.event.flow == event.flow;
            match event.kind {
                EventKind::Connect | EventKind::Accept => {
                    let endpoint_closed = if event.flow.protocol == 17 {
                        closed.iter().any(|e| e.endpoint_id == event.endpoint_id
                            && (e.owner != event.owner || e.flow == event.flow))
                    } else {
                        closed.iter().any(|e| e.endpoint_id == event.endpoint_id)
                    };
                    if endpoint_closed {
                        return Verdict::Ambiguous;
                    }
                    if intervals.iter().any(|i| same(i)
                        && i.event.kind == EventKind::Established && i.end.is_none()) {
                        continue;
                    }
                    intervals.push(Interval { event, end: None });
                }
                EventKind::Established => {
                    // Reinforces an existing opening. Never resurrect a closed
                    // endpoint merely because a later established event exists.
                    let endpoint_closed = if event.flow.protocol == 17 {
                        closed.iter().any(|e| e.endpoint_id == event.endpoint_id
                            && (e.owner != event.owner || e.flow == event.flow))
                    } else {
                        closed.iter().any(|e| e.endpoint_id == event.endpoint_id)
                    };
                    if !intervals.iter().any(same)
                        && !endpoint_closed {
                        intervals.push(Interval { event, end: None });
                    }
                }
                EventKind::Close | EventKind::Deleted => {
                    closed.push(event);
                    for interval in intervals.iter_mut().filter(|i| same(i)) {
                        if interval.end.is_none() { interval.end = Some(event.timestamp_qpc); }
                    }
                }
            }
        }
        // Two generations of the same oriented tuple remain ambiguous. Native
        // socket-close does not end all TCP tail packets, so choosing the newest
        // generation here would require packet sequence/handshake evidence.
        for (index, interval) in intervals.iter().enumerate() {
            if intervals[..index].iter().any(|earlier| earlier.event.flow == interval.event.flow) {
                return Verdict::Ambiguous;
            }
        }
        let active: Vec<_> = intervals.iter().filter(|i| i.end.is_none()).collect();
        if active.iter().any(|i| selected.contains(&i.event.owner)) { return Verdict::Selected; }
        // Opposite loopback endpoint can still be active after the selected
        // socket closes. That is not proof that a late selected TCP tail is Other.
        if intervals.iter().any(|i| selected.contains(&i.event.owner)) { return Verdict::Unknown; }
        if !active.is_empty() { Verdict::Other } else { Verdict::Unknown }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn multiple_selected_processes_share_one_flow_classification() {
        let mut ledger = Ledger::new(10);
        assert!(ledger.ingest(event(EventKind::Connect, 10)));
        assert_eq!(ledger.classify_any(&flow(), 11, &[id(200), id(100)]), Verdict::Selected);
        assert_eq!(ledger.classify_any(&flow(), 11, &[id(200), id(300)]), Verdict::Other);
        assert_eq!(ledger.classify_any(&flow(), 11, &[]), Verdict::Invalid);
        assert!(ledger.ingest(event(EventKind::Close, 12)));
        assert_eq!(ledger.classify_any(&flow(), 13, &[id(200), id(100)]), Verdict::Unknown);
    }
    use super::*;
    fn id(pid: u32) -> Identity { Identity { pid, creation_time_100ns: 134_337_154_568_108_137 } }
    fn flow() -> Flow { Flow { protocol: 6, local: "127.0.0.1:40000".parse().unwrap(), remote: "127.0.0.1:40001".parse().unwrap() } }
    fn event(kind: EventKind, at: i64) -> Event { Event { timestamp_qpc: at, endpoint_id: 10, owner: id(100), flow: flow(), kind } }
    #[test]
    fn process_selection_uses_metadata_and_not_time_domain_conversion() {
        let mut l = Ledger::new(8); assert!(l.ingest(event(EventKind::Connect, 10)));
        assert_eq!(l.classify(&flow(), 11, id(100)), Verdict::Selected);
        assert_eq!(l.classify(&flow(), 11, id(200)), Verdict::Other);
        assert_eq!(l.classify(&flow(), 9, id(100)), Verdict::Unknown);
    }
    #[test]
    fn opposite_loopback_owner_is_legitimate_for_either_app() {
        let mut l = Ledger::new(8); l.ingest(event(EventKind::Connect, 10));
        let mut server = event(EventKind::Accept, 11);
        server.owner = id(200); server.endpoint_id = 20;
        std::mem::swap(&mut server.flow.local, &mut server.flow.remote);
        l.ingest(server);
        assert_eq!(l.classify(&flow(), 12, id(100)), Verdict::Selected);
        assert_eq!(l.classify(&flow(), 12, id(200)), Verdict::Selected);
        l.ingest(event(EventKind::Close, 13));
        assert_eq!(l.classify(&flow(), 14, id(100)), Verdict::Unknown);
        assert_eq!(l.classify(&flow(), 14, id(200)), Verdict::Selected);
    }
    #[test]
    fn late_arriving_close_is_applied_by_timestamp() {
        let mut l = Ledger::new(8); l.ingest(event(EventKind::Deleted, 20));
        l.ingest(event(EventKind::Established, 12)); l.ingest(event(EventKind::Connect, 10));
        assert_eq!(l.classify(&flow(), 19, id(100)), Verdict::Selected);
        assert_eq!(l.classify(&flow(), 20, id(100)), Verdict::Unknown);
        assert_eq!(l.classify(&flow(), 3000, id(100)), Verdict::Unknown);
    }
    #[test]
    fn closed_tuple_reuse_does_not_authorize_old_tail_as_new_app() {
        let mut l = Ledger::new(8); l.ingest(event(EventKind::Connect, 10));
        l.ingest(event(EventKind::Close, 20));
        let mut next = event(EventKind::Connect, 30); next.endpoint_id = 11; next.owner = id(200); l.ingest(next);
        assert_eq!(l.classify(&flow(), 15, id(100)), Verdict::Selected);
        assert_eq!(l.classify(&flow(), 31, id(100)), Verdict::Ambiguous);
        assert_eq!(l.classify(&flow(), 31, id(200)), Verdict::Ambiguous);
    }
    #[test]
    fn pid_and_endpoint_reuse_changes_identity() {
        let mut l = Ledger::new(8); l.ingest(event(EventKind::Connect, 10));
        let mut next = event(EventKind::Connect, 20); next.owner.creation_time_100ns += 1; l.ingest(next);
        assert_eq!(l.classify(&flow(), 21, id(100)), Verdict::Ambiguous);
    }
    #[test]
    fn same_perspective_conflict_is_not_hidden_by_matching_selected_pid() {
        let mut l = Ledger::new(8); l.ingest(event(EventKind::Connect, 10));
        let mut other = event(EventKind::Connect, 11); other.owner = id(200); other.endpoint_id = 20; l.ingest(other);
        assert_eq!(l.classify(&flow(), 12, id(100)), Verdict::Ambiguous);
    }
    #[test]
    fn one_udp_endpoint_can_serve_multiple_remote_flows() {
        let mut l = Ledger::new(8);
        let server = id(200);
        let mut first = event(EventKind::Accept, 10);
        first.flow.protocol = 17;
        first.owner = server;
        first.endpoint_id = 20;
        std::mem::swap(&mut first.flow.local, &mut first.flow.remote);
        assert!(l.ingest(first));
        let mut second = first;
        second.timestamp_qpc = 11;
        second.flow.remote = "127.0.0.1:40002".parse().unwrap();
        assert!(l.ingest(second));
        assert_eq!(l.classify(&second.flow, 12, server), Verdict::Selected);
    }
    #[test]
    fn inbound_udp_server_event_matches_reverse_packet() {
        let server = id(200);
        let event_flow = Flow {
            protocol: 17,
            local: "192.0.2.2:5353".parse().unwrap(),
            remote: "192.0.2.1:53000".parse().unwrap(),
        };
        let packet_flow = Flow {
            protocol: 17,
            local: event_flow.remote,
            remote: event_flow.local,
        };
        let mut l = Ledger::new(8);
        assert!(l.ingest(Event {
            timestamp_qpc: 10,
            endpoint_id: 20,
            owner: server,
            flow: event_flow,
            kind: EventKind::Established,
        }));
        assert_eq!(l.classify(&packet_flow, 11, server), Verdict::Selected);
        assert_eq!(l.classify(&packet_flow, 11, id(100)), Verdict::Other);
    }
    #[test]
    fn preexisting_flow_without_a_capture_event_stays_unknown() {
        let flow = Flow {
            protocol: 6,
            local: "192.0.2.1:40000".parse().unwrap(),
            remote: "192.0.2.2:443".parse().unwrap(),
        };
        let l = Ledger::new(8);
        assert_eq!(l.classify(&flow, 11, id(100)), Verdict::Unknown);
    }
    #[test]
    fn inbound_ipv6_event_matches_reverse_packet() {
        let server = id(200);
        let event_flow = Flow {
            protocol: 6,
            local: "[2001:db8::2]:443".parse().unwrap(),
            remote: "[2001:db8::1]:40000".parse().unwrap(),
        };
        let packet_flow = Flow {
            protocol: 6,
            local: event_flow.remote,
            remote: event_flow.local,
        };
        let mut l = Ledger::new(8);
        assert!(l.ingest(Event {
            timestamp_qpc: 10,
            endpoint_id: 21,
            owner: server,
            flow: event_flow,
            kind: EventKind::Accept,
        }));
        assert_eq!(l.classify(&packet_flow, 11, server), Verdict::Selected);
    }
    #[test]
    fn udp_and_ipv6_use_the_same_evidence_boundary() {
        let mut l = Ledger::new(8); let mut e = event(EventKind::Connect, 10);
        e.flow = Flow { protocol: 17, local: "[::1]:40000".parse().unwrap(), remote: "[::1]:40001".parse().unwrap() };
        l.ingest(e); assert_eq!(l.classify(&e.flow, 11, id(100)), Verdict::Selected);
        e.kind = EventKind::Deleted; e.timestamp_qpc = 12; l.ingest(e);
        assert_eq!(l.classify(&e.flow, 12, id(100)), Verdict::Unknown);
    }
    #[test]
    fn established_before_connect_is_one_endpoint_lifetime() {
        let mut l = Ledger::new(8);
        l.ingest(event(EventKind::Connect, 12));
        l.ingest(event(EventKind::Established, 10));
        assert_eq!(l.classify(&flow(), 11, id(100)), Verdict::Selected);
        assert_eq!(l.classify(&flow(), 13, id(100)), Verdict::Selected);
    }
    #[test]
    fn orphan_close_cannot_be_resurrected_by_established() {
        let mut l = Ledger::new(8);
        l.ingest(event(EventKind::Close, 10));
        l.ingest(event(EventKind::Established, 12));
        assert_eq!(l.classify(&flow(), 13, id(100)), Verdict::Unknown);
        l.ingest(event(EventKind::Connect, 14));
        assert_eq!(l.classify(&flow(), 15, id(100)), Verdict::Ambiguous);
    }
    #[test]
    fn overflow_and_incomplete_identities_fail_closed() {
        let mut l = Ledger::new(1); let e = event(EventKind::Connect, 10);
        assert!(l.ingest(e)); assert!(l.ingest(e));
        assert!(!l.ingest(event(EventKind::Close, 20)));
        assert_eq!(l.classify(&flow(), 11, id(100)), Verdict::Invalid);
        let mut l = Ledger::new(8); let mut bad = e; bad.owner.creation_time_100ns = 0;
        assert!(!l.ingest(bad)); assert_eq!(l.classify(&flow(), 11, id(100)), Verdict::Invalid);
    }
}
