//! Bounded offline TCP generations. Not a general TCP reassembly engine.
use super::attribution::{Event, EventKind, Flow, Identity, Verdict};

#[derive(Clone, Copy)]
pub struct Packet {
    pub flow: Flow, pub at: i64, pub seq: u32, pub ack: u32,
    pub flags: u8, pub payload: u32,
}
#[derive(Clone)]
struct Side { next: u32, boundaries: Vec<u32>, fins: Vec<u32> }
#[derive(Clone)]
struct Generation {
    flow: Flow, start: i64, syn: u32, owners: Vec<Identity>,
    sides: [Option<Side>; 2], poisoned: bool,
}
pub struct Generations {
    events: Vec<Event>, generations: Vec<Generation>, capacity: usize,
    last: i64, invalid: bool,
}
impl Generations {
    pub fn new(events: Vec<Event>, capacity: usize) -> Self {
        Self { events, generations: Vec::new(), capacity, last: -1, invalid: capacity == 0 }
    }
    fn owners(&self, flow: Flow, at: i64) -> Vec<Identity> {
        let mut result = Vec::new();
        let mut endpoints = Vec::new();
        for e in &self.events {
            // A late ACCEPT cannot retroactively authorize an earlier SYN.
            if !e.flow.matches(&flow) || e.timestamp_qpc > at
                || !matches!(e.kind, EventKind::Connect | EventKind::Accept)
                || e.owner.pid == 0 || e.owner.creation_time_100ns == 0 || e.endpoint_id == 0 { continue; }
            if self.events.iter().any(|c| c.endpoint_id == e.endpoint_id && c.timestamp_qpc <= at
                && (c.owner != e.owner || !c.flow.matches(&e.flow)
                    || matches!(c.kind, EventKind::Close | EventKind::Deleted))) { continue; }
            if !endpoints.contains(&(e.endpoint_id, e.owner)) {
                endpoints.push((e.endpoint_id, e.owner)); result.push(e.owner);
            }
        }
        result
    }
    pub fn classify(&mut self, packet: Packet, selected: Identity) -> Verdict {
        self.classify_any(packet, &[selected])
    }
    pub fn classify_any(&mut self, packet: Packet, selected: &[Identity]) -> Verdict {
        if self.invalid || packet.at < self.last || packet.flow.protocol != 6 {
            self.invalid = true; return Verdict::Invalid;
        }
        self.last = packet.at;
        if packet.flags & 4 != 0 { self.poison(packet.flow); return Verdict::Unknown; }
        let plain_syn = packet.flags == 2 && packet.payload == 0;
        if plain_syn {
            let owners = self.owners(packet.flow, packet.at);
            if owners.len() != 1 { self.poison(packet.flow); return Verdict::Unknown; }
            if self.generations.iter().any(|g| g.flow == packet.flow && g.syn == packet.seq) {
                // A repeated ISN cannot distinguish retransmission from reuse.
                self.poison(packet.flow); return Verdict::Ambiguous;
            }
            let opening = self.events.iter().filter(|e| e.flow.matches(&packet.flow)
                && e.owner == owners[0] && e.timestamp_qpc <= packet.at
                && matches!(e.kind, EventKind::Connect | EventKind::Accept))
                .map(|e| e.timestamp_qpc).max().unwrap_or(-1);
            if self.generations.iter().any(|g| g.flow == packet.flow
                && g.owners.contains(&owners[0]) && g.start >= opening) {
                self.poison(packet.flow); return Verdict::Unknown;
            }
            if self.generations.len() >= self.capacity { self.invalid = true; return Verdict::Invalid; }
            let end = packet.seq.wrapping_add(1);
            self.generations.push(Generation { flow: packet.flow, start: packet.at, syn: packet.seq,
                owners: owners.clone(), poisoned: false, sides: [Some(Side { next: end, boundaries: vec![end], fins: vec![] }), None] });
            return if owners.iter().any(|id| selected.contains(id)) { Verdict::Selected } else { Verdict::Other };
        }
        let mut candidates = Vec::new();
        for (index, old) in self.generations.iter().enumerate() {
            if old.poisoned { continue; }
            let reverse = Flow { protocol: 6, local: old.flow.remote, remote: old.flow.local };
            let direction = if packet.flow == old.flow { 0 } else if packet.flow == reverse { 1 } else { continue; };
            if packet.at < old.start { continue; }
            let mut g = old.clone();
            let Some(peer) = &g.sides[1-direction] else { continue; };
            if packet.flags & 16 == 0 || !peer.boundaries.contains(&packet.ack) { continue; }
            if g.sides[direction].is_none() {
                if direction != 1 || packet.flags != 18 || packet.payload != 0 { continue; }
                let end = packet.seq.wrapping_add(1);
                g.sides[direction] = Some(Side { next: end, boundaries: vec![end], fins: vec![] });
                let owners = self.owners(packet.flow, packet.at);
                if owners.len() > 1 { continue; }
                for owner in owners { if !g.owners.contains(&owner) { g.owners.push(owner); } }
            } else {
                if packet.flags & 2 != 0 { continue; }
                let side = g.sides[direction].as_mut().unwrap();
                let fin = packet.flags & 1 != 0;
                let repeated_fin = packet.flags == 17 && packet.payload == 0 && side.fins.contains(&packet.seq);
                if !side.fins.is_empty() && fin && !repeated_fin { continue; }
                if !side.fins.is_empty() && packet.payload != 0 { continue; }
                if !repeated_fin && packet.seq != side.next { continue; }
                if !repeated_fin {
                    if side.boundaries.len() >= 4096 { self.invalid = true; return Verdict::Invalid; }
                    let end = packet.seq.wrapping_add(packet.payload).wrapping_add(u32::from(fin));
                    side.next = end;
                    if !side.boundaries.contains(&end) { side.boundaries.push(end); }
                    if fin && !side.fins.contains(&packet.seq) { side.fins.push(packet.seq); }
                }
            }
            candidates.push((index, g));
        }
        if candidates.len() > 1 { return Verdict::Ambiguous; }
        let Some((index, generation)) = candidates.pop() else { return Verdict::Unknown; };
        let verdict = if generation.owners.iter().any(|id| selected.contains(id)) { Verdict::Selected } else { Verdict::Other };
        self.generations[index] = generation;
        verdict
    }
    fn poison(&mut self, flow: Flow) {
        for g in &mut self.generations {
            if g.flow == flow || (g.flow.local == flow.remote && g.flow.remote == flow.local) {
                g.poisoned = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(pid: u32) -> Identity { Identity { pid, creation_time_100ns: pid as u64 } }
    fn flow() -> Flow { Flow { protocol: 6, local: "127.0.0.1:41000".parse().unwrap(), remote: "127.0.0.1:42000".parse().unwrap() } }
    fn event(at: i64, pid: u32, kind: EventKind) -> Event { Event { timestamp_qpc: at, endpoint_id: pid as u64, owner: id(pid), flow: flow(), kind } }
    fn p(at: i64, seq: u32, ack: u32, flags: u8, rev: bool) -> Packet {
        let mut f = flow(); if rev { std::mem::swap(&mut f.local, &mut f.remote); }
        Packet { flow: f, at, seq, ack, flags, payload: 0 }
    }
    #[test]
    fn old_fin_after_new_handshake_keeps_old_owner() {
        for selected in [id(100), id(200)] {
            let mut g = Generations::new(vec![event(10,100,EventKind::Connect),event(20,100,EventKind::Close),event(30,200,EventKind::Connect)], 8);
            for packet in [p(11,10,0,2,false),p(12,50,11,18,true),p(13,11,51,16,false),p(16,11,51,17,false),p(17,51,12,17,true),p(18,12,52,16,false),p(31,1000,0,2,false),p(32,2000,1001,18,true),p(33,1001,2001,16,false)] { g.classify(packet,selected); }
            assert_eq!(g.classify(p(35,11,52,17,false),selected), if selected.pid == 100 { Verdict::Selected } else { Verdict::Other });
        }
    }
    #[test]
    fn missing_metadata_or_handshake_does_not_authorize() {
        let mut g = Generations::new(vec![], 8);
        assert_eq!(g.classify(p(11,10,0,2,false),id(100)),Verdict::Unknown);
        assert_eq!(g.classify(p(12,11,51,16,false),id(100)),Verdict::Unknown);
    }
    #[test]
    fn inbound_syn_is_attributed_to_verified_accept_owner() {
        let mut server = event(10,200,EventKind::Accept);
        server.flow = Flow { protocol: 6,
            local: "127.0.0.1:42000".parse().unwrap(),
            remote: "127.0.0.1:41000".parse().unwrap() };
        let mut g = Generations::new(vec![server], 8);
        assert_eq!(g.classify(p(11,10,0,2,false),id(200)),Verdict::Selected);
        assert_eq!(g.classify(p(12,50,11,18,true),id(200)),Verdict::Selected);
        assert_eq!(g.classify(p(13,11,51,16,false),id(200)),Verdict::Selected);
    }
    #[test]
    fn inbound_ipv6_syn_is_attributed_to_verified_accept_owner() {
        let server_flow = Flow { protocol: 6,
            local: "[2001:db8::2]:443".parse().unwrap(),
            remote: "[2001:db8::1]:41000".parse().unwrap() };
        let client_flow = Flow { protocol: 6,
            local: server_flow.remote, remote: server_flow.local };
        let server = Event { timestamp_qpc: 10, endpoint_id: 201,
            owner: id(200), flow: server_flow, kind: EventKind::Accept };
        let mut g = Generations::new(vec![server], 8);
        assert_eq!(g.classify(Packet { flow: client_flow, at: 11,
            seq: 10, ack: 0, flags: 2, payload: 0 }, id(200)), Verdict::Selected);
        assert_eq!(g.classify(Packet { flow: server_flow, at: 12,
            seq: 50, ack: 11, flags: 18, payload: 0 }, id(200)), Verdict::Selected);
        assert_eq!(g.classify(Packet { flow: client_flow, at: 13,
            seq: 11, ack: 51, flags: 16, payload: 0 }, id(200)), Verdict::Selected);
    }
    #[test]
    fn same_owner_different_endpoint_ids_without_close_stay_unknown() {
        let mut first = event(10, 100, EventKind::Connect);
        first.endpoint_id = 100;
        let mut second = event(30, 100, EventKind::Connect);
        second.endpoint_id = 101;
        let mut g = Generations::new(vec![first, second], 8);
        assert_eq!(g.classify(p(31, 200, 0, 2, false), id(100)), Verdict::Unknown);
    }
    #[test]
    fn old_close_before_new_endpoint_opening_allows_distinct_isn() {
        let old = event(10, 100, EventKind::Connect);
        let old_close = event(20, 100, EventKind::Close);
        let mut new = event(30, 100, EventKind::Connect);
        new.endpoint_id = 101;
        // Deliberately out of timestamp order, as metadata can be queued this way.
        let mut g = Generations::new(vec![new, old_close, old], 8);
        assert_eq!(g.classify(p(11, 10, 0, 2, false), id(100)), Verdict::Selected);
        assert_eq!(g.classify(p(31, 200, 0, 2, false), id(100)), Verdict::Selected);
    }
    #[test]
    fn delayed_old_close_keeps_same_owner_endpoint_reuse_ambiguous() {
        let old = event(10, 100, EventKind::Connect);
        let mut new = event(30, 100, EventKind::Connect);
        new.endpoint_id = 101;
        let old_close = event(40, 100, EventKind::Close);
        let mut g = Generations::new(vec![new, old_close, old], 8);
        assert_eq!(g.classify(p(31, 200, 0, 2, false), id(100)), Verdict::Unknown);
    }
    #[test]
    fn accept_after_inbound_syn_does_not_retroactively_authorize_it() {
        let mut server = event(20, 200, EventKind::Accept);
        server.flow = Flow { protocol: 6,
            local: "127.0.0.1:42000".parse().unwrap(),
            remote: "127.0.0.1:41000".parse().unwrap() };
        let mut g = Generations::new(vec![server], 8);
        assert_eq!(g.classify(p(11, 10, 0, 2, false), id(200)), Verdict::Unknown);
    }
    #[test]
    fn app_group_matches_any_verified_identity_once_per_packet() {
        let mut g = Generations::new(vec![event(10,100,EventKind::Connect)],8);
        assert_eq!(g.classify_any(p(11,10,0,2,false),&[id(200),id(100)]),Verdict::Selected);
        assert_eq!(g.classify_any(p(12,50,11,18,true),&[id(200),id(100)]),Verdict::Selected);
    }
    #[test]
    fn second_fin_cannot_advance_a_closed_direction() {
        let mut g = Generations::new(vec![event(10,100,EventKind::Connect)],8);
        g.classify(p(11,10,0,2,false),id(100));
        g.classify(p(12,50,11,18,true),id(100));
        assert_eq!(g.classify(p(13,11,51,17,false),id(100)),Verdict::Selected);
        assert_eq!(g.classify(p(14,12,51,17,false),id(100)),Verdict::Unknown);
    }
    #[test]
    fn reset_does_not_leave_generation_active() {
        let mut g = Generations::new(vec![event(10,100,EventKind::Connect)],8);
        g.classify(p(11,10,0,2,false),id(100));
        g.classify(p(12,50,11,18,true),id(100));
        assert_eq!(g.classify(p(13,11,51,20,false),id(100)),Verdict::Unknown);
        assert_eq!(g.classify(p(14,11,51,16,false),id(100)),Verdict::Unknown);
    }
    #[test]
    fn new_sequence_requires_new_socket_opening() {
        let mut g = Generations::new(vec![event(10,100,EventKind::Connect)],8);
        g.classify(p(11,10,0,2,false),id(100));
        assert_eq!(g.classify(p(12,1000,0,2,false),id(100)),Verdict::Unknown);
    }
    #[test]
    fn sequence_wrap_is_preserved() {
        let mut g = Generations::new(vec![event(10,100,EventKind::Connect)],8);
        assert_eq!(g.classify(p(11,u32::MAX,0,2,false),id(100)),Verdict::Selected);
        assert_eq!(g.classify(p(12,50,0,18,true),id(100)),Verdict::Selected);
        assert_eq!(g.classify(p(13,0,51,16,false),id(100)),Verdict::Selected);
    }
    #[test]
    fn conflicting_syn_does_not_leave_old_owner_authorized() {
        let mut g = Generations::new(vec![event(10,100,EventKind::Connect)],8);
        g.classify(p(11,10,0,2,false),id(100));
        g.classify(p(12,50,11,18,true),id(100));
        assert_eq!(g.classify(p(13,10,0,2,false),id(100)),Verdict::Ambiguous);
        assert_eq!(g.classify(p(14,11,51,16,false),id(100)),Verdict::Unknown);
    }
    #[test]
    fn reversed_time_and_capacity_fail_closed() {
        let mut g = Generations::new(vec![event(10,100,EventKind::Connect),event(12,100,EventKind::Close),event(13,200,EventKind::Connect)],1);
        assert_eq!(g.classify(p(11,10,0,2,false),id(100)),Verdict::Selected);
        assert_eq!(g.classify(p(14,20,0,2,false),id(100)),Verdict::Invalid);
        let mut g = Generations::new(vec![],1);
        g.classify(p(11,10,0,2,false),id(100));
        assert_eq!(g.classify(p(10,10,0,2,false),id(100)),Verdict::Invalid);
    }
}
