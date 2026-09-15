//! Bounded offline TCP generations. Not a general TCP reassembly engine.
use super::attribution::{Event, EventKind, Flow, Identity, Verdict};

#[derive(Clone, Copy)]
pub struct Packet {
    pub flow: Flow,
    pub at: i64,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload: u32,
}
#[derive(Clone)]
struct Side {
    next: u32,
    boundaries: Vec<u32>,
    fins: Vec<u32>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Opening {
    endpoint_id: u64,
    owner: Identity,
}
#[derive(Clone)]
struct OwnerEvidence {
    sides: [Vec<Opening>; 2],
    ambiguous: bool,
}
impl OwnerEvidence {
    fn new() -> Self {
        Self {
            sides: [Vec::new(), Vec::new()],
            ambiguous: false,
        }
    }
    fn add(&mut self, side: usize, opening: Opening) {
        if self.sides[side].contains(&opening) {
            return;
        }
        if !self.sides[side].is_empty() {
            // Multiple unclosed openings on one oriented side can be tuple
            // reuse or an identity conflict. Opposite-side ownership is
            // legitimate for an inbound connection.
            self.ambiguous = true;
        }
        self.sides[side].push(opening);
    }
    fn owners(&self) -> Vec<Identity> {
        let mut owners = Vec::new();
        for opening in self.sides.iter().flatten() {
            if !owners.contains(&opening.owner) {
                owners.push(opening.owner);
            }
        }
        owners
    }
}
#[derive(Clone)]
struct Generation {
    flow: Flow,
    start: i64,
    syn: u32,
    owners: Vec<Identity>,
    evidence: OwnerEvidence,
    sides: [Option<Side>; 2],
    poisoned: bool,
}
pub struct Generations {
    events: Vec<Event>,
    generations: Vec<Generation>,
    capacity: usize,
    last: i64,
    invalid: bool,
}
impl Generations {
    pub fn new(events: Vec<Event>, capacity: usize) -> Self {
        Self {
            events,
            generations: Vec::new(),
            capacity,
            last: -1,
            invalid: capacity == 0,
        }
    }
    fn owner_evidence(&self, flow: Flow, at: i64) -> OwnerEvidence {
        let mut evidence = OwnerEvidence::new();
        for e in &self.events {
            // A late ACCEPT cannot retroactively authorize an earlier SYN.
            if !e.flow.matches(&flow)
                || e.timestamp_qpc > at
                || !matches!(e.kind, EventKind::Connect | EventKind::Accept)
                || e.owner.pid == 0
                || e.owner.creation_time_100ns == 0
                || e.endpoint_id == 0
            {
                continue;
            }
            if self.events.iter().any(|c| {
                c.endpoint_id == e.endpoint_id
                    && c.timestamp_qpc <= at
                    && (c.owner != e.owner
                        || !c.flow.matches(&e.flow)
                        || matches!(c.kind, EventKind::Close | EventKind::Deleted))
            }) {
                continue;
            }
            let side = if e.flow == flow {
                0
            } else if e.flow.protocol == flow.protocol
                && e.flow.local == flow.remote
                && e.flow.remote == flow.local
            {
                1
            } else {
                continue;
            };
            // An ACCEPT from an older lifetime must not authorize a new
            // client opening. When a current-side CONNECT is present, only
            // an ACCEPT at or after that opening can belong to this tuple.
            if side == 1
                && matches!(e.kind, EventKind::Accept)
                && self
                    .events
                    .iter()
                    .filter(|c| {
                        c.flow == flow
                            && c.timestamp_qpc <= at
                            && matches!(c.kind, EventKind::Connect)
                    })
                    .map(|c| c.timestamp_qpc)
                    .max()
                    .is_some_and(|connect_at| e.timestamp_qpc < connect_at)
            {
                continue;
            }
            evidence.add(
                side,
                Opening {
                    endpoint_id: e.endpoint_id,
                    owner: e.owner,
                },
            );
        }
        evidence
    }
    fn merge_evidence(generation: &mut Generation, incoming: OwnerEvidence) -> bool {
        if incoming.ambiguous {
            return false;
        }
        for side in 0..2 {
            // A later opening on the same side belongs to a possible tuple
            // reuse. TCP sequence evidence already selected this generation,
            // so retain its owner and do not merge the unrelated opening.
            for opening in incoming.sides[side].iter().copied() {
                if generation.evidence.sides[side].is_empty() {
                    generation.evidence.sides[side].push(opening);
                } else if generation.evidence.sides[side].contains(&opening) {
                    continue;
                }
            }
        }
        generation.owners = generation.evidence.owners();
        true
    }
    pub fn classify(&mut self, packet: Packet, selected: Identity) -> Verdict {
        self.classify_any(packet, &[selected])
    }
    pub fn classify_any(&mut self, packet: Packet, selected: &[Identity]) -> Verdict {
        if self.invalid || packet.at < self.last || packet.flow.protocol != 6 {
            self.invalid = true;
            return Verdict::Invalid;
        }
        self.last = packet.at;
        if packet.flags & 4 != 0 {
            self.poison(packet.flow);
            return Verdict::Unknown;
        }
        let plain_syn = packet.flags == 2 && packet.payload == 0;
        if plain_syn {
            let evidence = self.owner_evidence(packet.flow, packet.at);
            if evidence.ambiguous {
                self.poison(packet.flow);
                return Verdict::Unknown;
            }
            let owners = evidence.owners();
            if self
                .generations
                .iter()
                .any(|g| g.flow == packet.flow && g.syn == packet.seq)
            {
                // A repeated ISN cannot distinguish retransmission from reuse.
                self.poison(packet.flow);
                return Verdict::Ambiguous;
            }
            // Keep one unowned handshake candidate so a late ACCEPT can
            // authorize only packets observed after that event. A second
            // candidate without endpoint evidence remains fail-closed.
            if self
                .generations
                .iter()
                .any(|g| g.flow == packet.flow && g.owners.is_empty())
            {
                self.poison(packet.flow);
                return Verdict::Unknown;
            }
            if let Some(owner) = owners.first().copied() {
                let opening = self
                    .events
                    .iter()
                    .filter(|e| {
                        e.flow.matches(&packet.flow)
                            && e.owner == owner
                            && e.timestamp_qpc <= packet.at
                            && matches!(e.kind, EventKind::Connect | EventKind::Accept)
                    })
                    .map(|e| e.timestamp_qpc)
                    .max()
                    .unwrap_or(-1);
                if self.generations.iter().any(|g| {
                    g.flow == packet.flow && g.owners.contains(&owner) && g.start >= opening
                }) {
                    self.poison(packet.flow);
                    return Verdict::Unknown;
                }
            }
            if self.generations.len() >= self.capacity {
                self.invalid = true;
                return Verdict::Invalid;
            }
            let end = packet.seq.wrapping_add(1);
            self.generations.push(Generation {
                flow: packet.flow,
                start: packet.at,
                syn: packet.seq,
                owners: owners.clone(),
                evidence,
                poisoned: false,
                sides: [
                    Some(Side {
                        next: end,
                        boundaries: vec![end],
                        fins: vec![],
                    }),
                    None,
                ],
            });
            return if owners.is_empty() {
                Verdict::Unknown
            } else if owners.iter().any(|id| selected.contains(id)) {
                Verdict::Selected
            } else {
                Verdict::Other
            };
        }
        let mut candidates = Vec::new();
        for (index, old) in self.generations.iter().enumerate() {
            if old.poisoned {
                continue;
            }
            let reverse = Flow {
                protocol: 6,
                local: old.flow.remote,
                remote: old.flow.local,
            };
            let direction = if packet.flow == old.flow {
                0
            } else if packet.flow == reverse {
                1
            } else {
                continue;
            };
            if packet.at < old.start {
                continue;
            }
            let mut g = old.clone();
            let Some(peer) = &g.sides[1 - direction] else {
                continue;
            };
            if packet.flags & 16 == 0 || !peer.boundaries.contains(&packet.ack) {
                continue;
            }
            if g.sides[direction].is_none() {
                if direction != 1 || packet.flags != 18 || packet.payload != 0 {
                    continue;
                }
                let end = packet.seq.wrapping_add(1);
                g.sides[direction] = Some(Side {
                    next: end,
                    boundaries: vec![end],
                    fins: vec![],
                });
            } else {
                if packet.flags & 2 != 0 {
                    continue;
                }
                let side = g.sides[direction].as_mut().unwrap();
                let fin = packet.flags & 1 != 0;
                let repeated_fin =
                    packet.flags == 17 && packet.payload == 0 && side.fins.contains(&packet.seq);
                if !side.fins.is_empty() && fin && !repeated_fin {
                    continue;
                }
                if !side.fins.is_empty() && packet.payload != 0 {
                    continue;
                }
                if !repeated_fin && packet.seq != side.next {
                    continue;
                }
                if !repeated_fin {
                    if side.boundaries.len() >= 4096 {
                        self.invalid = true;
                        return Verdict::Invalid;
                    }
                    let end = packet
                        .seq
                        .wrapping_add(packet.payload)
                        .wrapping_add(u32::from(fin));
                    side.next = end;
                    if !side.boundaries.contains(&end) {
                        side.boundaries.push(end);
                    }
                    if fin && !side.fins.contains(&packet.seq) {
                        side.fins.push(packet.seq);
                    }
                }
            }
            let generation_flow = g.flow;
            if !Self::merge_evidence(&mut g, self.owner_evidence(generation_flow, packet.at)) {
                continue;
            }
            candidates.push((index, g));
        }
        if candidates.len() > 1 {
            return Verdict::Ambiguous;
        }
        let Some((index, generation)) = candidates.pop() else {
            return Verdict::Unknown;
        };
        let verdict = if generation.owners.is_empty() {
            Verdict::Unknown
        } else if generation.owners.iter().any(|id| selected.contains(id)) {
            Verdict::Selected
        } else {
            Verdict::Other
        };
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
    fn id(pid: u32) -> Identity {
        Identity {
            pid,
            creation_time_100ns: pid as u64,
        }
    }
    fn flow() -> Flow {
        Flow {
            protocol: 6,
            local: "127.0.0.1:41000".parse().unwrap(),
            remote: "127.0.0.1:42000".parse().unwrap(),
        }
    }
    fn event(at: i64, pid: u32, kind: EventKind) -> Event {
        Event {
            timestamp_qpc: at,
            endpoint_id: pid as u64,
            owner: id(pid),
            flow: flow(),
            kind,
        }
    }
    fn p(at: i64, seq: u32, ack: u32, flags: u8, rev: bool) -> Packet {
        let mut f = flow();
        if rev {
            std::mem::swap(&mut f.local, &mut f.remote);
        }
        Packet {
            flow: f,
            at,
            seq,
            ack,
            flags,
            payload: 0,
        }
    }
    #[test]
    fn old_fin_after_new_handshake_keeps_old_owner() {
        for selected in [id(100), id(200)] {
            let mut g = Generations::new(
                vec![
                    event(10, 100, EventKind::Connect),
                    event(20, 100, EventKind::Close),
                    event(30, 200, EventKind::Connect),
                ],
                8,
            );
            for packet in [
                p(11, 10, 0, 2, false),
                p(12, 50, 11, 18, true),
                p(13, 11, 51, 16, false),
                p(16, 11, 51, 17, false),
                p(17, 51, 12, 17, true),
                p(18, 12, 52, 16, false),
                p(31, 1000, 0, 2, false),
                p(32, 2000, 1001, 18, true),
                p(33, 1001, 2001, 16, false),
            ] {
                g.classify(packet, selected);
            }
            assert_eq!(
                g.classify(p(35, 11, 52, 17, false), selected),
                if selected.pid == 100 {
                    Verdict::Selected
                } else {
                    Verdict::Other
                }
            );
        }
    }
    #[test]
    fn missing_metadata_or_handshake_does_not_authorize() {
        let mut g = Generations::new(vec![], 8);
        assert_eq!(
            g.classify(p(11, 10, 0, 2, false), id(100)),
            Verdict::Unknown
        );
        assert_eq!(
            g.classify(p(12, 11, 51, 16, false), id(100)),
            Verdict::Unknown
        );
    }
    #[test]
    fn inbound_syn_is_attributed_to_verified_accept_owner() {
        let mut server = event(10, 200, EventKind::Accept);
        server.flow = Flow {
            protocol: 6,
            local: "127.0.0.1:42000".parse().unwrap(),
            remote: "127.0.0.1:41000".parse().unwrap(),
        };
        let mut g = Generations::new(vec![server], 8);
        assert_eq!(
            g.classify(p(11, 10, 0, 2, false), id(200)),
            Verdict::Selected
        );
        assert_eq!(
            g.classify(p(12, 50, 11, 18, true), id(200)),
            Verdict::Selected
        );
        assert_eq!(
            g.classify(p(13, 11, 51, 16, false), id(200)),
            Verdict::Selected
        );
    }
    #[test]
    fn inbound_trace_accept_replaces_peer_connect_owner_after_syn() {
        let selected = id(200);
        let peer = id(100);
        let mut connect = event(10, peer.pid, EventKind::Connect);
        connect.endpoint_id = 10;
        let mut accept = event(20, selected.pid, EventKind::Accept);
        accept.endpoint_id = 20;
        std::mem::swap(&mut accept.flow.local, &mut accept.flow.remote);
        let mut g = Generations::new(vec![connect, accept], 8);

        // The inbound SYN can precede the selected process's ACCEPT event;
        // preserve the packet verdict already observed in the native trace.
        assert_eq!(g.classify(p(11, 10, 0, 2, false), selected), Verdict::Other);
        // Once the verified opposite endpoint is observed, the same TCP
        // generation must carry the selected owner for the remaining stream.
        assert_eq!(
            g.classify(p(21, 50, 11, 18, true), selected),
            Verdict::Selected
        );
        assert_eq!(
            g.classify(p(22, 11, 51, 16, false), selected),
            Verdict::Selected
        );
        assert_eq!(
            g.classify(
                Packet {
                    flow: flow(),
                    at: 23,
                    seq: 11,
                    ack: 51,
                    flags: 24,
                    payload: 21,
                },
                selected,
            ),
            Verdict::Selected
        );
    }
    #[test]
    fn stale_opposite_accept_does_not_authorize_new_syn() {
        let selected = id(200);
        let peer = id(100);
        let mut stale_accept = event(10, selected.pid, EventKind::Accept);
        stale_accept.endpoint_id = 10;
        std::mem::swap(&mut stale_accept.flow.local, &mut stale_accept.flow.remote);
        let mut current_connect = event(20, peer.pid, EventKind::Connect);
        current_connect.endpoint_id = 20;
        let mut g = Generations::new(vec![stale_accept, current_connect], 8);

        // The selected ACCEPT belongs to an older lifetime than this newer
        // client opening. Without a fresh selected-server ACCEPT, it cannot
        // authorize the new SYN.
        assert_eq!(g.classify(p(21, 99, 0, 2, false), selected), Verdict::Other);
        assert_eq!(
            g.classify(p(22, 50, 100, 18, true), selected),
            Verdict::Other
        );
        assert_eq!(
            g.classify(p(23, 100, 51, 16, false), selected),
            Verdict::Other
        );
        assert_eq!(
            g.classify(
                Packet {
                    flow: flow(),
                    at: 24,
                    seq: 100,
                    ack: 51,
                    flags: 24,
                    payload: 21
                },
                selected,
            ),
            Verdict::Other
        );
    }
    #[test]
    fn inbound_ipv6_syn_is_attributed_to_verified_accept_owner() {
        let server_flow = Flow {
            protocol: 6,
            local: "[2001:db8::2]:443".parse().unwrap(),
            remote: "[2001:db8::1]:41000".parse().unwrap(),
        };
        let client_flow = Flow {
            protocol: 6,
            local: server_flow.remote,
            remote: server_flow.local,
        };
        let server = Event {
            timestamp_qpc: 10,
            endpoint_id: 201,
            owner: id(200),
            flow: server_flow,
            kind: EventKind::Accept,
        };
        let mut g = Generations::new(vec![server], 8);
        assert_eq!(
            g.classify(
                Packet {
                    flow: client_flow,
                    at: 11,
                    seq: 10,
                    ack: 0,
                    flags: 2,
                    payload: 0
                },
                id(200)
            ),
            Verdict::Selected
        );
        assert_eq!(
            g.classify(
                Packet {
                    flow: server_flow,
                    at: 12,
                    seq: 50,
                    ack: 11,
                    flags: 18,
                    payload: 0
                },
                id(200)
            ),
            Verdict::Selected
        );
        assert_eq!(
            g.classify(
                Packet {
                    flow: client_flow,
                    at: 13,
                    seq: 11,
                    ack: 51,
                    flags: 16,
                    payload: 0
                },
                id(200)
            ),
            Verdict::Selected
        );
    }
    #[test]
    fn same_owner_different_endpoint_ids_without_close_stay_unknown() {
        let mut first = event(10, 100, EventKind::Connect);
        first.endpoint_id = 100;
        let mut second = event(30, 100, EventKind::Connect);
        second.endpoint_id = 101;
        let mut g = Generations::new(vec![first, second], 8);
        assert_eq!(
            g.classify(p(31, 200, 0, 2, false), id(100)),
            Verdict::Unknown
        );
    }
    #[test]
    fn old_close_before_new_endpoint_opening_allows_distinct_isn() {
        let old = event(10, 100, EventKind::Connect);
        let old_close = event(20, 100, EventKind::Close);
        let mut new = event(30, 100, EventKind::Connect);
        new.endpoint_id = 101;
        // Deliberately out of timestamp order, as metadata can be queued this way.
        let mut g = Generations::new(vec![new, old_close, old], 8);
        assert_eq!(
            g.classify(p(11, 10, 0, 2, false), id(100)),
            Verdict::Selected
        );
        assert_eq!(
            g.classify(p(31, 200, 0, 2, false), id(100)),
            Verdict::Selected
        );
    }
    #[test]
    fn delayed_old_close_keeps_same_owner_endpoint_reuse_ambiguous() {
        let old = event(10, 100, EventKind::Connect);
        let mut new = event(30, 100, EventKind::Connect);
        new.endpoint_id = 101;
        let old_close = event(40, 100, EventKind::Close);
        let mut g = Generations::new(vec![new, old_close, old], 8);
        assert_eq!(
            g.classify(p(31, 200, 0, 2, false), id(100)),
            Verdict::Unknown
        );
    }
    #[test]
    fn accept_after_inbound_syn_does_not_retroactively_authorize_it() {
        let mut server = event(20, 200, EventKind::Accept);
        server.flow = Flow {
            protocol: 6,
            local: "127.0.0.1:42000".parse().unwrap(),
            remote: "127.0.0.1:41000".parse().unwrap(),
        };
        let mut g = Generations::new(vec![server], 8);
        assert_eq!(
            g.classify(p(11, 10, 0, 2, false), id(200)),
            Verdict::Unknown
        );
        assert_eq!(
            g.classify(p(12, 50, 11, 18, true), id(200)),
            Verdict::Unknown
        );
        assert_eq!(
            g.classify(p(13, 11, 51, 16, false), id(200)),
            Verdict::Unknown
        );
        assert_eq!(
            g.classify(
                Packet {
                    flow: flow(),
                    at: 21,
                    seq: 11,
                    ack: 51,
                    flags: 16,
                    payload: 4,
                },
                id(200)
            ),
            Verdict::Selected
        );
    }
    #[test]
    fn peer_accept_after_selected_connect_does_not_poison_generation() {
        let selected = event(10, 100, EventKind::Connect);
        let mut peer = event(12, 200, EventKind::Accept);
        peer.endpoint_id = 200;
        peer.flow = Flow {
            protocol: 6,
            local: "127.0.0.1:42000".parse().unwrap(),
            remote: "127.0.0.1:41000".parse().unwrap(),
        };
        let mut g = Generations::new(vec![selected, peer], 8);
        assert_eq!(
            g.classify(p(11, 10, 0, 2, false), id(100)),
            Verdict::Selected
        );
        assert_eq!(
            g.classify(p(13, 50, 11, 18, true), id(100)),
            Verdict::Selected
        );
        assert_eq!(
            g.classify(p(14, 11, 51, 16, false), id(100)),
            Verdict::Selected
        );
    }
    #[test]
    fn app_group_matches_any_verified_identity_once_per_packet() {
        let mut g = Generations::new(vec![event(10, 100, EventKind::Connect)], 8);
        assert_eq!(
            g.classify_any(p(11, 10, 0, 2, false), &[id(200), id(100)]),
            Verdict::Selected
        );
        assert_eq!(
            g.classify_any(p(12, 50, 11, 18, true), &[id(200), id(100)]),
            Verdict::Selected
        );
    }
    #[test]
    fn second_fin_cannot_advance_a_closed_direction() {
        let mut g = Generations::new(vec![event(10, 100, EventKind::Connect)], 8);
        g.classify(p(11, 10, 0, 2, false), id(100));
        g.classify(p(12, 50, 11, 18, true), id(100));
        assert_eq!(
            g.classify(p(13, 11, 51, 17, false), id(100)),
            Verdict::Selected
        );
        assert_eq!(
            g.classify(p(14, 12, 51, 17, false), id(100)),
            Verdict::Unknown
        );
    }
    #[test]
    fn reset_does_not_leave_generation_active() {
        let mut g = Generations::new(vec![event(10, 100, EventKind::Connect)], 8);
        g.classify(p(11, 10, 0, 2, false), id(100));
        g.classify(p(12, 50, 11, 18, true), id(100));
        assert_eq!(
            g.classify(p(13, 11, 51, 20, false), id(100)),
            Verdict::Unknown
        );
        assert_eq!(
            g.classify(p(14, 11, 51, 16, false), id(100)),
            Verdict::Unknown
        );
    }
    #[test]
    fn new_sequence_requires_new_socket_opening() {
        let mut g = Generations::new(vec![event(10, 100, EventKind::Connect)], 8);
        g.classify(p(11, 10, 0, 2, false), id(100));
        assert_eq!(
            g.classify(p(12, 1000, 0, 2, false), id(100)),
            Verdict::Unknown
        );
    }
    #[test]
    fn sequence_wrap_is_preserved() {
        let mut g = Generations::new(vec![event(10, 100, EventKind::Connect)], 8);
        assert_eq!(
            g.classify(p(11, u32::MAX, 0, 2, false), id(100)),
            Verdict::Selected
        );
        assert_eq!(
            g.classify(p(12, 50, 0, 18, true), id(100)),
            Verdict::Selected
        );
        assert_eq!(
            g.classify(p(13, 0, 51, 16, false), id(100)),
            Verdict::Selected
        );
    }
    #[test]
    fn conflicting_syn_does_not_leave_old_owner_authorized() {
        let mut g = Generations::new(vec![event(10, 100, EventKind::Connect)], 8);
        g.classify(p(11, 10, 0, 2, false), id(100));
        g.classify(p(12, 50, 11, 18, true), id(100));
        assert_eq!(
            g.classify(p(13, 10, 0, 2, false), id(100)),
            Verdict::Ambiguous
        );
        assert_eq!(
            g.classify(p(14, 11, 51, 16, false), id(100)),
            Verdict::Unknown
        );
    }
    #[test]
    fn reversed_time_and_capacity_fail_closed() {
        let mut g = Generations::new(
            vec![
                event(10, 100, EventKind::Connect),
                event(12, 100, EventKind::Close),
                event(13, 200, EventKind::Connect),
            ],
            1,
        );
        assert_eq!(
            g.classify(p(11, 10, 0, 2, false), id(100)),
            Verdict::Selected
        );
        assert_eq!(
            g.classify(p(14, 20, 0, 2, false), id(100)),
            Verdict::Invalid
        );
        let mut g = Generations::new(vec![], 1);
        g.classify(p(11, 10, 0, 2, false), id(100));
        assert_eq!(
            g.classify(p(10, 10, 0, 2, false), id(100)),
            Verdict::Invalid
        );
    }
}
