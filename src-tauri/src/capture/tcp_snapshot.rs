//! Existing TCP socket ownership, independent of observed handshake generations.
use super::{
    attribution::{Event, Flow, Identity, Verdict},
    bind_snapshot::{decode, read_owner_table},
};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
};
use windows::Win32::{
    NetworkManagement::IpHelper::{
        MIB_TCP6ROW_OWNER_MODULE, MIB_TCP6TABLE_OWNER_MODULE, MIB_TCPROW_OWNER_MODULE,
        MIB_TCPTABLE_OWNER_MODULE, MIB_TCP_STATE_ESTAB,
    },
    Networking::WinSock::{AF_INET, AF_INET6},
};

const LIMIT: usize = 32_768;
type Key = (SocketAddr, SocketAddr);
fn key(flow: &Flow) -> Key {
    if flow.local <= flow.remote {
        (flow.local, flow.remote)
    } else {
        (flow.remote, flow.local)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Connection {
    flow: Flow,
    owner: Option<Identity>,
    created: u64,
    established: bool,
}
pub struct Snapshot {
    rows: Vec<Connection>,
}
enum Seed {
    Known(Vec<Identity>),
    Unknown,
    Ambiguous,
}
pub struct PriorTcp {
    seeds: HashMap<Key, Seed>,
    ready_at: i64,
    changed: HashMap<Key, i64>,
    handshakes: HashSet<Key>,
    invalid_after: Option<i64>,
}
impl PriorTcp {
    pub fn new(before: Snapshot, after: Snapshot, ready_at: i64) -> Result<Self, String> {
        let mut groups: HashMap<Key, (Vec<Connection>, Vec<Connection>)> = HashMap::new();
        for (second, snapshot) in [(false, before), (true, after)] {
            for row in snapshot.rows {
                let entry = groups.entry(key(&row.flow)).or_default();
                let rows = if second { &mut entry.1 } else { &mut entry.0 };
                if !rows.contains(&row) {
                    rows.push(row);
                }
                if groups.len() > LIMIT {
                    return Err("TCP snapshot exceeds connection limit".into());
                }
            }
        }
        let seeds = groups
            .into_iter()
            .map(|(key, (before, after))| (key, reconcile(&before, &after)))
            .collect();
        Ok(Self {
            seeds,
            ready_at,
            changed: HashMap::new(),
            handshakes: HashSet::new(),
            invalid_after: None,
        })
    }
    pub fn observe(&mut self, event: &Event) {
        if event.flow.protocol != 6 {
            return;
        }
        let key = key(&event.flow);
        if self.seeds.contains_key(&key) {
            self.changed
                .entry(key)
                .and_modify(|at| *at = (*at).min(event.timestamp_qpc))
                .or_insert(event.timestamp_qpc);
        }
    }
    pub fn invalidate_all(&mut self, at: i64) {
        self.invalid_after = Some(self.invalid_after.map_or(at, |old| old.min(at)));
    }
    pub fn classify(&mut self, flow: &Flow, at: i64, flags: u8, selected: &[Identity]) -> Verdict {
        if flow.protocol != 6
            || selected.is_empty()
            || selected
                .iter()
                .any(|owner| owner.pid == 0 || owner.creation_time_100ns == 0)
        {
            return Verdict::Invalid;
        }
        let key = key(flow);
        let Some(seed) = self.seeds.get(&key) else {
            return Verdict::Unknown;
        };
        if flags & (2 | 4) != 0 {
            self.handshakes.insert(key);
        }
        if self.ready_at < 0
            || at < self.ready_at
            || self.handshakes.contains(&key)
            || self.invalid_after.is_some_and(|changed| changed <= at)
            || self.changed.get(&key).is_some_and(|changed| *changed <= at)
        {
            return Verdict::Unknown;
        }
        match seed {
            Seed::Known(owners) if owners.iter().any(|owner| selected.contains(owner)) => {
                Verdict::Selected
            }
            Seed::Known(_) => Verdict::Other,
            Seed::Unknown => Verdict::Unknown,
            Seed::Ambiguous => Verdict::Ambiguous,
        }
    }
}
fn reconcile(before: &[Connection], after: &[Connection]) -> Seed {
    if before.is_empty()
        || after.is_empty()
        || before.iter().any(|row| !after.contains(row))
        || after.iter().any(|row| !before.contains(row))
    {
        return Seed::Unknown;
    }
    let mut owners = Vec::new();
    for (index, row) in before.iter().enumerate() {
        let Some(owner) = row.owner else {
            return Seed::Unknown;
        };
        if !row.established
            || owner.pid == 0
            || owner.creation_time_100ns == 0
            || row.created < owner.creation_time_100ns
        {
            return Seed::Unknown;
        }
        if before[..index]
            .iter()
            .any(|other| other.flow == row.flow && other != row)
        {
            return Seed::Ambiguous;
        }
        if !owners.contains(&owner) {
            owners.push(owner);
        }
    }
    Seed::Known(owners)
}
impl Snapshot {
    pub fn read() -> Result<Self, String> {
        let mut rows = Vec::new();
        let ipv4 = read_owner_table(AF_INET.0 as u32, true)?;
        for row in decode::<MIB_TCPROW_OWNER_MODULE>(
            &ipv4,
            std::mem::offset_of!(MIB_TCPTABLE_OWNER_MODULE, table),
        )? {
            add(
                &mut rows,
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
                    u16::from_be(row.dwLocalPort as u16),
                ),
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes())),
                    u16::from_be(row.dwRemotePort as u16),
                ),
                row.dwOwningPid,
                row.liCreateTimestamp,
                row.dwState,
            );
        }
        let ipv6 = read_owner_table(AF_INET6.0 as u32, true)?;
        for row in decode::<MIB_TCP6ROW_OWNER_MODULE>(
            &ipv6,
            std::mem::offset_of!(MIB_TCP6TABLE_OWNER_MODULE, table),
        )? {
            add(
                &mut rows,
                SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(row.ucLocalAddr),
                    u16::from_be(row.dwLocalPort as u16),
                    0,
                    row.dwLocalScopeId,
                )),
                SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(row.ucRemoteAddr),
                    u16::from_be(row.dwRemotePort as u16),
                    0,
                    row.dwRemoteScopeId,
                )),
                row.dwOwningPid,
                row.liCreateTimestamp,
                row.dwState,
            );
        }
        if rows.len() > LIMIT {
            return Err("TCP snapshot exceeds row limit".into());
        }
        Ok(Self { rows })
    }
}
fn canonical(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(v6) if v6.scope_id() == 0 => v6
            .ip()
            .to_ipv4_mapped()
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), v6.port()))
            .unwrap_or(address),
        _ => address,
    }
}
fn add(
    rows: &mut Vec<Connection>,
    local: SocketAddr,
    remote: SocketAddr,
    pid: u32,
    created: i64,
    state: u32,
) {
    // LISTEN/unbound rows have no complete connection tuple. Other states stay
    // present so a competing transitional row cannot disappear from comparison.
    if local.port() == 0
        || remote.port() == 0
        || local.ip().is_unspecified()
        || remote.ip().is_unspecified()
    {
        return;
    }
    let created = u64::try_from(created).unwrap_or(0);
    let owner = super::windivert::identity(pid)
        .filter(|owner| owner.creation_time_100ns != 0 && created >= owner.creation_time_100ns);
    rows.push(Connection {
        flow: Flow {
            protocol: 6,
            local: canonical(local),
            remote: canonical(remote),
        },
        owner,
        created,
        established: state == MIB_TCP_STATE_ESTAB.0 as u32,
    });
}
#[cfg(test)]
mod tests {
    use super::super::attribution::EventKind;
    use super::*;
    fn owner(pid: u32) -> Identity {
        Identity {
            pid,
            creation_time_100ns: 100,
        }
    }
    fn row(pid: u32) -> Connection {
        Connection {
            flow: Flow {
                protocol: 6,
                local: "127.0.0.1:8000".parse().unwrap(),
                remote: "127.0.0.1:9000".parse().unwrap(),
            },
            owner: Some(owner(pid)),
            created: 200,
            established: true,
        }
    }
    fn prior(rows: Vec<Connection>) -> PriorTcp {
        PriorTcp::new(Snapshot { rows: rows.clone() }, Snapshot { rows }, 10).unwrap()
    }
    #[test]
    fn stable_connection_accepts_payload_in_both_directions_without_inventing_a_syn() {
        let row = row(1);
        let mut prior = prior(vec![row.clone()]);
        assert_eq!(
            prior.classify(&row.flow, 20, 24, &[owner(1)]),
            Verdict::Selected
        );
        let reverse = Flow {
            local: row.flow.remote,
            remote: row.flow.local,
            ..row.flow
        };
        assert_eq!(
            prior.classify(&reverse, 21, 24, &[owner(1)]),
            Verdict::Selected
        );
        assert_eq!(
            prior.classify(&reverse, 9, 24, &[owner(1)]),
            Verdict::Unknown
        );
    }
    #[test]
    fn valid_opposite_loopback_owners_are_distinct_from_same_side_conflicts() {
        let first = row(1);
        let mut second = row(2);
        second.flow = Flow {
            local: first.flow.remote,
            remote: first.flow.local,
            ..first.flow
        };
        assert_eq!(
            prior(vec![first.clone(), second]).classify(&first.flow, 20, 24, &[owner(1)]),
            Verdict::Selected
        );
        assert_eq!(
            prior(vec![first.clone(), row(2)]).classify(&first.flow, 20, 24, &[owner(1)]),
            Verdict::Ambiguous
        );
    }
    #[test]
    fn changing_lifetime_and_unknown_owner_are_not_seeded() {
        let first = row(1);
        let changed = Connection {
            created: 201,
            ..first.clone()
        };
        let mut evidence = PriorTcp::new(
            Snapshot {
                rows: vec![first.clone()],
            },
            Snapshot {
                rows: vec![changed],
            },
            10,
        )
        .unwrap();
        assert_ne!(
            evidence.classify(&first.flow, 20, 24, &[owner(1)]),
            Verdict::Selected
        );
        assert_ne!(
            prior(vec![Connection {
                owner: None,
                ..first.clone()
            }])
            .classify(&first.flow, 20, 24, &[owner(1)]),
            Verdict::Selected
        );
    }
    #[test]
    fn reused_pid_transitional_state_and_unknown_competitor_are_not_admitted() {
        let first = row(1);
        let replacement = Connection {
            owner: Some(Identity {
                creation_time_100ns: 101,
                ..owner(1)
            }),
            ..first.clone()
        };
        let mut changed = PriorTcp::new(
            Snapshot {
                rows: vec![first.clone()],
            },
            Snapshot {
                rows: vec![replacement],
            },
            10,
        )
        .unwrap();
        assert_ne!(
            changed.classify(&first.flow, 20, 24, &[owner(1)]),
            Verdict::Selected
        );
        assert_ne!(
            prior(vec![Connection {
                established: false,
                ..first.clone()
            }])
            .classify(&first.flow, 20, 24, &[owner(1)]),
            Verdict::Selected
        );
        assert_ne!(
            prior(vec![
                first.clone(),
                Connection {
                    owner: None,
                    ..first.clone()
                }
            ])
            .classify(&first.flow, 20, 24, &[owner(1)]),
            Verdict::Selected
        );
    }
    #[test]
    fn unrelated_events_preserve_seed_and_malformed_metadata_stops_future_admission() {
        let first = row(1);
        let mut evidence = prior(vec![first.clone()]);
        let mut other = first.flow;
        other.local.set_port(8001);
        evidence.observe(&Event {
            timestamp_qpc: 15,
            endpoint_id: 10,
            owner: owner(2),
            flow: other,
            kind: EventKind::Connect,
        });
        assert_eq!(
            evidence.classify(&first.flow, 20, 24, &[owner(1)]),
            Verdict::Selected
        );
        evidence.invalidate_all(25);
        assert_eq!(
            evidence.classify(&first.flow, 20, 24, &[owner(1)]),
            Verdict::Selected
        );
        assert_ne!(
            evidence.classify(&first.flow, 25, 24, &[owner(1)]),
            Verdict::Selected
        );
    }
    #[test]
    fn new_handshake_or_socket_event_invalidates_the_old_connection() {
        let first = row(1);
        for flags in [2, 18, 4] {
            let mut evidence = prior(vec![first.clone()]);
            assert_ne!(
                evidence.classify(&first.flow, 20, flags, &[owner(1)]),
                Verdict::Selected
            );
            assert_ne!(
                evidence.classify(&first.flow, 21, 24, &[owner(1)]),
                Verdict::Selected
            );
        }
        let mut evidence = prior(vec![first.clone()]);
        evidence.observe(&Event {
            timestamp_qpc: 25,
            endpoint_id: 1,
            owner: owner(1),
            flow: first.flow,
            kind: EventKind::Close,
        });
        assert_eq!(
            evidence.classify(&first.flow, 20, 24, &[owner(1)]),
            Verdict::Selected
        );
        assert_ne!(
            evidence.classify(&first.flow, 25, 24, &[owner(1)]),
            Verdict::Selected
        );
    }
    #[test]
    #[ignore = "Reads held established IPv4/IPv6 TCP socket ownership; no system changes"]
    fn live_snapshot_identifies_existing_tcp_connections() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let listener = std::net::TcpListener::bind(address).unwrap();
            let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (_server, _) = listener.accept().unwrap();
            let flow = Flow {
                protocol: 6,
                local: client.local_addr().unwrap(),
                remote: client.peer_addr().unwrap(),
            };
            let selected = super::super::windivert::identity(std::process::id()).unwrap();
            let mut prior =
                PriorTcp::new(Snapshot::read().unwrap(), Snapshot::read().unwrap(), 10).unwrap();
            assert_eq!(
                prior.classify(&flow, 20, 24, &[selected]),
                Verdict::Selected
            );
        }
    }
}
