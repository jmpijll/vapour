//! Packet-to-companion routing. No driver handles or system configuration.
//!
//! One serialized router belongs to one companion generation. A new reflected
//! tuple is authorized synchronously before its first packet may be injected.
//! Exhaustion and quarantined tuples require a new generation, never a bypass.

use super::{
    dns_filter::{build_dns_filters, DnsFilterConfig},
    dns_flow::{FlowError, FlowRegistry, Interface, OriginalFlow},
    dns_packet::{decode, Protocol},
    dns_process::{DnsProcessStatus, TransparentFlowRegistration},
};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr, SocketAddrV6},
};

const FLOW_LIMIT: usize = 4096;
const FLOW_LIFETIME_MS: u64 = 120_000;

#[derive(Debug, PartialEq)]
pub(crate) enum RouteError {
    InvalidPacket,
    InvalidInterface,
    Reflection(FlowError),
    RolloverRequired,
    Companion(String),
    Stopped,
    ClockReversed,
}

#[derive(Debug, PartialEq)]
pub(crate) enum RoutedPacket {
    /// This packet was not part of this generation's intercepted traffic.
    Unchanged,
    /// Never let an unsolicited proxy reply leave the host unchanged.
    Discard,
    /// Both request reflection and reply restoration are injected inbound.
    Inbound {
        packet: Vec<u8>,
        interface: Interface,
    },
}

struct Slot {
    id: usize,
    udp: SocketAddr,
    tcp: SocketAddr,
    assignment: Option<(Protocol, SocketAddr)>,
}

pub(crate) struct PacketRouter {
    filters: Vec<String>,
    udp_listeners: Vec<SocketAddr>,
    tcp_listeners: Vec<SocketAddr>,
    slots: Vec<Slot>,
    flows: FlowRegistry,
    registered: HashSet<OriginalFlow>,
    accepting: bool,
    last_ms: u64,
}

impl PacketRouter {
    pub(crate) fn new(ready: &DnsProcessStatus) -> Result<Self, String> {
        let parse = |text: &str| {
            text.parse::<SocketAddr>()
                .map_err(|_| "invalid companion endpoint".to_owned())
        };
        let udp_listeners = ready
            .udp_addrs
            .iter()
            .map(|s| parse(s))
            .collect::<Result<Vec<_>, _>>()?;
        let tcp_listeners = ready
            .tcp_addrs
            .iter()
            .map(|s| parse(s))
            .collect::<Result<Vec<_>, _>>()?;
        let mut ids = HashSet::new();
        let mut slots = Vec::new();
        for slot in &ready.slots {
            let udp = parse(&slot.udp_addr)?;
            let tcp = parse(&slot.tcp_addr)?;
            if !ids.insert(slot.id) || host(udp) != host(tcp) {
                return Err("invalid companion slot identity".into());
            }
            slots.push(Slot {
                id: slot.id,
                udp,
                tcp,
                assignment: None,
            });
        }
        let local_ips = udp_listeners.iter().map(SocketAddr::ip).collect();
        let filters = build_dns_filters(&DnsFilterConfig {
            local_ips,
            udp_proxy_listeners: udp_listeners.clone(),
            tcp_proxy_listeners: tcp_listeners.clone(),
            udp_upstreams: slots.iter().map(|s| s.udp).collect(),
            tcp_upstreams: slots.iter().map(|s| s.tcp).collect(),
        })?;
        Ok(Self {
            filters,
            udp_listeners,
            tcp_listeners,
            slots,
            flows: FlowRegistry::new(FLOW_LIMIT, FLOW_LIFETIME_MS),
            registered: HashSet::new(),
            accepting: true,
            last_ms: 0,
        })
    }

    pub(crate) fn filters(&self) -> &[String] {
        &self.filters
    }

    /// Freeze registration before the owner quiesces the companion. Drain
    /// still restores known proxy replies and passes original requests back.
    pub(crate) fn stop_admission(&mut self) {
        self.accepting = false;
    }

    pub(crate) fn route(
        &mut self,
        packet: &[u8],
        interface: Interface,
        now_ms: u64,
        mut register: impl FnMut(TransparentFlowRegistration) -> Result<(), String>,
    ) -> Result<RoutedPacket, RouteError> {
        if now_ms < self.last_ms {
            return Err(RouteError::ClockReversed);
        }
        self.last_ms = now_ms;
        let info = decode(packet).map_err(|_| RouteError::InvalidPacket)?;
        let source = scoped(info.source, interface)?;
        let listeners = match info.protocol {
            Protocol::Udp => &self.udp_listeners,
            Protocol::Tcp => &self.tcp_listeners,
        };

        // A proxy-sourced packet is never treated as a fresh request, even if
        // its reflected client port happens to be 53.
        if listeners.contains(&source) {
            return match self.flows.reflect_reply(packet, now_ms) {
                Ok(reply) if self.registered.contains(&reply.original_flow) => {
                    Ok(RoutedPacket::Inbound {
                        packet: reply.packet,
                        interface: reply.original_flow.interface,
                    })
                }
                Ok(_) => Ok(RoutedPacket::Discard),
                Err(FlowError::UnknownFlow) => Ok(RoutedPacket::Discard),
                Err(error) => Err(RouteError::Reflection(error)),
            };
        }
        if info.destination.port() != 53 {
            return Ok(RoutedPacket::Unchanged);
        }
        let Some(listener) = listeners
            .iter()
            .find(|addr| host(**addr) == host(source))
            .copied()
        else {
            return Ok(RoutedPacket::Unchanged);
        };
        if self.slots.iter().any(|slot| match info.protocol { Protocol::Udp => slot.udp, Protocol::Tcp => slot.tcp } == source) {
            return Ok(RoutedPacket::Unchanged);
        }
        if !self.accepting {
            return Err(RouteError::Stopped);
        }
        let resolver = scoped(info.destination, interface)?;
        let assignment = (info.protocol, resolver);
        let matches_host = |slot: &Slot| host(slot.udp) == host(listener);
        let selected = self
            .slots
            .iter()
            .position(|slot| matches_host(slot) && slot.assignment == Some(assignment))
            .or_else(|| {
                self.slots
                    .iter()
                    .position(|slot| matches_host(slot) && slot.assignment.is_none())
            })
            .ok_or(RouteError::RolloverRequired)?;
        let reflected = self
            .flows
            .reflect_request(packet, interface, listener.port(), now_ms)
            .map_err(|error| match error {
                FlowError::KeyQuarantined | FlowError::AtCapacity => RouteError::RolloverRequired,
                other => RouteError::Reflection(other),
            })?;
        if !self.registered.contains(&reflected.original_flow) {
            let peer = SocketAddr::new(resolver.ip(), source.port());
            let registration = TransparentFlowRegistration {
                protocol: match info.protocol {
                    Protocol::Udp => "udp",
                    Protocol::Tcp => "tcp",
                }
                .into(),
                peer: scoped(peer, interface)?.to_string(),
                local: listener.to_string(),
                resolver: resolver.to_string(),
                slot: self.slots[selected].id,
                lifetime_ms: FLOW_LIFETIME_MS,
            };
            if let Err(error) = register(registration) {
                // The acknowledgement may have been lost. Keep the generation
                // frozen until its owner has closed interception and stopped it.
                self.accepting = false;
                return Err(RouteError::Companion(error));
            }
            self.slots[selected].assignment = Some(assignment);
            self.registered.insert(reflected.original_flow);
        }
        Ok(RoutedPacket::Inbound {
            packet: reflected.packet,
            interface,
        })
    }

    /// During driver drain, original requests may resume their normal path;
    /// proxy replies still require an existing exact reverse mapping.
    pub(crate) fn drain(
        &mut self,
        packet: &[u8],
        interface: Interface,
        now_ms: u64,
    ) -> Result<RoutedPacket, RouteError> {
        self.stop_admission();
        match self.route(packet, interface, now_ms, |_| {
            unreachable!("drain cannot register")
        }) {
            Err(RouteError::Stopped) => Ok(RoutedPacket::Unchanged),
            other => other,
        }
    }
}

fn host(mut endpoint: SocketAddr) -> SocketAddr {
    endpoint.set_port(0);
    endpoint
}

fn scoped(endpoint: SocketAddr, interface: Interface) -> Result<SocketAddr, RouteError> {
    match endpoint.ip() {
        IpAddr::V6(ip) if ip.is_unicast_link_local() => {
            if interface.index == 0 {
                return Err(RouteError::InvalidInterface);
            }
            Ok(SocketAddr::V6(SocketAddrV6::new(
                ip,
                endpoint.port(),
                0,
                interface.index,
            )))
        }
        _ => Ok(endpoint),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{dns_packet::rewrite, dns_process::UpstreamSlot};
    use super::*;
    const IFACE: Interface = Interface::new(7, 0);

    fn ready(ip: &str) -> DnsProcessStatus {
        let endpoint = |port| {
            format!("{ip}:{port}")
                .parse::<SocketAddr>()
                .unwrap()
                .to_string()
        };
        DnsProcessStatus {
            udp_addr: endpoint(40000),
            tcp_addr: endpoint(40001),
            udp_addrs: vec![endpoint(40000)],
            tcp_addrs: vec![endpoint(40001)],
            rules_count: 1,
            slots: (0..8)
                .map(|id| UpstreamSlot {
                    id,
                    udp_addr: endpoint(41000 + id),
                    tcp_addr: endpoint(42000 + id),
                })
                .collect(),
        }
    }

    fn packet(client: &str, resolver: &str, protocol: Protocol) -> Vec<u8> {
        let client: SocketAddr = client.parse().unwrap();
        let resolver: SocketAddr = resolver.parse().unwrap();
        let header = if client.is_ipv4() { 20 } else { 40 };
        let transport = if protocol == Protocol::Udp { 8 } else { 20 };
        let length = header + transport;
        let mut packet = vec![0; length];
        let proto = if protocol == Protocol::Udp { 17 } else { 6 };
        if client.is_ipv4() {
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&(length as u16).to_be_bytes());
            packet[8] = 64;
            packet[9] = proto;
        } else {
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&(transport as u16).to_be_bytes());
            packet[6] = proto;
            packet[7] = 64;
        }
        if protocol == Protocol::Udp {
            packet[header + 4..header + 6].copy_from_slice(&8u16.to_be_bytes());
        } else {
            packet[header + 12] = 0x50;
            packet[header + 13] = 2;
        }
        rewrite(&packet, client, resolver).unwrap()
    }

    fn injected(action: RoutedPacket) -> Vec<u8> {
        match action {
            RoutedPacket::Inbound { packet, .. } => packet,
            other => panic!("expected injection: {other:?}"),
        }
    }

    #[test]
    fn authorizes_once_before_reflection_and_restores_all_transports() {
        for (local, client, resolver) in [
            ("[::1]", "[::1]:53000", "[::1]:53"),
            ("192.0.2.10", "192.0.2.10:53000", "198.51.100.53:53"),
            (
                "[2001:db8::10]",
                "[2001:db8::10]:53000",
                "[2001:db8::53]:53",
            ),
        ] {
            for proto in [Protocol::Udp, Protocol::Tcp] {
                let mut router = PacketRouter::new(&ready(local)).unwrap();
                assert_eq!(router.filters().len(), 1);
                let request = packet(client, resolver, proto);
                let mut registrations = Vec::new();
                let reflected = injected(
                    router
                        .route(&request, IFACE, 0, |flow| {
                            registrations.push(flow);
                            Ok(())
                        })
                        .unwrap(),
                );
                assert_eq!(registrations.len(), 1);
                let info = decode(&reflected).unwrap();
                let flow = &registrations[0];
                assert_eq!(flow.local, info.destination.to_string());
                assert_eq!(flow.peer, info.source.to_string());
                assert_eq!(flow.resolver, resolver);
                assert_eq!(flow.lifetime_ms, 120_000);
                router
                    .route(&request, IFACE, 1, |_| panic!("retry must not reauthorize"))
                    .unwrap();
                let reply = rewrite(&reflected, info.destination, info.source).unwrap();
                let action = router
                    .route(&reply, IFACE, 2, |_| panic!("reply cannot register"))
                    .unwrap();
                assert!(
                    matches!(&action, RoutedPacket::Inbound { interface, .. } if *interface == IFACE)
                );
                let restored = decode(&injected(action)).unwrap();
                assert_eq!(restored.source, resolver.parse().unwrap());
                assert_eq!(restored.destination, client.parse().unwrap());
            }
        }
    }

    #[test]
    fn failed_authorization_freezes_requests_and_cannot_admit_reply() {
        let mut router = PacketRouter::new(&ready("192.0.2.10")).unwrap();
        let request = packet("192.0.2.10:53000", "198.51.100.53:53", Protocol::Udp);
        assert_eq!(
            router.route(&request, IFACE, 0, |_| Err("lost ack".into())),
            Err(RouteError::Companion("lost ack".into()))
        );
        assert_eq!(
            router.route(&request, IFACE, 1, |_| panic!()),
            Err(RouteError::Stopped)
        );
        let reply = packet("192.0.2.10:40000", "198.51.100.53:53000", Protocol::Udp);
        assert_eq!(
            router.route(&reply, IFACE, 2, |_| panic!()).unwrap(),
            RoutedPacket::Discard
        );
    }

    #[test]
    fn reservations_and_unknown_traffic_never_create_reflections() {
        let mut router = PacketRouter::new(&ready("192.0.2.10")).unwrap();
        for (source, dest, proto) in [
            ("192.0.2.10:41000", "198.51.100.53:53", Protocol::Udp),
            ("192.0.2.10:42000", "198.51.100.53:53", Protocol::Tcp),
            ("192.0.2.11:53000", "198.51.100.53:53", Protocol::Udp),
            ("192.0.2.10:53000", "198.51.100.53:443", Protocol::Tcp),
        ] {
            assert_eq!(
                router
                    .route(&packet(source, dest, proto), IFACE, 0, |_| panic!())
                    .unwrap(),
                RoutedPacket::Unchanged
            );
        }
        for proto in [Protocol::Udp, Protocol::Tcp] {
            let port = if proto == Protocol::Udp { 40000 } else { 40001 };
            let reply = packet(&format!("192.0.2.10:{port}"), "198.51.100.53:53", proto);
            assert_eq!(
                router.route(&reply, IFACE, 0, |_| panic!()).unwrap(),
                RoutedPacket::Discard
            );
        }
    }

    #[test]
    fn slots_are_fixed_by_resolver_and_transport_with_bounded_rollover() {
        let mut router = PacketRouter::new(&ready("192.0.2.10")).unwrap();
        for id in 0..8 {
            let request = packet(
                &format!("192.0.2.10:{}", 53000 + id),
                &format!("198.51.100.{}:53", id + 1),
                Protocol::Udp,
            );
            router
                .route(&request, IFACE, 0, |flow| {
                    assert_eq!(flow.slot, id);
                    Ok(())
                })
                .unwrap();
        }
        let same_resolver = packet("192.0.2.10:54000", "198.51.100.1:53", Protocol::Udp);
        router
            .route(&same_resolver, IFACE, 1, |flow| {
                assert_eq!(flow.slot, 0);
                Ok(())
            })
            .unwrap();
        let tcp = packet("192.0.2.10:54001", "198.51.100.1:53", Protocol::Tcp);
        assert_eq!(
            router.route(&tcp, IFACE, 2, |_| panic!()),
            Err(RouteError::RolloverRequired)
        );
        assert_eq!(
            router.route(&same_resolver, IFACE, 120_001, |_| panic!()),
            Err(RouteError::RolloverRequired)
        );
    }

    #[test]
    fn scopes_follow_capture_interface_without_appearing_on_wire() {
        let mut router = PacketRouter::new(&ready("[fe80::10%7]")).unwrap();
        let request = packet("[fe80::10]:53000", "[fe80::53]:53", Protocol::Udp);
        assert_eq!(
            router
                .route(&request, Interface::new(8, 0), 0, |_| panic!())
                .unwrap(),
            RoutedPacket::Unchanged
        );
        router
            .route(&request, IFACE, 1, |flow| {
                assert_eq!(flow.peer, "[fe80::53%7]:53000");
                assert_eq!(flow.local, "[fe80::10%7]:40000");
                assert_eq!(flow.resolver, "[fe80::53%7]:53");
                Ok(())
            })
            .unwrap();
        assert_eq!(
            router.route(&request, Interface::new(0, 0), 2, |_| panic!()),
            Err(RouteError::InvalidInterface)
        );
    }

    #[test]
    fn draining_restores_known_replies_and_never_registers() {
        let mut router = PacketRouter::new(&ready("192.0.2.10")).unwrap();
        let request = packet("192.0.2.10:53000", "198.51.100.53:53", Protocol::Udp);
        let reflected = injected(router.route(&request, IFACE, 0, |_| Ok(())).unwrap());
        let info = decode(&reflected).unwrap();
        let reply = rewrite(&reflected, info.destination, info.source).unwrap();
        assert_eq!(
            router.drain(&request, IFACE, 1).unwrap(),
            RoutedPacket::Unchanged
        );
        assert!(matches!(
            router.drain(&reply, IFACE, 2).unwrap(),
            RoutedPacket::Inbound { .. }
        ));
        assert_eq!(
            router.route(&request, IFACE, 1, |_| panic!()),
            Err(RouteError::ClockReversed)
        );
    }

    #[test]
    fn reservations_are_protocol_specific_and_bad_readiness_is_rejected() {
        let mut router = PacketRouter::new(&ready("192.0.2.10")).unwrap();
        let request = packet("192.0.2.10:41000", "198.51.100.53:53", Protocol::Tcp);
        let mut called = false;
        assert!(matches!(
            router
                .route(&request, IFACE, 0, |_| {
                    called = true;
                    Ok(())
                })
                .unwrap(),
            RoutedPacket::Inbound { .. }
        ));
        assert!(called, "a UDP reservation must not exempt TCP");
        let mut bad = ready("192.0.2.10");
        bad.slots[1].id = bad.slots[0].id;
        assert!(PacketRouter::new(&bad).is_err());
        let mut bad = ready("192.0.2.10");
        bad.slots.pop();
        assert!(PacketRouter::new(&bad).is_err());
        assert!(PacketRouter::new(&ready("[::ffff:192.0.2.10]")).is_err());
        assert_eq!(
            router.route(&[0x45], IFACE, 1, |_| panic!()),
            Err(RouteError::InvalidPacket)
        );
    }
}
