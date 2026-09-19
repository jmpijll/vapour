//! Bounded, pure packet reflection for transparent DNS interception.
//!
//! This module owns only the packet tuple and flow lifetime.  It deliberately
//! has no socket, WinDivert, UI, or clock dependencies: callers supply the
//! capture interface metadata and a monotonic millisecond timestamp.

use super::dns_packet::{decode, rewrite, PacketError, PacketInfo, Protocol};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

/// A WinDivert interface identity kept alongside a packet, never put on wire.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct Interface {
    pub(crate) index: u32,
    pub(crate) sub_index: u32,
}

impl Interface {
    pub(crate) const fn new(index: u32, sub_index: u32) -> Self {
        Self { index, sub_index }
    }
}

/// The complete original client-to-resolver flow captured before reflection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct OriginalFlow {
    pub(crate) client: SocketAddr,
    pub(crate) resolver: SocketAddr,
    pub(crate) protocol: Protocol,
    pub(crate) interface: Interface,
}

/// A rewritten packet and the flow it must be routed through by the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReflectedPacket {
    pub(crate) packet: Vec<u8>,
    pub(crate) original_flow: OriginalFlow,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ReflectedTuple {
    source: SocketAddr,
    destination: SocketAddr,
    protocol: Protocol,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FlowError {
    Packet(PacketError),
    InvalidClientPort,
    InvalidResolverPort,
    InvalidProxyPort,
    ProxyPortMismatch,
    ReflectedCollision,
    KeyQuarantined,
    AtCapacity,
    UnknownFlow,
    NotTcp,
}

struct ActiveFlow {
    reflected: ReflectedTuple,
    expires_at_ms: u64,
}

/// A bounded registry of active reflections and permanently quarantined keys.
///
/// `capacity` limits lifetime allocations, not merely active rows.  Expired
/// rows are removed from the active maps but their original and reflected keys
/// stay quarantined until this registry is dropped.  This prevents a delayed
/// packet from a previous generation being accepted by a newly allocated flow.
pub(crate) struct FlowRegistry {
    capacity: usize,
    ttl_ms: u64,
    tcp_close_grace_ms: u64,
    allocated: usize,
    active: HashMap<OriginalFlow, ActiveFlow>,
    by_reflected: HashMap<ReflectedTuple, OriginalFlow>,
    quarantined_original: HashSet<OriginalFlow>,
    quarantined_reflected: HashSet<ReflectedTuple>,
}

impl FlowRegistry {
    /// Construct a registry whose timestamps are monotonic milliseconds.
    pub(crate) fn new(capacity: usize, ttl_ms: u64) -> Self {
        Self::with_tcp_close_grace(capacity, ttl_ms, 5_000)
    }

    /// Construct a registry with an explicit conservative TCP close grace.
    pub(crate) fn with_tcp_close_grace(
        capacity: usize,
        ttl_ms: u64,
        tcp_close_grace_ms: u64,
    ) -> Self {
        Self {
            capacity,
            ttl_ms,
            tcp_close_grace_ms,
            allocated: 0,
            active: HashMap::new(),
            by_reflected: HashMap::new(),
            quarantined_original: HashSet::new(),
            quarantined_reflected: HashSet::new(),
        }
    }

    /// Reflect `C:c -> R:53` into `R:c -> C:proxy_port`.
    ///
    /// An active exact original key is reused for retries.  A changed proxy
    /// port for that key is rejected so the caller cannot silently route a
    /// retry through a different reflected tuple.
    pub(crate) fn reflect_request(
        &mut self,
        packet: &[u8],
        interface: Interface,
        proxy_port: u16,
        now_ms: u64,
    ) -> Result<ReflectedPacket, FlowError> {
        let info = decode(packet).map_err(FlowError::Packet)?;
        validate_request_ports(&info, proxy_port)?;
        self.expire(now_ms);

        let original_flow = OriginalFlow {
            client: info.source,
            resolver: info.destination,
            protocol: info.protocol,
            interface,
        };

        if let Some(active) = self.active.get(&original_flow) {
            if active.reflected.destination.port() != proxy_port {
                return Err(FlowError::ProxyPortMismatch);
            }
            let reflected_packet = rewrite(
                packet,
                active.reflected.source,
                active.reflected.destination,
            )
            .map_err(FlowError::Packet)?;
            let closing = has_tcp_close_flag(packet, info)?;
            if closing {
                self.shorten_for_tcp_close(original_flow, now_ms);
            }
            return Ok(ReflectedPacket {
                packet: reflected_packet,
                original_flow,
            });
        }

        if self.quarantined_original.contains(&original_flow) {
            return Err(FlowError::KeyQuarantined);
        }

        let reflected = reflected_tuple_for_request(&info, proxy_port);
        if self.quarantined_reflected.contains(&reflected) {
            return Err(FlowError::KeyQuarantined);
        }
        // The wire tuple has no interface field after routing.  A collision
        // therefore remains unsafe even if the captures came from interfaces
        // with different metadata.
        if self.by_reflected.contains_key(&reflected) {
            return Err(FlowError::ReflectedCollision);
        }
        if self.allocated >= self.capacity {
            return Err(FlowError::AtCapacity);
        }

        let reflected_packet =
            rewrite(packet, reflected.source, reflected.destination).map_err(FlowError::Packet)?;
        self.active.insert(
            original_flow,
            ActiveFlow {
                reflected,
                expires_at_ms: deadline(now_ms, self.ttl_ms),
            },
        );
        self.by_reflected.insert(reflected, original_flow);
        self.allocated += 1;

        if has_tcp_close_flag(packet, info)? {
            self.shorten_for_tcp_close(original_flow, now_ms);
        }

        Ok(ReflectedPacket {
            packet: reflected_packet,
            original_flow,
        })
    }

    /// Reflect an exact registered reverse `C:proxy_port -> R:c` reply into
    /// `R:53 -> C:c`. The reply's capture interface is not part of lookup:
    /// routing can deliver it on a different interface, and the returned
    /// original flow carries the interface to use for reinjection.
    pub(crate) fn reflect_reply(
        &mut self,
        packet: &[u8],
        now_ms: u64,
    ) -> Result<ReflectedPacket, FlowError> {
        let info = decode(packet).map_err(FlowError::Packet)?;
        self.expire(now_ms);

        let reflected = reflected_tuple_for_reply(&info);
        let original_flow = *self
            .by_reflected
            .get(&reflected)
            .ok_or(FlowError::UnknownFlow)?;

        let restored_packet = rewrite(packet, original_flow.resolver, original_flow.client)
            .map_err(FlowError::Packet)?;
        if has_tcp_close_flag(packet, info)? {
            self.shorten_for_tcp_close(original_flow, now_ms);
        }

        Ok(ReflectedPacket {
            packet: restored_packet,
            original_flow,
        })
    }

    /// Observe a TCP FIN/RST and shorten that flow's deadline conservatively.
    ///
    /// The row remains active through the close grace, so FIN tails and their
    /// corresponding replies continue to pass while the row is alive.
    pub(crate) fn observe_tcp_close(
        &mut self,
        packet: &[u8],
        interface: Interface,
        now_ms: u64,
    ) -> Result<(), FlowError> {
        let info = decode(packet).map_err(FlowError::Packet)?;
        if info.protocol != Protocol::Tcp {
            return Err(FlowError::NotTcp);
        }
        self.expire(now_ms);
        if !has_tcp_close_flag(packet, info)? {
            return Ok(());
        }

        if info.destination.port() == 53 {
            let original_flow = OriginalFlow {
                client: info.source,
                resolver: info.destination,
                protocol: info.protocol,
                interface,
            };
            if self.active.contains_key(&original_flow) {
                self.shorten_for_tcp_close(original_flow, now_ms);
                return Ok(());
            }
        }

        let reflected = reflected_tuple_for_reply(&info);
        let original_flow = *self
            .by_reflected
            .get(&reflected)
            .ok_or(FlowError::UnknownFlow)?;
        self.shorten_for_tcp_close(original_flow, now_ms);
        Ok(())
    }

    /// Move all rows whose deadline has elapsed into permanent quarantine.
    pub(crate) fn expire(&mut self, now_ms: u64) {
        let expired: Vec<(OriginalFlow, ReflectedTuple)> = self
            .active
            .iter()
            .filter_map(|(original_flow, active)| {
                (active.expires_at_ms <= now_ms).then_some((*original_flow, active.reflected))
            })
            .collect();

        for (original_flow, reflected) in expired {
            if self.active.remove(&original_flow).is_some() {
                self.by_reflected.remove(&reflected);
                self.quarantined_original.insert(original_flow);
                self.quarantined_reflected.insert(reflected);
            }
        }
    }

    pub(crate) fn active_len(&self) -> usize {
        self.active.len()
    }

    pub(crate) fn quarantined_len(&self) -> usize {
        self.quarantined_original.len()
    }

    pub(crate) fn allocated_len(&self) -> usize {
        self.allocated
    }

    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    fn shorten_for_tcp_close(&mut self, original_flow: OriginalFlow, now_ms: u64) {
        if let Some(active) = self.active.get_mut(&original_flow) {
            active.expires_at_ms = active
                .expires_at_ms
                .min(deadline(now_ms, self.tcp_close_grace_ms));
        }
    }
}

fn validate_request_ports(info: &PacketInfo, proxy_port: u16) -> Result<(), FlowError> {
    if info.source.port() == 0 {
        return Err(FlowError::InvalidClientPort);
    }
    if info.destination.port() != 53 {
        return Err(FlowError::InvalidResolverPort);
    }
    if proxy_port == 0 || proxy_port == 53 || proxy_port == info.source.port() {
        return Err(FlowError::InvalidProxyPort);
    }
    Ok(())
}

fn reflected_tuple_for_request(info: &PacketInfo, proxy_port: u16) -> ReflectedTuple {
    ReflectedTuple {
        source: SocketAddr::new(info.destination.ip(), info.source.port()),
        destination: SocketAddr::new(info.source.ip(), proxy_port),
        protocol: info.protocol,
    }
}

fn reflected_tuple_for_reply(info: &PacketInfo) -> ReflectedTuple {
    ReflectedTuple {
        source: info.destination,
        destination: info.source,
        protocol: info.protocol,
    }
}

fn deadline(now_ms: u64, duration_ms: u64) -> u64 {
    now_ms.saturating_add(duration_ms)
}

fn has_tcp_close_flag(packet: &[u8], info: PacketInfo) -> Result<bool, FlowError> {
    if info.protocol != Protocol::Tcp {
        return Ok(false);
    }
    let transport_offset = match packet.first().map(|byte| byte >> 4) {
        Some(4) => usize::from(packet[0] & 0x0f) * 4,
        Some(6) => 40,
        _ => return Err(FlowError::Packet(PacketError::UnsupportedVersion)),
    };
    let flags = *packet
        .get(transport_offset + 13)
        .ok_or(FlowError::Packet(PacketError::Truncated))?;
    Ok(flags & 0x05 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const IFACE_A: Interface = Interface {
        index: 7,
        sub_index: 0,
    };
    const IFACE_B: Interface = Interface {
        index: 8,
        sub_index: 0,
    };
    const V4_CLIENT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 53000);
    const V4_RESOLVER: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53)), 53);
    const V6_CLIENT: SocketAddr = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 10)),
        53000,
    );
    const V6_RESOLVER: SocketAddr = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 53)),
        53,
    );

    #[test]
    fn reflects_all_family_protocol_combinations_and_exact_inverse_replies() {
        for (client, resolver, protocol) in [
            (V4_CLIENT, V4_RESOLVER, Protocol::Udp),
            (V4_CLIENT, V4_RESOLVER, Protocol::Tcp),
            (V6_CLIENT, V6_RESOLVER, Protocol::Udp),
            (V6_CLIENT, V6_RESOLVER, Protocol::Tcp),
        ] {
            let packet = packet(client, resolver, protocol);
            let mut registry = FlowRegistry::new(8, 1000);
            let reflected = registry
                .reflect_request(&packet, IFACE_A, 40000, 10)
                .expect("request should reflect");
            let reflected_info = decode(&reflected.packet).unwrap();
            assert_eq!(
                reflected_info.source,
                SocketAddr::new(resolver.ip(), client.port())
            );
            assert_eq!(
                reflected_info.destination,
                SocketAddr::new(client.ip(), 40000)
            );
            assert_eq!(reflected_info.protocol, protocol);

            let restored = registry
                .reflect_reply(&inverse(&reflected.packet), 20)
                .expect("only the registered inverse should be admitted");
            let restored_info = decode(&restored.packet).unwrap();
            assert_eq!(restored_info.source, resolver);
            assert_eq!(restored_info.destination, client);
            assert_eq!(restored_info.protocol, protocol);
            assert_eq!(restored.original_flow.interface, IFACE_A);
        }
    }

    #[test]
    fn retries_reuse_rows_wrong_replies_do_not_remove_them_and_collisions_are_global() {
        let first_packet = packet(V4_CLIENT, V4_RESOLVER, Protocol::Udp);
        let mut registry = FlowRegistry::new(4, 1000);
        let first = registry
            .reflect_request(&first_packet, IFACE_A, 40000, 0)
            .expect("first request should register");
        assert_eq!(
            registry
                .reflect_request(&first_packet, IFACE_A, 40000, 1)
                .unwrap(),
            first
        );

        let mut wrong = inverse(&first.packet);
        wrong[20..22].copy_from_slice(&40001u16.to_be_bytes());
        assert_eq!(
            registry.reflect_reply(&wrong, 2),
            Err(FlowError::UnknownFlow)
        );
        registry
            .reflect_reply(&inverse(&first.packet), 3)
            .expect("wrong reply must not remove the row");

        assert_eq!(
            registry
                .reflect_request(&first_packet, IFACE_B, 40000, 4)
                .unwrap_err(),
            FlowError::ReflectedCollision
        );
    }

    #[test]
    fn expiry_quarantines_keys_and_consumes_lifetime_capacity() {
        let first_packet = packet(V4_CLIENT, V4_RESOLVER, Protocol::Udp);
        let mut registry = FlowRegistry::new(1, 100);
        let first = registry
            .reflect_request(&first_packet, IFACE_A, 40000, 0)
            .expect("first mapping should fit");
        registry.expire(100);
        assert_eq!(registry.active_len(), 0);
        assert_eq!(registry.quarantined_len(), 1);
        assert_eq!(
            registry.reflect_reply(&inverse(&first.packet), 101),
            Err(FlowError::UnknownFlow)
        );
        assert_eq!(
            registry.reflect_request(&first_packet, IFACE_A, 40000, 102),
            Err(FlowError::KeyQuarantined)
        );
        let other = packet(
            V4_CLIENT,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 53)), 53),
            Protocol::Udp,
        );
        assert_eq!(
            registry.reflect_request(&other, IFACE_A, 40001, 103),
            Err(FlowError::AtCapacity)
        );
    }

    #[test]
    fn tcp_close_keeps_fin_tails_alive_only_through_close_grace() {
        let packet = packet(V4_CLIENT, V4_RESOLVER, Protocol::Tcp);
        let mut registry = FlowRegistry::with_tcp_close_grace(2, 1000, 50);
        let reflected = registry
            .reflect_request(&packet, IFACE_A, 40000, 100)
            .expect("TCP request should register");
        let mut fin = packet.clone();
        fin[33] |= 0x01;
        registry
            .observe_tcp_close(&fin, IFACE_A, 200)
            .expect("FIN should shorten the deadline");
        registry
            .reflect_reply(&inverse(&reflected.packet), 249)
            .expect("FIN tail should remain alive through close grace");
        registry.expire(250);
        assert_eq!(
            registry.reflect_reply(&inverse(&reflected.packet), 251),
            Err(FlowError::UnknownFlow)
        );
    }

    #[test]
    fn malformed_requests_and_replies_are_rejected_by_the_codec() {
        let mut registry = FlowRegistry::new(2, 1000);
        assert!(matches!(
            registry.reflect_request(&[0], IFACE_A, 40000, 0),
            Err(FlowError::Packet(_))
        ));
        assert!(matches!(
            registry.reflect_reply(&[0], 0),
            Err(FlowError::Packet(_))
        ));

        let mut truncated = packet(V4_CLIENT, V4_RESOLVER, Protocol::Udp);
        truncated.truncate(20);
        assert!(matches!(
            registry.reflect_request(&truncated, IFACE_A, 40000, 0),
            Err(FlowError::Packet(_))
        ));
    }

    #[test]
    fn reply_protocol_must_match_the_registered_request() {
        let mut registry = FlowRegistry::new(2, 1000);
        let request = packet(V4_CLIENT, V4_RESOLVER, Protocol::Udp);
        let reflected = registry
            .reflect_request(&request, IFACE_A, 40000, 0)
            .expect("UDP request should register");
        let mismatched = packet(
            SocketAddr::new(V4_CLIENT.ip(), 40000),
            SocketAddr::new(V4_RESOLVER.ip(), V4_CLIENT.port()),
            Protocol::Tcp,
        );
        assert_eq!(
            registry.reflect_reply(&mismatched, 1),
            Err(FlowError::UnknownFlow)
        );
        registry
            .reflect_reply(&inverse(&reflected.packet), 2)
            .expect("matching UDP reply should remain admitted");
    }

    #[test]
    fn same_client_port_can_target_multiple_resolvers() {
        let resolver_two = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 53)), 53);
        let mut registry = FlowRegistry::new(3, 1000);
        let first = registry
            .reflect_request(
                &packet(V4_CLIENT, V4_RESOLVER, Protocol::Udp),
                IFACE_A,
                40000,
                0,
            )
            .expect("first resolver should register");
        let second = registry
            .reflect_request(
                &packet(V4_CLIENT, resolver_two, Protocol::Udp),
                IFACE_A,
                40000,
                1,
            )
            .expect("second resolver should register");
        assert_eq!(registry.active_len(), 2);
        assert_ne!(
            decode(&first.packet).unwrap().source,
            decode(&second.packet).unwrap().source
        );
    }

    #[test]
    fn retry_does_not_extend_the_original_fixed_expiry() {
        let request = packet(V4_CLIENT, V4_RESOLVER, Protocol::Udp);
        let mut registry = FlowRegistry::new(2, 100);
        let first = registry
            .reflect_request(&request, IFACE_A, 40000, 0)
            .expect("request should register");
        assert_eq!(
            registry.reflect_request(&request, IFACE_A, 40000, 50),
            Ok(first.clone())
        );
        assert_eq!(registry.active_len(), 1);
        registry.expire(99);
        assert_eq!(registry.active_len(), 1);
        registry.expire(100);
        assert_eq!(registry.active_len(), 0);
        assert_eq!(
            registry.reflect_reply(&inverse(&first.packet), 101),
            Err(FlowError::UnknownFlow)
        );
        assert_eq!(
            registry.reflect_request(&request, IFACE_A, 40000, 102),
            Err(FlowError::KeyQuarantined)
        );
    }

    #[test]
    fn zero_reserved_and_client_colliding_proxy_ports_are_rejected() {
        let request = packet(V4_CLIENT, V4_RESOLVER, Protocol::Udp);
        let mut registry = FlowRegistry::new(8, 1000);
        for proxy_port in [0, 53, V4_CLIENT.port()] {
            assert_eq!(
                registry.reflect_request(&request, IFACE_A, proxy_port, 0),
                Err(FlowError::InvalidProxyPort)
            );
        }
        let zero_client = packet(
            SocketAddr::new(V4_CLIENT.ip(), 0),
            V4_RESOLVER,
            Protocol::Udp,
        );
        assert_eq!(
            registry.reflect_request(&zero_client, IFACE_A, 40000, 0),
            Err(FlowError::InvalidClientPort)
        );
        let wrong_resolver_port = packet(
            V4_CLIENT,
            SocketAddr::new(V4_RESOLVER.ip(), 54),
            Protocol::Udp,
        );
        assert_eq!(
            registry.reflect_request(&wrong_resolver_port, IFACE_A, 40000, 0),
            Err(FlowError::InvalidResolverPort)
        );

        registry
            .reflect_request(&request, IFACE_A, 40000, 0)
            .expect("valid proxy port should register");
        assert_eq!(
            registry.reflect_request(&request, IFACE_B, 40000, 1),
            Err(FlowError::ReflectedCollision)
        );
    }

    #[test]
    fn zero_capacity_and_saturated_monotonic_timestamps_stay_bounded() {
        let request = packet(V4_CLIENT, V4_RESOLVER, Protocol::Udp);
        let mut zero = FlowRegistry::new(0, 1000);
        assert_eq!(
            zero.reflect_request(&request, IFACE_A, 40000, 0),
            Err(FlowError::AtCapacity)
        );

        let mut saturated = FlowRegistry::new(1, 20);
        let first = saturated
            .reflect_request(&request, IFACE_A, 40000, u64::MAX - 10)
            .expect("saturating deadline should not reject the request");
        saturated
            .reflect_reply(&inverse(&first.packet), u64::MAX - 1)
            .expect("the saturated deadline remains active before MAX");
        saturated.expire(u64::MAX);
        assert_eq!(saturated.active_len(), 0);
        assert_eq!(saturated.quarantined_len(), 1);
        assert_eq!(
            saturated.reflect_request(&request, IFACE_A, 40001, u64::MAX),
            Err(FlowError::KeyQuarantined)
        );
    }

    #[test]
    fn fin_on_request_and_rst_on_reply_shorten_deadlines_automatically() {
        let request = packet(V4_CLIENT, V4_RESOLVER, Protocol::Tcp);
        let mut fin_registry = FlowRegistry::with_tcp_close_grace(2, 1000, 50);
        let mut fin_request = request.clone();
        set_tcp_flags(&mut fin_request, 0x01);
        let fin_reflected = fin_registry
            .reflect_request(&fin_request, IFACE_A, 40000, 100)
            .expect("FIN request should register");
        fin_registry
            .reflect_reply(&inverse(&fin_reflected.packet), 149)
            .expect("FIN tail should remain active through grace");
        fin_registry.expire(150);
        assert_eq!(
            fin_registry.reflect_reply(&inverse(&fin_reflected.packet), 151),
            Err(FlowError::UnknownFlow)
        );

        let mut rst_registry = FlowRegistry::with_tcp_close_grace(2, 1000, 50);
        let rst_reflected = rst_registry
            .reflect_request(&request, IFACE_A, 40000, 100)
            .expect("RST flow request should register");
        let mut rst_reply = inverse(&rst_reflected.packet);
        set_tcp_flags(&mut rst_reply, 0x04);
        rst_registry
            .reflect_reply(&rst_reply, 200)
            .expect("RST reply should be admitted and shorten the deadline");
        rst_registry
            .reflect_reply(&inverse(&rst_reflected.packet), 249)
            .expect("reply tail should remain active through RST grace");
        rst_registry.expire(250);
        assert_eq!(
            rst_registry.reflect_reply(&inverse(&rst_reflected.packet), 251),
            Err(FlowError::UnknownFlow)
        );
    }

    fn inverse(reflected: &[u8]) -> Vec<u8> {
        let info = decode(reflected).unwrap();
        rewrite(
            reflected,
            SocketAddr::new(info.destination.ip(), info.destination.port()),
            SocketAddr::new(info.source.ip(), info.source.port()),
        )
        .unwrap()
    }

    fn set_tcp_flags(packet: &mut [u8], flags: u8) {
        let transport_offset = if packet[0] >> 4 == 4 { 20 } else { 40 };
        packet[transport_offset + 13] = flags;
    }

    fn packet(source: SocketAddr, destination: SocketAddr, protocol: Protocol) -> Vec<u8> {
        let payload = b"dns";
        let (header_len, transport_len) = match protocol {
            Protocol::Udp => (if source.is_ipv4() { 20 } else { 40 }, 8 + payload.len()),
            Protocol::Tcp => (if source.is_ipv4() { 20 } else { 40 }, 20 + payload.len()),
        };
        let mut packet = vec![0; header_len + transport_len];
        if source.is_ipv4() {
            packet[0] = 0x45;
            let total_len = packet.len() as u16;
            packet[2..4].copy_from_slice(&total_len.to_be_bytes());
            packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
            packet[8] = 64;
            packet[9] = protocol_number(protocol);
            packet[12..16].copy_from_slice(&ipv4_bytes(source));
            packet[16..20].copy_from_slice(&ipv4_bytes(destination));
        } else {
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&(transport_len as u16).to_be_bytes());
            packet[6] = protocol_number(protocol);
            packet[8..24].copy_from_slice(&ipv6_bytes(source));
            packet[24..40].copy_from_slice(&ipv6_bytes(destination));
        }
        let transport = header_len;
        packet[transport..transport + 2].copy_from_slice(&source.port().to_be_bytes());
        packet[transport + 2..transport + 4].copy_from_slice(&destination.port().to_be_bytes());
        match protocol {
            Protocol::Udp => packet[transport + 4..transport + 6]
                .copy_from_slice(&(transport_len as u16).to_be_bytes()),
            Protocol::Tcp => packet[transport + 12] = 0x50,
        }
        packet[transport + transport_len - payload.len()..].copy_from_slice(payload);
        packet
    }

    fn protocol_number(protocol: Protocol) -> u8 {
        match protocol {
            Protocol::Udp => 17,
            Protocol::Tcp => 6,
        }
    }

    fn ipv4_bytes(address: SocketAddr) -> [u8; 4] {
        match address.ip() {
            IpAddr::V4(address) => address.octets(),
            IpAddr::V6(_) => panic!("expected IPv4 address"),
        }
    }

    fn ipv6_bytes(address: SocketAddr) -> [u8; 16] {
        match address.ip() {
            IpAddr::V6(address) => address.octets(),
            IpAddr::V4(_) => panic!("expected IPv6 address"),
        }
    }
}
