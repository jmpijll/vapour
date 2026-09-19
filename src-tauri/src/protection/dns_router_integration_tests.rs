#![cfg(windows)]

//! Unelevated end-to-end checks for the Rust router and the real transparent
//! companion. These tests model the packet reflection that WinDivert performs
//! without opening a driver handle or changing host networking configuration.

use super::{
    dns_flow::Interface,
    dns_packet::{decode, rewrite},
    dns_process::{DnsProcessManager, DnsProcessStatus, TransparentDnsConfig},
    dns_router::{PacketRouter, RoutedPacket},
};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    path::PathBuf,
    process,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

const IFACE: Interface = Interface::new(7, 0);
static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

#[test]
#[ignore = "requires the real unelevated transparent companion; no driver or system changes"]
fn real_companion_router_udp_ipv4_round_trip() {
    run_udp_round_trip(IpAddr::V4(Ipv4Addr::LOCALHOST));
}

#[test]
#[ignore = "requires the real unelevated transparent companion; no driver or system changes"]
fn real_companion_router_udp_ipv6_round_trip() {
    run_udp_round_trip(IpAddr::V6(Ipv6Addr::LOCALHOST));
}

fn run_udp_round_trip(ip: IpAddr) {
    let mut companion = start_companion();
    let listener = companion
        .status
        .udp_addrs
        .iter()
        .filter_map(|address| address.parse::<SocketAddr>().ok())
        .find(|address| address.ip() == ip)
        .expect("transparent companion listener for requested loopback family");

    let client = UdpSocket::bind(SocketAddr::new(ip, 0)).expect("bind loopback DNS client");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set DNS response timeout");
    let client_addr = client.local_addr().expect("read DNS client endpoint");
    let resolver = SocketAddr::new(ip, 53);
    let query = blocked_query();
    let request = udp_packet(client_addr, resolver, &query);

    let mut router = PacketRouter::new(&companion.status).expect("construct packet router");
    let mut registrations = Vec::new();
    let reflected = match router.route(&request, IFACE, 0, |flow| {
        registrations.push(flow.clone());
        companion.manager.register_flow(flow)
    }) {
        Ok(RoutedPacket::Inbound { packet, .. }) => packet,
        other => panic!("router did not reflect DNS request: {other:?}"),
    };
    assert_eq!(registrations.len(), 1);
    assert_eq!(registrations[0].protocol, "udp");
    assert_eq!(
        registrations[0].peer,
        SocketAddr::new(ip, client_addr.port()).to_string()
    );
    assert_eq!(registrations[0].local, listener.to_string());
    assert_eq!(registrations[0].resolver, resolver.to_string());

    let reflected_info = decode(&reflected).expect("decode reflected DNS request");
    assert_eq!(
        reflected_info.source,
        SocketAddr::new(ip, client_addr.port())
    );
    assert_eq!(reflected_info.destination, listener);
    let reflected_payload = udp_payload(&reflected);
    assert_eq!(reflected_payload, query.as_slice());

    client
        .send_to(reflected_payload, listener)
        .expect("send reflected DNS request to companion");
    let mut response = [0u8; 4096];
    let (response_len, response_peer) = client
        .recv_from(&mut response)
        .expect("receive blocked DNS response from companion");
    let response = &response[..response_len];
    assert_eq!(response_peer, listener);
    assert!(
        response.len() >= 12,
        "companion returned a short DNS response"
    );
    assert_eq!(&response[..2], &query[..2]);
    assert_eq!(
        response[3] & 0x0f,
        3,
        "blocked query did not return NXDOMAIN"
    );

    let proxy_response = udp_packet(listener, client_addr, response);
    let restored = match router
        .route(&proxy_response, IFACE, 1, |_| {
            panic!("reply cannot register")
        })
        .expect("route companion response")
    {
        RoutedPacket::Inbound { packet, interface } => {
            assert_eq!(interface, IFACE);
            packet
        }
        other => panic!("router did not restore companion response: {other:?}"),
    };
    let restored_info = decode(&restored).expect("decode restored DNS response");
    assert_eq!(restored_info.source, resolver);
    assert_eq!(restored_info.destination, client_addr);
    assert_eq!(udp_payload(&restored), response);

    companion.shutdown().expect("quiesce and stop companion");
}

struct Companion {
    manager: DnsProcessManager,
    status: DnsProcessStatus,
    path: PathBuf,
    stopped: bool,
}

fn start_companion() -> Companion {
    let path = test_directory();
    let manager = DnsProcessManager::new(path.clone());
    let status = match manager.start_transparent(TransparentDnsConfig {
        listen_addresses: vec!["127.0.0.1".to_owned(), "::1".to_owned()],
        listen_port: 0,
        rules: "||blocked.example.test^".to_owned(),
    }) {
        Ok(status) => status,
        Err(error) => {
            let _ = manager.stop();
            let _ = fs::remove_dir_all(&path);
            panic!("real transparent companion did not start: {error}");
        }
    };
    Companion {
        manager,
        status,
        path,
        stopped: false,
    }
}

impl Companion {
    fn shutdown(&mut self) -> Result<(), String> {
        // Keep the quiesce barrier explicit: it is part of the contract this
        // test covers, and stop remains the sole owner of socket teardown.
        let quiesce = self.manager.quiesce();
        let stop = self.manager.stop();
        let remove = fs::remove_dir_all(&self.path)
            .map_err(|error| format!("cannot remove companion test directory: {error}"));
        self.stopped = true;
        quiesce.and(stop).and(remove)
    }
}

impl Drop for Companion {
    fn drop(&mut self) {
        if self.stopped {
            return;
        }
        let _ = self.manager.quiesce();
        let _ = self.manager.stop();
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn test_directory() -> PathBuf {
    let root = std::env::temp_dir();
    for _ in 0..128 {
        let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = root.join(format!(
            "vapour-router-integration-{}-{sequence}",
            process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("cannot create companion test directory: {error}"),
        }
    }
    panic!("cannot allocate companion test directory");
}

fn blocked_query() -> Vec<u8> {
    let mut query = vec![
        0x42, 0x17, // transaction ID
        0x01, 0x00, // recursion desired
        0x00, 0x01, // one question
        0x00, 0x00, // no answers
        0x00, 0x00, // no authority records
        0x00, 0x00, // no additional records
    ];
    for label in ["blocked", "example", "test"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]); // root, A, IN
    query
}

fn udp_packet(source: SocketAddr, destination: SocketAddr, payload: &[u8]) -> Vec<u8> {
    assert_eq!(source.is_ipv4(), destination.is_ipv4());
    let ip_header_len = if source.is_ipv4() { 20 } else { 40 };
    let transport_len = 8 + payload.len();
    let total_len = ip_header_len + transport_len;
    assert!(total_len <= usize::from(u16::MAX));
    let mut packet = vec![0u8; total_len];
    if source.is_ipv4() {
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        let source = match source.ip() {
            IpAddr::V4(address) => address.octets(),
            IpAddr::V6(_) => unreachable!(),
        };
        let destination = match destination.ip() {
            IpAddr::V4(address) => address.octets(),
            IpAddr::V6(_) => unreachable!(),
        };
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
    } else {
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(transport_len as u16).to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        let source = match source.ip() {
            IpAddr::V6(address) => address.octets(),
            IpAddr::V4(_) => unreachable!(),
        };
        let destination = match destination.ip() {
            IpAddr::V6(address) => address.octets(),
            IpAddr::V4(_) => unreachable!(),
        };
        packet[8..24].copy_from_slice(&source);
        packet[24..40].copy_from_slice(&destination);
    }
    let transport = ip_header_len;
    packet[transport..transport + 2].copy_from_slice(&source.port().to_be_bytes());
    packet[transport + 2..transport + 4].copy_from_slice(&destination.port().to_be_bytes());
    packet[transport + 4..transport + 6].copy_from_slice(&(transport_len as u16).to_be_bytes());
    packet[transport + 8..].copy_from_slice(payload);
    rewrite(&packet, source, destination).expect("construct valid UDP packet")
}

fn udp_payload(packet: &[u8]) -> &[u8] {
    let ip_header_len = match packet.first().map(|byte| byte >> 4) {
        Some(4) => usize::from(packet[0] & 0x0f) * 4,
        Some(6) => 40,
        _ => panic!("unsupported packet for UDP payload extraction"),
    };
    &packet[ip_header_len + 8..]
}
