//! Explicitly scheduled native acceptance only. Never run automatically.
use super::{dns_process::TransparentDnsConfig, dns_session::DnsSession};
use std::{
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

struct Resolver {
    stop: Arc<AtomicBool>,
    seen: Arc<AtomicUsize>,
    unexpected: Arc<AtomicBool>,
    udp: Option<thread::JoinHandle<()>>,
    tcp: Option<thread::JoinHandle<()>>,
}

// A failed assertion must request and wait for cleanup before the resolver
// fixture disappears. If the driver itself cannot finish, the supervisor
// retains ownership until the isolated test process exits; do not delete its
// runtime files or falsely report successful cleanup.
struct SessionGuard(DnsSession);
impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Err(error) = self.0.stop(Duration::from_secs(15)) {
            eprintln!("Native DNS test cleanup did not complete successfully: {error}");
        }
    }
}

impl Resolver {
    fn start(endpoint: SocketAddr) -> Self {
        // A conflicting DNS service causes the test to fail before interception.
        let udp = UdpSocket::bind(endpoint).expect("isolated UDP port 53 must be available");
        udp.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let tcp = TcpListener::bind(endpoint).expect("isolated TCP port 53 must be available");
        tcp.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(AtomicUsize::new(0));
        let unexpected = Arc::new(AtomicBool::new(false));
        let (s, n, bad) = (stop.clone(), seen.clone(), unexpected.clone());
        let udp = thread::spawn(move || {
            let mut bytes = [0; 4096];
            while !s.load(Ordering::Acquire) {
                match udp.recv_from(&mut bytes) {
                    Ok((length, peer)) => {
                        if let Some(reply) = response(&bytes[..length], &n, &bad) {
                            let _ = udp.send_to(&reply, peer);
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                        ) => {}
                    Err(_) => break,
                }
            }
        });
        let (s, n, bad) = (stop.clone(), seen.clone(), unexpected.clone());
        let tcp = thread::spawn(move || {
            let mut connections = Vec::new();
            while !s.load(Ordering::Acquire) {
                match tcp.accept() {
                    Ok((mut stream, _)) => {
                        let (s, n, bad) = (s.clone(), n.clone(), bad.clone());
                        connections.push(thread::spawn(move || {
                            stream
                                .set_read_timeout(Some(Duration::from_millis(100)))
                                .unwrap();
                            stream
                                .set_write_timeout(Some(Duration::from_secs(1)))
                                .unwrap();
                            while !s.load(Ordering::Acquire) {
                                let mut length = [0; 2];
                                if !read_frame_bytes(&mut stream, &mut length, &s) {
                                    break;
                                }
                                let length = u16::from_be_bytes(length) as usize;
                                if length > 4096 {
                                    break;
                                }
                                let mut bytes = vec![0; length];
                                if !read_frame_bytes(&mut stream, &mut bytes, &s) {
                                    break;
                                }
                                if let Some(reply) = response(&bytes, &n, &bad) {
                                    if stream
                                        .write_all(&(reply.len() as u16).to_be_bytes())
                                        .is_err()
                                        || stream.write_all(&reply).is_err()
                                    {
                                        break;
                                    }
                                }
                            }
                        }));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => break,
                }
            }
            for worker in connections {
                worker.join().unwrap();
            }
        });
        Self {
            stop,
            seen,
            unexpected,
            udp: Some(udp),
            tcp: Some(tcp),
        }
    }
}

impl Drop for Resolver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.udp.take() {
            let _ = worker.join();
        }
        if let Some(worker) = self.tcp.take() {
            let _ = worker.join();
        }
    }
}

// Preserve partial TCP framing across socket timeouts. Retrying read_exact
// with a fresh prefix buffer would discard a consumed first length byte.
fn read_frame_bytes(stream: &mut TcpStream, bytes: &mut [u8], stop: &AtomicBool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut offset = 0;
    while offset < bytes.len() && !stop.load(Ordering::Acquire) && Instant::now() < deadline {
        match stream.read(&mut bytes[offset..]) {
            Ok(0) => return false,
            Ok(n) => offset += n,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => return false,
        }
    }
    offset == bytes.len()
}

fn query(name: &str) -> Vec<u8> {
    let mut bytes = vec![0x71, 0x42, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.extend_from_slice(&[0, 0, 1, 0, 1]);
    bytes
}

fn response(query: &[u8], seen: &AtomicUsize, unexpected: &AtomicBool) -> Option<Vec<u8>> {
    if query.len() < 17 {
        unexpected.store(true, Ordering::Release);
        return None;
    }
    // Requests forwarded during filtering must be the allowed fixture. After
    // stop the test sends a subdomain of the blocked rule, proving its removal.
    if !query.windows(7).any(|part| part == b"allowed")
        && !query.windows(6).any(|part| part == b"direct")
    {
        unexpected.store(true, Ordering::Release);
    }
    seen.fetch_add(1, Ordering::AcqRel);
    let mut reply = query.to_vec();
    reply[2] = 0x81;
    reply[3] = 0x80;
    Some(reply)
}

fn exchange(local: IpAddr, resolver: SocketAddr, tcp: bool, name: &str) -> Vec<u8> {
    let request = query(name);
    if tcp {
        let socket = socket2::Socket::new(
            if local.is_ipv4() {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            },
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        socket.bind(&SocketAddr::new(local, 0).into()).unwrap();
        socket
            .connect_timeout(&resolver.into(), Duration::from_secs(3))
            .expect("intercepted TCP handshake");
        let mut stream: TcpStream = socket.into();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .write_all(&(request.len() as u16).to_be_bytes())
            .unwrap();
        stream.write_all(&request).unwrap();
        let mut length = [0; 2];
        stream.read_exact(&mut length).unwrap();
        let mut reply = vec![0; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut reply).unwrap();
        reply
    } else {
        let socket = UdpSocket::bind(SocketAddr::new(local, 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket.send_to(&request, resolver).unwrap();
        let mut bytes = [0; 4096];
        let (size, source) = socket
            .recv_from(&mut bytes)
            .expect("intercepted UDP response");
        assert_eq!(
            source, resolver,
            "response must retain the original resolver tuple"
        );
        bytes[..size].to_vec()
    }
}

fn native_session_case(local: &str, resolver: &str) {
    let local: IpAddr = local.parse().unwrap();
    let resolver: SocketAddr = resolver.parse().unwrap();
    let server = Resolver::start(resolver);
    let directory = std::env::temp_dir().join(format!(
        "vapour-dns-session-native-{}-{}",
        std::process::id(),
        if local.is_ipv4() { "v4" } else { "v6" }
    ));
    let session = SessionGuard(
        DnsSession::start(
            directory.join("helper"),
            &directory.join("driver"),
            TransparentDnsConfig {
                listen_addresses: vec![local.to_string()],
                listen_port: 0,
                rules: "||blocked.example.test^".into(),
            },
        )
        .expect("native DNS session should start"),
    );
    for tcp in [false, true] {
        let blocked = exchange(local, resolver, tcp, "blocked.example.test");
        assert_eq!(&blocked[..2], &[0x71, 0x42]);
        assert_eq!(blocked[3] & 15, 3, "blocked query must return NXDOMAIN");
        let allowed = exchange(local, resolver, tcp, "allowed.example.test");
        assert_eq!(allowed[3] & 15, 0);
    }
    assert_eq!(server.seen.load(Ordering::Acquire), 2);
    assert!(
        !server.unexpected.load(Ordering::Acquire),
        "blocked query reached the resolver"
    );
    session
        .0
        .reload(
            "||blocked.example.test^\n||allowed.example.test^".into(),
            Duration::from_secs(12),
        )
        .expect("reload rules without replacing the interception session");
    for tcp in [false, true] {
        let blocked = exchange(local, resolver, tcp, "allowed.example.test");
        assert_eq!(
            blocked[3] & 15,
            3,
            "new rules must affect existing resolver slots"
        );
    }
    assert_eq!(server.seen.load(Ordering::Acquire), 2);
    session
        .0
        .reload("||blocked.example.test^".into(), Duration::from_secs(12))
        .expect("restore original rules in the same session");
    for tcp in [false, true] {
        let allowed = exchange(local, resolver, tcp, "allowed.example.test");
        assert_eq!(allowed[3] & 15, 0);
    }
    assert_eq!(server.seen.load(Ordering::Acquire), 4);
    let started = Instant::now();
    session
        .0
        .stop(Duration::from_secs(10))
        .expect("driver drain and helper stop");
    assert!(started.elapsed() < Duration::from_secs(10));
    for tcp in [false, true] {
        let direct = exchange(local, resolver, tcp, "direct.blocked.example.test");
        assert_eq!(direct[3] & 15, 0);
    }
    assert_eq!(server.seen.load(Ordering::Acquire), 6);
    assert!(!server.unexpected.load(Ordering::Acquire));
    drop(session);
    drop(server);
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
#[ignore = "requires explicit elevated native DNS interception test; user must be present"]
fn native_session_filters_ipv4_udp_tcp_and_restores_direct_dns() {
    native_session_case("127.0.0.11", "127.0.0.12:53");
}

#[test]
#[ignore = "requires explicit elevated native DNS interception test; user must be present"]
fn native_session_filters_ipv6_udp_tcp_and_restores_direct_dns() {
    native_session_case("::1", "[::1]:53");
}
