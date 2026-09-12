use parking_lot::Mutex;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        mpsc::{sync_channel, SyncSender},
        Arc,
    },
    time::{Duration, Instant},
};

struct Entry {
    host: Option<String>,
    expires: Instant,
    pending: bool,
}
pub struct DestinationResolver {
    cache: Arc<Mutex<HashMap<IpAddr, Entry>>>,
    queue: SyncSender<IpAddr>,
}
fn clean_hostname(value: &str) -> Option<String> {
    let name = value.trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty()
        || name.len() > 253
        || name.parse::<IpAddr>().is_ok()
        || !name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        })
    {
        return None;
    }
    Some(name)
}
pub fn reverse_lookup(ip: IpAddr) -> Option<String> {
    use windows::Win32::Networking::WinSock::{
        GetNameInfoW, WSACleanup, WSAStartup, NI_NAMEREQD, NI_NUMERICSERV, WSADATA,
    };
    let address = socket2::SockAddr::from(SocketAddr::new(ip, 0));
    let mut buffer = [0u16; 1025];
    unsafe {
        let mut data = WSADATA::default();
        if WSAStartup(0x202, &mut data) != 0 {
            return None;
        }
        let result = GetNameInfoW(
            address.as_ptr().cast(),
            windows::Win32::Networking::WinSock::socklen_t(address.len() as i32),
            Some(&mut buffer),
            None,
            (NI_NAMEREQD | NI_NUMERICSERV) as i32,
        );
        WSACleanup();
        if result != 0 {
            return None;
        }
    }
    let end = buffer.iter().position(|&c| c == 0)?;
    clean_hostname(&String::from_utf16(&buffer[..end]).ok()?)
}
impl DestinationResolver {
    pub fn new() -> Self {
        let cache = Arc::new(Mutex::new(HashMap::<IpAddr, Entry>::new()));
        let (queue, receiver) = sync_channel::<IpAddr>(64);
        let receiver = Arc::new(Mutex::new(receiver));
        // The OS owns lookup timeouts. Two dedicated workers bound stalled calls;
        // no DNS work runs on the sampler, UI or Tokio's blocking thread pool.
        for _ in 0..2 {
            let receiver = Arc::clone(&receiver);
            let cache = Arc::clone(&cache);
            std::thread::spawn(move || loop {
                let next = receiver.lock().recv();
                let Ok(ip) = next else {
                    break;
                };
                let host = reverse_lookup(ip);
                let ttl = if host.is_some() { 300 } else { 60 };
                cache.lock().insert(
                    ip,
                    Entry {
                        host,
                        expires: Instant::now() + Duration::from_secs(ttl),
                        pending: false,
                    },
                );
            });
        }
        Self { cache, queue }
    }
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        if super::enricher::TrafficEnricher::is_private_ip(&ip) {
            return None;
        }
        let now = Instant::now();
        let mut cache = self.cache.lock();
        if let Some(entry) = cache.get(&ip) {
            if entry.pending || entry.expires > now {
                return entry.host.clone();
            }
        }
        if cache.len() >= 1024 && !cache.contains_key(&ip) {
            let oldest = cache
                .iter()
                .filter(|(_, e)| !e.pending)
                .min_by_key(|(_, e)| e.expires)
                .map(|(ip, _)| *ip);
            if let Some(oldest) = oldest {
                cache.remove(&oldest);
            } else {
                return None;
            }
        }
        cache.insert(
            ip,
            Entry {
                host: None,
                expires: now,
                pending: true,
            },
        );
        if self.queue.try_send(ip).is_err() {
            cache.remove(&ip);
        }
        None
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_and_overflow_requests_do_not_grow_the_queue() {
        let (queue, receiver) = sync_channel(64);
        let resolver = DestinationResolver { cache: Arc::new(Mutex::new(HashMap::new())), queue };
        let ip = "1.1.1.1".parse().unwrap();
        for _ in 0..100 { resolver.lookup(ip); }
        assert_eq!(receiver.try_iter().count(), 1);
        for n in 1..5000u32 { resolver.lookup(IpAddr::V4(std::net::Ipv4Addr::from(0x08000000 + n))); }
        assert!(resolver.cache.lock().len() <= 65);
        assert_eq!(receiver.try_iter().count(), 64);
    }
    #[test]
    fn negative_answers_are_cached_until_expiry() {
        let (queue, receiver) = sync_channel(64);
        let cache = Arc::new(Mutex::new(HashMap::new()));
        let ip = "1.1.1.1".parse().unwrap();
        cache.lock().insert(ip, Entry { host: None, expires: Instant::now() + Duration::from_secs(60), pending: false });
        let resolver = DestinationResolver { cache, queue };
        assert_eq!(resolver.lookup(ip), None);
        assert!(receiver.try_recv().is_err());
        resolver.cache.lock().get_mut(&ip).unwrap().expires = Instant::now() - Duration::from_secs(1);
        resolver.lookup(ip);
        assert_eq!(receiver.try_recv().unwrap(), ip);
    }
    #[test]
    fn names_are_hints_not_numeric_fallbacks_or_markup() {
        assert_eq!(
            clean_hostname("ONE.ONE.ONE.ONE."),
            Some("one.one.one.one".into())
        );
        for value in ["1.1.1.1", "::1", "", "<img>", "a\nb", "a..b"] {
            assert_eq!(clean_hostname(value), None);
        }
    }
    #[test]
    fn local_addresses_do_not_enter_the_lookup_queue() {
        let resolver = DestinationResolver::new();
        for ip in ["127.0.0.1", "192.168.1.1", "::1", "::"] {
            assert_eq!(resolver.lookup(ip.parse().unwrap()), None);
        }
        assert!(resolver.cache.lock().is_empty());
    }
}
