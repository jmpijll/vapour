use std::{collections::HashMap, mem::size_of, net::{Ipv4Addr, Ipv6Addr}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use serde::{Deserialize, Serialize};
use parking_lot::Mutex;
use std::sync::Arc;
use windows::Win32::{NetworkManagement::IpHelper::*, Networking::WinSock::*};

const REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const STALE_AFTER: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpAddress { pub address: String, pub prefix_length: u8, pub family: String }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpConfiguration {
    pub source: String,
    pub sampled_at: u64,
    pub addresses: Vec<IpAddress>,
    pub dns_servers: Vec<String>,
    pub gateways: Vec<String>,
    pub dhcpv4_enabled: bool,
    pub dhcpv4_server: Option<String>,
    pub dhcpv6_server: Option<String>,
    pub ipv4_metric: u32,
    pub ipv6_metric: u32,
}
#[derive(Default)]
pub struct ConfigCache {
    sampled: Option<Instant>,
    ip_refresh_started: Option<Instant>,
    ip_success_at: Option<Instant>,
    routes_sampled: Option<Instant>,
    routes_refresh_started: Option<Instant>,
    routes_success_at: Option<Instant>,
    values: HashMap<u64, IpConfiguration>,
    pub failed: bool,
    routes: HashMap<u64, super::routes::RouteConfiguration>,
    pub routes_failed: bool,
}
impl ConfigCache {
    fn begin_ip_refresh(&mut self, now: Instant) -> bool {
        if self.ip_refresh_started.is_some()
            || self
                .sampled
                .is_some_and(|last| now.saturating_duration_since(last) < REFRESH_INTERVAL)
        {
            return false;
        }
        self.sampled = Some(now);
        self.ip_refresh_started = Some(now);
        true
    }

    fn begin_routes_refresh(&mut self, now: Instant) -> bool {
        if self.routes_refresh_started.is_some()
            || self
                .routes_sampled
                .is_some_and(|last| now.saturating_duration_since(last) < REFRESH_INTERVAL)
        {
            return false;
        }
        self.routes_sampled = Some(now);
        self.routes_refresh_started = Some(now);
        true
    }

    fn complete_ip(&mut self, result: Result<HashMap<u64, IpConfiguration>, u32>, sampled_at: Instant) {
        self.ip_refresh_started = None;
        match result {
            Ok(values) => {
                self.values = values;
                self.failed = false;
                self.ip_success_at = Some(sampled_at);
            }
            Err(_) => {
                self.values.clear();
                self.failed = true;
                self.ip_success_at = None;
            }
        }
    }

    fn complete_routes(
        &mut self,
        result: Result<HashMap<u64, super::routes::RouteConfiguration>, u32>,
        sampled_at: Instant,
    ) {
        self.routes_refresh_started = None;
        match result {
            Ok(values) => {
                self.routes = values;
                self.routes_failed = false;
                self.routes_success_at = Some(sampled_at);
            }
            Err(_) => {
                self.routes.clear();
                self.routes_failed = true;
                self.routes_success_at = None;
            }
        }
    }

    pub fn pending(&self) -> bool { self.ip_refresh_started.is_some() && self.ip_success_at.is_none() && !self.failed }

    pub fn ip_configuration_status(&self, now: Instant) -> &'static str {
        collector_status(
            now,
            self.ip_refresh_started,
            self.ip_success_at,
            self.failed,
        )
    }

    pub fn route_configuration_status(&self, now: Instant) -> &'static str {
        collector_status(
            now,
            self.routes_refresh_started,
            self.routes_success_at,
            self.routes_failed,
        )
    }

    pub fn routes(&self, luid: u64) -> Option<super::routes::RouteConfiguration> { self.routes.get(&luid).cloned() }
    pub fn get(&self, luid: u64) -> Option<IpConfiguration> { self.values.get(&luid).cloned() }
}

fn collector_status(
    now: Instant,
    refreshing_since: Option<Instant>,
    success_at: Option<Instant>,
    failed: bool,
) -> &'static str {
    if let Some(sampled_at) = success_at {
        if now.saturating_duration_since(sampled_at) >= STALE_AFTER {
            return "stale";
        }
        return "available";
    }
    if let Some(started_at) = refreshing_since {
        return if now.saturating_duration_since(started_at) >= STALE_AFTER {
            "stale"
        } else {
            "pending"
        };
    }
    if failed {
        return "query_failed";
    }
    "not_available"
}
/// At most one bounded-result query worker runs per collector. Windows calls
/// do not hold the cache lock or delay the throughput sampler. Arc keeps state
/// alive if a driver stalls; a stalled worker cannot cause more workers to spawn.
pub fn request_refresh(cache: &Arc<Mutex<ConfigCache>>, now: Instant) {
    request_refresh_with(cache, now, super::routes::collect, collect);
}

fn request_refresh_with<R, I>(
    cache: &Arc<Mutex<ConfigCache>>,
    now: Instant,
    route_collect: R,
    ip_collect: I,
) where
    R: FnOnce() -> Result<HashMap<u64, super::routes::RouteConfiguration>, u32> + Send + 'static,
    I: FnOnce() -> Result<HashMap<u64, IpConfiguration>, u32> + Send + 'static,
{
    let (refresh_routes, refresh_ip) = {
        let mut state = cache.lock();
        (state.begin_routes_refresh(now), state.begin_ip_refresh(now))
    };

    if refresh_routes {
        let target = Arc::clone(cache);
        if std::thread::Builder::new()
            .name("vapour-route-config".into())
            .spawn(move || {
                let result = route_collect();
                target.lock().complete_routes(result, Instant::now());
            })
            .is_err()
        {
            cache.lock().complete_routes(Err(8), Instant::now());
        }
    }

    if refresh_ip {
        let target = Arc::clone(cache);
        if std::thread::Builder::new()
            .name("vapour-ip-config".into())
            .spawn(move || {
                let result = ip_collect();
                target.lock().complete_ip(result, Instant::now());
            })
            .is_err()
        {
            cache.lock().complete_ip(Err(8), Instant::now());
        }
    }
}

// Windows returns pointers into this allocation. Validate each node before
// copying it; neither linked-list cycles nor unexpected lengths grow the work.
struct Buffer { storage: Vec<u64> }
fn contains_range(start: usize, capacity: usize, ptr: usize, len: usize) -> bool {
    let Some(end) = start.checked_add(capacity) else { return false; };
    ptr >= start && ptr.checked_add(len).is_some_and(|last| last <= end)
}
impl Buffer {
    fn new(bytes: usize) -> Self { Self { storage: vec![0; bytes.div_ceil(8)] } }
    fn contains(&self, ptr: *const u8, len: usize) -> bool {
        let start = self.storage.as_ptr() as usize;
        let Some(capacity) = self.storage.len().checked_mul(8) else { return false; };
        contains_range(start, capacity, ptr as usize, len)
    }
    fn read<T: Copy>(&self, ptr: *const T) -> Option<T> {
        self.contains(ptr.cast(), size_of::<T>()).then(|| unsafe { ptr.read_unaligned() })
    }
    fn node<T: Copy>(&self, ptr: *const T) -> Option<T> {
        let declared = self.read(ptr.cast::<u32>())? as usize;
        if declared < size_of::<T>() || !self.contains(ptr.cast(), declared) { return None; }
        self.read(ptr)
    }
    fn address(&self, address: SOCKET_ADDRESS) -> Option<(String, bool)> {
        if address.iSockaddrLength < 2 || !self.contains(address.lpSockaddr.cast(), address.iSockaddrLength as usize) { return None; }
        let family = unsafe { address.lpSockaddr.cast::<u16>().read_unaligned() };
        unsafe {
            if family == AF_INET.0 && address.iSockaddrLength as usize >= size_of::<SOCKADDR_IN>() {
                let value = self.read(address.lpSockaddr.cast::<SOCKADDR_IN>())?;
                Some((Ipv4Addr::from(value.sin_addr.S_un.S_addr.to_ne_bytes()).to_string(), false))
            } else if family == AF_INET6.0 && address.iSockaddrLength as usize >= size_of::<SOCKADDR_IN6>() {
                let value = self.read(address.lpSockaddr.cast::<SOCKADDR_IN6>())?;
                let ip = Ipv6Addr::from(value.sin6_addr.u.Byte);
                let scope = value.Anonymous.sin6_scope_id;
                Some((if scope == 0 { ip.to_string() } else { format!("{ip}%{scope}") }, true))
            } else { None }
        }
    }
}
pub fn collect() -> Result<HashMap<u64, IpConfiguration>, u32> {
    let mut bytes = 15_000u32;
    for _ in 0..3 {
        if bytes as usize > 8 * 1024 * 1024 { return Err(8); }
        let mut buffer = Buffer::new(bytes as usize);
        let head = buffer.storage.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let result = unsafe { GetAdaptersAddresses(AF_UNSPEC.0 as u32,
            GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_ALL_INTERFACES | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
            None, Some(head), &mut bytes) };
        if result == 111 { continue; } // ERROR_BUFFER_OVERFLOW: topology can change between calls.
        if result == 232 { return Ok(HashMap::new()); } // ERROR_NO_DATA
        if result != 0 { return Err(result); }
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
        let mut values = HashMap::new();
        let mut current = head;
        for _ in 0..4096 {
            if current.is_null() { return Ok(values); }
            let row = buffer.node(current).ok_or(13u32)?;
            let mut config = IpConfiguration { source: "windows_get_adapters_addresses".into(), sampled_at: timestamp,
                addresses: vec![], dns_servers: vec![], gateways: vec![],
                dhcpv4_enabled: unsafe { row.Anonymous2.Flags & IP_ADAPTER_DHCP_ENABLED != 0 },
                dhcpv4_server: buffer.address(row.Dhcpv4Server).map(|(ip, _)| ip),
                dhcpv6_server: buffer.address(row.Dhcpv6Server).map(|(ip, _)| ip),
                ipv4_metric: row.Ipv4Metric, ipv6_metric: row.Ipv6Metric };
            let mut node = row.FirstUnicastAddress;
            for _ in 0..4096 {
                if node.is_null() { break; }
                let a = buffer.node(node).ok_or(13u32)?;
                if let Some((address, v6)) = buffer.address(a.Address) {
                    if a.OnLinkPrefixLength <= if v6 {128} else {32} {
                        config.addresses.push(IpAddress {address, prefix_length: a.OnLinkPrefixLength, family: if v6 {"ipv6"} else {"ipv4"}.into()});
                    }
                }
                node = a.Next;
            }
            if !node.is_null() { return Err(13); }
            let mut node = row.FirstDnsServerAddress;
            for _ in 0..4096 {
                if node.is_null() { break; }
                let a = buffer.node(node).ok_or(13u32)?;
                if let Some((address, _)) = buffer.address(a.Address) { config.dns_servers.push(address); }
                node = a.Next;
            }
            if !node.is_null() { return Err(13); }
            let mut node = row.FirstGatewayAddress;
            for _ in 0..4096 {
                if node.is_null() { break; }
                let a = buffer.node(node).ok_or(13u32)?;
                if let Some((address, _)) = buffer.address(a.Address) { config.gateways.push(address); }
                node = a.Next;
            }
            if !node.is_null() { return Err(13); }
            values.insert(unsafe {row.Luid.Value}, config);
            current = row.Next;
        }
        return Err(13);
    }
    Err(111)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_null_and_truncated_socket_buffers() {
        let b = Buffer::new(16);
        assert!(b.address(SOCKET_ADDRESS::default()).is_none());
        assert!(b.read::<IP_ADAPTER_ADDRESSES_LH>(b.storage.as_ptr().cast()).is_none());
    }
    #[test]
    fn decodes_ipv4_network_order_and_ipv6_scope() {
        let mut b = Buffer::new(64);
        let mut v4 = SOCKADDR_IN::default();
        v4.sin_family = AF_INET;
        v4.sin_addr.S_un.S_addr = u32::from_ne_bytes([192, 0, 2, 7]);
        unsafe { b.storage.as_mut_ptr().cast::<SOCKADDR_IN>().write_unaligned(v4); }
        let mut socket = SOCKET_ADDRESS { lpSockaddr: b.storage.as_mut_ptr().cast(), iSockaddrLength: size_of::<SOCKADDR_IN>() as i32 };
        assert_eq!(b.address(socket), Some(("192.0.2.7".into(), false)));
        let mut v6 = SOCKADDR_IN6::default();
        v6.sin6_family = AF_INET6;
        v6.sin6_addr.u.Byte = [0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1];
        v6.Anonymous.sin6_scope_id = 12;
        unsafe { b.storage.as_mut_ptr().cast::<SOCKADDR_IN6>().write_unaligned(v6); }
        socket.iSockaddrLength = size_of::<SOCKADDR_IN6>() as i32;
        assert_eq!(b.address(socket), Some(("fe80::1%12".into(), true)));
        socket.iSockaddrLength = 2;
        assert!(b.address(socket).is_none());
    }
    #[test]
    fn rejects_short_declared_node_even_inside_large_allocation() {
        let mut b = Buffer::new(size_of::<IP_ADAPTER_ADDRESSES_LH>());
        unsafe { b.storage.as_mut_ptr().cast::<u32>().write_unaligned(8); }
        assert!(b.node::<IP_ADAPTER_ADDRESSES_LH>(b.storage.as_ptr().cast()).is_none());
    }
    #[test]
    fn cache_retains_same_sample_within_interval() {
        let now = Instant::now();
        let mut cache = ConfigCache {sampled: Some(now), failed: true, ..Default::default()};
        assert!(!cache.begin_ip_refresh(now + Duration::from_secs(29)));
        assert_eq!(cache.sampled, Some(now));
        assert!(cache.failed);
    }
    #[test]
    fn stalled_refresh_cannot_spawn_additional_workers() {
        let now = Instant::now();
        let mut state = ConfigCache::default();
        assert!(state.begin_ip_refresh(now));
        assert!(!state.begin_ip_refresh(now + Duration::from_secs(120)));
        state.ip_refresh_started = None;
        assert!(state.begin_ip_refresh(now + Duration::from_secs(120)));
    }
    #[test]
    fn each_collector_reports_stale_after_a_hung_first_query() {
        let now = Instant::now();
        let mut state = ConfigCache::default();

        assert_eq!(state.ip_configuration_status(now), "not_available");
        assert_eq!(state.route_configuration_status(now), "not_available");
        assert!(state.begin_ip_refresh(now));
        assert!(state.begin_routes_refresh(now));

        assert_eq!(state.ip_configuration_status(now + Duration::from_secs(59)), "pending");
        assert_eq!(state.route_configuration_status(now + Duration::from_secs(59)), "pending");
        assert_eq!(state.ip_configuration_status(now + Duration::from_secs(60)), "stale");
        assert_eq!(state.route_configuration_status(now + Duration::from_secs(60)), "stale");
    }
    #[test]
    fn route_and_ip_refresh_state_can_complete_independently() {
        let now = Instant::now();
        let mut state = ConfigCache::default();
        assert!(state.begin_ip_refresh(now));
        assert!(state.begin_routes_refresh(now));

        state.complete_routes(Ok(HashMap::new()), now + Duration::from_secs(1));

        assert_eq!(state.route_configuration_status(now + Duration::from_secs(1)), "available");
        assert_eq!(state.ip_configuration_status(now + Duration::from_secs(1)), "pending");
        assert!(state.ip_refresh_started.is_some());
        assert!(state.routes_refresh_started.is_none());
    }
    #[test]
    fn collector_refresh_cannot_spawn_a_second_worker_after_stale_deadline() {
        let now = Instant::now();
        let mut state = ConfigCache::default();
        assert!(state.begin_ip_refresh(now));
        assert!(!state.begin_ip_refresh(now + Duration::from_secs(61)));
        assert!(state.begin_routes_refresh(now));
        assert!(!state.begin_routes_refresh(now + Duration::from_secs(61)));
    }
    #[test]
    fn failed_retry_reports_pending_then_stale() {
        let now = Instant::now();
        let mut state = ConfigCache::default();
        assert!(state.begin_ip_refresh(now));
        state.complete_ip(Err(5), now + Duration::from_secs(1));
        assert_eq!(state.ip_configuration_status(now + Duration::from_secs(1)), "query_failed");

        let retry = now + Duration::from_secs(31);
        assert!(state.begin_ip_refresh(retry));
        assert_eq!(state.ip_configuration_status(retry), "pending");
        assert_eq!(state.ip_configuration_status(retry + Duration::from_secs(60)), "stale");
    }
    #[test]
    fn checked_bounds_reject_pointer_arithmetic_overflow() {
        assert!(contains_range(100, 8, 104, 4));
        assert!(!contains_range(usize::MAX - 3, 8, usize::MAX - 2, 1));
        assert!(!contains_range(0, 8, usize::MAX, 1));
    }
    #[test]
    #[ignore = "Reads live local IP configuration; run explicitly"]
    fn live_ip_configuration() {
        let values = collect().expect("Windows IP configuration query");
        for config in values.values() {
            assert!(config.sampled_at > 0);
            assert!(serde_json::to_string(config).is_ok());
        }
        println!("Validated IP configuration for {} interfaces; addresses not logged", values.len());
    }
}
