use std::{collections::HashMap, mem::size_of, net::{Ipv4Addr, Ipv6Addr}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use serde::{Deserialize, Serialize};
use windows::Win32::{NetworkManagement::IpHelper::*, Networking::WinSock::*};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpAddress { pub address: String, pub prefix_length: u8, pub family: String }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpConfiguration {
    pub source: String,
    pub sampled_at: u64,
    pub addresses: Vec<IpAddress>,
    pub dns_servers: Vec<String>,
    pub gateways: Vec<String>,
    pub ipv4_metric: u32,
    pub ipv6_metric: u32,
}
#[derive(Default)]
pub struct ConfigCache { sampled: Option<Instant>, values: HashMap<u64, IpConfiguration>, pub failed: bool }
impl ConfigCache {
    pub fn refresh(&mut self, now: Instant) {
        if self.sampled.is_some_and(|last| now.duration_since(last) < Duration::from_secs(30)) { return; }
        self.sampled = Some(now);
        match collect() {
            Ok(values) => { self.values = values; self.failed = false; }
            Err(_) => { self.values.clear(); self.failed = true; }
        }
    }
    pub fn get(&self, luid: u64) -> Option<IpConfiguration> { self.values.get(&luid).cloned() }
}

// Windows returns pointers into this allocation. Validate each node before
// copying it; neither linked-list cycles nor unexpected lengths grow the work.
struct Buffer { storage: Vec<u64> }
impl Buffer {
    fn new(bytes: usize) -> Self { Self { storage: vec![0; bytes.div_ceil(8)] } }
    fn contains(&self, ptr: *const u8, len: usize) -> bool {
        let start = self.storage.as_ptr() as usize;
        let end = start + self.storage.len() * 8;
        let p = ptr as usize;
        p >= start && p.checked_add(len).is_some_and(|last| last <= end)
    }
    fn read<T: Copy>(&self, ptr: *const T) -> Option<T> {
        self.contains(ptr.cast(), size_of::<T>()).then(|| unsafe { ptr.read_unaligned() })
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
            let row = buffer.read(current).ok_or(13u32)?;
            let mut config = IpConfiguration { source: "windows_get_adapters_addresses".into(), sampled_at: timestamp,
                addresses: vec![], dns_servers: vec![], gateways: vec![], ipv4_metric: row.Ipv4Metric, ipv6_metric: row.Ipv6Metric };
            let mut node = row.FirstUnicastAddress;
            for _ in 0..4096 {
                if node.is_null() { break; }
                let a = buffer.read(node).ok_or(13u32)?;
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
                let a = buffer.read(node).ok_or(13u32)?;
                if let Some((address, _)) = buffer.address(a.Address) { config.dns_servers.push(address); }
                node = a.Next;
            }
            if !node.is_null() { return Err(13); }
            let mut node = row.FirstGatewayAddress;
            for _ in 0..4096 {
                if node.is_null() { break; }
                let a = buffer.read(node).ok_or(13u32)?;
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
    fn cache_retains_same_sample_within_interval() {
        let now = Instant::now();
        let mut cache = ConfigCache {sampled: Some(now), failed: true, ..Default::default()};
        cache.refresh(now + Duration::from_secs(29));
        assert_eq!(cache.sampled, Some(now));
        assert!(cache.failed);
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
