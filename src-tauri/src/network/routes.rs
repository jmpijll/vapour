use std::{collections::HashMap, net::{Ipv4Addr, Ipv6Addr}, time::{SystemTime, UNIX_EPOCH}};
use serde::{Deserialize, Serialize};
use windows::Win32::{NetworkManagement::IpHelper::*, Networking::WinSock::*};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub destination: String,
    pub prefix_length: u8,
    pub family: String,
    pub next_hop: String,
    pub route_metric: Option<u32>,
    pub protocol_code: i32,
    pub origin_code: i32,
    pub is_default: bool,
    pub valid_lifetime_seconds: Option<u32>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfiguration {
    pub source: String,
    pub sampled_at: u64,
    pub routes: Vec<Route>,
}
fn address(value: SOCKADDR_INET) -> Option<(String, bool, bool)> {
    unsafe {
        if value.si_family == AF_INET {
            let ip = Ipv4Addr::from(value.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes());
            Some((ip.to_string(), false, ip.is_unspecified()))
        } else if value.si_family == AF_INET6 {
            let ip = Ipv6Addr::from(value.Ipv6.sin6_addr.u.Byte);
            let scope = value.Ipv6.Anonymous.sin6_scope_id;
            Some((if scope == 0 { ip.to_string() } else { format!("{ip}%{scope}") }, true, ip.is_unspecified()))
        } else { None }
    }
}
fn decode(row: &MIB_IPFORWARD_ROW2) -> Option<Route> {
    let (destination, v6, zero) = address(row.DestinationPrefix.Prefix)?;
    let (next_hop, next_v6, _) = address(row.NextHop)?;
    let prefix = row.DestinationPrefix.PrefixLength;
    if v6 != next_v6 || prefix > if v6 {128} else {32} { return None; }
    Some(Route {
        destination, prefix_length: prefix, family: if v6 {"ipv6"} else {"ipv4"}.into(), next_hop,
        route_metric: (row.Metric != u32::MAX).then_some(row.Metric),
        protocol_code: row.Protocol.0, origin_code: row.Origin.0,
        is_default: prefix == 0 && zero,
        valid_lifetime_seconds: (row.ValidLifetime != u32::MAX).then_some(row.ValidLifetime),
    })
}
pub fn collect() -> Result<HashMap<u64, RouteConfiguration>, u32> {
    unsafe {
        let mut table = std::ptr::null_mut();
        let error = GetIpForwardTable2(AF_UNSPEC, &mut table).0;
        if error != 0 { return Err(error); }
        if table.is_null() { return Err(13); }
        struct Guard(*mut MIB_IPFORWARD_TABLE2);
        impl Drop for Guard { fn drop(&mut self) { unsafe {FreeMibTable(self.0.cast());} } }
        let _guard = Guard(table);
        let count = (*table).NumEntries as usize;
        if count > 65536 { return Err(8); }
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
        let mut values: HashMap<u64, RouteConfiguration> = HashMap::new();
        for row in rows {
            let route = decode(row).ok_or(13u32)?;
            values.entry(row.InterfaceLuid.Value).or_insert_with(|| RouteConfiguration {
                source: "windows_get_ip_forward_table2".into(), sampled_at: timestamp, routes: vec![],
            }).routes.push(route);
        }
        Ok(values)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_requires_zero_address_and_prefix_and_metrics_keep_unknown() {
        let mut row = MIB_IPFORWARD_ROW2::default();
        row.DestinationPrefix.Prefix.si_family = AF_INET;
        row.NextHop.si_family = AF_INET;
        row.Metric = u32::MAX; row.ValidLifetime = u32::MAX;
        let route = decode(&row).unwrap();
        assert!(route.is_default); assert_eq!(route.route_metric, None);
        assert_eq!(route.valid_lifetime_seconds, None);
        row.DestinationPrefix.PrefixLength = 24;
        assert!(!decode(&row).unwrap().is_default);
        row.DestinationPrefix.PrefixLength = 33;
        assert!(decode(&row).is_none());
    }
    #[test]
    fn rejects_cross_family_next_hop() {
        let mut row = MIB_IPFORWARD_ROW2::default();
        row.DestinationPrefix.Prefix.si_family = AF_INET;
        row.NextHop.si_family = AF_INET6;
        assert!(decode(&row).is_none());
    }
    #[test]
    #[ignore = "Reads local Windows routes; run explicitly"]
    fn live_routes() {
        let values = collect().expect("Windows route table");
        let count: usize = values.values().map(|v| v.routes.len()).sum();
        for value in values.values() { assert!(serde_json::to_string(value).is_ok()); }
        println!("Validated {count} routes; destinations not logged");
    }
}
