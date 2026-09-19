//! Pure, bounded construction of the NETWORK-layer WinDivert DNS filter.
//!
//! The transparent DNS session owns a set of source ports before this filter
//! is installed.  The request clauses below deliberately exempt only those
//! exact `(source address, source port, transport)` tuples.  In particular,
//! an owned UDP port does not exempt TCP traffic, another local address, or a
//! packet whose source port merely falls in a convenient range.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    net::{IpAddr, Ipv6Addr, SocketAddr},
};

/// Maximum number of local source addresses covered by one filter.
pub(crate) const MAX_LOCAL_IPS: usize = 16;
/// Number of owned source endpoints for either transport and address.
///
/// The transparent companion reports a complete set of eight slots for every
/// covered local address before the driver filter is installed.
pub(crate) const MAX_OWNED_SLOTS_PER_IP: usize = 8;
/// Keep the generated filter below the WinDivert wrapper's bounded input.
pub(crate) const MAX_FILTER_BYTES: usize = 32 * 1024;
/// WinDivert's compiled instruction budget is tighter than the input bound.
/// Keep each handle's address set small and return disjoint filters for the
/// remaining covered addresses.
pub(crate) const MAX_FILTER_IPS: usize = 4;

/// Explicit addresses used by one transparent DNS interception session.
///
/// `udp_upstreams` and `tcp_upstreams` are the already-bound local source
/// endpoints returned by the companion.  They are named upstreams because
/// those sockets forward the original DNS request to its retained resolver
/// destination.  Every endpoint must use an address in `local_ips`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DnsFilterConfig {
    pub(crate) local_ips: Vec<IpAddr>,
    pub(crate) udp_proxy_listeners: Vec<SocketAddr>,
    pub(crate) tcp_proxy_listeners: Vec<SocketAddr>,
    pub(crate) udp_upstreams: Vec<SocketAddr>,
    pub(crate) tcp_upstreams: Vec<SocketAddr>,
}

type ScopedPorts = BTreeMap<Option<u32>, BTreeSet<u16>>;
type PortsByIp = BTreeMap<IpAddr, ScopedPorts>;
type EndpointKey = (IpAddr, u16);

/// Build a deterministic NETWORK-layer WinDivert filter for transparent DNS.
///
/// The resulting expression captures outbound conventional DNS requests whose
/// source address is one of `local_ips`, except for exact owned source ports
/// of the same protocol.  It also captures outbound packets sourced by an
/// exact proxy listener, which includes TCP handshakes and control packets.
pub(crate) fn build_dns_filter(config: &DnsFilterConfig) -> Result<String, String> {
    let local_ips = validate_config(config)?;
    if local_ips.len() > MAX_FILTER_IPS {
        return Err(format!(
            "one DNS filter supports at most {MAX_FILTER_IPS} local IPs; use build_dns_filters"
        ));
    }

    let udp_owned = collect_ports(&config.udp_upstreams);
    let tcp_owned = collect_ports(&config.tcp_upstreams);

    build_filter_for_ips(config, &local_ips, &udp_owned, &tcp_owned)
}

/// Build disjoint filters when the session covers more addresses than one
/// WinDivert handle can compile within its internal instruction budget.
///
/// The returned filters are sorted by address and each one contains complete
/// request and proxy-listener clauses for its address group.  The caller may
/// open one active handle per returned string; no address is silently omitted.
pub(crate) fn build_dns_filters(config: &DnsFilterConfig) -> Result<Vec<String>, String> {
    let local_ips = validate_config(config)?;
    let udp_owned = collect_ports(&config.udp_upstreams);
    let tcp_owned = collect_ports(&config.tcp_upstreams);
    let addresses = local_ips.iter().copied().collect::<Vec<_>>();
    let mut filters = Vec::new();
    for group in addresses.chunks(MAX_FILTER_IPS) {
        let group = group.iter().copied().collect::<BTreeSet<_>>();
        filters.push(build_filter_for_ips(
            config, &group, &udp_owned, &tcp_owned,
        )?);
    }
    Ok(filters)
}

fn build_filter_for_ips(
    config: &DnsFilterConfig,
    local_ips: &BTreeSet<IpAddr>,
    udp_owned: &PortsByIp,
    tcp_owned: &PortsByIp,
) -> Result<String, String> {
    debug_assert!(!local_ips.is_empty());
    debug_assert!(local_ips.len() <= MAX_FILTER_IPS);

    let mut clauses = Vec::new();
    clauses.extend(request_clauses("udp", "udp", &local_ips, &udp_owned));
    clauses.extend(request_clauses("tcp", "tcp", &local_ips, &tcp_owned));
    let udp_listeners = config
        .udp_proxy_listeners
        .iter()
        .copied()
        .filter(|endpoint| local_ips.contains(&endpoint.ip()))
        .collect::<Vec<_>>();
    let tcp_listeners = config
        .tcp_proxy_listeners
        .iter()
        .copied()
        .filter(|endpoint| local_ips.contains(&endpoint.ip()))
        .collect::<Vec<_>>();
    clauses.extend(listener_clauses("udp", "udp", &udp_listeners));
    clauses.extend(listener_clauses("tcp", "tcp", &tcp_listeners));

    if clauses.is_empty() {
        return Err("DNS filter configuration has no proxy listener or owned upstream".into());
    }

    // Keep precedence explicit.  A single outer `outbound` applies to every
    // branch, including the exact proxy-listener branches.
    let mut filter = String::from("outbound and (");
    filter.push_str(&clauses.join(" or "));
    filter.push(')');
    if filter.len() > MAX_FILTER_BYTES {
        return Err(format!(
            "DNS interception filter exceeds {} bytes",
            MAX_FILTER_BYTES
        ));
    }
    Ok(filter)
}

/// Validate all typed inputs and return the addresses in deterministic order.
fn validate_config(config: &DnsFilterConfig) -> Result<BTreeSet<IpAddr>, String> {
    if config.local_ips.is_empty() {
        return Err("DNS filter requires at least one local IP".into());
    }
    if config.local_ips.len() > MAX_LOCAL_IPS {
        return Err(format!(
            "DNS filter supports at most {} local IPs",
            MAX_LOCAL_IPS
        ));
    }

    let mut local_ips = BTreeSet::new();
    for &ip in &config.local_ips {
        validate_ip(ip, "local IP")?;
        if !local_ips.insert(ip) {
            return Err(format!("duplicate local IP {ip}"));
        }
    }

    validate_endpoints(
        "UDP proxy listener",
        &config.udp_proxy_listeners,
        &local_ips,
        MAX_OWNED_SLOTS_PER_IP,
    )?;
    validate_endpoints(
        "TCP proxy listener",
        &config.tcp_proxy_listeners,
        &local_ips,
        MAX_OWNED_SLOTS_PER_IP,
    )?;
    validate_endpoints(
        "UDP reserved upstream",
        &config.udp_upstreams,
        &local_ips,
        MAX_OWNED_SLOTS_PER_IP,
    )?;
    validate_endpoints(
        "TCP reserved upstream",
        &config.tcp_upstreams,
        &local_ips,
        MAX_OWNED_SLOTS_PER_IP,
    )?;

    reject_ambiguous_scopes(config)?;

    validate_complete_layout(
        &local_ips,
        &config.udp_proxy_listeners,
        &config.tcp_proxy_listeners,
        &config.udp_upstreams,
        &config.tcp_upstreams,
    )?;

    reject_same_protocol_overlap("UDP", &config.udp_proxy_listeners, &config.udp_upstreams)?;
    reject_same_protocol_overlap("TCP", &config.tcp_proxy_listeners, &config.tcp_upstreams)?;

    if config.udp_proxy_listeners.is_empty()
        && config.tcp_proxy_listeners.is_empty()
        && config.udp_upstreams.is_empty()
        && config.tcp_upstreams.is_empty()
    {
        return Err("DNS filter configuration has no endpoints".into());
    }
    Ok(local_ips)
}

fn validate_endpoints(
    kind: &str,
    endpoints: &[SocketAddr],
    local_ips: &BTreeSet<IpAddr>,
    max_per_ip: usize,
) -> Result<(), String> {
    let mut exact = BTreeSet::new();
    let mut occupied = BTreeSet::<EndpointKey>::new();
    let mut count_by_ip = BTreeMap::<IpAddr, usize>::new();
    for &endpoint in endpoints {
        let ip = endpoint.ip();
        validate_ip(ip, kind)?;
        if endpoint.port() == 0 {
            return Err(format!("{kind} {endpoint} has port zero"));
        }
        if endpoint.port() == 53 {
            return Err(format!("{kind} {endpoint} may not use port 53"));
        }
        validate_scope(endpoint, kind)?;
        if !local_ips.contains(&ip) {
            return Err(format!(
                "{kind} {endpoint} uses an IP that is not in local_ips"
            ));
        }

        let scope = endpoint_scope(endpoint);
        let exact_key = (ip, scope, endpoint.port());
        if !exact.insert(exact_key) {
            return Err(format!("duplicate {kind} {endpoint}"));
        }

        // A same-protocol source address and port may not be represented with
        // two scopes.  Keeping one ownership decision avoids an ambiguous
        // exclusion on systems where outbound IfIdx is unavailable.
        if !occupied.insert((ip, endpoint.port())) {
            return Err(format!(
                "overlapping {kind} endpoint {}:{}",
                ip,
                endpoint.port()
            ));
        }
        let count = count_by_ip.entry(ip).or_default();
        *count += 1;
        if *count > max_per_ip {
            return Err(format!(
                "{kind} has more than {max_per_ip} endpoints for {ip}"
            ));
        }
    }
    Ok(())
}

fn reject_same_protocol_overlap(
    protocol: &str,
    listeners: &[SocketAddr],
    upstreams: &[SocketAddr],
) -> Result<(), String> {
    let listener_keys: BTreeSet<EndpointKey> = listeners
        .iter()
        .map(|endpoint| (endpoint.ip(), endpoint.port()))
        .collect();
    for endpoint in upstreams {
        if listener_keys.contains(&(endpoint.ip(), endpoint.port())) {
            return Err(format!(
                "{protocol} proxy listener and reserved upstream overlap at {}:{}",
                endpoint.ip(),
                endpoint.port()
            ));
        }
    }
    Ok(())
}

fn reject_ambiguous_scopes(config: &DnsFilterConfig) -> Result<(), String> {
    let mut scopes = BTreeMap::<IpAddr, BTreeSet<Option<u32>>>::new();
    for endpoint in config
        .udp_proxy_listeners
        .iter()
        .chain(config.tcp_proxy_listeners.iter())
        .chain(config.udp_upstreams.iter())
        .chain(config.tcp_upstreams.iter())
    {
        scopes
            .entry(endpoint.ip())
            .or_default()
            .insert(endpoint_scope(*endpoint));
    }
    for (ip, scopes) in scopes {
        if scopes.len() > 1 {
            return Err(format!(
                "IPv6 scope for {ip} is ambiguous across configured endpoints"
            ));
        }
    }
    Ok(())
}

fn validate_complete_layout(
    local_ips: &BTreeSet<IpAddr>,
    udp_proxy_listeners: &[SocketAddr],
    tcp_proxy_listeners: &[SocketAddr],
    udp_upstreams: &[SocketAddr],
    tcp_upstreams: &[SocketAddr],
) -> Result<(), String> {
    for &ip in local_ips {
        let expected = [
            ("UDP proxy listener", udp_proxy_listeners, 1usize),
            ("TCP proxy listener", tcp_proxy_listeners, 1usize),
            (
                "UDP reserved upstream",
                udp_upstreams,
                MAX_OWNED_SLOTS_PER_IP,
            ),
            (
                "TCP reserved upstream",
                tcp_upstreams,
                MAX_OWNED_SLOTS_PER_IP,
            ),
        ];
        for (kind, endpoints, expected_count) in expected {
            let actual = endpoints
                .iter()
                .filter(|endpoint| endpoint.ip() == ip)
                .count();
            if actual != expected_count {
                return Err(format!(
                    "{kind} requires exactly {expected_count} endpoint(s) for {ip}, found {actual}"
                ));
            }
        }
    }
    Ok(())
}

fn validate_ip(ip: IpAddr, kind: &str) -> Result<(), String> {
    let invalid = match ip {
        IpAddr::V4(ip) => ip.is_unspecified() || ip.is_multicast(),
        IpAddr::V6(ip) => ip.is_unspecified() || ip.is_multicast() || ip.to_ipv4_mapped().is_some(),
    };
    if invalid {
        return Err(format!("{kind} {ip} is unspecified, multicast, or mapped"));
    }
    Ok(())
}

fn validate_scope(endpoint: SocketAddr, kind: &str) -> Result<(), String> {
    let SocketAddr::V6(address) = endpoint else {
        return Ok(());
    };
    let scope = address.scope_id();
    if is_ipv6_link_local(*address.ip()) && scope == 0 {
        return Err(format!("{kind} {endpoint} needs a numeric IPv6 scope id"));
    }
    Ok(())
}

fn is_ipv6_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

fn endpoint_scope(endpoint: SocketAddr) -> Option<u32> {
    match endpoint {
        SocketAddr::V6(address) if address.scope_id() != 0 => Some(address.scope_id()),
        _ => None,
    }
}

fn collect_ports(endpoints: &[SocketAddr]) -> PortsByIp {
    let mut result = PortsByIp::new();
    for &endpoint in endpoints {
        result
            .entry(endpoint.ip())
            .or_default()
            .entry(endpoint_scope(endpoint))
            .or_default()
            .insert(endpoint.port());
    }
    result
}

fn request_clauses(
    protocol: &str,
    port_field_protocol: &str,
    local_ips: &BTreeSet<IpAddr>,
    owned: &PortsByIp,
) -> Vec<String> {
    local_ips
        .iter()
        .map(|&ip| {
            let source_scope = owned.get(&ip).and_then(single_scope);
            let source = address_test("SrcAddr", ip, source_scope);
            let mut clause =
                format!("({protocol} and {source} and {port_field_protocol}.DstPort == 53");
            if let Some(scoped_ports) = owned.get(&ip) {
                for port in scoped_ports.values().flat_map(BTreeSet::iter) {
                    // WinDivert's `!` grammar only negates a single TEST.
                    // De Morgan's form keeps the generated expression valid
                    // while retaining exact source-port ownership.
                    write!(clause, " and {port_field_protocol}.SrcPort != {port}").unwrap();
                }
            }
            clause.push(')');
            clause
        })
        .collect()
}

fn single_scope(scoped_ports: &ScopedPorts) -> Option<u32> {
    (scoped_ports.len() == 1)
        .then(|| scoped_ports.keys().next().copied().flatten())
        .flatten()
}

fn listener_clauses(
    protocol: &str,
    port_field_protocol: &str,
    listeners: &[SocketAddr],
) -> Vec<String> {
    let mut grouped = BTreeMap::<(IpAddr, Option<u32>), BTreeSet<u16>>::new();
    for &endpoint in listeners {
        grouped
            .entry((endpoint.ip(), endpoint_scope(endpoint)))
            .or_default()
            .insert(endpoint.port());
    }

    grouped
        .into_iter()
        .flat_map(|((ip, scope), ports)| {
            let source = address_test("SrcAddr", ip, scope);
            ports.into_iter().map(move |port| {
                format!("({protocol} and {source} and {port_field_protocol}.SrcPort == {port})")
            })
        })
        .collect()
}

fn address_test(field: &str, ip: IpAddr, scope: Option<u32>) -> String {
    let (family, address) = match ip {
        IpAddr::V4(ip) => ("ip", ip.to_string()),
        IpAddr::V6(ip) => ("ipv6", format_ipv6(ip)),
    };
    let scope_test = scope
        .map(|scope| format!(" and ifIdx == {scope}"))
        .unwrap_or_default();
    format!("{family} and {family}.{field} == {address}{scope_test}")
}

fn format_ipv6(ip: Ipv6Addr) -> String {
    // Ipv6Addr::Display never includes SocketAddrV6's scope id.  Keeping this
    // helper explicit documents that `%zone` syntax must never reach WinDivert.
    ip.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

    fn v4(value: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::from(value), port))
    }

    fn base_config() -> DnsFilterConfig {
        let mut config = DnsFilterConfig {
            local_ips: vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
            udp_proxy_listeners: vec![v4([127, 0, 0, 1], 5301)],
            tcp_proxy_listeners: vec![v4([127, 0, 0, 1], 5302)],
            udp_upstreams: Vec::new(),
            tcp_upstreams: Vec::new(),
        };
        for slot in 0..MAX_OWNED_SLOTS_PER_IP as u16 {
            config.udp_upstreams.push(v4([127, 0, 0, 1], 41001 + slot));
            config.tcp_upstreams.push(v4([127, 0, 0, 1], 42001 + slot));
        }
        config
    }

    #[test]
    fn requests_are_source_address_and_protocol_specific() {
        let filter = build_dns_filter(&base_config()).unwrap();
        assert!(filter.starts_with("outbound and ("));
        assert!(filter.contains("udp and ip and ip.SrcAddr == 127.0.0.1 and udp.DstPort == 53"));
        assert!(filter.contains("udp.SrcPort != 41001"));
        assert!(filter.contains("tcp and ip and ip.SrcAddr == 127.0.0.1 and tcp.DstPort == 53"));
        assert!(filter.contains("tcp.SrcPort != 42001"));
        assert!(filter.contains("udp and ip and ip.SrcAddr == 127.0.0.1 and udp.SrcPort == 5301"));
        assert!(filter.contains("tcp and ip and ip.SrcAddr == 127.0.0.1 and tcp.SrcPort == 5302"));
    }

    #[test]
    fn same_numeric_port_is_not_cross_protocol_exempted() {
        let mut config = base_config();
        config.udp_upstreams[0] = v4([127, 0, 0, 1], 42000);
        config.tcp_upstreams[0] = v4([127, 0, 0, 1], 42000);
        let filter = build_dns_filter(&config).unwrap();
        assert!(filter.contains("udp.SrcPort != 42000"));
        assert!(filter.contains("tcp.SrcPort != 42000"));
        assert!(!filter.contains("not ("));
    }

    #[test]
    fn same_owned_port_on_another_local_ip_is_not_exempted() {
        let mut config = base_config();
        config
            .local_ips
            .push(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));
        config.udp_proxy_listeners.push(v4([127, 0, 0, 2], 5303));
        config.tcp_proxy_listeners.push(v4([127, 0, 0, 2], 5304));
        for slot in 0..MAX_OWNED_SLOTS_PER_IP as u16 {
            config.udp_upstreams.push(v4([127, 0, 0, 2], 43001 + slot));
            config.tcp_upstreams.push(v4([127, 0, 0, 2], 44001 + slot));
        }
        let filter = build_dns_filter(&config).unwrap();
        let second_udp = filter
            .split(" or ")
            .find(|clause| {
                clause.contains("udp and ip and ip.SrcAddr == 127.0.0.2")
                    && clause.contains("udp.DstPort == 53")
            })
            .expect("second local UDP request clause");
        assert!(!second_udp.contains("41001"));
    }

    #[test]
    fn max_local_ips_and_owned_slots_remain_bounded() {
        let mut config = DnsFilterConfig {
            local_ips: Vec::new(),
            udp_proxy_listeners: Vec::new(),
            tcp_proxy_listeners: Vec::new(),
            udp_upstreams: Vec::new(),
            tcp_upstreams: Vec::new(),
        };
        for octet in 1..=16u8 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet));
            config.local_ips.push(ip);
            config
                .udp_proxy_listeners
                .push(SocketAddr::new(ip, 30000 + u16::from(octet)));
            config
                .tcp_proxy_listeners
                .push(SocketAddr::new(ip, 30100 + u16::from(octet)));
            for slot in 0..MAX_OWNED_SLOTS_PER_IP as u16 {
                config
                    .udp_upstreams
                    .push(SocketAddr::new(ip, 31000 + u16::from(octet) * 8 + slot));
                config
                    .tcp_upstreams
                    .push(SocketAddr::new(ip, 32000 + u16::from(octet) * 8 + slot));
            }
        }
        assert!(build_dns_filter(&config).is_err());
        let filters = build_dns_filters(&config).unwrap();
        assert_eq!(filters.len(), 4);
        assert!(filters.iter().all(|filter| filter.len() < MAX_FILTER_BYTES));
        let combined = filters.join("\n");
        assert!(combined.contains("10.0.0.16"));
        assert!(combined.contains("udp.SrcPort != 31135"));
        assert!(combined.contains("tcp.SrcPort != 32135"));
    }

    #[test]
    fn scoped_ipv6_uses_numeric_ifidx_without_zone_literal() {
        let ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x1234, 0, 0, 1);
        let mut config = DnsFilterConfig {
            local_ips: vec![IpAddr::V6(ip)],
            udp_proxy_listeners: vec![SocketAddr::V6(SocketAddrV6::new(ip, 5301, 0, 7))],
            tcp_proxy_listeners: vec![SocketAddr::V6(SocketAddrV6::new(ip, 5302, 0, 7))],
            udp_upstreams: Vec::new(),
            tcp_upstreams: Vec::new(),
        };
        for slot in 0..MAX_OWNED_SLOTS_PER_IP as u16 {
            config
                .udp_upstreams
                .push(SocketAddr::V6(SocketAddrV6::new(ip, 41001 + slot, 0, 7)));
            config
                .tcp_upstreams
                .push(SocketAddr::V6(SocketAddrV6::new(ip, 42001 + slot, 0, 7)));
        }
        let filter = build_dns_filter(&config).unwrap();
        assert!(filter.contains("ipv6.SrcAddr == fe80::1234:0:0:1"));
        assert!(filter.contains("ifIdx == 7"));
        assert!(!filter.contains('%'));
        config.udp_proxy_listeners[0] = SocketAddr::V6(SocketAddrV6::new(ip, 5301, 0, 0));
        assert!(build_dns_filter(&config).is_err());
    }

    #[test]
    fn malformed_and_overlapping_inputs_are_rejected() {
        let mut config = base_config();
        config
            .local_ips
            .push(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(build_dns_filter(&config).is_err());

        let mut config = base_config();
        config.udp_upstreams[0] = v4([127, 0, 0, 1], 53);
        assert!(build_dns_filter(&config).is_err());

        let mut config = base_config();
        config.tcp_upstreams[0] = v4([127, 0, 0, 2], 41002);
        assert!(build_dns_filter(&config).is_err());

        let mut config = base_config();
        config.udp_upstreams[0] = config.udp_proxy_listeners[0];
        assert!(build_dns_filter(&config).is_err());

        let mut config = base_config();
        config.local_ips = vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)];
        assert!(build_dns_filter(&config).is_err());

        let mut config = base_config();
        config.local_ips = vec![IpAddr::V6(Ipv6Addr::LOCALHOST)];
        assert!(build_dns_filter(&config).is_err());
    }
}
