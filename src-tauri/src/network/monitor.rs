use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStringExt;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use windows::Win32::Foundation::{BOOL, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetExtendedTcpTable, GetExtendedUdpTable, GetIfTable2, MIB_IF_ROW2,
    MIB_IF_TABLE2, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID,
    MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows::Win32::System::ProcessStatus::GetProcessImageFileNameW;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::enricher::TrafficEnricher;
use super::icon::IconExtractor;
use super::types::{InterfaceInfo, NetworkSnapshot, ProcessTraffic, SocketStream};

struct InterfaceDelta {
    in_octets: u64,
    out_octets: u64,
    timestamp: Instant,
}

pub struct NetworkMonitor {
    enricher: Arc<TrafficEnricher>,
    icon_extractor: Arc<IconExtractor>,
    if_history: Mutex<HashMap<u64, InterfaceDelta>>,
    muted_streams: Mutex<HashSet<String>>,
    process_names_cache: Mutex<HashMap<u32, (String, String)>>,
    usage: super::usage::UsageCollector,
    firewall_cache: Mutex<Option<(Instant, HashSet<String>)>>,
}

impl NetworkMonitor {
    pub fn new() -> Self {
        Self {
            enricher: Arc::new(TrafficEnricher::new()),
            icon_extractor: Arc::new(IconExtractor::new()),
            if_history: Mutex::new(HashMap::new()),
            muted_streams: Mutex::new(HashSet::new()),
            process_names_cache: Mutex::new(HashMap::new()),
            usage: super::usage::UsageCollector::new(),
            firewall_cache: Mutex::new(None),
        }
    }

    pub fn stop(&self) {
        self.usage.stop();
    }

    pub fn set_stream_muted(&self, stream_id: String, muted: bool) {
        let mut set = self.muted_streams.lock();
        if muted {
            set.insert(stream_id);
        } else {
            set.remove(&stream_id);
        }
    }

    pub fn capture_snapshot(&self) -> NetworkSnapshot {
        let now = Instant::now();
        let (interfaces, total_down_bps, total_up_bps) = self.sample_interfaces(now);
        let raw_sockets = self.sample_all_sockets();
        let processes = self.build_process_traffic(raw_sockets);

        let total_active_connections = processes.iter().map(|p| p.active_sockets_count).sum();

        NetworkSnapshot {
            measurement_status: self.usage.status.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            total_download_speed_bps: total_down_bps,
            total_upload_speed_bps: total_up_bps,
            total_active_connections,
            interfaces,
            processes,
        }
    }

    fn sample_interfaces(&self, now: Instant) -> (Vec<InterfaceInfo>, u64, u64) {
        let mut interfaces = Vec::new();
        let mut total_down = 0u64;
        let mut total_up = 0u64;

        unsafe {
            let mut table_ptr: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
            if GetIfTable2(&mut table_ptr).0 == NO_ERROR.0 && !table_ptr.is_null() {
                let table = &*table_ptr;
                let num_entries = table.NumEntries as usize;
                let rows_slice =
                    std::slice::from_raw_parts(&table.Table[0] as *const MIB_IF_ROW2, num_entries);

                let mut history = self.if_history.lock();

                for row in rows_slice {
                    // Filter out non-operational or internal loopback interface clutter
                    let if_index = row.InterfaceIndex as u64;
                    let if_type = row.Type; // 6 = Ethernet, 71 = Wi-Fi, 24 = Loopback
                    let type_str = match if_type {
                        71 => "wifi",
                        6 => "ethernet",
                        24 => "loopback",
                        _ => "other",
                    };

                    let is_connected = row.OperStatus.0 == 1; // 1 = IfOperStatusUp
                    let alias_raw = &row.Alias;
                    let alias = string_from_wide_null_terminated(alias_raw);
                    let desc_raw = &row.Description;
                    let desc = string_from_wide_null_terminated(desc_raw);

                    let in_octets = row.InOctets;
                    let out_octets = row.OutOctets;

                    let mut down_bps = 0u64;
                    let mut up_bps = 0u64;

                    if let Some(prev) = history.get(&if_index) {
                        let elapsed_sec = now.duration_since(prev.timestamp).as_secs_f64();
                        if elapsed_sec > 0.05 {
                            let in_diff = in_octets.saturating_sub(prev.in_octets);
                            let out_diff = out_octets.saturating_sub(prev.out_octets);
                            down_bps = (in_diff as f64 / elapsed_sec) as u64;
                            up_bps = (out_diff as f64 / elapsed_sec) as u64;
                        }
                    }

                    history.insert(
                        if_index,
                        InterfaceDelta {
                            in_octets,
                            out_octets,
                            timestamp: now,
                        },
                    );

                    // Skip loopback from total WAN calculation
                    if if_type != 24 && is_connected {
                        total_down += down_bps;
                        total_up += up_bps;
                    }

                    interfaces.push(InterfaceInfo {
                        id: format!("if-{}", if_index),
                        name: desc,
                        alias,
                        interface_type: type_str.to_string(),
                        status: if is_connected {
                            "connected".to_string()
                        } else {
                            "disconnected".to_string()
                        },
                        ipv4: None,
                        ipv6: None,
                        download_speed_bps: down_bps,
                        upload_speed_bps: up_bps,
                        is_default_gateway: if_type == 71 || if_type == 6,
                    });
                }

                FreeMibTable(table_ptr as *const _);
            }
        }

        // Sort interfaces: connected physical adapters first
        interfaces.sort_by(|a, b| {
            let rank = |i: &InterfaceInfo| match (i.status.as_str(), i.interface_type.as_str()) {
                ("connected", "wifi") => 0,
                ("connected", "ethernet") => 1,
                ("connected", _) => 2,
                _ => 3,
            };
            rank(a).cmp(&rank(b))
        });

        (interfaces, total_down, total_up)
    }

    fn sample_all_sockets(&self) -> Vec<RawSocketRow> {
        let mut sockets = Vec::new();
        sockets.extend(sample_tcp_v4());
        sockets.extend(sample_tcp_v6());
        sockets.extend(sample_udp_v4());
        sockets.extend(sample_udp_v6());
        sockets
    }

    fn build_process_traffic(&self, raw_sockets: Vec<RawSocketRow>) -> Vec<ProcessTraffic> {
        let muted = self.muted_streams.lock();
        let mut proc_map: HashMap<u32, Vec<SocketStream>> = HashMap::new();

        for raw in raw_sockets {
            let is_muted = muted.contains(&raw.id);
            let enriched = self.enricher.enrich(&raw.remote_ip, raw.remote_port);

            let stream = SocketStream {
                id: raw.id,
                protocol: raw.protocol,
                state: raw.state,
                local_ip: raw.local_ip,
                local_port: raw.local_port,
                remote_ip: raw.remote_ip,
                remote_port: raw.remote_port,
                remote_host: enriched.host,
                country_code: enriched.country_code,
                country_name: enriched.country_name,
                cloud_provider: enriched.cloud_provider,
                service_tag: enriched.service_tag,
                is_tls: enriched.is_tls,
                is_local: enriched.is_local,
                is_muted,
                download_speed_bps: 0,
                upload_speed_bps: 0,
            };

            proc_map.entry(raw.pid).or_default().push(stream);
        }

        let mut processes = Vec::new();

        let usage = self.usage.sample();
        for &pid in usage.keys() {
            proc_map.entry(pid).or_default();
        }
        let blocked_rules = {
            let mut cache = self.firewall_cache.lock();
            if cache
                .as_ref()
                .map_or(true, |(at, _)| at.elapsed().as_secs() >= 30)
            {
                *cache = Some((
                    Instant::now(),
                    crate::firewall::FirewallManager::get_blocked_rules(),
                ));
            }
            cache.as_ref().unwrap().1.clone()
        };
        let toolhelp_map = snapshot_all_process_names();
        self.process_names_cache.lock().retain(|pid, (name, _)| {
            toolhelp_map
                .get(pid)
                .is_some_and(|current| current.eq_ignore_ascii_case(name))
        });

        for (pid, sockets) in proc_map {
            let (name, path) = self.resolve_process_identity(pid, &toolhelp_map);
            let icon_data_url = self.icon_extractor.get_icon_data_url(&path);

            let active_count = sockets.len();
            let external_count = sockets.iter().filter(|s| !s.is_local).count();
            let unencrypted_count = sockets
                .iter()
                .filter(|s| !s.is_local && !s.is_tls && s.state == "ESTABLISHED")
                .count();

            let measured = usage.get(&pid).cloned().unwrap_or_default();
            let proc_down = measured.down;
            let proc_up = measured.up;

            let is_blocked =
                blocked_rules.contains(&crate::firewall::rule_id(&crate::firewall::BlockTarget {
                    path: path.clone(),
                    remote_ip: None,
                    remote_port: None,
                    local_ip: None,
                    local_port: None,
                    protocol: None,
                }));

            let is_system = pid <= 4
                || name.eq_ignore_ascii_case("system")
                || name.eq_ignore_ascii_case("ntoskrnl.exe")
                || name.eq_ignore_ascii_case("svchost.exe")
                || name.eq_ignore_ascii_case("services.exe")
                || name.eq_ignore_ascii_case("lsass.exe")
                || name.eq_ignore_ascii_case("csrss.exe")
                || name.eq_ignore_ascii_case("smss.exe")
                || name.eq_ignore_ascii_case("wininit.exe")
                || name.eq_ignore_ascii_case("SearchIndexer.exe");

            processes.push(ProcessTraffic {
                pid,
                name,
                path,
                icon_data_url,
                download_speed_bps: proc_down,
                upload_speed_bps: proc_up,
                total_bytes_received: measured.received,
                total_bytes_sent: measured.sent,
                active_sockets_count: active_count,
                is_blocked,
                is_system,
                has_external_traffic: external_count > 0,
                has_unencrypted_traffic: unencrypted_count > 0,
                sockets,
            });
        }

        // Sort processes: by download rate descending, then active sockets count
        processes.sort_by(|a, b| {
            b.download_speed_bps
                .cmp(&a.download_speed_bps)
                .then_with(|| b.active_sockets_count.cmp(&a.active_sockets_count))
        });

        processes
    }

    fn resolve_process_identity(
        &self,
        pid: u32,
        toolhelp_map: &HashMap<u32, String>,
    ) -> (String, String) {
        if pid == 0 {
            return ("System Idle Process".to_string(), "".to_string());
        }
        if pid == 4 {
            return (
                "System".to_string(),
                "C:\\Windows\\System32\\ntoskrnl.exe".to_string(),
            );
        }

        if let Some(cached) = self.process_names_cache.lock().get(&pid) {
            return cached.clone();
        }

        let mut name = format!("PID: {}", pid);
        let mut path = String::new();

        unsafe {
            if let Ok(handle) = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION,
                false,
                pid,
            ) {
                let mut buffer = [0u16; 1024];
                let mut size = buffer.len() as u32;
                if QueryFullProcessImageNameW(
                    handle,
                    PROCESS_NAME_FORMAT(0),
                    windows::core::PWSTR(buffer.as_mut_ptr()),
                    &mut size,
                )
                .is_ok()
                    && size > 0
                {
                    path = OsString::from_wide(&buffer[..size as usize])
                        .to_string_lossy()
                        .into_owned();
                    if let Some(filename) = std::path::Path::new(&path).file_name() {
                        name = filename.to_string_lossy().into_owned();
                    }
                } else {
                    let mut dev_buf = [0u16; 1024];
                    let len = GetProcessImageFileNameW(handle, &mut dev_buf);
                    if len > 0 {
                        let dev_path = OsString::from_wide(&dev_buf[..len as usize])
                            .to_string_lossy()
                            .into_owned();
                        if let Some(filename) = std::path::Path::new(&dev_path).file_name() {
                            name = filename.to_string_lossy().into_owned();
                        }
                    }
                }
                let _ = windows::Win32::Foundation::CloseHandle(handle);
            }
        }

        // Fallback to ToolHelp process snapshot if OpenProcess was restricted (e.g. system services)
        if (name.starts_with("PID:") || path.is_empty()) && toolhelp_map.contains_key(&pid) {
            let found_name = toolhelp_map[&pid].clone();
            if !found_name.is_empty() {
                name = found_name.clone();
                if path.is_empty() {
                    let sys32_test = format!("C:\\Windows\\System32\\{}", found_name);
                    if std::path::Path::new(&sys32_test).exists() {
                        path = sys32_test;
                    }
                }
            }
        }

        self.process_names_cache
            .lock()
            .insert(pid, (name.clone(), path.clone()));
        (name, path)
    }
}

fn snapshot_all_process_names() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    unsafe {
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            let mut entry = PROCESSENTRY32W::default();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let pid = entry.th32ProcessID;
                    let name_len = entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len());
                    let name = OsString::from_wide(&entry.szExeFile[..name_len])
                        .to_string_lossy()
                        .into_owned();

                    if !name.is_empty() {
                        map.insert(pid, name);
                    }

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = windows::Win32::Foundation::CloseHandle(snapshot);
        }
    }
    map
}

fn string_from_wide_null_terminated(slice: &[u16]) -> String {
    let len = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    OsString::from_wide(&slice[..len])
        .to_string_lossy()
        .into_owned()
}

struct RawSocketRow {
    id: String,
    pid: u32,
    protocol: String,
    state: String,
    local_ip: String,
    local_port: u16,
    remote_ip: String,
    remote_port: u16,
}

fn tcp_state_to_str(state: u32) -> &'static str {
    match state {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT_1",
        7 => "FIN_WAIT_2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

fn sample_tcp_v4() -> Vec<RawSocketRow> {
    let mut rows = Vec::new();
    unsafe {
        let mut size = 0u32;
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            BOOL(1),
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if size > 0 {
            let mut buf = vec![0u8; size as usize];
            if GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                BOOL(1),
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            ) == NO_ERROR.0
            {
                let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                let num_entries = table.dwNumEntries as usize;
                let items = std::slice::from_raw_parts(
                    &table.table[0] as *const MIB_TCPROW_OWNER_PID,
                    num_entries,
                );

                for item in items {
                    let local_ip = Ipv4Addr::from(u32::from_be(item.dwLocalAddr)).to_string();
                    let local_port = u16::from_be(item.dwLocalPort as u16);
                    let remote_ip = Ipv4Addr::from(u32::from_be(item.dwRemoteAddr)).to_string();
                    let remote_port = u16::from_be(item.dwRemotePort as u16);
                    let state = tcp_state_to_str(item.dwState);

                    let id = format!(
                        "tcp4-{}-{}:{}-{}:{}",
                        item.dwOwningPid, local_ip, local_port, remote_ip, remote_port
                    );

                    rows.push(RawSocketRow {
                        id,
                        pid: item.dwOwningPid,
                        protocol: "TCP".to_string(),
                        state: state.to_string(),
                        local_ip,
                        local_port,
                        remote_ip,
                        remote_port,
                    });
                }
            }
        }
    }
    rows
}

fn sample_tcp_v6() -> Vec<RawSocketRow> {
    let mut rows = Vec::new();
    unsafe {
        let mut size = 0u32;
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            BOOL(1),
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if size > 0 {
            let mut buf = vec![0u8; size as usize];
            if GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                BOOL(1),
                AF_INET6.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            ) == NO_ERROR.0
            {
                let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
                let num_entries = table.dwNumEntries as usize;
                let items = std::slice::from_raw_parts(
                    &table.table[0] as *const MIB_TCP6ROW_OWNER_PID,
                    num_entries,
                );

                for item in items {
                    let local_ip = Ipv6Addr::from(item.ucLocalAddr).to_string();
                    let local_port = u16::from_be(item.dwLocalPort as u16);
                    let remote_ip = Ipv6Addr::from(item.ucRemoteAddr).to_string();
                    let remote_port = u16::from_be(item.dwRemotePort as u16);
                    let state = tcp_state_to_str(item.dwState);

                    let id = format!(
                        "tcp6-{}-{}:{}-{}:{}",
                        item.dwOwningPid, local_ip, local_port, remote_ip, remote_port
                    );

                    rows.push(RawSocketRow {
                        id,
                        pid: item.dwOwningPid,
                        protocol: "TCP".to_string(),
                        state: state.to_string(),
                        local_ip,
                        local_port,
                        remote_ip,
                        remote_port,
                    });
                }
            }
        }
    }
    rows
}

fn sample_udp_v4() -> Vec<RawSocketRow> {
    let mut rows = Vec::new();
    unsafe {
        let mut size = 0u32;
        let _ = GetExtendedUdpTable(
            None,
            &mut size,
            BOOL(1),
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if size > 0 {
            let mut buf = vec![0u8; size as usize];
            if GetExtendedUdpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                BOOL(1),
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            ) == NO_ERROR.0
            {
                let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
                let num_entries = table.dwNumEntries as usize;
                let items = std::slice::from_raw_parts(
                    &table.table[0] as *const MIB_UDPROW_OWNER_PID,
                    num_entries,
                );

                for item in items {
                    let local_ip = Ipv4Addr::from(u32::from_be(item.dwLocalAddr)).to_string();
                    let local_port = u16::from_be(item.dwLocalPort as u16);
                    let id = format!("udp4-{}-{}:{}-*", item.dwOwningPid, local_ip, local_port);

                    rows.push(RawSocketRow {
                        id,
                        pid: item.dwOwningPid,
                        protocol: "UDP".to_string(),
                        state: "ACTIVE".to_string(),
                        local_ip,
                        local_port,
                        remote_ip: "*".to_string(),
                        remote_port: 0,
                    });
                }
            }
        }
    }
    rows
}

fn sample_udp_v6() -> Vec<RawSocketRow> {
    let mut rows = Vec::new();
    unsafe {
        let mut size = 0u32;
        let _ = GetExtendedUdpTable(
            None,
            &mut size,
            BOOL(1),
            AF_INET6.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if size > 0 {
            let mut buf = vec![0u8; size as usize];
            if GetExtendedUdpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                BOOL(1),
                AF_INET6.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            ) == NO_ERROR.0
            {
                let table = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
                let num_entries = table.dwNumEntries as usize;
                let items = std::slice::from_raw_parts(
                    &table.table[0] as *const MIB_UDP6ROW_OWNER_PID,
                    num_entries,
                );

                for item in items {
                    let local_ip = Ipv6Addr::from(item.ucLocalAddr).to_string();
                    let local_port = u16::from_be(item.dwLocalPort as u16);
                    let id = format!("udp6-{}-{}:{}-*", item.dwOwningPid, local_ip, local_port);

                    rows.push(RawSocketRow {
                        id,
                        pid: item.dwOwningPid,
                        protocol: "UDP".to_string(),
                        state: "ACTIVE".to_string(),
                        local_ip,
                        local_port,
                        remote_ip: "*".to_string(),
                        remote_port: 0,
                    });
                }
            }
        }
    }
    rows
}

/// Fresh ownership table check, without sampling throughput or retaining closed sockets.
pub fn established_socket_exists(id: &str) -> bool {
    sample_tcp_v4().into_iter().chain(sample_tcp_v6()).any(|s|s.id==id && s.state=="ESTABLISHED")
}
