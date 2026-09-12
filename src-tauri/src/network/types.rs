use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSnapshot {
    pub measurement_status: String,
    pub timestamp: u64,
    pub total_download_speed_bps: u64,
    pub total_upload_speed_bps: u64,
    pub total_active_connections: usize,
    pub interfaces: Vec<InterfaceInfo>,
    pub processes: Vec<ProcessTraffic>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub id: String,
    pub name: String,
    pub alias: String,
    pub interface_type: String, // "wifi", "ethernet", "loopback", "other"
    pub status: String,         // "connected", "disconnected"
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub download_speed_bps: u64,
    pub upload_speed_bps: u64,
    pub is_default_gateway: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTraffic {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub icon_data_url: Option<String>,
    pub download_speed_bps: u64,
    pub upload_speed_bps: u64,
    pub total_bytes_received: u64,
    pub total_bytes_sent: u64,
    pub active_sockets_count: usize,
    pub is_blocked: bool,
    pub is_system: bool,
    pub has_external_traffic: bool,
    pub has_unencrypted_traffic: bool,
    pub sockets: Vec<SocketStream>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketStream {
    pub id: String,
    pub protocol: String, // "TCP" or "UDP"
    pub state: String,    // "ESTABLISHED", "LISTEN", "TIME_WAIT", etc.
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub remote_host: Option<String>,
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub cloud_provider: Option<String>,
    pub service_tag: Option<String>,
    pub is_tls: bool,
    pub is_local: bool,
    pub is_muted: bool,
    pub download_speed_bps: u64,
    pub upload_speed_bps: u64,
}
