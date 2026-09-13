export interface NetworkSnapshot {
  measurement_status?: string;
  timestamp: number;
  total_download_speed_bps: number;
  total_upload_speed_bps: number;
  total_active_connections: number;
  interfaces: InterfaceInfo[];
  processes: ProcessTraffic[];
}

export interface InterfaceInfo {
  id: string;
  name: string;
  alias: string;
  interface_type: 'wifi' | 'ethernet' | 'loopback' | 'other' | string;
  status: 'connected' | 'disconnected' | string;
  ipv4?: string | null;
  ipv6?: string | null;
  download_speed_bps: number;
  upload_speed_bps: number;
  receive_link_speed_bps?: number | null;
  transmit_link_speed_bps?: number | null;
  is_default_gateway: boolean;
}

export interface ProcessTraffic {
  pid: number;
  name: string;
  displayName?: string;
  path: string;
  icon_data_url?: string | null;
  download_speed_bps: number;
  upload_speed_bps: number;
  total_bytes_received: number;
  total_bytes_sent: number;
  active_sockets_count: number;
  is_blocked: boolean;
  is_system: boolean;
  has_external_traffic: boolean;
  has_unencrypted_traffic: boolean;
  sockets: SocketStream[];
}

export interface SocketStream {
  closed_at?: number;
  id: string;
  protocol: string;
  state: string;
  local_ip: string;
  local_port: number;
  remote_ip: string;
  remote_port: number;
  remote_host?: string | null;
  country_code?: string | null;
  country_name?: string | null;
  cloud_provider?: string | null;
  service_tag?: string | null;
  is_tls: boolean;
  is_local: boolean;
  is_muted: boolean;
  download_speed_bps: number;
  upload_speed_bps: number;
}
