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
  is_default_gateway: boolean | null;
  details?: AdapterDetails;
  route_configuration_status?: "pending" | "available" | "query_failed";
  route_configuration?: {
    source: "windows_get_ip_forward_table2"; sampled_at: number;
    routes: { destination: string; prefix_length: number; family: "ipv4" | "ipv6"; next_hop: string; route_metric: number | null; protocol_code: number; origin_code: number; is_default: boolean; valid_lifetime_seconds: number | null }[];
  } | null;
  ip_configuration_status?: "pending" | "available" | "not_available" | "query_failed";
  ip_configuration?: {
    source: "windows_get_adapters_addresses";
    sampled_at: number;
    addresses: { address: string; prefix_length: number; family: "ipv4" | "ipv6" }[];
    dns_servers: string[]; gateways: string[];
    dhcpv4_enabled: boolean;
    dhcpv4_server: string | null; dhcpv6_server: string | null;
    ipv4_metric: number; ipv6_metric: number;
  } | null;
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

export interface AdapterDetails {
  source: "windows_mib_if_row2";
  interface_guid: string;
  interface_index: number;
  mtu_bytes: number | null;
  operational_status: "up" | "down" | "testing" | "unknown" | "dormant" | "not_present" | "lower_layer_down";
  administrative_status: "up" | "down" | "testing" | "unknown";
  media_state: "connected" | "disconnected" | "unknown";
  interface_type_code: number;
  physical_medium_code: number;
  tunnel_type_code: number;
  hardware_interface: boolean;
  connector_present: boolean;
  filter_interface: boolean;
  paused: boolean;
  low_power: boolean;
  /** Driver lifetime totals; decimal strings preserve 64-bit precision. */
  counters: {
    received_bytes: string; sent_bytes: string;
    received_unicast_packets: string; sent_unicast_packets: string;
    received_non_unicast_packets: string; sent_non_unicast_packets: string;
    receive_errors: string; transmit_errors: string;
    receive_discards: string; transmit_discards: string;
    unknown_protocol_packets: string;
  };
}
