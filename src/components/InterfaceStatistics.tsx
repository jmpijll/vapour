import { ArrowLeft, ArrowDown, ArrowUp, Wifi, Cable, Network } from "lucide-react";
import type { InterfaceInfo } from "../types";
import { Rate } from "./Rate";

function linkSpeed(value?: number | null) {
  if (!value || !Number.isFinite(value) || value <= 0) return "—";
  return value >= 1e9 ? `${Number((value / 1e9).toFixed(2))} Gbps` : `${Number((value / 1e6).toFixed(1))} Mbps`;
}
export function InterfaceStatistics({ interfaces, back, advanced = false }: { interfaces: InterfaceInfo[]; back: () => void; advanced?: boolean }) {
  return <section className="settings-view view-enter">
    <div className="page-heading"><button className="back-button" onClick={back} aria-label="Back" title="Back"><ArrowLeft size={15}/></button><h1>Interfaces</h1></div>
    <div className="interface-statistics">
      {interfaces.map(item => {
        const Icon = item.interface_type === "wifi" ? Wifi : item.interface_type === "ethernet" ? Cable : Network;
        return <article className="interface-stat" key={item.id}>
          <div className="interface-stat-heading"><Icon size={19}/><div><h2>{item.alias || item.name}</h2><span className="muted">{item.status === "connected" ? "Connected" : "Disconnected"}</span></div></div>
          <p className="interface-description muted">{item.name}</p>
          <div className="interface-rates"><Rate value={item.download_speed_bps}/><Rate value={item.upload_speed_bps} up/></div>
          <div className="interface-link"><span className="muted" title="Adapter link rate reported by Windows; not internet throughput">Link speed</span><span aria-label={`Receive link speed ${linkSpeed(item.receive_link_speed_bps)}`}><ArrowDown size={13}/>{linkSpeed(item.receive_link_speed_bps)}</span><span aria-label={`Transmit link speed ${linkSpeed(item.transmit_link_speed_bps)}`}><ArrowUp size={13}/>{linkSpeed(item.transmit_link_speed_bps)}</span></div>
          {item.wifi?.status === "available" && item.wifi.value?.status === "measured" && item.wifi.value.link_quality_percent != null && <div className="wifi-quality" title="Wi-Fi link quality"><Wifi size={14}/><meter min="0" max="100" value={item.wifi.value.link_quality_percent} aria-label="Wi-Fi link quality"/><span>{item.wifi.value.link_quality_percent}%</span></div>}
          {advanced && <AdapterDetailsView item={item}/>}
        </article>;
      })}
      {!interfaces.length && <p className="detail-note">No interfaces available</p>}
    </div>
  </section>;
}

function AdapterDetailsView({item}: {item: InterfaceInfo}) {
  const d = item.details, ip = item.ip_configuration, routing = item.route_configuration;
  return <div className="adapter-details">
    <details><summary>Adapter</summary>{d ? <dl>
      <dt>State</dt><dd>{d.operational_status} · {d.administrative_status} · {d.media_state}</dd>
      <dt>MTU</dt><dd>{d.mtu_bytes ?? "—"} B</dd>
      <dt>Hardware</dt><dd>{d.hardware_interface ? "Yes" : "No"}</dd>
      <dt>Index</dt><dd>{d.interface_index}</dd>
      <dt>GUID</dt><dd>{d.interface_guid}</dd>
    </dl> : <p className="detail-note">Unavailable</p>}</details>
    {item.interface_type === "wifi" && <details><summary>Wi-Fi</summary><p className="detail-note">{item.wifi?.status || "Unavailable"}{item.wifi?.value && ` · ${item.wifi.value.status}`}</p>{item.wifi?.value && <><p className="detail-note">{item.wifi.value.phy_type || "Unknown PHY"}{item.wifi.value.is_mlo_connection ? " · MLO" : ""}</p>{item.wifi.value.links.map(link=><div className="adapter-route" key={link.link_id}>{link.center_frequency_khz/1000} MHz · {link.rssi_dbm} dBm</div>)}</>}</details>}
    <details><summary>Driver</summary><p className="detail-note">{item.driver?.status || "Unavailable"}</p>{item.driver?.value && <dl><dt>Provider</dt><dd>{item.driver.value.provider || "—"}</dd><dt>Version</dt><dd>{item.driver.value.version || "—"}</dd><dt>Date</dt><dd>{item.driver.value.date || "—"}</dd></dl>}</details>
    <details><summary>IP configuration</summary><p className="detail-note">{item.ip_configuration_status || "Unavailable"}{ip && ` · ${new Date(ip.sampled_at).toLocaleTimeString()}`}</p>{ip && <dl>
      <dt>Addresses</dt><dd>{ip.addresses.map(a=><div key={`${a.address}/${a.prefix_length}`}>{a.address}/{a.prefix_length}</div>)}</dd>
      <dt>DNS</dt><dd>{ip.dns_servers.join(", ") || "—"}</dd>
      <dt>Gateways</dt><dd>{ip.gateways.join(", ") || "—"}</dd>
      <dt>DHCPv4</dt><dd>{ip.dhcpv4_enabled ? "Enabled" : "Disabled"}{ip.dhcpv4_server && ` · ${ip.dhcpv4_server}`}</dd>
      <dt>DHCPv6 server</dt><dd>{ip.dhcpv6_server || "—"}</dd>
      <dt>Interface metric</dt><dd>IPv4 {ip.ipv4_metric} · IPv6 {ip.ipv6_metric}</dd>
    </dl>}</details>
    <details><summary>Routes{routing ? ` · ${routing.routes.length}` : ""}</summary><p className="detail-note">{item.route_configuration_status || "Unavailable"}{routing && ` · ${new Date(routing.sampled_at).toLocaleTimeString()}`}</p>{routing?.routes.map((r,index)=><div className="adapter-route" key={index}><div>{r.destination}/{r.prefix_length} → {r.next_hop}</div><span className="muted">{r.is_default ? "Default · " : ""}Metric {r.route_metric ?? "—"}</span></div>)}</details>
    <details><summary>Counters</summary>{d ? <dl>{Object.entries(d.counters).map(([key,value])=><div className="counter-pair" key={key}><dt>{key.replaceAll("_", " ")}</dt><dd>{value}</dd></div>)}</dl> : <p className="detail-note">Unavailable</p>}</details>
  </div>;
}
