import { ArrowLeft, ArrowDown, ArrowUp, Wifi, Cable, Network } from "lucide-react";
import type { InterfaceInfo } from "../types";
import { Rate } from "./Rate";

function linkSpeed(value?: number | null) {
  if (!value || !Number.isFinite(value) || value <= 0) return "—";
  return value >= 1e9 ? `${Number((value / 1e9).toFixed(2))} Gbps` : `${Number((value / 1e6).toFixed(1))} Mbps`;
}
export function InterfaceStatistics({ interfaces, back }: { interfaces: InterfaceInfo[]; back: () => void }) {
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
        </article>;
      })}
      {!interfaces.length && <p className="detail-note">No interfaces available</p>}
    </div>
  </section>;
}
