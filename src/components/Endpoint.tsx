import { useEffect, useRef, useState } from "react";
import { Copy, Check, ShieldBan, Circle, Globe, Building2 } from "lucide-react";
import type { SocketStream } from "../types";
export function Endpoint({
  socket,
  blocked,
  busy,
  canBlock,
  onBlock,
  canCapture,
  captureBusy,
  onCapture,
}: {
  socket: SocketStream;
  blocked: boolean;
  busy: boolean;
  canBlock: boolean;
  onBlock: () => void;
  canCapture?: boolean;
  captureBusy?: boolean;
  onCapture?: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  const address =
    socket.remote_ip === "*"
      ? "Remote address unavailable"
      : (socket.remote_ip.includes(":")
          ? "[" + socket.remote_ip + "]"
          : socket.remote_ip) +
        (socket.remote_port ? ":" + socket.remote_port : "");
  const tags = socket.destination_tags?.status === "known" ? socket.destination_tags.tags : null;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(address);
      setCopied(true);
      setError(false);
      clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 1800);
    } catch {
      setError(true);
    }
  };
  return (
    <div className={"endpoint" + (socket.closed_at ? " closed" : "")}>
      <div className="endpoint-main">
        <span className="endpoint-address" title={socket.remote_host ? "Reverse DNS · destination hint" : undefined}>
          {socket.remote_host && socket.remote_host !== socket.remote_ip ? socket.remote_host : address}
        </span>
        {canCapture&&<button className="icon-button" aria-label={"Capture connection " + address} title="Capture connection" disabled={captureBusy} onClick={onCapture}><Circle size={14}/></button>}
        <button
          className={"icon-button " + (blocked ? "selected" : "")}
          aria-label={
            (blocked ? "Unblock connection " : "Block connection ") + address
          }
          title={
            blocked
              ? "Unblock this connection"
              : "Block outgoing traffic for this exact connection"
          }
          disabled={busy || !canBlock}
          onClick={onBlock}
        >
          <ShieldBan size={14} />
        </button>
        {socket.remote_ip !== "*" && (
          <button
            className="icon-button"
            aria-label={"Copy " + address}
            title="Copy address"
            onClick={copy}
          >
            {copied ? <Check size={14} /> : <Copy size={14} />}
          </button>
        )}
      </div>
      <div className="endpoint-meta">
        <span>{socket.protocol}</span>
        {socket.remote_host && socket.remote_host !== socket.remote_ip && <span className="endpoint-ip">{address}</span>}
        <span>{socket.state.toLowerCase().replaceAll("_", " ")}</span>
        <span className="advanced-only">{socket.local_ip}:{socket.local_port}</span>
        {tags?.country_code && <span className="destination-tag" title={tags.country_name || "IP registration country"}><Globe size={11}/>{tags.country_code}</span>}
        {tags?.organization && <span className="destination-tag destination-organization" title={"Network operator · " + tags.organization}><Building2 size={11}/>{tags.organization}</span>}
        {tags?.asn != null && <span className="advanced-only" title={socket.destination_tags?.source || "Offline dataset"}>AS{tags.asn}</span>}
        {error && <span role="status">Select address to copy</span>}
      </div>
    </div>
  );
}
